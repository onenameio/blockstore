// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//!
//! The `AtlasDB` stores `Attachment` and `AttachmentInstance` objects.
//! `AttachmentInstance` objects indicate what corresponding `Attachment`
//! data a node is interesting in fetching and storing.
//!
//! In the `AtlasDB`, `AttachmentInstance` objects have a status field
//! and an availability field. The status field indicates whether or
//! not the attachment instance has been checked by the
//! `AttachmentDownloader`. The `AttachmentDownloader` does not
//! immediately check entries before insertion in the database:
//! Atlas event processing and downloader logic proceed in
//! different threads.
//!
//! Once the `AttachmentDownloader` checks an attachment instance, it
//! either marks the instance as available (if the content data is
//! already stored on the node) or it adds the attachment instance
//! to its download queue.
//!

use std::collections::HashSet;
use std::fs;

use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite::types::{FromSql, FromSqlError, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, Transaction};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util;
use stacks_common::util::hash::{bin_bytes, hex_bytes, to_bin, to_hex, Hash160};
use stacks_common::util::log;
use stacks_common::util::macros::is_big_endian;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};

use super::{AtlasConfig, Attachment, AttachmentInstance};
use crate::burnchains::Txid;
use crate::util_lib::db::{
    query_count, query_int, query_row, query_rows, sqlite_open, tx_begin_immediate, u64_to_sql,
    DBConn, Error as db_error, FromColumn, FromRow,
};

pub const ATLASDB_VERSION: &str = "2";

/// The maximum number of atlas attachment instances that should be
/// checked at once (this is used to limit the return size of
/// `queued_attachments`). Because these checks will sometimes surface
/// existing attachment data associated with those instances, the
/// memory impact of these checks is not limited to the
/// AttachmentInstance size (which is small), but can include the
/// Attachment as well (which is larger).
pub const MAX_PROCESS_PER_ROUND: u32 = 1_000;

const ATLASDB_INITIAL_SCHEMA: &[&str] = &[
    r#"
    CREATE TABLE attachments(
        hash TEXT UNIQUE PRIMARY KEY,
        content BLOB NOT NULL,
        was_instantiated INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    );"#,
    r#"
    CREATE TABLE attachment_instances(
        content_hash TEXT,
        created_at INTEGER NOT NULL,
        index_block_hash STRING NOT NULL,
        attachment_index INTEGER NOT NULL,
        block_height INTEGER NOT NULL,
        is_available INTEGER NOT NULL,
        metadata TEXT NOT NULL,
        contract_id STRING NOT NULL,
        tx_id STRING NOT NULL,
        PRIMARY KEY(index_block_hash, contract_id, attachment_index)
    );"#,
    "CREATE TABLE db_config(version TEXT NOT NULL);",
];

const ATLASDB_SCHEMA_2: &[&str] = &[
    // We have to allow status to be null, because SQLite won't let us add
    //  a not null column without a default. The default defeats the point of
    //  having not-null here anyways, so we leave this field nullable.
    r#"
    ALTER TABLE attachment_instances
    ADD status INTEGER
    ;"#,
    // All of the attachment instances that previously existed in the database
    //  already were "checked", so set status to 2 (which corresponds to "checked").
    r#"
    UPDATE attachment_instances SET status = 2;
    "#,
];

const ATLASDB_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS index_was_instantiated ON attachments(was_instantiated);",
    "CREATE INDEX IF NOT EXISTS index_instance_status ON attachment_instances(status);",
];

/// Attachment instances pass through different states once written to the AtlasDB.
/// These instances are initially written as a new Stacks block is processed, and marked
/// as `Queued`. These queued instances contain all the data of the new attachment instance,
/// but they have not yet been checked against the AtlasDB to determine if there is extant
/// Attachment content/data associated with them. The network run loop (`p2p` thread) checks
/// for any queued attachment instances on each pass, and performs that check. Once the check
/// is completed, any checked instances are updated to `Checked`.
pub enum AttachmentInstanceStatus {
    /// This variant indicates that the attachments instance has been written,
    /// but the AtlasDownloader has not yet checked that the attachment matched
    Queued,
    /// This variant indicates that the attachments instance has been written,
    /// and checked for whether or not an already existing attachment matched
    Checked,
}

impl FromRow<Attachment> for Attachment {
    fn from_row(row: &Row) -> Result<Attachment, db_error> {
        let content: Vec<u8> = row.get_unwrap("content");
        Ok(Attachment { content })
    }
}

impl FromRow<AttachmentInstance> for AttachmentInstance {
    fn from_row(row: &Row) -> Result<AttachmentInstance, db_error> {
        let hex_content_hash: String = row.get_unwrap("content_hash");
        let attachment_index: u32 = row.get_unwrap("attachment_index");
        let block_height =
            u64::from_column(row, "block_height").map_err(|_| db_error::TypeError)?;
        let content_hash = Hash160::from_hex(&hex_content_hash).map_err(|_| db_error::TypeError)?;
        let index_block_hash = StacksBlockId::from_column(row, "index_block_hash")?;
        let metadata: String = row.get_unwrap("metadata");
        let contract_id = QualifiedContractIdentifier::from_column(row, "contract_id")?;
        let hex_tx_id: String = row.get_unwrap("tx_id");
        let tx_id = Txid::from_hex(&hex_tx_id).map_err(|_| db_error::TypeError)?;

        Ok(AttachmentInstance {
            content_hash,
            attachment_index,
            index_block_hash,
            stacks_block_height: block_height,
            metadata,
            contract_id,
            tx_id,
            canonical_stacks_tip_height: None,
        })
    }
}

impl FromRow<(u32, u32)> for (u32, u32) {
    fn from_row(row: &Row) -> Result<(u32, u32), db_error> {
        let t1: u32 = row.get_unwrap(0);
        let t2: u32 = row.get_unwrap(1);
        Ok((t1, t2))
    }
}

impl ToSql for AttachmentInstanceStatus {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>, rusqlite::Error> {
        let integer_rep: i64 = match self {
            AttachmentInstanceStatus::Queued => 1,
            AttachmentInstanceStatus::Checked => 2,
        };
        Ok(integer_rep.into())
    }
}

impl FromSql for AttachmentInstanceStatus {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        let integer_rep: i64 = value.as_i64()?;
        match integer_rep {
            1 => Ok(AttachmentInstanceStatus::Queued),
            2 => Ok(AttachmentInstanceStatus::Checked),
            x => Err(FromSqlError::OutOfRange(x)),
        }
    }
}

#[derive(Debug)]
pub struct AtlasDB {
    pub atlas_config: AtlasConfig,
    pub conn: Connection,
    pub readwrite: bool,
}

impl AtlasDB {
    fn add_indexes(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        for row_text in ATLASDB_INDEXES {
            tx.execute_batch(row_text).map_err(db_error::SqliteError)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Get the database schema version, given a DB connection
    fn get_schema_version(conn: &Connection) -> Result<String, db_error> {
        let version = conn.query_row("SELECT MAX(version) from db_config", NO_PARAMS, |row| {
            row.get(0)
        })?;
        Ok(version)
    }

    fn instantiate(&mut self) -> Result<(), db_error> {
        let genesis_attachments = self.atlas_config.genesis_attachments.take();

        let tx = self.tx_begin()?;

        for row_text in ATLASDB_INITIAL_SCHEMA {
            tx.execute_batch(row_text)?;
        }
        for row_text in ATLASDB_SCHEMA_2 {
            tx.execute_batch(row_text)?;
        }

        tx.execute(
            "INSERT INTO db_config (version) VALUES (?1)",
            params![ATLASDB_VERSION],
        )?;

        if let Some(attachments) = genesis_attachments {
            let now = util::get_epoch_time_secs() as i64;
            for attachment in attachments {
                tx.execute(
                    "INSERT INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 1, ?)",
                    params![
                        attachment.hash(),
                        attachment.content,
                        now,
                    ],
                )
                .map_err(db_error::SqliteError)?;
            }
        }

        tx.commit().map_err(db_error::SqliteError)?;

        self.add_indexes()?;
        Ok(())
    }

    pub fn should_keep_attachment(
        &self,
        contract_id: &QualifiedContractIdentifier,
        attachment: &Attachment,
    ) -> bool {
        if !self.atlas_config.contracts.contains(contract_id) {
            info!(
                "Atlas: will discard posted attachment - {} not in supported contracts",
                contract_id
            );
            return false;
        }
        if attachment.content.len() as u32 > self.atlas_config.attachments_max_size {
            info!("Atlas: will discard posted attachment - attachment too large");
            return false;
        }
        true
    }

    // Open the burn database at the given path.  Open read-only or read/write.
    // If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(
        atlas_config: AtlasConfig,
        path: &str,
        readwrite: bool,
    ) -> Result<AtlasDB, db_error> {
        let mut create_flag = false;
        let open_flags = if fs::metadata(path).is_err() {
            // need to create
            if readwrite {
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(db_error::NoDBError);
            }
        } else if readwrite {
            // can just open
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = sqlite_open(path, open_flags, false)?;
        Self::check_instantiate_db(atlas_config, conn, readwrite, create_flag)
    }

    /// Inner method for instantiating the db if necessary, updating the schema, or adding indexes
    fn check_instantiate_db(
        atlas_config: AtlasConfig,
        conn: Connection,
        readwrite: bool,
        create_flag: bool,
    ) -> Result<AtlasDB, db_error> {
        let mut db = AtlasDB {
            atlas_config,
            conn,
            readwrite,
        };
        if create_flag {
            db.instantiate()?;
        }
        if readwrite {
            db.check_schema_version_and_update()?;
            db.add_indexes()?;
        } else {
            db.check_schema_version_or_error()?;
        }

        Ok(db)
    }

    fn check_schema_version_or_error(&mut self) -> Result<(), db_error> {
        match Self::get_schema_version(self.conn()) {
            Ok(version) => {
                let expected_version = ATLASDB_VERSION.to_string();
                if version == expected_version {
                    Ok(())
                } else {
                    let version = version.parse().expect(
                        "Invalid schema version for AtlasDB: should be a parseable integer",
                    );
                    Err(db_error::OldSchema(version))
                }
            }
            Err(e) => panic!("Error obtaining the version of the Atlas DB: {:?}", e),
        }
    }

    fn apply_schema_2(db_conn: &Connection) -> Result<(), db_error> {
        for row_text in ATLASDB_SCHEMA_2 {
            db_conn.execute_batch(row_text)?;
        }

        db_conn.execute(
            "INSERT OR REPLACE INTO db_config (version) VALUES (?1)",
            params!["2"],
        )?;

        Ok(())
    }

    fn check_schema_version_and_update(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        match AtlasDB::get_schema_version(&tx) {
            Ok(version) => {
                let expected_version = ATLASDB_VERSION.to_string();
                if version == expected_version {
                    return Ok(());
                }
                if version == "1" {
                    Self::apply_schema_2(&tx)?;
                    tx.commit()?;
                    Ok(())
                } else {
                    panic!("The schema version of the Atlas DB is invalid.")
                }
            }
            Err(e) => panic!("Error obtaining the version of the Atlas DB: {:?}", e),
        }
    }

    // Open an atlas database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_memory(atlas_config: AtlasConfig) -> Result<AtlasDB, db_error> {
        let conn = Connection::open_in_memory().map_err(db_error::SqliteError)?;
        let mut db = AtlasDB {
            atlas_config,
            conn,
            readwrite: true,
        };

        db.instantiate()?;
        Ok(db)
    }

    #[cfg(test)]
    /// Only ever to be used in testing, open and instantiate a V1 atlasdb
    pub fn connect_memory_db_v1(atlas_config: AtlasConfig) -> Result<AtlasDB, db_error> {
        let conn = Connection::open_in_memory()?;
        let mut db = AtlasDB {
            atlas_config,
            conn,
            readwrite: true,
        };

        let genesis_attachments = db.atlas_config.genesis_attachments.take();

        let tx = db.tx_begin()?;

        for row_text in ATLASDB_INITIAL_SCHEMA {
            tx.execute_batch(row_text)?;
        }

        tx.execute("INSERT INTO db_config (version) VALUES (?1)", params!["1"])?;

        if let Some(attachments) = genesis_attachments {
            let now = util::get_epoch_time_secs() as i64;
            for attachment in attachments {
                tx.execute(
                    "INSERT INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 1, ?)",
                    params![
                        attachment.hash(),
                        attachment.content,
                        now,
                    ],
                )?;
            }
        }

        tx.commit()?;

        let tx = db.tx_begin()?;
        for row_text in &ATLASDB_INDEXES[0..1] {
            tx.execute_batch(row_text)?;
        }
        tx.commit()?;

        Ok(db)
    }

    #[cfg(test)]
    /// Only ever to be used in testing, connect to db, but using existing sqlconn
    pub fn connect_with_sqlconn(
        atlas_config: AtlasConfig,
        conn: Connection,
    ) -> Result<AtlasDB, db_error> {
        Self::check_instantiate_db(atlas_config, conn, true, false)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn tx_begin(&mut self) -> Result<Transaction<'_>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut self.conn)?;
        Ok(tx)
    }

    pub fn get_minmax_heights_window_for_page_index(
        &self,
        page_index: u32,
    ) -> Result<(u64, u64), db_error> {
        let min = page_index * AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let max = (page_index + 1) * AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
        let qry = "SELECT MIN(block_height) as min, MAX(block_height) as max FROM attachment_instances WHERE attachment_index >= ?1 AND attachment_index < ?2";
        let args = params![min, max];
        let mut stmt = self.conn.prepare(&qry)?;
        let mut rows = stmt.query(args)?;

        match rows.next() {
            Ok(Some(row)) => {
                let min: i64 = row.get("min").map_err(|_| db_error::NotFoundError)?;
                let max: i64 = row.get("max").map_err(|_| db_error::NotFoundError)?;
                Ok((min as u64, max as u64))
            }
            _ => Err(db_error::NotFoundError),
        }
    }

    pub fn get_attachments_available_at_page_index(
        &self,
        page_index: u32,
        block_id: &StacksBlockId,
    ) -> Result<Vec<u8>, db_error> {
        let page = self.get_attachments_missing_at_page_index(page_index, block_id)?;
        let mut bit_vector = vec![];
        for (_index, is_attachment_missing) in page.iter().enumerate() {
            // todo(ludo): use a bitvector instead
            bit_vector.push(if *is_attachment_missing { 0 } else { 1 });
        }
        Ok(bit_vector)
    }

    pub fn get_attachments_missing_at_page_index(
        &self,
        page_index: u32,
        block_id: &StacksBlockId,
    ) -> Result<Vec<bool>, db_error> {
        let min = page_index
            .checked_mul(AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE)
            .ok_or(db_error::Overflow)?;
        let max = min
            .checked_add(AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE)
            .ok_or(db_error::Overflow)?;
        let qry = "SELECT attachment_index, is_available FROM attachment_instances WHERE attachment_index >= ?1 AND attachment_index < ?2 AND index_block_hash = ?3 ORDER BY attachment_index ASC";
        let args = params![min, max, block_id,];
        let rows = query_rows::<(u32, u32), _>(&self.conn, &qry, args)?;

        let mut bool_vector = vec![true; AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE as usize];
        for (attachment_index, is_available) in rows.into_iter() {
            let index = attachment_index % AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
            bool_vector[index as usize] = is_available == 0;
        }
        Ok(bool_vector)
    }

    pub fn insert_uninstantiated_attachment(
        &mut self,
        attachment: &Attachment,
    ) -> Result<(), db_error> {
        // Insert the new attachment
        let uninstantiated_attachments = self.count_uninstantiated_attachments()?;
        if uninstantiated_attachments >= self.atlas_config.max_uninstantiated_attachments {
            let to_delete =
                1 + uninstantiated_attachments - self.atlas_config.max_uninstantiated_attachments;
            self.evict_k_oldest_uninstantiated_attachments(to_delete)?;
        }

        let tx = self.tx_begin()?;
        let now = util::get_epoch_time_secs() as i64;
        let res = tx.execute(
            "INSERT OR REPLACE INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 0, ?)",
            params![
                attachment.hash(),
                attachment.content,
                now,
            ],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn evict_k_oldest_uninstantiated_attachments(&mut self, k: u32) -> Result<(), db_error> {
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachments WHERE hash IN (SELECT hash FROM attachments WHERE was_instantiated = 0 ORDER BY created_at ASC LIMIT ?)",
            params![k],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn evict_expired_uninstantiated_attachments(&mut self) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let cut_off = now - self.atlas_config.uninstantiated_attachments_expire_after as i64;
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachments WHERE was_instantiated = 0 AND created_at < ?",
            params![cut_off],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn count_uninstantiated_attachments(&self) -> Result<u32, db_error> {
        let qry = "SELECT COUNT(rowid) FROM attachments
                   WHERE was_instantiated = 0";
        let count = query_count(&self.conn, qry, NO_PARAMS)? as u32;
        Ok(count)
    }

    pub fn count_unresolved_attachment_instances(&self) -> Result<u32, db_error> {
        let qry = "SELECT COUNT(rowid) FROM attachment_instances
                   WHERE is_available = 0";
        let count = query_count(&self.conn, qry, NO_PARAMS)? as u32;
        Ok(count)
    }

    pub fn insert_instantiated_attachment(
        &mut self,
        attachment: &Attachment,
    ) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let tx = self.tx_begin()?;
        tx.execute(
            "INSERT OR REPLACE INTO attachments (hash, content, was_instantiated, created_at) VALUES (?, ?, 1, ?)",
            params![attachment.hash(), attachment.content, now],
        )?;
        tx.execute(
            "UPDATE attachment_instances SET is_available = 1 WHERE content_hash = ?1 AND status = ?2",
            params![attachment.hash(), AttachmentInstanceStatus::Checked],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn find_uninstantiated_attachment(
        &mut self,
        content_hash: &Hash160,
    ) -> Result<Option<Attachment>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT content, hash FROM attachments WHERE hash = ?1 AND was_instantiated = 0"
            .to_string();
        let args = params![hex_content_hash];
        let row = query_row::<Attachment, _>(&self.conn, &qry, args)?;
        Ok(row)
    }

    pub fn evict_expired_unresolved_attachment_instances(&mut self) -> Result<(), db_error> {
        let now = util::get_epoch_time_secs() as i64;
        let cut_off = now
            - self
                .atlas_config
                .unresolved_attachment_instances_expire_after as i64;
        let tx = self.tx_begin()?;
        let res = tx.execute(
            "DELETE FROM attachment_instances WHERE is_available = 0 AND created_at < ?",
            params![cut_off],
        );
        res.map_err(db_error::SqliteError)?;
        tx.commit().map_err(db_error::SqliteError)?;
        Ok(())
    }

    pub fn find_unresolved_attachment_instances(
        &mut self,
    ) -> Result<Vec<AttachmentInstance>, db_error> {
        let qry = "SELECT * FROM attachment_instances WHERE is_available = 0 AND status = ?";
        let rows = query_rows(&self.conn, qry, params![AttachmentInstanceStatus::Checked])?;
        Ok(rows)
    }

    pub fn find_all_attachment_instances(
        &self,
        content_hash: &Hash160,
    ) -> Result<Vec<AttachmentInstance>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT * FROM attachment_instances WHERE content_hash = ?1 AND status = ?2";
        let args = params![hex_content_hash, AttachmentInstanceStatus::Checked];
        let rows = query_rows(&self.conn, qry, args)?;
        Ok(rows)
    }

    pub fn find_attachment(&self, content_hash: &Hash160) -> Result<Option<Attachment>, db_error> {
        let hex_content_hash = to_hex(&content_hash.0[..]);
        let qry = "SELECT content, hash FROM attachments WHERE hash = ?1 AND was_instantiated = 1"
            .to_string();
        let args = params![hex_content_hash];
        let row = query_row::<Attachment, _>(&self.conn, &qry, args)?;
        Ok(row)
    }

    /// Queue a new attachment instance, status will be set to "queued",
    /// and the is_available field set to false.
    ///
    /// This is invoked after block processing by the coordinator thread (which
    /// handles atlas event logic).
    pub fn queue_attachment_instance(
        &mut self,
        attachment: &AttachmentInstance,
    ) -> Result<(), db_error> {
        self.insert_attachment_instance(attachment, AttachmentInstanceStatus::Queued, false)
    }

    /// Insert an attachment instance from an initial batch.
    /// All such instances are marked "checked", and is_available = true
    ///
    /// This is invoked by the AtlasDownloader when it first runs. The AtlasDownloader
    /// is currently managed in the P2P thread.
    pub fn insert_initial_attachment_instance(
        &mut self,
        attachment: &AttachmentInstance,
    ) -> Result<(), db_error> {
        self.insert_attachment_instance(attachment, AttachmentInstanceStatus::Checked, true)
    }

    /// Return all the queued attachment instances, limited by `MAX_PROCESS_PER_ROUND`
    pub fn queued_attachments(&self) -> Result<Vec<AttachmentInstance>, db_error> {
        query_rows(
            &self.conn,
            "SELECT * FROM attachment_instances WHERE status = ?1 LIMIT ?2",
            params![AttachmentInstanceStatus::Queued, MAX_PROCESS_PER_ROUND],
        )
    }

    /// Update a queued attachment to "checked", setting the `is_available` field.
    pub fn mark_attachment_instance_checked(
        &mut self,
        attachment: &AttachmentInstance,
        is_available: bool,
    ) -> Result<(), db_error> {
        self.conn.execute(
            "UPDATE attachment_instances SET status = ?1, is_available = ?2
              WHERE index_block_hash = ?3 AND contract_id = ?4 AND attachment_index = ?5",
            params![
                AttachmentInstanceStatus::Checked,
                is_available,
                attachment.index_block_hash,
                attachment.contract_id.to_string(),
                attachment.attachment_index,
            ],
        )?;
        Ok(())
    }

    /// Insert an attachment instance.
    fn insert_attachment_instance(
        &mut self,
        attachment: &AttachmentInstance,
        status: AttachmentInstanceStatus,
        is_available: bool,
    ) -> Result<(), db_error> {
        let sql_tx = self.tx_begin()?;
        let now = util::get_epoch_time_secs() as i64;
        sql_tx.execute(
            "INSERT OR REPLACE INTO attachment_instances (
               content_hash, created_at, index_block_hash,
               attachment_index, block_height, is_available,
                metadata, contract_id, tx_id, status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                attachment.content_hash,
                now,
                attachment.index_block_hash,
                attachment.attachment_index,
                u64_to_sql(attachment.stacks_block_height)?,
                is_available,
                attachment.metadata,
                attachment.contract_id.to_string(),
                attachment.tx_id,
                status
            ],
        )?;
        sql_tx.commit()?;
        Ok(())
    }
}
