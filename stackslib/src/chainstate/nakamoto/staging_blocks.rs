// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::{fmt, fs};

use lazy_static::lazy_static;
use rusqlite::blob::Blob;
use rusqlite::types::{FromSql, FromSqlError, ToSql};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksBlockId};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::{get_epoch_time_secs, sleep_ms};

use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::{Error as ChainstateError, StacksBlock, StacksBlockHeader};
use crate::stacks_common::codec::StacksMessageCodec;
use crate::util_lib::db::{
    query_int, query_row, query_row_columns, query_row_panic, query_rows, sqlite_open,
    table_exists, tx_begin_immediate, u64_to_sql, DBConn, Error as DBError, FromRow,
};

/// The means by which a block is obtained.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum NakamotoBlockObtainMethod {
    /// The block was fetched by te block downloader
    Downloaded,
    /// The block was uploaded to us via p2p
    Pushed,
    /// This node mined the block
    Mined,
    /// The block was uploaded to us via HTTP
    Uploaded,
    /// This is a shadow block -- it was created by a SIP to fix a consensus bug
    Shadow,
}

impl fmt::Display for NakamotoBlockObtainMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub const NAKAMOTO_STAGING_DB_SCHEMA_1: &[&str] = &[
    r#"
  -- Table for staging nakamoto blocks
  CREATE TABLE nakamoto_staging_blocks (
                 -- SHA512/256 hash of this block
                 block_hash TEXT NOT NULL,
                 -- The consensus hash of the burnchain block that selected this block's miner's block-commit.
                 -- This identifies the tenure to which this block belongs.
                 consensus_hash TEXT NOT NULL,
                 -- the parent index_block_hash
                 parent_block_id TEXT NOT NULL,
                 -- whether or not this is the first block in its tenure
                 is_tenure_start BOOL NOT NULL,

                 -- has the burnchain block with this block's `consensus_hash` been processed?
                 burn_attachable INT NOT NULL,
                 -- has this block been processed?
                 processed INT NOT NULL,
                 -- set to 1 if this block can never be attached
                 orphaned INT NOT NULL,

                 -- block height
                 height INT NOT NULL,

                 -- used internally -- this is the StacksBlockId of this block's consensus hash and block hash
                 index_block_hash TEXT NOT NULL,
                 -- how long the block was in-flight
                 download_time INT NOT NULL,
                 -- when this block was stored
                 arrival_time INT NOT NULL,
                 -- when this block was processed
                 processed_time INT NOT NULL,

                 -- block data, including its header
                 data BLOB NOT NULL,

                 PRIMARY KEY(block_hash,consensus_hash)
    );"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash ON nakamoto_staging_blocks(index_block_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash_and_consensus_hash ON nakamoto_staging_blocks(index_block_hash,consensus_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_tenure_start_block ON nakamoto_staging_blocks(is_tenure_start,consensus_hash);"#,
];

pub const NAKAMOTO_STAGING_DB_SCHEMA_2: &[&str] = &[
    r#"
  DROP TABLE nakamoto_staging_blocks;
  "#,
    r#"
  -- Table for staging nakamoto blocks
  CREATE TABLE nakamoto_staging_blocks (
                 -- SHA512/256 hash of this block (derived value from `data`)
                 block_hash TEXT NOT NULL,
                 -- The consensus hash of the burnchain block that selected this block's miner's block-commit.
                 -- This identifies the tenure to which this block belongs.
                 consensus_hash TEXT NOT NULL,
                 -- the parent index_block_hash
                 parent_block_id TEXT NOT NULL,
                 -- whether or not this is the first block in its tenure
                 is_tenure_start BOOL NOT NULL,

                 -- has the burnchain block with this block's `consensus_hash` been processed?
                 burn_attachable INT NOT NULL,
                 -- has this block been processed?
                 processed INT NOT NULL,
                 -- set to 1 if this block can never be attached
                 orphaned INT NOT NULL,

                 -- block height
                 height INT NOT NULL,

                 -- used internally -- this is the StacksBlockId of this block's consensus hash and block hash
                 -- (derived value from `data`)
                 index_block_hash TEXT UNIQUE NOT NULL,
                 -- when this block was processed
                 processed_time INT NOT NULL,
                 -- how the block was obtained -- was it pushed? downloaded? uploaded? etc.
                 -- (encoded as text for forwards-compatibility)
                 obtain_method TEXT NOT NULL,
                 -- signing weight of this block
                 signing_weight INTEGER NOT NULL,

                 -- block data, including its header
                 data BLOB NOT NULL,

                 PRIMARY KEY(block_hash,consensus_hash)
    );"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash ON nakamoto_staging_blocks(index_block_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_index_block_hash_and_consensus_hash ON nakamoto_staging_blocks(index_block_hash,consensus_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_tenure_start_block ON nakamoto_staging_blocks(is_tenure_start,consensus_hash);"#,
    r#"CREATE INDEX nakamoto_staging_blocks_by_burn_attachable ON nakamoto_staging_blocks(consensus_hash,burn_attachable);"#,
    r#"CREATE TABLE db_version (
        version INTEGER NOT NULL
    );"#,
    r#"INSERT INTO db_version (version) VALUES (2)"#,
];

pub const NAKAMOTO_STAGING_DB_SCHEMA_3: &[&str] = &[
    r#"CREATE INDEX nakamoto_staging_blocks_by_obtain_method ON nakamoto_staging_blocks(consensus_hash,obtain_method);"#,
    r#"UPDATE db_version SET version = 3"#,
];

pub const NAKAMOTO_STAGING_DB_SCHEMA_LATEST: u32 = 3;

pub struct NakamotoStagingBlocksConn(rusqlite::Connection);

impl Deref for NakamotoStagingBlocksConn {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NakamotoStagingBlocksConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl NakamotoStagingBlocksConn {
    pub fn conn(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(&self.0)
    }
}

pub struct NakamotoStagingBlocksConnRef<'a>(&'a rusqlite::Connection);

impl NakamotoStagingBlocksConnRef<'_> {
    pub fn conn(&self) -> NakamotoStagingBlocksConnRef<'_> {
        NakamotoStagingBlocksConnRef(self.0)
    }
}

impl Deref for NakamotoStagingBlocksConnRef<'_> {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

pub struct NakamotoStagingBlocksTx<'a>(rusqlite::Transaction<'a>);

impl NakamotoStagingBlocksTx<'_> {
    pub fn commit(self) -> Result<(), rusqlite::Error> {
        self.0.commit()
    }

    pub fn conn(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(self.0.deref())
    }
}

impl<'a> Deref for NakamotoStagingBlocksTx<'a> {
    type Target = rusqlite::Transaction<'a>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for NakamotoStagingBlocksTx<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
/// Open a Blob handle to a Nakamoto block
fn inner_open_nakamoto_block(
    conn: &Connection,
    rowid: i64,
    readwrite: bool,
) -> Result<Blob<'_>, ChainstateError> {
    let blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "nakamoto_staging_blocks",
        "data",
        rowid,
        !readwrite,
    )?;
    Ok(blob)
}

impl NakamotoStagingBlocksConn {
    /// Open a Blob handle to a Nakamoto block
    pub fn open_nakamoto_block(
        &self,
        rowid: i64,
        readwrite: bool,
    ) -> Result<Blob<'_>, ChainstateError> {
        inner_open_nakamoto_block(self.deref(), rowid, readwrite)
    }
}

impl<'a> NakamotoStagingBlocksConnRef<'a> {
    /// Open a Blob handle to a Nakamoto block
    pub fn open_nakamoto_block(
        &'a self,
        rowid: i64,
        readwrite: bool,
    ) -> Result<Blob<'a>, ChainstateError> {
        inner_open_nakamoto_block(self.deref(), rowid, readwrite)
    }

    /// Determine if we have a particular block with the given index hash.
    /// Returns Ok(true) if so
    /// Returns Ok(false) if not
    /// Returns Err(..) on DB error
    pub fn has_nakamoto_block_with_index_hash(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<bool, ChainstateError> {
        let qry = "SELECT 1 FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args = params![index_block_hash];
        let res: Option<i64> = query_row(self, qry, args)?;
        Ok(res.is_some())
    }

    /// Get the block ID, processed-status, orphan-status, and signing weight of the non-orphaned
    /// block with the given consensus hash and sighash with the most amount of signatures.
    /// There will be at most one such block.
    ///
    /// NOTE: for Nakamoto blocks, the sighash is the same as the block hash.
    pub fn get_block_processed_and_signed_weight(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Option<(StacksBlockId, bool, bool, u32)>, ChainstateError> {
        let sql = "SELECT index_block_hash,processed,orphaned,signing_weight FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND block_hash = ?2 ORDER BY signing_weight DESC, index_block_hash LIMIT 1";
        let args = params![consensus_hash, block_hash];

        let mut stmt = self.deref().prepare(sql)?;
        Ok(stmt
            .query_row(args, |row| {
                let block_id: StacksBlockId = row.get(0)?;
                let processed: bool = row.get(1)?;
                let orphaned: bool = row.get(2)?;
                let signing_weight: u32 = row.get(3)?;

                Ok((block_id, processed, orphaned, signing_weight))
            })
            .optional()?)
    }

    /// Get the rowid of a staging Nakamoto block
    pub fn get_nakamoto_block_rowid(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<i64>, ChainstateError> {
        let sql = "SELECT rowid FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args = params![index_block_hash];
        let res: Option<i64> = query_row(self, sql, args)?;
        Ok(res)
    }

    /// Get the tenure and parent block ID of a staging block.
    /// Used for downloads
    pub fn get_tenure_and_parent_block_id(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<(ConsensusHash, StacksBlockId)>, ChainstateError> {
        let sql = "SELECT consensus_hash,parent_block_id FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args = params![index_block_hash];

        let mut stmt = self.deref().prepare(sql)?;
        Ok(stmt
            .query_row(args, |row| {
                let ch: ConsensusHash = row.get(0)?;
                let parent_id: StacksBlockId = row.get(1)?;

                Ok((ch, parent_id))
            })
            .optional()?)
    }

    /// Get a Nakamoto block by index block hash, as well as its size.
    /// Verifies its integrity.
    /// Returns Ok(Some(block, size)) if the block was present
    /// Returns Ok(None) if there was no such block
    /// Returns Err(..) on DB error, including block corruption
    pub fn get_nakamoto_block(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<(NakamotoBlock, u64)>, ChainstateError> {
        let qry = "SELECT data FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args = params![index_block_hash];
        let res: Option<Vec<u8>> = query_row(self, qry, args)?;
        let Some(block_bytes) = res else {
            return Ok(None);
        };
        let block = NakamotoBlock::consensus_deserialize(&mut block_bytes.as_slice())?;
        if &block.header.block_id() != index_block_hash {
            error!(
                "Staging DB corruption: expected {}, got {}",
                index_block_hash,
                &block.header.block_id()
            );
            return Err(DBError::Corruption.into());
        }
        Ok(Some((
            block,
            u64::try_from(block_bytes.len()).expect("FATAL: block is greater than a u64"),
        )))
    }

    /// Get a Nakamoto block header by index block hash.
    /// Verifies its integrity
    /// Returns Ok(Some(header)) if the block was present
    /// Returns Ok(None) if there was no such block
    /// Returns Err(..) on DB error, including corruption
    pub fn get_nakamoto_block_header(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<NakamotoBlockHeader>, ChainstateError> {
        let Some(rowid) = self.get_nakamoto_block_rowid(index_block_hash)? else {
            return Ok(None);
        };

        let mut fd = self.open_nakamoto_block(rowid, false)?;
        let block_header = NakamotoBlockHeader::consensus_deserialize(&mut fd)?;
        if &block_header.block_id() != index_block_hash {
            error!(
                "Staging DB corruption: expected {}, got {}",
                index_block_hash,
                &block_header.block_id()
            );
            return Err(DBError::Corruption.into());
        }
        Ok(Some(block_header))
    }

    /// Get the size of a Nakamoto block, given its index block hash
    /// Returns Ok(Some(size)) if the block was present
    /// Returns Ok(None) if there was no such block
    /// Returns Err(..) on DB error, including block corruption
    pub fn get_nakamoto_block_size(
        &self,
        index_block_hash: &StacksBlockId,
    ) -> Result<Option<u64>, ChainstateError> {
        let qry = "SELECT length(data) FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        let args = params![index_block_hash];
        let res = query_row(self, qry, args)?
            .map(|size: i64| u64::try_from(size).expect("FATAL: block size exceeds i64::MAX"));
        Ok(res)
    }

    /// Get all Nakamoto blocks in a tenure that report being tenure-start blocks
    /// (depending on signer behavior, there can be more than one; none are guaranteed to be
    /// canonical).
    ///
    /// Used by the block downloader
    pub fn get_nakamoto_tenure_start_blocks(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<Vec<NakamotoBlock>, ChainstateError> {
        let qry = "SELECT data FROM nakamoto_staging_blocks WHERE is_tenure_start = 1 AND consensus_hash = ?1";
        let args = params![consensus_hash];
        let block_data: Vec<Vec<u8>> = query_rows(self, qry, args)?;
        Ok(block_data
            .into_iter()
            .filter_map(|block_vec| {
                NakamotoBlock::consensus_deserialize(&mut &block_vec[..])
                    .map_err(|e| {
                        error!("Failed to deserialize block from DB, likely database corruption";
                               "consensus_hash" => %consensus_hash,
                               "error" => ?e);
                        e
                    })
                    .ok()
            })
            .collect())
    }

    /// Find the next ready-to-process Nakamoto block, given a connection to the staging blocks DB.
    /// NOTE: the relevant field queried from `nakamoto_staging_blocks` are updated by a separate
    /// tx from block-processing, so it's imperative that the thread that calls this function is
    /// the *same* thread that goes to process blocks.
    /// Returns (the block, the size of the block)
    pub(crate) fn next_ready_nakamoto_block(
        &self,
        header_conn: &Connection,
    ) -> Result<Option<(NakamotoBlock, u64)>, ChainstateError> {
        let query = "SELECT child.data FROM nakamoto_staging_blocks child JOIN nakamoto_staging_blocks parent
                     ON child.parent_block_id = parent.index_block_hash
                     WHERE child.burn_attachable = 1
                       AND child.orphaned = 0
                       AND child.processed = 0
                       AND parent.processed = 1
                     ORDER BY child.height ASC";
        self
            .query_row_and_then(query, NO_PARAMS, |row| {
                let data: Vec<u8> = row.get("data")?;
                let block = NakamotoBlock::consensus_deserialize(&mut data.as_slice())?;
                Ok(Some((
                    block,
                    u64::try_from(data.len()).expect("FATAL: block is bigger than a u64"),
                )))
            })
            .or_else(|e| {
                if let ChainstateError::DBError(DBError::SqliteError(
                    rusqlite::Error::QueryReturnedNoRows,
                )) = e
                {
                    // This query can fail if the parent of `child` is not a Nakamoto block, which
                    // is allowed -- a Nakamoto block can descend from an epoch2 block (but since
                    // Nakamoto does not fork without a Bitcoin fork, it'll be the only such child
                    // within that Bitcoin fork unless either signers screw up, or there are
                    // multiple malleablized copies of this first-ever block available).
                    //
                    // Regardless, this query usually returns zero rows.  It will return one or
                    // more rows in the above case for an epoch2 parent, or when there are
                    // discontiguous Nakamoto blocks available for processing.
                    let sql = "SELECT index_block_hash,parent_block_id FROM nakamoto_staging_blocks WHERE processed = 0 AND orphaned = 0 AND burn_attachable = 1 ORDER BY height ASC";
                    let mut stmt = self.deref().prepare(sql)?;
                    let mut qry = stmt.query(NO_PARAMS)?;
                    let mut next_nakamoto_block_id = None;
                    while let Some(row) = qry.next()? {
                        let index_block_hash : StacksBlockId = row.get(0)?;
                        let parent_block_id : StacksBlockId = row.get(1)?;

                        // this naturally will ignore nakamoto blocks whose parent nakamoto blocks
                        // are not yet known -- they won't be epoch2 blocks either!
                        if !NakamotoChainState::has_block_header_epoch2(header_conn, &parent_block_id)? {
                            continue;
                        };

                        // epoch2 parent exists, so this Nakamoto block is processable!
                        next_nakamoto_block_id = Some(index_block_hash);
                        break;
                    }
                    let Some(next_nakamoto_block_id) = next_nakamoto_block_id else {
                        // no stored nakamoto block had an epoch2 parent
                        return Ok(None);
                    };

                    self.get_nakamoto_block(&next_nakamoto_block_id)
                } else {
                    Err(e)
                }
            })
    }

    /// Given a consensus hash, determine if the burn block has been processed.
    /// Because this is stored in a denormalized way, we'll want to do this whenever we store a
    /// block (so we can set `burn_attachable` accordingly)
    pub fn is_burn_block_processed(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        let sql = "SELECT 1 FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND burn_attachable = 1";
        let args = rusqlite::params![consensus_hash];
        let res: Option<u64> = query_row(self, sql, args)?;
        Ok(res.is_some())
    }
}

impl NakamotoStagingBlocksTx<'_> {
    /// Notify the staging database that a given stacks block has been processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    ///  block itself as processed.
    pub fn set_block_processed(&self, block: &StacksBlockId) -> Result<(), ChainstateError> {
        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2
                                  WHERE index_block_hash = ?1";
        self.execute(
            &clear_staged_block,
            params![block, u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Modify the staging database that a given stacks block can never be processed.
    /// This will update the attachable status for children blocks, as well as marking the stacks
    /// block itself as orphaned.
    pub fn set_block_orphaned(&self, block: &StacksBlockId) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET orphaned = 1
                                 WHERE parent_block_id = ?";

        self.execute(&update_dependents, &[&block])?;

        let clear_staged_block =
            "UPDATE nakamoto_staging_blocks SET processed = 1, processed_time = ?2, orphaned = 1
                                  WHERE index_block_hash = ?1";
        self.execute(
            &clear_staged_block,
            params![block, u64_to_sql(get_epoch_time_secs())?],
        )?;

        Ok(())
    }

    /// Notify the staging database that a given burn block has been processed.
    /// This is required for staged blocks to be eligible for processing.
    pub fn set_burn_block_processed(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<(), ChainstateError> {
        let update_dependents = "UPDATE nakamoto_staging_blocks SET burn_attachable = 1
                                 WHERE consensus_hash = ?";
        self.execute(&update_dependents, &[consensus_hash])?;

        Ok(())
    }

    /// Store a block into the staging DB.
    pub(crate) fn store_block(
        &self,
        block: &NakamotoBlock,
        burn_attachable: bool,
        signing_weight: u32,
        obtain_method: NakamotoBlockObtainMethod,
    ) -> Result<(), ChainstateError> {
        let Ok(tenure_start) = block.is_wellformed_tenure_start_block() else {
            return Err(ChainstateError::InvalidStacksBlock(
                "Tried to store a tenure-start block that is not well-formed".into(),
            ));
        };

        let burn_attachable = burn_attachable || {
            // if it's burn_attachable before, it's burn_attachable always
            self.conn()
                .is_burn_block_processed(&block.header.consensus_hash)?
        };

        let obtain_method = if block.is_shadow_block() {
            // override
            NakamotoBlockObtainMethod::Shadow
        } else {
            obtain_method
        };

        if self.conn().is_shadow_tenure(&block.header.consensus_hash)? && !block.is_shadow_block() {
            return Err(ChainstateError::InvalidStacksBlock(
                "Tried to insert a non-shadow block into a shadow tenure".into(),
            ));
        }

        self.execute(
            "INSERT INTO nakamoto_staging_blocks (
                     block_hash,
                     consensus_hash,
                     parent_block_id,
                     is_tenure_start,
                     burn_attachable,
                     orphaned,
                     processed,

                     height,
                     index_block_hash,
                     processed_time,
                     obtain_method,
                     signing_weight,

                     data
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &block.header.block_hash(),
                &block.header.consensus_hash,
                &block.header.parent_block_id,
                &tenure_start,
                if burn_attachable { 1 } else { 0 },
                0,
                0,
                u64_to_sql(block.header.chain_length)?,
                &block.block_id(),
                0,
                obtain_method.to_string(),
                signing_weight,
                block.serialize_to_vec(),
            ],
        )?;
        if burn_attachable {
            self.set_burn_block_processed(&block.header.consensus_hash)?;
        }
        Ok(())
    }

    /// Do we have a block with the given signer sighash?
    /// NOTE: the block hash and sighash are the same for Nakamoto blocks
    pub(crate) fn has_nakamoto_block_with_block_hash(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<bool, ChainstateError> {
        let qry =
            "SELECT 1 FROM nakamoto_staging_blocks WHERE consensus_hash = ?1 AND block_hash = ?2";
        let args = rusqlite::params![consensus_hash, block_hash];
        let present: Option<u32> = query_row(self, qry, args)?;
        Ok(present.is_some())
    }

    /// Store a block into the staging DB if its sighash has never been seen before.
    /// NOTE: the block hash and sighash are the same for Nakamoto blocks, so this is equivalent to
    /// storing a new block.
    /// Return true if stored; false if not.
    pub(crate) fn try_store_block_with_new_signer_sighash(
        &self,
        block: &NakamotoBlock,
        burn_attachable: bool,
        signing_weight: u32,
        obtain_method: NakamotoBlockObtainMethod,
    ) -> Result<bool, ChainstateError> {
        let block_hash = block.header.block_hash();
        if self.has_nakamoto_block_with_block_hash(&block.header.consensus_hash, &block_hash)? {
            return Ok(false);
        }
        self.store_block(block, burn_attachable, signing_weight, obtain_method)?;
        Ok(true)
    }

    /// Replace an already-stored block with a newer copy with more signing
    /// power.  Arguments will not be validated; the caller must do this.
    pub(crate) fn replace_block(
        &self,
        block: &NakamotoBlock,
        signing_weight: u32,
        obtain_method: NakamotoBlockObtainMethod,
    ) -> Result<(), ChainstateError> {
        self.execute("UPDATE nakamoto_staging_blocks SET data = ?1, signing_weight = ?2, obtain_method = ?3 WHERE consensus_hash = ?4 AND block_hash = ?5",
                    params![
                        &block.serialize_to_vec(),
                        &signing_weight,
                        &obtain_method.to_string(),
                        &block.header.consensus_hash,
                        &block.header.block_hash(),
                    ])?;
        Ok(())
    }
}

impl StacksChainState {
    /// Begin a transaction against the staging blocks DB.
    /// Note that this DB is (or will eventually be) in a separate database from the headers.
    pub fn staging_db_tx_begin(&mut self) -> Result<NakamotoStagingBlocksTx<'_>, ChainstateError> {
        let tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok(NakamotoStagingBlocksTx(tx))
    }

    /// Begin a tx to both the headers DB and the staging DB
    pub fn headers_and_staging_tx_begin(
        &mut self,
    ) -> Result<(rusqlite::Transaction<'_>, NakamotoStagingBlocksTx<'_>), ChainstateError> {
        let header_tx = self
            .state_index
            .storage_tx()
            .map_err(ChainstateError::DBError)?;
        let staging_tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok((header_tx, NakamotoStagingBlocksTx(staging_tx)))
    }

    /// Open a connection to the headers DB, and open a tx to the staging DB
    pub fn headers_conn_and_staging_tx_begin(
        &mut self,
    ) -> Result<(&rusqlite::Connection, NakamotoStagingBlocksTx<'_>), ChainstateError> {
        let header_conn = self.state_index.sqlite_conn();
        let staging_tx = tx_begin_immediate(&mut self.nakamoto_staging_blocks_conn)?;
        Ok((header_conn, NakamotoStagingBlocksTx(staging_tx)))
    }

    /// Get a ref to the nakamoto staging blocks connection
    pub fn nakamoto_blocks_db(&self) -> NakamotoStagingBlocksConnRef {
        NakamotoStagingBlocksConnRef(&self.nakamoto_staging_blocks_conn)
    }

    /// Get the path to the Nakamoto staging blocks DB.
    /// It's separate from the headers DB in order to avoid DB contention between downloading
    /// blocks and processing them.
    pub fn static_get_nakamoto_staging_blocks_path(
        root_path: PathBuf,
    ) -> Result<String, ChainstateError> {
        let mut nakamoto_blocks_path = Self::blocks_path(root_path);
        nakamoto_blocks_path.push("nakamoto.sqlite");
        Ok(nakamoto_blocks_path
            .to_str()
            .ok_or(ChainstateError::DBError(DBError::ParseError))?
            .to_string())
    }

    /// Get the path to the Nakamoto staging blocks DB.
    pub fn get_nakamoto_staging_blocks_path(&self) -> Result<String, ChainstateError> {
        Self::static_get_nakamoto_staging_blocks_path(PathBuf::from(self.root_path.as_str()))
    }

    /// Get the database version
    pub fn get_nakamoto_staging_blocks_db_version(
        conn: &Connection,
    ) -> Result<u32, ChainstateError> {
        let db_version_exists = table_exists(&conn, "db_version")?;
        if !db_version_exists {
            return Ok(1);
        }
        let qry = "SELECT version FROM db_version ORDER BY version DESC LIMIT 1";
        let args = NO_PARAMS;
        let version: Option<i64> = match query_row(&conn, qry, args) {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to get Nakamoto staging blocks DB version: {:?}", &e);
                return Err(ChainstateError::DBError(DBError::Corruption));
            }
        };

        match version {
            Some(ver_i64) => {
                let ver = u32::try_from(ver_i64)
                    .map_err(|_e| ChainstateError::DBError(DBError::Corruption))?;
                Ok(ver)
            }
            None => {
                error!("No version present in Nakamoto staging blocks `db_version` table");
                Err(ChainstateError::DBError(DBError::Corruption))
            }
        }
    }

    /// Perform migrations
    pub fn migrate_nakamoto_staging_blocks(conn: &Connection) -> Result<(), ChainstateError> {
        loop {
            let version = Self::get_nakamoto_staging_blocks_db_version(conn)?;
            if version == NAKAMOTO_STAGING_DB_SCHEMA_LATEST {
                return Ok(());
            }
            match version {
                1 => {
                    debug!("Migrate Nakamoto staging blocks DB to schema 2");
                    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_2.iter() {
                        conn.execute(cmd, NO_PARAMS)?;
                    }
                    let version = Self::get_nakamoto_staging_blocks_db_version(conn)?;
                    assert_eq!(version, 2, "Nakamoto staging DB migration failure");
                    debug!("Migrated Nakamoto staging blocks DB to schema 2");
                }
                2 => {
                    debug!("Migrate Nakamoto staging blocks DB to schema 3");
                    for cmd in NAKAMOTO_STAGING_DB_SCHEMA_3.iter() {
                        conn.execute(cmd, NO_PARAMS)?;
                    }
                    let version = Self::get_nakamoto_staging_blocks_db_version(conn)?;
                    assert_eq!(version, 3, "Nakamoto staging DB migration failure");
                    debug!("Migrated Nakamoto staging blocks DB to schema 3");
                }
                NAKAMOTO_STAGING_DB_SCHEMA_LATEST => {
                    break;
                }
                _ => {
                    panic!("Unusable staging DB: Unknown schema version {}", version);
                }
            }
        }
        Ok(())
    }

    /// Open and set up a DB for nakamoto staging blocks.
    /// If it doesn't exist, then instantiate it if `readwrite` is true.
    pub fn open_nakamoto_staging_blocks(
        path: &str,
        readwrite: bool,
    ) -> Result<NakamotoStagingBlocksConn, ChainstateError> {
        let exists = fs::metadata(&path).is_ok();
        let flags = if !exists {
            // try to instantiate
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(DBError::NotFoundError.into());
            }
        } else if readwrite {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let conn = sqlite_open(path, flags, false)?;
        if !exists {
            for cmd in NAKAMOTO_STAGING_DB_SCHEMA_1.iter() {
                conn.execute(cmd, NO_PARAMS)?;
            }
            for cmd in NAKAMOTO_STAGING_DB_SCHEMA_2.iter() {
                conn.execute(cmd, NO_PARAMS)?;
            }
        } else if readwrite {
            Self::migrate_nakamoto_staging_blocks(&conn)?;
        }

        Ok(NakamotoStagingBlocksConn(conn))
    }
}
