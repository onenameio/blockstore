// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{params, Connection, OptionalExtension};
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, TrieHash};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::db::tx_busy_handler;
use stacks_common::util::hash::Sha512Trunc256Sum;

use super::clarity_store::{make_contract_hash_key, ContractCommitment};
use super::{
    ClarityBackingStore, ClarityDatabase, ClarityDeserializable, SpecialCaseHandler,
    NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::analysis::{AnalysisDatabase, CheckErrors};
use crate::vm::costs::ExecutionCost;
use crate::vm::errors::{
    IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};
use crate::vm::types::QualifiedContractIdentifier;

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteConnection {
    conn: Connection,
}

fn sqlite_put(conn: &Connection, key: &str, value: &str) -> Result<()> {
    let params = params![key, value];
    match conn.execute("REPLACE INTO data_table (key, value) VALUES (?, ?)", params) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Failed to insert/replace ({},{}): {:?}", key, value, &e);
            Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
        }
    }
}

fn sqlite_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    trace!("sqlite_get {}", key);
    let params = params![key];
    let res = match conn
        .query_row(
            "SELECT value FROM data_table WHERE key = ?",
            params,
            |row| row.get(0),
        )
        .optional()
    {
        Ok(x) => Ok(x),
        Err(e) => {
            error!("Failed to query '{}': {:?}", key, &e);
            Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
        }
    };

    trace!("sqlite_get {}: {:?}", key, &res);
    res
}

fn sqlite_has_entry(conn: &Connection, key: &str) -> Result<bool> {
    Ok(sqlite_get(conn, key)?.is_some())
}

pub fn sqlite_get_contract_hash(
    store: &mut dyn ClarityBackingStore,
    contract: &QualifiedContractIdentifier,
) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
    let key = make_contract_hash_key(contract);
    let contract_commitment = store
        .get_data(&key)?
        .map(|x| ContractCommitment::deserialize(&x))
        .ok_or_else(|| CheckErrors::NoSuchContract(contract.to_string()))?;
    let ContractCommitment {
        block_height,
        hash: contract_hash,
    } = contract_commitment?;
    let bhh = store.get_block_at_height(block_height)
            .ok_or_else(|| InterpreterError::Expect("Should always be able to map from height to block hash when looking up contract information.".into()))?;
    Ok((bhh, contract_hash))
}

pub fn sqlite_insert_metadata(
    store: &mut dyn ClarityBackingStore,
    contract: &QualifiedContractIdentifier,
    key: &str,
    value: &str,
) -> Result<()> {
    let bhh = store.get_open_chain_tip();
    SqliteConnection::insert_metadata(
        store.get_side_store(),
        &bhh,
        &contract.to_string(),
        key,
        value,
    )
}

pub fn sqlite_get_metadata(
    store: &mut dyn ClarityBackingStore,
    contract: &QualifiedContractIdentifier,
    key: &str,
) -> Result<Option<String>> {
    let (bhh, _) = store.get_contract_hash(contract)?;
    SqliteConnection::get_metadata(store.get_side_store(), &bhh, &contract.to_string(), key)
}

pub fn sqlite_get_metadata_manual(
    store: &mut dyn ClarityBackingStore,
    at_height: u32,
    contract: &QualifiedContractIdentifier,
    key: &str,
) -> Result<Option<String>> {
    let bhh = store.get_block_at_height(at_height).ok_or_else(|| {
        warn!("Unknown block height when manually querying metadata"; "block_height" => at_height);
        RuntimeErrorType::BadBlockHeight(at_height.to_string())
    })?;
    SqliteConnection::get_metadata(store.get_side_store(), &bhh, &contract.to_string(), key)
}

impl SqliteConnection {
    pub fn put(conn: &Connection, key: &str, value: &str) -> Result<()> {
        sqlite_put(conn, key, value)
    }

    pub fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
        sqlite_get(conn, key)
    }

    pub fn insert_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params = params![bhh, key, value];

        if let Err(e) = conn.execute(
            "INSERT INTO metadata_table (blockhash, key, value) VALUES (?, ?, ?)",
            params,
        ) {
            error!(
                "Failed to insert ({},{},{}): {:?}",
                &bhh,
                &key,
                &value.to_string(),
                &e
            );
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
        }
        Ok(())
    }

    pub fn commit_metadata_to(
        conn: &Connection,
        from: &StacksBlockId,
        to: &StacksBlockId,
    ) -> Result<()> {
        let params = params![to, from];
        if let Err(e) = conn.execute(
            "UPDATE metadata_table SET blockhash = ? WHERE blockhash = ?",
            params,
        ) {
            error!("Failed to update {} to {}: {:?}", &from, &to, &e);
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
        }
        Ok(())
    }

    pub fn drop_metadata(conn: &Connection, from: &StacksBlockId) -> Result<()> {
        if let Err(e) = conn.execute(
            "DELETE FROM metadata_table WHERE blockhash = ?",
            params![from],
        ) {
            error!("Failed to drop metadata from {}: {:?}", &from, &e);
            return Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into());
        }
        Ok(())
    }

    pub fn get_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
    ) -> Result<Option<String>> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params = params![bhh, key];

        match conn
            .query_row(
                "SELECT value FROM metadata_table WHERE blockhash = ? AND key = ?",
                params,
                |row| row.get(0),
            )
            .optional()
        {
            Ok(x) => Ok(x),
            Err(e) => {
                error!("Failed to query ({},{}): {:?}", &bhh, &key, &e);
                Err(InterpreterError::DBError(SQL_FAIL_MESSAGE.into()).into())
            }
        }
    }

    pub fn has_entry(conn: &Connection, key: &str) -> Result<bool> {
        sqlite_has_entry(conn, key)
    }
}

impl SqliteConnection {
    pub fn initialize_conn(conn: &Connection) -> Result<()> {
        conn.query_row("PRAGMA journal_mode = WAL;", NO_PARAMS, |_row| Ok(()))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS data_table
                      (key TEXT PRIMARY KEY, value TEXT)",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS metadata_table
                      (key TEXT NOT NULL, blockhash TEXT, value TEXT,
                       UNIQUE (key, blockhash))",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS md_blockhashes ON metadata_table(blockhash)",
            NO_PARAMS,
        )
        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Self::check_schema(conn)?;

        Ok(())
    }
    pub fn memory() -> Result<Connection> {
        let contract_db = SqliteConnection::inner_open(":memory:")?;
        SqliteConnection::initialize_conn(&contract_db)?;
        Ok(contract_db)
    }
    pub fn open(filename: &str) -> Result<Connection> {
        let contract_db = SqliteConnection::inner_open(filename)?;
        SqliteConnection::check_schema(&contract_db)?;
        Ok(contract_db)
    }
    pub fn check_schema(conn: &Connection) -> Result<()> {
        let sql = "SELECT sql FROM sqlite_master WHERE name=?";
        let _: String = conn
            .query_row(sql, params!["data_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        let _: String = conn
            .query_row(sql, params!["metadata_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Connection> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.busy_handler(Some(tx_busy_handler))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(conn)
    }
}

pub struct MemoryBackingStore {
    side_store: Connection,
}

impl Default for MemoryBackingStore {
    fn default() -> Self {
        MemoryBackingStore::new()
    }
}

impl MemoryBackingStore {
    #[allow(clippy::unwrap_used)]
    pub fn new() -> MemoryBackingStore {
        let side_store = SqliteConnection::memory().unwrap();

        let mut memory_marf = MemoryBackingStore { side_store };

        memory_marf.as_clarity_db().initialize();

        memory_marf
    }

    pub fn as_clarity_db(&mut self) -> ClarityDatabase {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase {
        AnalysisDatabase::new(self)
    }
}

impl ClarityBackingStore for MemoryBackingStore {
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId> {
        Err(RuntimeErrorType::UnknownBlockHeaderHash(BlockHeaderHash(bhh.0)).into())
    }

    fn get_data(&mut self, key: &str) -> Result<Option<String>> {
        SqliteConnection::get(self.get_side_store(), key)
    }

    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>> {
        SqliteConnection::get(self.get_side_store(), hash.to_string().as_str())
    }

    fn get_data_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>> {
        Ok(SqliteConnection::get(self.get_side_store(), key)?.map(|x| (x, vec![])))
    }

    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>> {
        self.get_data_with_proof(&hash.to_string())
    }

    fn get_side_store(&mut self) -> &Connection {
        &self.side_store
    }

    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId> {
        if height == 0 {
            Some(StacksBlockId([255; 32]))
        } else {
            None
        }
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        StacksBlockId([255; 32])
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        0
    }

    fn get_current_block_height(&mut self) -> u32 {
        1
    }

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        None
    }

    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<()> {
        for (key, value) in items.into_iter() {
            SqliteConnection::put(self.get_side_store(), &key, &value)?;
        }
        Ok(())
    }

    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
        sqlite_get_contract_hash(self, contract)
    }

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<()> {
        sqlite_insert_metadata(self, contract, key, value)
    }

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        sqlite_get_metadata(self, contract, key)
    }

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>> {
        sqlite_get_metadata_manual(self, at_height, contract, key)
    }
}

impl ToSql for ExecutionCost {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        let val = serde_json::to_string(self)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(ToSqlOutput::from(val))
    }
}

impl FromSql for ExecutionCost {
    fn column_result(value: ValueRef) -> FromSqlResult<ExecutionCost> {
        let str_val = String::column_result(value)?;
        let parsed = serde_json::from_str(&str_val)
            .map_err(|e| rusqlite::types::FromSqlError::Other(Box::new(e)))?;
        Ok(parsed)
    }
}
