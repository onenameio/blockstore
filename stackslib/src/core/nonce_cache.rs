// Copyright (C) 2024 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use clarity::types::chainstate::StacksAddress;
use clarity::util::lru_cache::LruCache;
use clarity::vm::clarity::ClarityConnection;
use rand::Rng;
use rusqlite::params;

use super::mempool::MemPoolTx;
use super::MemPoolDB;
use crate::chainstate::stacks::db::StacksChainState;
use crate::util_lib::db::{query_row, u64_to_sql, DBConn, Error as db_error};

/// Used to cache nonces in memory and in the mempool database.
/// 1. MARF - source of truth for nonces
/// 2. Nonce DB - table in mempool sqlite database
/// 3. HashMap - in-memory cache for nonces
/// The in-memory cache is restricted to a maximum size to avoid memory
/// exhaustion. When the cache is full, it should be flushed to the database
/// and cleared. It is recommended to do this in between batches of candidate
/// transactions from the mempool.
pub struct NonceCache {
    /// In-memory LRU cache of nonces.
    cache: LruCache<StacksAddress, u64>,
}

impl NonceCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: LruCache::new(max_size),
        }
    }

    /// Get a nonce.
    /// First, the RAM cache will be checked for this address.
    /// If absent, then the `nonces` table will be queried for this address.
    /// If absent, then the MARF will be queried for this address.
    ///
    /// If not in RAM, the nonce will be opportunistically stored to the `nonces` table.  If that
    /// fails due to lock contention, then the method will return `true` for its second tuple argument.
    ///
    /// Returns (nonce, should-try-store-again?)
    pub fn get<C>(
        &mut self,
        address: &StacksAddress,
        clarity_tx: &mut C,
        mempool_db: &mut DBConn,
    ) -> u64
    where
        C: ClarityConnection,
    {
        // Check in-memory cache
        match self.cache.get(address) {
            Some(nonce) => nonce,
            None => {
                // Check sqlite cache
                let opt_nonce = match db_get_nonce(mempool_db, address) {
                    Ok(opt_nonce) => opt_nonce,
                    Err(e) => {
                        warn!("error retrieving nonce from mempool db: {}", e);
                        None
                    }
                };
                match opt_nonce {
                    Some(nonce) => {
                        // Insert into in-memory cache, but it is not dirty,
                        // since we just got it from the database.
                        let evicted = self.cache.insert_clean(address.clone(), nonce);
                        if evicted.is_some() {
                            // If we evicted something, we need to flush the cache.
                            self.flush_with_evicted(mempool_db, evicted);
                        }
                        nonce
                    }
                    None => {
                        let nonce =
                            StacksChainState::get_nonce(clarity_tx, &address.clone().into());

                        self.set(address.clone(), nonce, mempool_db);
                        nonce
                    }
                }
            }
        }
    }

    /// Store the (address, nonce) pair to the `nonces` table.
    /// If storage fails, return false.
    /// Otherwise return true.
    pub fn set(&mut self, address: StacksAddress, value: u64, conn: &mut DBConn) {
        let evicted = self.cache.insert(address.clone(), value);
        if evicted.is_some() {
            // If we evicted something, we need to flush the cache.
            self.flush_with_evicted(conn, evicted);
        }
    }

    pub fn flush_with_evicted(&mut self, conn: &mut DBConn, evicted: Option<(StacksAddress, u64)>) {
        const MAX_BACKOFF: Duration = Duration::from_secs(30);
        let mut backoff = Duration::from_millis(rand::thread_rng().gen_range(50..200));

        loop {
            let result = self.try_flush_with_evicted(conn, evicted);

            match result {
                Ok(_) => return, // Success: exit the loop
                Err(e) => {
                    // Calculate a backoff duration
                    warn!("Nonce cache flush failed: {e}. Retrying in {backoff:?}");

                    // Sleep for the backoff duration
                    thread::sleep(backoff);

                    if backoff < MAX_BACKOFF {
                        // Exponential backoff
                        backoff = backoff * 2
                            + Duration::from_millis(rand::thread_rng().gen_range(50..200));
                    }
                }
            }
        }
    }

    pub fn try_flush_with_evicted(
        &mut self,
        conn: &mut DBConn,
        evicted: Option<(StacksAddress, u64)>,
    ) -> Result<(), db_error> {
        // Flush the cache to the database
        let sql = "INSERT OR REPLACE INTO nonces (address, nonce) VALUES (?1, ?2)";

        let tx = conn.transaction()?;

        if let Some((addr, nonce)) = evicted {
            tx.execute(sql, params![addr, nonce])?;
        }

        self.cache.flush(|addr, nonce| {
            tx.execute(sql, params![addr, nonce])?;
            Ok::<(), db_error>(())
        })?;

        tx.commit()?;

        Ok(())
    }

    pub fn flush(&mut self, conn: &mut DBConn) {
        self.flush_with_evicted(conn, None)
    }
}

fn db_set_nonce(conn: &DBConn, address: &StacksAddress, nonce: u64) -> Result<(), db_error> {
    let addr_str = address.to_string();
    let nonce_i64 = u64_to_sql(nonce)?;

    let sql = "INSERT OR REPLACE INTO nonces (address, nonce) VALUES (?1, ?2)";
    conn.execute(sql, params![addr_str, nonce_i64])?;
    Ok(())
}

fn db_get_nonce(conn: &DBConn, address: &StacksAddress) -> Result<Option<u64>, db_error> {
    let addr_str = address.to_string();

    let sql = "SELECT nonce FROM nonces WHERE address = ?";
    query_row(conn, sql, params![addr_str])
}

#[cfg(test)]
mod tests {
    use clarity::consts::CHAIN_ID_TESTNET;
    use clarity::types::chainstate::StacksBlockId;
    use clarity::types::Address;
    use clarity::vm::tests::{TEST_BURN_STATE_DB, TEST_HEADER_DB};

    use super::*;
    use crate::chainstate::stacks::db::test::{chainstate_path, instantiate_chainstate};
    use crate::chainstate::stacks::index::ClarityMarfTrieId;
    use crate::clarity_vm::clarity::ClarityInstance;
    use crate::clarity_vm::database::marf::MarfedKV;

    #[test]
    fn test_nonce_cache() {
        let _chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let chainstate_path = chainstate_path(function_name!());
        let mut mempool = MemPoolDB::open_test(false, CHAIN_ID_TESTNET, &chainstate_path).unwrap();
        let mut cache = NonceCache::new(2);

        let addr1 =
            StacksAddress::from_string("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM").unwrap();
        let addr2 =
            StacksAddress::from_string("ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5").unwrap();
        let addr3 =
            StacksAddress::from_string("ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG").unwrap();

        let conn = &mut mempool.db;
        cache.set(addr1.clone(), 1, conn);
        cache.set(addr2.clone(), 2, conn);

        let marf = MarfedKV::temporary();
        let mut clarity_instance = ClarityInstance::new(false, CHAIN_ID_TESTNET, marf);
        clarity_instance
            .begin_test_genesis_block(
                &StacksBlockId::sentinel(),
                &StacksBlockId([0u8; 32]),
                &TEST_HEADER_DB,
                &TEST_BURN_STATE_DB,
            )
            .commit_block();
        let mut clarity_conn = clarity_instance.begin_block(
            &StacksBlockId([0 as u8; 32]),
            &StacksBlockId([1 as u8; 32]),
            &TEST_HEADER_DB,
            &TEST_BURN_STATE_DB,
        );

        clarity_conn.as_transaction(|clarity_tx| {
            assert_eq!(cache.get(&addr1, clarity_tx, conn), 1);
            assert_eq!(cache.get(&addr2, clarity_tx, conn), 2);
            // addr3 is not in the cache, so it should be fetched from the
            // clarity instance (and get 0)
            assert_eq!(cache.get(&addr3, clarity_tx, conn), 0);
        });
    }

    #[test]
    fn test_db_set_nonce() {
        let _chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let chainstate_path = chainstate_path(function_name!());
        let mut mempool = MemPoolDB::open_test(false, CHAIN_ID_TESTNET, &chainstate_path).unwrap();
        let conn = &mut mempool.db;
        let addr = StacksAddress::from_string("ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC").unwrap();
        db_set_nonce(&conn, &addr, 123).unwrap();
        assert_eq!(db_get_nonce(&conn, &addr).unwrap().unwrap(), 123);
    }
}
