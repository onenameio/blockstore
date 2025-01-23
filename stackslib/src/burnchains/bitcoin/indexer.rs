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

use std::net::Shutdown;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, fs, net, path, time};

use rand::{thread_rng, Rng};
use stacks_common::deps_common::bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::network::encodable::VarInt;
use stacks_common::deps_common::bitcoin::network::message::NetworkMessage;
use stacks_common::deps_common::bitcoin::network::serialize::{
    BitcoinHash, Error as btc_serialization_err,
};
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::util::{get_epoch_time_secs, log};

use crate::burnchains::bitcoin::blocks::{
    BitcoinBlockDownloader, BitcoinBlockParser, BitcoinHeaderIPC,
};
use crate::burnchains::bitcoin::messages::BitcoinMessageHandler;
use crate::burnchains::bitcoin::spv::*;
use crate::burnchains::bitcoin::{BitcoinNetworkType, Error as btc_error};
use crate::burnchains::db::BurnchainHeaderReader;
use crate::burnchains::indexer::{BurnchainIndexer, *};
use crate::burnchains::{
    Burnchain, BurnchainBlockHeader, Error as burnchain_error, MagicBytes, BLOCKSTACK_MAGIC_MAINNET,
};
use crate::core::{
    EpochList, StacksEpoch, StacksEpochExtension, STACKS_EPOCHS_MAINNET, STACKS_EPOCHS_REGTEST,
    STACKS_EPOCHS_TESTNET,
};
use crate::util_lib::db::Error as DBError;

pub const USER_AGENT: &str = "Stacks/2.1";

pub const BITCOIN_MAINNET: u32 = 0xD9B4BEF9;
pub const BITCOIN_TESTNET: u32 = 0x0709110B;
pub const BITCOIN_REGTEST: u32 = 0xDAB5BFFA;

pub const BITCOIN_MAINNET_NAME: &str = "mainnet";
pub const BITCOIN_TESTNET_NAME: &str = "testnet";
pub const BITCOIN_REGTEST_NAME: &str = "regtest";

// batch size for searching for a reorg
// kept small since sometimes bitcoin will just send us one header at a time
#[cfg(not(test))]
const REORG_BATCH_SIZE: u64 = 16;
#[cfg(test)]
const REORG_BATCH_SIZE: u64 = 2;

pub fn network_id_to_bytes(network_id: BitcoinNetworkType) -> u32 {
    match network_id {
        BitcoinNetworkType::Mainnet => BITCOIN_MAINNET,
        BitcoinNetworkType::Testnet => BITCOIN_TESTNET,
        BitcoinNetworkType::Regtest => BITCOIN_REGTEST,
    }
}

impl TryFrom<u32> for BitcoinNetworkType {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<BitcoinNetworkType, Self::Error> {
        match value {
            BITCOIN_MAINNET => Ok(BitcoinNetworkType::Mainnet),
            BITCOIN_TESTNET => Ok(BitcoinNetworkType::Testnet),
            BITCOIN_REGTEST => Ok(BitcoinNetworkType::Regtest),
            _ => Err("Invalid network type"),
        }
    }
}

/// Get the default epochs definitions for the given BitcoinNetworkType.
/// Should *not* be used except by the BitcoinIndexer when no epochs vector
/// was specified.
pub fn get_bitcoin_stacks_epochs(network_id: BitcoinNetworkType) -> EpochList {
    match network_id {
        BitcoinNetworkType::Mainnet => (*STACKS_EPOCHS_MAINNET).clone(),
        BitcoinNetworkType::Testnet => (*STACKS_EPOCHS_TESTNET).clone(),
        BitcoinNetworkType::Regtest => (*STACKS_EPOCHS_REGTEST).clone(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitcoinIndexerConfig {
    // config fields
    pub peer_host: String,
    pub peer_port: u16,
    pub rpc_port: u16,
    pub rpc_ssl: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: u32,
    pub spv_headers_path: String,
    pub first_block: u64,
    pub magic_bytes: MagicBytes,
    pub epochs: Option<EpochList>,
}

#[derive(Debug)]
pub struct BitcoinIndexerRuntime {
    sock: Option<net::TcpStream>,
    pub services: u64,
    pub user_agent: String,
    pub version_nonce: u64,
    pub network_id: BitcoinNetworkType,
    pub block_height: u64,
    pub last_getdata_send_time: u64,
    pub last_getheaders_send_time: u64,
    pub timeout: u64,
}

pub struct BitcoinIndexer {
    pub config: BitcoinIndexerConfig,
    pub runtime: BitcoinIndexerRuntime,
    pub should_keep_running: Option<Arc<AtomicBool>>,
}

impl BitcoinIndexerConfig {
    pub fn default(first_block: u64) -> BitcoinIndexerConfig {
        BitcoinIndexerConfig {
            peer_host: "bitcoin.blockstack.com".to_string(),
            peer_port: 8333,
            rpc_port: 8332,
            rpc_ssl: false,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path: "./headers.sqlite".to_string(),
            first_block,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            epochs: None,
        }
    }

    pub fn default_regtest(spv_headers_path: String) -> BitcoinIndexerConfig {
        BitcoinIndexerConfig {
            peer_host: "127.0.0.1".to_string(),
            peer_port: 18444,
            rpc_port: 18443,
            rpc_ssl: false,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path,
            first_block: 0,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            epochs: None,
        }
    }

    #[cfg(test)]
    pub fn test_default(spv_headers_path: String) -> BitcoinIndexerConfig {
        BitcoinIndexerConfig {
            peer_host: "127.0.0.1".to_string(),
            peer_port: 18444,
            rpc_port: 18443,
            rpc_ssl: false,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path,
            first_block: 0,
            magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
            epochs: None,
        }
    }
}

impl BitcoinIndexerRuntime {
    pub fn new(network_id: BitcoinNetworkType) -> BitcoinIndexerRuntime {
        let mut rng = thread_rng();
        BitcoinIndexerRuntime {
            sock: None,
            services: 0,
            user_agent: USER_AGENT.to_owned(),
            version_nonce: rng.gen(),
            network_id,
            block_height: 0,
            last_getdata_send_time: 0,
            last_getheaders_send_time: 0,
            timeout: 300,
        }
    }
}

impl BitcoinIndexer {
    #[cfg(test)]
    pub fn new(
        config: BitcoinIndexerConfig,
        runtime: BitcoinIndexerRuntime,
        should_keep_running: Option<Arc<AtomicBool>>,
    ) -> BitcoinIndexer {
        BitcoinIndexer {
            config,
            runtime,
            should_keep_running,
        }
    }

    #[cfg(test)]
    pub fn new_unit_test(working_dir: &str) -> BitcoinIndexer {
        let mut working_dir_path = PathBuf::from(working_dir);
        if fs::metadata(&working_dir_path).is_err() {
            fs::create_dir_all(&working_dir_path).unwrap();
        }

        working_dir_path.push("headers.sqlite");

        // instantiate headers DB
        let _ = SpvClient::new(
            &working_dir_path.to_str().unwrap().to_string(),
            0,
            None,
            BitcoinNetworkType::Regtest,
            true,
            false,
        )
        .expect(&format!(
            "Failed to open {:?}",
            &working_dir_path.to_str().unwrap().to_string()
        ));

        BitcoinIndexer {
            config: BitcoinIndexerConfig::default_regtest(
                working_dir_path.to_str().unwrap().to_string(),
            ),
            runtime: BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest),
            should_keep_running: None,
        }
    }

    pub fn dup(&self) -> BitcoinIndexer {
        BitcoinIndexer {
            config: self.config.clone(),
            runtime: BitcoinIndexerRuntime::new(self.runtime.network_id),
            should_keep_running: self.should_keep_running.clone(),
        }
    }

    /// (re)connect to our configured network peer.
    /// Sets self.runtime.sock to a new socket referring to our configured
    /// Bitcoin peer.  If we fail to connect, this method sets the socket
    /// to None.
    fn reconnect_peer(&mut self) -> Result<(), btc_error> {
        match net::TcpStream::connect((self.config.peer_host.as_str(), self.config.peer_port)) {
            Ok(s) => {
                // Disable Nagle algorithm
                s.set_nodelay(true).map_err(|_e| {
                    test_debug!("Failed to set TCP_NODELAY: {:?}", &_e);
                    btc_error::ConnectionError
                })?;

                // set timeout
                s.set_read_timeout(Some(Duration::from_secs(self.runtime.timeout)))
                    .map_err(|_e| {
                        test_debug!("Failed to set TCP read timeout: {:?}", &_e);
                        btc_error::ConnectionError
                    })?;

                s.set_write_timeout(Some(Duration::from_secs(self.runtime.timeout)))
                    .map_err(|_e| {
                        test_debug!("Failed to set TCP write timeout: {:?}", &_e);
                        btc_error::ConnectionError
                    })?;

                match self.runtime.sock.take() {
                    Some(s) => {
                        let _ = s.shutdown(Shutdown::Both);
                    }
                    None => {}
                }

                self.runtime.sock = Some(s);
                Ok(())
            }
            Err(_e) => {
                let s = self.runtime.sock.take();
                match s {
                    Some(s) => {
                        let _ = s.shutdown(Shutdown::Both);
                    }
                    None => {}
                }
                Err(btc_error::ConnectionError)
            }
        }
    }

    /// Run code with the socket
    pub fn with_socket<F, R>(&mut self, closure: F) -> Result<R, btc_error>
    where
        F: FnOnce(&mut net::TcpStream) -> Result<R, btc_error>,
    {
        let mut sock = self.runtime.sock.take();
        let res = match sock {
            Some(ref mut s) => closure(s),
            None => Err(btc_error::SocketNotConnectedToPeer),
        };
        self.runtime.sock = sock;
        res
    }

    /// Are we connected?
    fn is_connected(&mut self) -> bool {
        self.runtime.sock.is_some()
    }

    /// Carry on a conversation with the bitcoin peer.
    /// Handle version, verack, ping, and pong messages automatically.
    /// Reconnect to the peer automatically if the peer closes the connection.
    /// Pass any other messages to a given message handler.
    pub fn peer_communicate<T: BitcoinMessageHandler>(
        &mut self,
        message_handler: &mut T,
        initial_handshake: bool,
    ) -> Result<(), btc_error> {
        let mut do_handshake = initial_handshake || !self.is_connected();
        let mut keep_going = true;
        let mut initiated = false;

        while keep_going {
            if let Some(ref should_keep_running) = self.should_keep_running {
                if !should_keep_running.load(Ordering::SeqCst) {
                    return Err(btc_error::TimedOut);
                }
            }

            if do_handshake {
                debug!("(Re)establish peer connection");

                initiated = false;
                let handshake_result = self.connect_handshake_backoff();
                match handshake_result {
                    Ok(_block_height) => {
                        // connection established!
                        do_handshake = false;
                    }
                    Err(_) => {
                        // need to try again
                        continue;
                    }
                }
            }

            if !initiated {
                // initiate the conversation
                match message_handler.begin_session(self) {
                    Ok(status) => {
                        if !status {
                            debug!("begin_session() terminates conversation");
                            break;
                        }
                        initiated = true;
                    }
                    Err(btc_error::ConnectionBroken) => {
                        debug!("Re-establish peer connection");
                        do_handshake = true;
                    }
                    Err(e) => {
                        warn!("Unhandled error while initiating conversation: {:?}", e);
                        return Err(e);
                    }
                }
            }

            match self.recv_message() {
                Ok(msg) => {
                    // got a message; go consume it
                    let handled = self.handle_message(msg, Some(message_handler));
                    match handled {
                        Ok(do_continue) => {
                            keep_going = do_continue;
                            if !keep_going {
                                debug!("Message handler indicates to stop");
                            }
                        }
                        Err(btc_error::UnhandledMessage(m)) => {
                            match m {
                                // some Bitcoin nodes send this to tell us to upgrade, so just
                                // consume it
                                NetworkMessage::Alert(..) => {}
                                _ => {
                                    // TODO: handle inv block-push
                                    debug!("Unhandled message {:?}", m);
                                }
                            }
                        }
                        Err(btc_error::ConnectionBroken) => {
                            debug!("Re-establish peer connection");
                            do_handshake = true;
                        }
                        Err(e) => {
                            warn!("Unhandled error {:?}", e);
                            return Err(e);
                        }
                    }
                }
                Err(btc_error::ConnectionBroken) => {
                    do_handshake = true;
                }
                Err(btc_error::SerializationError(
                    btc_serialization_err::UnrecognizedNetworkCommand(s),
                )) => {
                    debug!("Received unrecognized network command while receiving a message: {}, ignoring", s);
                }
                Err(e) => {
                    warn!("Unhandled error while receiving a message: {:?}", e);
                    do_handshake = true;
                }
            }
        }
        Ok(())
    }

    /// Synchronize a range of headers from bitcoin to a specific file.
    /// If last_block is None, then sync as many headers as the remote peer has to offer.
    /// Returns the height of the last block fetched
    pub fn sync_last_headers(
        &mut self,
        start_block: u64,
        last_block: Option<u64>,
    ) -> Result<u64, btc_error> {
        debug!("Sync all headers starting at block {}", start_block);
        let mut spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            start_block,
            last_block,
            self.runtime.network_id,
            true,
            false,
        )?;
        if let Some(last_block) = last_block.as_ref() {
            // do we need to do anything?
            let cur_height = spv_client.get_headers_height()?;
            if *last_block <= cur_height {
                debug!("SPV client has all headers up to {}", cur_height);
                return Ok(cur_height);
            }
        }
        spv_client
            .run(self)
            .map(|_r| spv_client.end_block_height.unwrap())
    }

    #[cfg(test)]
    fn new_reorg_spv_client(
        reorg_headers_path: &str,
        start_block: u64,
        end_block: Option<u64>,
        network_id: BitcoinNetworkType,
    ) -> Result<SpvClient, btc_error> {
        SpvClient::new_without_migration(
            &reorg_headers_path,
            start_block,
            end_block,
            network_id,
            true,
            true,
        )
    }

    #[cfg(not(test))]
    fn new_reorg_spv_client(
        reorg_headers_path: &str,
        start_block: u64,
        end_block: Option<u64>,
        network_id: BitcoinNetworkType,
    ) -> Result<SpvClient, btc_error> {
        SpvClient::new(
            &reorg_headers_path,
            start_block,
            end_block,
            network_id,
            true,
            true,
        )
    }

    /// Create a SPV client for starting reorg processing
    fn setup_reorg_headers(
        &mut self,
        canonical_spv_client: &SpvClient,
        reorg_headers_path: &str,
        start_block: u64,
        remove_old: bool,
    ) -> Result<SpvClient, btc_error> {
        if remove_old && PathBuf::from(&reorg_headers_path).exists() {
            fs::remove_file(&reorg_headers_path).map_err(|e| {
                error!("Failed to remove {}", reorg_headers_path);
                btc_error::Io(e)
            })?;
        }

        // bootstrap reorg client
        let mut reorg_spv_client = BitcoinIndexer::new_reorg_spv_client(
            reorg_headers_path,
            start_block,
            Some(start_block + REORG_BATCH_SIZE),
            self.runtime.network_id,
        )?;

        if start_block > 0 {
            if start_block > BLOCK_DIFFICULTY_CHUNK_SIZE {
                if remove_old {
                    // set up a .reorg db
                    // * needs the last difficulty interval of headers (note that the current
                    // interval is `start_block / BLOCK_DIFFICULTY_CHUNK_SIZE - 1).
                    // * needs the last interval's chain work calculation
                    let interval_start_block =
                        (start_block / BLOCK_DIFFICULTY_CHUNK_SIZE).saturating_sub(2);
                    let base_block = interval_start_block * BLOCK_DIFFICULTY_CHUNK_SIZE;

                    if base_block > 0 {
                        let interval_headers =
                            canonical_spv_client.read_block_headers(base_block, start_block + 1)?;
                        assert!(
                            interval_headers.len() >= (start_block - base_block) as usize,
                            "BUG: missing headers for {}-{}",
                            base_block,
                            start_block
                        );

                        debug!(
                            "Copy headers {}-{}",
                            base_block,
                            base_block + interval_headers.len() as u64
                        );
                        reorg_spv_client
                            .insert_block_headers_before(base_block - 1, interval_headers)?;
                    } else {
                        let interval_headers =
                            canonical_spv_client.read_block_headers(1, start_block + 1)?;
                        assert!(
                            interval_headers.len() >= start_block as usize,
                            "BUG: missing headers for 1-{}",
                            start_block
                        );

                        debug!("Copy headers 1-{}", interval_headers.len() as u64);
                        reorg_spv_client.insert_block_headers_before(0, interval_headers)?;
                    }

                    let last_interval = canonical_spv_client.find_highest_work_score_interval()?;

                    // copy over the relevant difficulty intervals as well
                    for interval in interval_start_block..(last_interval + 1) {
                        test_debug!("Copy interval {} to {}", interval, &reorg_headers_path);
                        let work_score = canonical_spv_client
                            .find_interval_work(interval)?
                            .unwrap_or_else(|| {
                                panic!("FATAL: no work score for interval {}", interval)
                            });
                        reorg_spv_client.store_interval_work(interval, work_score)?;
                    }
                }
            } else {
                // no full difficulty intervals yet
                let interval_headers =
                    canonical_spv_client.read_block_headers(1, start_block + 1)?;
                reorg_spv_client.insert_block_headers_before(0, interval_headers)?;
            }
        }

        Ok(reorg_spv_client)
    }

    /// Search for a bitcoin reorg.  Return the offset into the canonical bitcoin headers where
    /// the reorg starts.  Returns the hight of the highest common ancestor.
    /// Note that under certain testnet settings, the bitcoin chain itself can shrink.
    pub fn find_bitcoin_reorg<F>(
        &mut self,
        canonical_headers_path: &str,
        reorg_headers_path: &str,
        load_reorg_headers: F,
    ) -> Result<u64, btc_error>
    where
        F: FnMut(&mut BitcoinIndexer, &mut SpvClient, u64, Option<u64>) -> Result<(), btc_error>,
    {
        // always check chain work, except in testing
        self.inner_find_bitcoin_reorg(
            canonical_headers_path,
            reorg_headers_path,
            load_reorg_headers,
            true,
        )
    }

    fn inner_find_bitcoin_reorg<F>(
        &mut self,
        canonical_headers_path: &str,
        reorg_headers_path: &str,
        mut load_reorg_headers: F,
        check_chain_work: bool,
    ) -> Result<u64, btc_error>
    where
        F: FnMut(&mut BitcoinIndexer, &mut SpvClient, u64, Option<u64>) -> Result<(), btc_error>,
    {
        let mut new_tip = 0;
        let mut found_common_ancestor = false;

        let mut orig_spv_client = SpvClient::new(
            canonical_headers_path,
            0,
            None,
            self.runtime.network_id,
            true,
            false,
        )?;

        // what's the last header we have from the canonical history?
        let canonical_end_block = orig_spv_client.get_headers_height().map_err(|e| {
            error!(
                "Failed to get the last block from {}",
                canonical_headers_path
            );
            e
        })?;

        // bootstrap reorg client
        let mut start_block = canonical_end_block.saturating_sub(REORG_BATCH_SIZE);
        let mut reorg_spv_client =
            self.setup_reorg_headers(&orig_spv_client, reorg_headers_path, start_block, true)?;
        let mut discontiguous_header_error_count = 0;

        while !found_common_ancestor {
            debug!(
                "Search for reorg'ed Bitcoin headers from {} - {}",
                start_block,
                start_block + REORG_BATCH_SIZE
            );

            // get new headers, starting off of start_block.  Feed them into the given
            // reorg_spv_client.
            match load_reorg_headers(
                self,
                &mut reorg_spv_client,
                start_block,
                Some(start_block + REORG_BATCH_SIZE),
            ) {
                Ok(_) => {}
                Err(btc_error::NoncontiguousHeader) | Err(btc_error::InvalidPoW) => {
                    warn!(
                        "Received invalid headers from {} - {} -- possible reorg in progress",
                        start_block,
                        start_block + REORG_BATCH_SIZE
                    );
                    if start_block == 0 {
                        // reorg all the way back to genesis
                        new_tip = 0;
                        break;
                    }

                    // try again
                    discontiguous_header_error_count += 1;
                    start_block = start_block
                        .saturating_sub(REORG_BATCH_SIZE * discontiguous_header_error_count);
                    reorg_spv_client = self.setup_reorg_headers(
                        &orig_spv_client,
                        reorg_headers_path,
                        start_block,
                        false,
                    )?;
                    continue;
                }
                Err(e) => {
                    error!(
                        "Failed to fetch Bitcoin headers from {} - {}: {:?}",
                        start_block,
                        start_block + REORG_BATCH_SIZE,
                        &e
                    );
                    return Err(e);
                }
            }

            let reorg_headers = reorg_spv_client
                .read_block_headers(start_block, start_block + REORG_BATCH_SIZE)
                .map_err(|e| {
                    error!(
                        "Failed to read reorg Bitcoin headers from {} to {}",
                        start_block,
                        start_block + REORG_BATCH_SIZE
                    );
                    e
                })?;

            if reorg_headers.is_empty() {
                // chain shrank considerably
                info!(
                    "Missing Bitcoin headers in block range {}-{} -- did the Bitcoin chain shrink?",
                    start_block,
                    start_block + REORG_BATCH_SIZE
                );
                if start_block == 0 {
                    // reorg chain is empty
                    new_tip = 0;
                    break;
                }

                start_block = start_block.saturating_sub(REORG_BATCH_SIZE);
                reorg_spv_client.set_scan_range(start_block, Some(start_block + REORG_BATCH_SIZE));
                continue;
            }

            // got reorg headers.  Find the equivalent headers in our canonical history
            let canonical_headers = orig_spv_client
                .read_block_headers(start_block, start_block + REORG_BATCH_SIZE)
                .map_err(|e| {
                    error!(
                        "Failed to read canonical headers from {} to {}",
                        start_block,
                        start_block + REORG_BATCH_SIZE
                    );
                    e
                })?;

            assert!(
                !canonical_headers.is_empty(),
                "BUG: uninitialized canonical SPV headers DB"
            );

            let max_headers_len = if canonical_headers.len() < reorg_headers.len() {
                canonical_headers.len()
            } else {
                reorg_headers.len()
            };
            let max_height = start_block + (max_headers_len as u64);

            // scan for common ancestor, but excluding the block we wrote to bootstrap the
            // reorg_spv_client.
            for i in (start_block + 1..max_height).rev() {
                if canonical_headers[(i - start_block) as usize].header
                    == reorg_headers[(i - start_block) as usize].header
                {
                    // found common ancestor
                    debug!(
                        "Found common Bitcoin block ancestor at height {}: {:?}",
                        i,
                        &canonical_headers[(i - start_block) as usize].header
                    );
                    new_tip = i;
                    found_common_ancestor = true;
                    break;
                } else {
                    debug!(
                        "Diverged headers at {}: {:?} != {:?}",
                        i,
                        &canonical_headers[(i - start_block) as usize].header,
                        &reorg_headers[(i - start_block) as usize].header
                    );
                }
            }
            if found_common_ancestor {
                break;
            }

            debug!(
                "No common ancestor found between Bitcoin headers {}-{}",
                start_block, max_height
            );

            if start_block == 0 {
                break;
            }

            // try again
            start_block = start_block.saturating_sub(REORG_BATCH_SIZE);
            reorg_spv_client =
                self.setup_reorg_headers(&orig_spv_client, reorg_headers_path, start_block, false)?;
        }

        if check_chain_work {
            let reorg_total_work = reorg_spv_client.update_chain_work()?;
            let orig_total_work = orig_spv_client.update_chain_work()?;

            debug!("Bitcoin headers history is consistent up to {}", new_tip;
                   "Orig chainwork" => %orig_total_work,
                   "Reorg chainwork" => %reorg_total_work);

            if orig_total_work < reorg_total_work {
                let reorg_tip = reorg_spv_client.get_headers_height()?;
                let hdr_reorg = reorg_spv_client
                    .read_block_header(reorg_tip - 1)?
                    .expect("FATAL: no tip hash for existing chain tip");
                info!(
                    "New canonical Bitcoin chain found! New tip is {}",
                    &hdr_reorg.header.bitcoin_hash()
                );

                // merge the new headers and chain difficulty to the original headers
                let mut orig_spv_client = SpvClient::new(
                    canonical_headers_path,
                    0,
                    None,
                    self.runtime.network_id,
                    true,
                    false,
                )?;

                // copy over new headers
                if new_tip > 0 {
                    let new_headers =
                        reorg_spv_client.read_block_headers(new_tip, reorg_tip + 1)?;
                    orig_spv_client.drop_headers(new_tip)?;
                    orig_spv_client.insert_block_headers_after(new_tip - 1, new_headers)?;
                }

                // copy over new chain work
                let orig_highest_interval = orig_spv_client.find_highest_work_score_interval()?;
                let reorg_highest_interval = reorg_spv_client.find_highest_work_score_interval()?;
                for interval in cmp::min(orig_highest_interval, reorg_highest_interval)
                    ..(cmp::max(orig_highest_interval, reorg_highest_interval) + 1)
                {
                    if let Some(work_score) = reorg_spv_client.find_interval_work(interval)? {
                        test_debug!(
                            "Copy work score for interval {} ({}) to original SPV client DB",
                            interval,
                            &work_score
                        );
                        orig_spv_client
                            .store_interval_work(interval, work_score)
                            .expect("FATAL: failed to store better chain work");
                    }
                }
            } else {
                // ignore the reorg
                test_debug!(
                    "Reorg chain does not overtake original Bitcoin chain ({} >= {})",
                    orig_total_work,
                    reorg_total_work
                );
                new_tip = orig_spv_client.get_headers_height()?;
            }
        }

        let hdr_reorg = reorg_spv_client.read_block_header(new_tip)?;
        let hdr_canonical = orig_spv_client.read_block_header(new_tip)?;
        assert_eq!(hdr_reorg, hdr_canonical);

        Ok(new_tip)
    }

    #[cfg(test)]
    pub fn raw_store_header(&mut self, header: BurnchainBlockHeader) -> Result<(), btc_error> {
        let mut spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            self.config.first_block,
            None,
            self.runtime.network_id,
            true,
            false,
        )?;
        spv_client.disable_check_txcount();

        let hdr = LoneBlockHeader {
            header: BitcoinIndexer::mock_bitcoin_header(
                &header.parent_block_hash,
                header.timestamp as u32,
            ),
            tx_count: VarInt(header.num_txs),
        };

        assert!(header.block_height > 0);
        let start_height = header.block_height - 1;
        spv_client.insert_block_headers_after(start_height, vec![hdr])?;
        Ok(())
    }

    #[cfg(test)]
    pub fn mock_bitcoin_header(
        parent_block_hash: &BurnchainHeaderHash,
        timestamp: u32,
    ) -> BlockHeader {
        BlockHeader {
            bits: 0,
            merkle_root: Sha256dHash([0u8; 32]),
            nonce: 0,
            prev_blockhash: parent_block_hash.to_bitcoin_hash(),
            time: timestamp,
            version: 0x20000000,
        }
    }

    /// Verify that the last block header we have is within 2 hours of now.
    /// Return burnchain_error::TrySyncAgain if not, and delete the offending header
    pub fn check_chain_tip_timestamp(&mut self) -> Result<(), burnchain_error> {
        // if there was no target block height, then verify that the highest header fetched is within
        // 2 hours of now.  Remove headers that don't meet this criterion.
        let highest_header_height = self.get_highest_header_height()?;
        if highest_header_height == 0 {
            return Err(burnchain_error::TrySyncAgain);
        }

        let highest_header = self
            .read_headers(highest_header_height, highest_header_height + 1)?
            .pop()
            .expect("FATAL: no header at highest known height");
        let now = get_epoch_time_secs();
        if now - 2 * 60 * 60 <= (highest_header.block_header.header.time as u64)
            && (highest_header.block_header.header.time as u64) <= now + 2 * 60 * 60
        {
            // we're good
            return Ok(());
        }
        warn!(
            "Header at height {} is not within 2 hours of now (is at {})",
            highest_header_height, highest_header.block_header.header.time
        );
        self.drop_headers(highest_header_height.saturating_sub(1))?;
        return Err(burnchain_error::TrySyncAgain);
    }
}

impl Drop for BitcoinIndexer {
    fn drop(&mut self) {
        match self.runtime.sock {
            Some(ref mut s) => {
                let _ = s.shutdown(Shutdown::Both);
            }
            None => {}
        }
    }
}

impl BurnchainIndexer for BitcoinIndexer {
    type P = BitcoinBlockParser;

    /// Connect to the Bitcoin peer network.
    /// Use the peer host and peer port given in the config file,
    /// and loaded in on setup.
    fn connect(&mut self) -> Result<(), burnchain_error> {
        self.reconnect_peer().map_err(burnchain_error::Bitcoin)
    }

    /// Get the location on disk where we keep headers
    fn get_headers_path(&self) -> String {
        self.config.spv_headers_path.clone()
    }

    /// Get the number of headers we have
    fn get_headers_height(&self) -> Result<u64, burnchain_error> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )
        .map_err(burnchain_error::Bitcoin)?;
        spv_client
            .get_headers_height()
            .map_err(burnchain_error::Bitcoin)
    }

    fn get_highest_header_height(&self) -> Result<u64, burnchain_error> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )
        .map_err(burnchain_error::Bitcoin)?;
        spv_client
            .get_highest_header_height()
            .map_err(burnchain_error::Bitcoin)
    }

    /// Get the first block height
    fn get_first_block_height(&self) -> u64 {
        self.config.first_block
    }

    /// Get the first block header hash
    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, burnchain_error> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )?;
        let first_block_height = self.get_first_block_height();
        let first_header = spv_client
            .read_block_header(first_block_height)?
            .expect("BUG: no first block header hash");

        let first_block_header_hash =
            BurnchainHeaderHash::from_bitcoin_hash(&first_header.header.bitcoin_hash());
        Ok(first_block_header_hash)
    }

    /// Get the first block header timestamp
    fn get_first_block_header_timestamp(&self) -> Result<u64, burnchain_error> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )?;
        let first_block_height = self.get_first_block_height();
        let first_header = spv_client
            .read_block_header(first_block_height)?
            .expect("BUG: no first block header timestamp");

        let first_block_header_timestamp = first_header.header.time as u64;
        Ok(first_block_header_timestamp)
    }

    /// Get a vector of the stacks epochs. This notion of epochs is dependent on the burn block height.
    /// Valid epochs include stacks 1.0, stacks 2.0, stacks 2.05, and so on.
    ///
    /// Choose according to:
    /// 1) Use the custom epochs defined on the underlying `BitcoinIndexerConfig`, if they exist.
    /// 2) Use hard-coded static values, otherwise.
    ///
    /// It is an error (panic) to set custom epochs if running on `Mainnet`.
    fn get_stacks_epochs(&self) -> EpochList {
        StacksEpoch::get_epochs(self.runtime.network_id, self.config.epochs.as_ref())
    }

    /// Read downloaded headers within a range
    fn read_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<BitcoinHeaderIPC>, burnchain_error> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )?;

        let headers = spv_client.read_block_headers(start_block, end_block)?;
        let mut ret_headers: Vec<BitcoinHeaderIPC> = vec![];
        for i in 0..headers.len() {
            ret_headers.push({
                BitcoinHeaderIPC {
                    block_header: headers[i].clone(),
                    block_height: (i as u64) + start_block,
                }
            });
        }
        Ok(ret_headers)
    }

    /// Identify underlying reorgs and return the block height of the highest block in common
    /// between the remote node and our block headers.
    fn find_chain_reorg(&mut self) -> Result<u64, burnchain_error> {
        let headers_path = self.config.spv_headers_path.clone();
        let reorg_path = format!("{}.reorg", &self.config.spv_headers_path);
        self.find_bitcoin_reorg(
            &headers_path,
            &reorg_path,
            |ref mut indexer, ref mut spv_client, start_block, end_block_opt| {
                spv_client.set_scan_range(start_block, end_block_opt);
                spv_client.run(indexer)
            },
        )
        .map_err(|e| match e {
            btc_error::TimedOut => burnchain_error::TrySyncAgain,
            x => burnchain_error::Bitcoin(x),
        })
    }

    /// Download and store all headers between two block heights
    /// end_heights, if given, is inclusive.
    /// Returns the height of the last header fetched
    fn sync_headers(
        &mut self,
        start_height: u64,
        end_height: Option<u64>,
    ) -> Result<u64, burnchain_error> {
        if let Some(end_height) = end_height {
            if end_height <= start_height {
                return Ok(end_height);
            }
        }

        let new_height = self
            .sync_last_headers(start_height, end_height)
            .map_err(|e| match e {
                btc_error::TimedOut => burnchain_error::TrySyncAgain,
                x => burnchain_error::Bitcoin(x),
            })?;

        // make sure the headers are up-to-date if we have no target height
        if end_height.is_none() {
            self.check_chain_tip_timestamp()?;
        }
        Ok(new_height)
    }

    /// Drop headers after a given height -- i.e. to accomodate a reorg
    fn drop_headers(&mut self, new_height: u64) -> Result<(), burnchain_error> {
        let mut spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            true,
            false,
        )
        .map_err(burnchain_error::Bitcoin)?;
        spv_client
            .drop_headers(new_height)
            .map_err(burnchain_error::Bitcoin)
    }

    fn downloader(&self) -> BitcoinBlockDownloader {
        BitcoinBlockDownloader::new(self.dup())
    }

    fn parser(&self) -> BitcoinBlockParser {
        BitcoinBlockParser::new(self.runtime.network_id, self.config.magic_bytes)
    }

    fn reader(&self) -> BitcoinIndexer {
        self.dup()
    }
}

impl BurnchainHeaderReader for BitcoinIndexer {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError> {
        let hdrs = self
            .read_headers(start_height, end_height)
            .map_err(|e| DBError::Other(format!("Burnchain error: {:?}", &e)))?;

        Ok(hdrs
            .into_iter()
            .map(|hdr| BurnchainBlockHeader {
                block_height: hdr.block_height,
                block_hash: BurnchainHeaderHash::from_bitcoin_hash(&Sha256dHash(hdr.header_hash())),
                parent_block_hash: BurnchainHeaderHash::from_bitcoin_hash(
                    &hdr.block_header.header.prev_blockhash,
                ),
                num_txs: hdr.block_header.tx_count.0,
                timestamp: hdr.block_header.header.time as u64,
            })
            .collect())
    }

    fn get_burnchain_headers_height(&self) -> Result<u64, DBError> {
        self.get_headers_height()
            .map_err(|e| DBError::Other(format!("Burnchain error: {:?}", &e)))
    }

    fn find_burnchain_header_height(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        let spv_client = SpvClient::new(
            &self.config.spv_headers_path,
            0,
            None,
            self.runtime.network_id,
            false,
            false,
        )
        .map_err(|e| DBError::Other(format!("Burnchain error: {:?}", &e)))?;
        spv_client
            .find_block_header_height(burn_header_hash)
            .map_err(|e| DBError::Other(format!("Burnchain error: {:?}", &e)))
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;
    use std::{env, thread};

    use stacks_common::deps_common::bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
    use stacks_common::deps_common::bitcoin::network::encodable::VarInt;
    use stacks_common::deps_common::bitcoin::network::serialize::{
        deserialize, serialize, BitcoinHash,
    };
    use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::uint::Uint256;

    use super::*;
    use crate::burnchains::bitcoin::{Error as btc_error, *};
    use crate::burnchains::{Error as burnchain_error, *};

    #[test]
    fn test_indexer_find_bitcoin_reorg_genesis() {
        let path_1 = "/tmp/test-indexer-find_bitcoin_reorg_genesis.dat";
        let path_2 = "/tmp/test-indexer-find_bitcoin_reorg_genesis.dat.reorg.bak";
        let path_reorg = "/tmp/test-indexer-find_bitcoin_reorg_genesis.dat.reorg";

        if fs::metadata(path_1).is_ok() {
            fs::remove_file(path_1).unwrap();
        }
        if fs::metadata(path_2).is_ok() {
            fs::remove_file(path_2).unwrap();
        }
        if fs::metadata(path_reorg).is_ok() {
            fs::remove_file(path_reorg).unwrap();
        }

        // two header sets -- both of which build off of the genesis block
        let headers_1 = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "20bee96458517fc5082a9720ce6207b5742f2b18e4e0a7e7373342725d80f88c",
                    )
                    .unwrap(),
                    nonce: 2,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                    )
                    .unwrap(),
                    time: 1587626881,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "39d1a6f1ee7a5903797f92ec89e4c58549013f38114186fc2eb6e5218cb2d0ac",
                    )
                    .unwrap(),
                    nonce: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "606d31daaaa5919f3720d8440dd99d31f2a4e4189c65879f19ae43268425e74b",
                    )
                    .unwrap(),
                    time: 1587626882,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "a7e04ed25f589938eb5627abb7b5913dd77b8955bcdf72d7f111d0a71e346e47",
                    )
                    .unwrap(),
                    nonce: 4,
                    prev_blockhash: Sha256dHash::from_hex(
                        "2fa2f451ac27f0e5cd3760ba6cdf34ef46adb76a44d96bc0f3bf3e713dd955f0",
                    )
                    .unwrap(),
                    time: 1587626882,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
        ];

        let headers_2 = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "677351ef5cd586c8d0ee7c242e0c5794d0bb4564107e567fd24e508aa66c8b79",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                    )
                    .unwrap(),
                    time: 1587612061,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "a92e6612c0cde9b029081d90b1dcef97f95508b92dd982223c8fcbe9e953fc79",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f4865e8169da0cb265ab0ea9eef440e6b7cc9bc1d5e74e4627c0f1e83e67e95",
                    )
                    .unwrap(),
                    time: 1587612062,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "5bd6f6f0863582bb6910d772829b7cf36be262b74ac5775ef9d78180c90a9fef",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "2dbbe38703af1918ef4091dfea226db8868843a55a4673e3d2d7259083b07063",
                    )
                    .unwrap(),
                    time: 1587612062,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
        ];

        let mut spv_client =
            SpvClient::new(path_1, 0, None, BitcoinNetworkType::Regtest, true, false).unwrap();
        let mut spv_client_reorg =
            SpvClient::new(path_2, 0, None, BitcoinNetworkType::Regtest, true, false).unwrap();

        spv_client
            .insert_block_headers_after(0, headers_1.clone())
            .unwrap();
        spv_client_reorg
            .insert_block_headers_after(0, headers_2.clone())
            .unwrap();

        spv_client.update_chain_work().unwrap();
        spv_client_reorg.update_chain_work().unwrap();

        assert_eq!(spv_client.read_block_headers(0, 10).unwrap().len(), 4);
        assert_eq!(spv_client_reorg.read_block_headers(0, 10).unwrap().len(), 4);

        assert_eq!(spv_client_reorg.read_block_headers(2, 10).unwrap().len(), 2);

        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(path_1.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest),
            None,
        );
        let common_ancestor_height = indexer
            .inner_find_bitcoin_reorg(
                path_1,
                path_reorg,
                |ref mut indexer, ref mut spv_client, start_block, end_block_opt| {
                    // mock the bitcoind by just copying over the relevant headers from our backup reorg db
                    let end_block = end_block_opt.unwrap_or(10000000);
                    let hdrs = spv_client_reorg
                        .read_block_headers(start_block, end_block)
                        .unwrap();

                    if start_block > 0 {
                        test_debug!("insert at {}: {:?}", start_block - 1, &hdrs);
                        spv_client
                            .insert_block_headers_before(start_block - 1, hdrs)
                            .unwrap();
                    } else if !hdrs.is_empty() {
                        test_debug!("insert at {}: {:?}", 0, &hdrs);
                        spv_client.test_write_block_headers(0, hdrs).unwrap();
                    }

                    Ok(())
                },
                false,
            )
            .unwrap();

        // lowest common ancestor is the genesis block
        assert_eq!(common_ancestor_height, 0);
    }

    #[test]
    fn test_indexer_find_bitcoin_reorg_midpoint() {
        let path_1 = "/tmp/test-indexer-find_bitcoin_reorg_midpoint.dat";
        let path_2 = "/tmp/test-indexer-find_bitcoin_reorg_midpoint.dat.reorg.bak";
        let path_reorg = "/tmp/test-indexer-find_bitcoin_reorg_midpoint.dat.reorg";

        if fs::metadata(path_1).is_ok() {
            fs::remove_file(path_1).unwrap();
        }
        if fs::metadata(path_2).is_ok() {
            fs::remove_file(path_2).unwrap();
        }

        // two header sets -- both of which build off of same first block
        let headers_1 = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "677351ef5cd586c8d0ee7c242e0c5794d0bb4564107e567fd24e508aa66c8b79",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                    )
                    .unwrap(),
                    time: 1587612061,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "39d1a6f1ee7a5903797f92ec89e4c58549013f38114186fc2eb6e5218cb2d0ac",
                    )
                    .unwrap(),
                    nonce: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f4865e8169da0cb265ab0ea9eef440e6b7cc9bc1d5e74e4627c0f1e83e67e95",
                    )
                    .unwrap(),
                    time: 1587626882,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "a7e04ed25f589938eb5627abb7b5913dd77b8955bcdf72d7f111d0a71e346e47",
                    )
                    .unwrap(),
                    nonce: 4,
                    prev_blockhash: Sha256dHash::from_hex(
                        "7a06268e099dafa4549d9e2511c251497779cf16ab3b5363e5b25d3dd6f552e7",
                    )
                    .unwrap(),
                    time: 1587626882,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
        ];

        let headers_2 = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "677351ef5cd586c8d0ee7c242e0c5794d0bb4564107e567fd24e508aa66c8b79",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                    )
                    .unwrap(),
                    time: 1587612061,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "a92e6612c0cde9b029081d90b1dcef97f95508b92dd982223c8fcbe9e953fc79",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f4865e8169da0cb265ab0ea9eef440e6b7cc9bc1d5e74e4627c0f1e83e67e95",
                    )
                    .unwrap(),
                    time: 1587612062,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "5bd6f6f0863582bb6910d772829b7cf36be262b74ac5775ef9d78180c90a9fef",
                    )
                    .unwrap(),
                    nonce: 0,
                    prev_blockhash: Sha256dHash::from_hex(
                        "2dbbe38703af1918ef4091dfea226db8868843a55a4673e3d2d7259083b07063",
                    )
                    .unwrap(),
                    time: 1587612062,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
        ];

        let mut spv_client =
            SpvClient::new(path_1, 0, None, BitcoinNetworkType::Regtest, true, false).unwrap();
        let mut spv_client_reorg =
            SpvClient::new(path_2, 0, None, BitcoinNetworkType::Regtest, true, false).unwrap();

        spv_client
            .insert_block_headers_after(0, headers_1.clone())
            .unwrap();
        spv_client_reorg
            .insert_block_headers_after(0, headers_2.clone())
            .unwrap();

        assert_eq!(spv_client.read_block_headers(0, 10).unwrap().len(), 4);
        assert_eq!(spv_client_reorg.read_block_headers(0, 10).unwrap().len(), 4);

        assert_eq!(spv_client_reorg.read_block_headers(2, 10).unwrap().len(), 2);

        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(path_1.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest),
            None,
        );
        let common_ancestor_height = indexer
            .inner_find_bitcoin_reorg(
                path_1,
                path_reorg,
                |ref mut indexer, ref mut spv_client, start_block, end_block_opt| {
                    // mock the bitcoind by just copying over the relevant headers from our backup reorg db
                    let end_block = end_block_opt.unwrap_or(10000000);
                    let hdrs = spv_client_reorg
                        .read_block_headers(start_block, end_block)
                        .unwrap();
                    if start_block > 0 {
                        spv_client
                            .insert_block_headers_before(start_block - 1, hdrs)
                            .unwrap();
                    } else if !hdrs.is_empty() {
                        test_debug!("insert at {}: {:?}", 0, &hdrs);
                        spv_client.test_write_block_headers(0, hdrs).unwrap();
                    }
                    Ok(())
                },
                false,
            )
            .unwrap();

        // lowest common ancestor is the first block
        assert_eq!(common_ancestor_height, 1);
    }

    #[test]
    fn test_indexer_sync_headers() {
        if !env::var("BLOCKSTACK_SPV_BITCOIN_HOST").is_ok() {
            eprintln!(
                "Skipping test_indexer_sync_headers -- no BLOCKSTACK_SPV_BITCOIN_HOST envar set"
            );
            return;
        }
        if !env::var("BLOCKSTACK_SPV_BITCOIN_PORT").is_ok() {
            eprintln!(
                "Skipping test_indexer_sync_headers -- no BLOCKSTACK_SPV_BITCOIN_PORT envar set"
            );
            return;
        }
        if !env::var("BLOCKSTACK_SPV_BITCOIN_MODE").is_ok() {
            eprintln!(
                "Skipping test_indexer_sync_headers -- no BLOCKSTACK_SPV_BITCOIN_MODE envar set"
            );
            return;
        }

        let host = env::var("BLOCKSTACK_SPV_BITCOIN_HOST").unwrap();
        let port = env::var("BLOCKSTACK_SPV_BITCOIN_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let mode = match env::var("BLOCKSTACK_SPV_BITCOIN_MODE").unwrap().as_str() {
            "mainnet" => BitcoinNetworkType::Mainnet,
            "testnet" => BitcoinNetworkType::Testnet,
            "regtest" => BitcoinNetworkType::Regtest,
            _ => {
                panic!("Invalid bitcoin mode -- expected mainnet, testnet, or regtest");
            }
        };

        let db_path = "/tmp/test_indexer_sync_headers.sqlite";
        let indexer_conf = BitcoinIndexerConfig {
            peer_host: host,
            peer_port: port,
            rpc_port: port + 1, // ignored
            rpc_ssl: false,
            username: Some("blockstack".to_string()),
            password: Some("blockstacksystem".to_string()),
            timeout: 30,
            spv_headers_path: db_path.to_string(),
            first_block: 0,
            magic_bytes: MagicBytes([105, 100]),
            epochs: None,
        };

        if fs::metadata(&indexer_conf.spv_headers_path).is_ok() {
            fs::remove_file(&indexer_conf.spv_headers_path).unwrap();
        }

        let mut indexer = BitcoinIndexer::new(indexer_conf, BitcoinIndexerRuntime::new(mode), None);
        let last_block = indexer.sync_headers(0, None).unwrap();
        eprintln!("sync'ed to block {}", last_block);

        // compare against known-good chain work
        let chain_work: Vec<(u64, &str)> = vec![
            (
                0,
                "000000000000000000000000000000000000000000000000000007e007e007e0",
            ),
            (
                1,
                "00000000000000000000000000000000000000000000000000000fc00fc00fc0",
            ),
            (
                2,
                "000000000000000000000000000000000000000000000000000017a017a017a0",
            ),
            (
                3,
                "00000000000000000000000000000000000000000000000000001f801f801f80",
            ),
            (
                4,
                "0000000000000000000000000000000000000000000000000000276027602760",
            ),
            (
                5,
                "00000000000000000000000000000000000000000000000000002f402f402f40",
            ),
            (
                6,
                "0000000000000000000000000000000000000000000000000000372037203720",
            ),
            (
                7,
                "00000000000000000000000000000000000000000000000000003f003f003f00",
            ),
            (
                8,
                "000000000000000000000000000000000000000000000000000046e046e046e0",
            ),
            (
                9,
                "00000000000000000000000000000000000000000000000000004ec04ec04ec0",
            ),
            (
                10,
                "000000000000000000000000000000000000000000000000000056a056a056a0",
            ),
            (
                11,
                "00000000000000000000000000000000000000000000000000005e805e805e80",
            ),
            (
                12,
                "0000000000000000000000000000000000000000000000000000666066606660",
            ),
            (
                13,
                "00000000000000000000000000000000000000000000000000006e406e406e40",
            ),
            (
                14,
                "0000000000000000000000000000000000000000000000000000762076207620",
            ),
            (
                15,
                "00000000000000000000000000000000000000000000000000007e007e007e00",
            ),
            (
                16,
                "00000000000000000000000000000000000000000000000000008751410913c0",
            ),
            (
                17,
                "000000000000000000000000000000000000000000000000000091984ca8a7c0",
            ),
            (
                18,
                "00000000000000000000000000000000000000000000000000009c2e4c600dc0",
            ),
            (
                19,
                "0000000000000000000000000000000000000000000000000000aa80bfeea100",
            ),
            (
                20,
                "0000000000000000000000000000000000000000000000000000be68bf6b8cc0",
            ),
            (
                21,
                "0000000000000000000000000000000000000000000000000000dc2fb8af3b80",
            ),
            (
                22,
                "0000000000000000000000000000000000000000000000000000ffde8588bce0",
            ),
            (
                23,
                "000000000000000000000000000000000000000000000000000123d207cd7780",
            ),
            (
                24,
                "000000000000000000000000000000000000000000000000000153be8a040220",
            ),
            (
                25,
                "000000000000000000000000000000000000000000000000000191537d8be600",
            ),
            (
                26,
                "0000000000000000000000000000000000000000000000000001eb9be75bf700",
            ),
            (
                27,
                "000000000000000000000000000000000000000000000000000250cc4092ede0",
            ),
            (
                28,
                "0000000000000000000000000000000000000000000000000002ae169cd3d9a0",
            ),
            (
                29,
                "000000000000000000000000000000000000000000000000000330f72fc5b200",
            ),
            (
                30,
                "0000000000000000000000000000000000000000000000000003b9d8cd2a7b60",
            ),
            (
                31,
                "000000000000000000000000000000000000000000000000000452a977bf36e0",
            ),
            (
                32,
                "00000000000000000000000000000000000000000000000000050bbcb9ab7b40",
            ),
            (
                33,
                "00000000000000000000000000000000000000000000000000067127f0749ce0",
            ),
            (
                34,
                "000000000000000000000000000000000000000000000000000c06d4cb992b40",
            ),
            (
                35,
                "00000000000000000000000000000000000000000000000000138a0a2a644e00",
            ),
            (
                36,
                "000000000000000000000000000000000000000000000000001e5f59ff0f0e00",
            ),
            (
                37,
                "000000000000000000000000000000000000000000000000002e1da12f45c380",
            ),
            (
                38,
                "00000000000000000000000000000000000000000000000000414ae078f5d1e0",
            ),
            (
                39,
                "000000000000000000000000000000000000000000000000005738ee4a11f0e0",
            ),
            (
                40,
                "000000000000000000000000000000000000000000000000007374f54c5c30a0",
            ),
            (
                41,
                "000000000000000000000000000000000000000000000000009c05a4af3fcdc0",
            ),
            (
                42,
                "00000000000000000000000000000000000000000000000000c669c7db3fed80",
            ),
            (
                43,
                "00000000000000000000000000000000000000000000000001088595f1a953e0",
            ),
            (
                44,
                "0000000000000000000000000000000000000000000000000167a1629fa7a960",
            ),
            (
                45,
                "00000000000000000000000000000000000000000000000001f32db747272760",
            ),
            (
                46,
                "00000000000000000000000000000000000000000000000002c66b5e31f1f5c0",
            ),
            (
                47,
                "00000000000000000000000000000000000000000000000003beec205689a020",
            ),
            (
                48,
                "0000000000000000000000000000000000000000000000000537d218c0d68ea0",
            ),
            (
                49,
                "00000000000000000000000000000000000000000000000006f5629da3560ee0",
            ),
            (
                50,
                "00000000000000000000000000000000000000000000000008eb0983e6ec8ee0",
            ),
            (
                51,
                "0000000000000000000000000000000000000000000000000b22382e2dcefd60",
            ),
            (
                52,
                "0000000000000000000000000000000000000000000000000dc75e541af84d60",
            ),
            (
                53,
                "00000000000000000000000000000000000000000000000010e71ec1cb23ca20",
            ),
            (
                54,
                "0000000000000000000000000000000000000000000000001548b4bf6b9d3100",
            ),
            (
                55,
                "0000000000000000000000000000000000000000000000001bf6c2e204f41b40",
            ),
            (
                56,
                "000000000000000000000000000000000000000000000000251e9cea79c2cce0",
            ),
            (
                57,
                "0000000000000000000000000000000000000000000000002d688542329dbac0",
            ),
            (
                58,
                "000000000000000000000000000000000000000000000000374da719dc958d00",
            ),
            (
                59,
                "0000000000000000000000000000000000000000000000004266777a08f8ce80",
            ),
            (
                60,
                "0000000000000000000000000000000000000000000000004f9428f4722a17c0",
            ),
            (
                61,
                "000000000000000000000000000000000000000000000000627ea20909250840",
            ),
            (
                62,
                "0000000000000000000000000000000000000000000000007fd41135d2b41520",
            ),
            (
                63,
                "000000000000000000000000000000000000000000000000b415d6336051fce0",
            ),
            (
                64,
                "000000000000000000000000000000000000000000000000f84049eaa2bdc920",
            ),
            (
                65,
                "00000000000000000000000000000000000000000000000161a153ee991e8a80",
            ),
            (
                66,
                "000000000000000000000000000000000000000000000002075c4ceea37a38c0",
            ),
            (
                67,
                "000000000000000000000000000000000000000000000002c32e7638f85db9e0",
            ),
            (
                68,
                "0000000000000000000000000000000000000000000000038e5e1ddb9420fbc0",
            ),
            (
                69,
                "00000000000000000000000000000000000000000000000471555420c8491da0",
            ),
            (
                70,
                "0000000000000000000000000000000000000000000000054a50a331db8feba0",
            ),
            (
                71,
                "0000000000000000000000000000000000000000000000061ff0deddce4307e0",
            ),
            (
                72,
                "000000000000000000000000000000000000000000000006f2e198344ff63d80",
            ),
            (
                73,
                "000000000000000000000000000000000000000000000007bde137a39a5782a0",
            ),
            (
                74,
                "0000000000000000000000000000000000000000000000086e4e1f0dc8b7fa60",
            ),
            (
                75,
                "000000000000000000000000000000000000000000000008feeb3e567cff41c0",
            ),
            (
                76,
                "0000000000000000000000000000000000000000000000098e37156a82413240",
            ),
            (
                77,
                "00000000000000000000000000000000000000000000000a1147e2764b0a21a0",
            ),
            (
                78,
                "00000000000000000000000000000000000000000000000a9c1364231203dde0",
            ),
            (
                79,
                "00000000000000000000000000000000000000000000000b27755c4f71b45e40",
            ),
            (
                80,
                "00000000000000000000000000000000000000000000000bbdc167cddde49e60",
            ),
            (
                81,
                "00000000000000000000000000000000000000000000000c5ae5fdc96e314540",
            ),
            (
                82,
                "00000000000000000000000000000000000000000000000d00aef727dc4d2a40",
            ),
            (
                83,
                "00000000000000000000000000000000000000000000000da61108e5fd222a00",
            ),
            (
                84,
                "00000000000000000000000000000000000000000000000e59f35f37e5c50260",
            ),
            (
                85,
                "00000000000000000000000000000000000000000000000f0dfe2f5e261117c0",
            ),
            (
                86,
                "00000000000000000000000000000000000000000000000fd172877cda20ea20",
            ),
            (
                87,
                "0000000000000000000000000000000000000000000000108f0e99cc0c40f240",
            ),
            (
                88,
                "00000000000000000000000000000000000000000000001144561ebe70d48900",
            ),
            (
                89,
                "000000000000000000000000000000000000000000000012149b602f9d5e4e40",
            ),
            (
                90,
                "000000000000000000000000000000000000000000000012d3cc52b3a56e4f80",
            ),
            (
                91,
                "000000000000000000000000000000000000000000000013920a567e1baf5720",
            ),
            (
                92,
                "00000000000000000000000000000000000000000000001461834d9e685448a0",
            ),
            (
                93,
                "00000000000000000000000000000000000000000000001533f9e08c3a70f180",
            ),
            (
                94,
                "00000000000000000000000000000000000000000000001614402859652da9e0",
            ),
            (
                95,
                "00000000000000000000000000000000000000000000001708fc9de8a9016820",
            ),
            (
                96,
                "000000000000000000000000000000000000000000000018104072b037fd6840",
            ),
            (
                97,
                "0000000000000000000000000000000000000000000000193587f47f44b318c0",
            ),
            (
                98,
                "00000000000000000000000000000000000000000000001a7942c3db3c544e00",
            ),
            (
                99,
                "00000000000000000000000000000000000000000000001bd16dfe8636359a80",
            ),
            (
                100,
                "00000000000000000000000000000000000000000000001d407d055b91205080",
            ),
            (
                101,
                "00000000000000000000000000000000000000000000001eb1ac5c2ea8ef52e0",
            ),
            (
                102,
                "0000000000000000000000000000000000000000000000203ebd97d829576860",
            ),
            (
                103,
                "000000000000000000000000000000000000000000000021d38c3de21fde2be0",
            ),
            (
                104,
                "00000000000000000000000000000000000000000000002370c89b2e2b749be0",
            ),
            (
                105,
                "00000000000000000000000000000000000000000000002505c2c5d3ae324400",
            ),
            (
                106,
                "0000000000000000000000000000000000000000000000266bceea3b91dfc7a0",
            ),
            (
                107,
                "000000000000000000000000000000000000000000000027f24a2bb126d7cfc0",
            ),
            (
                108,
                "0000000000000000000000000000000000000000000000295708322ca3f160e0",
            ),
            (
                109,
                "00000000000000000000000000000000000000000000002ae0a0a7639d5382c0",
            ),
            (
                110,
                "00000000000000000000000000000000000000000000002c9759c2b432e2cbc0",
            ),
            (
                111,
                "00000000000000000000000000000000000000000000002ea4372f1351e945c0",
            ),
            (
                112,
                "000000000000000000000000000000000000000000000030eabb6aea1e3372a0",
            ),
            (
                113,
                "0000000000000000000000000000000000000000000000340f55af7e1992dda0",
            ),
            (
                114,
                "000000000000000000000000000000000000000000000037a95bf3e36b001820",
            ),
            (
                115,
                "00000000000000000000000000000000000000000000003bdfc0ef666a1293c0",
            ),
            (
                116,
                "0000000000000000000000000000000000000000000000409a91c0ac3435e780",
            ),
            (
                117,
                "000000000000000000000000000000000000000000000045dae2457ed37e1a60",
            ),
            (
                118,
                "00000000000000000000000000000000000000000000004b8f4bcf1f459655e0",
            ),
            (
                119,
                "000000000000000000000000000000000000000000000052e28b37bc272455e0",
            ),
            (
                120,
                "00000000000000000000000000000000000000000000005bf6711e872f9c9c40",
            ),
            (
                121,
                "000000000000000000000000000000000000000000000065fa32870e624f9bc0",
            ),
            (
                122,
                "000000000000000000000000000000000000000000000072420dd4e9bfc326c0",
            ),
            (
                123,
                "000000000000000000000000000000000000000000000080ee0a56a1701d7e40",
            ),
            (
                124,
                "0000000000000000000000000000000000000000000000927b55a53fe0b5f960",
            ),
            (
                125,
                "0000000000000000000000000000000000000000000000aa54f2dade69a01dc0",
            ),
            (
                126,
                "0000000000000000000000000000000000000000000000c931ca9362b0377b20",
            ),
            (
                127,
                "0000000000000000000000000000000000000000000000f200146c9f43cd6f60",
            ),
            (
                128,
                "000000000000000000000000000000000000000000000126de11075b399a25c0",
            ),
            (
                129,
                "00000000000000000000000000000000000000000000016cb8e540a683fba740",
            ),
            (
                130,
                "0000000000000000000000000000000000000000000001c591d6a7ae7afa8d20",
            ),
            (
                131,
                "0000000000000000000000000000000000000000000002433db5b93a1c218940",
            ),
            (
                132,
                "0000000000000000000000000000000000000000000002fabd96a3c1683667a0",
            ),
            (
                133,
                "0000000000000000000000000000000000000000000003ea915b5e66b2ba4640",
            ),
            (
                134,
                "000000000000000000000000000000000000000000000508a7b83ce27d6e0d80",
            ),
            (
                135,
                "000000000000000000000000000000000000000000000654b54aef7d013eec60",
            ),
            (
                136,
                "0000000000000000000000000000000000000000000007ff151710fa2c0766a0",
            ),
            (
                137,
                "000000000000000000000000000000000000000000000a29667c9507de4f5860",
            ),
            (
                138,
                "000000000000000000000000000000000000000000000cc33a042440e69953e0",
            ),
            (
                139,
                "00000000000000000000000000000000000000000000100b3a9024583bf28b80",
            ),
            (
                140,
                "00000000000000000000000000000000000000000000141101d9154085911fe0",
            ),
            (
                141,
                "0000000000000000000000000000000000000000000018df7a6211abc5ab0f00",
            ),
            (
                142,
                "000000000000000000000000000000000000000000001e9c7ae8df8f81f56640",
            ),
            (
                143,
                "00000000000000000000000000000000000000000000259b8e9646e7349c0c00",
            ),
            (
                144,
                "000000000000000000000000000000000000000000002d66952994737e0a63e0",
            ),
            (
                145,
                "000000000000000000000000000000000000000000003694c58d08d508cc8300",
            ),
            (
                146,
                "0000000000000000000000000000000000000000000041cd5532605cb88f6a60",
            ),
            (
                147,
                "000000000000000000000000000000000000000000004e992868fd1d93ec6400",
            ),
            (
                148,
                "000000000000000000000000000000000000000000005d44b796f30b5b47bae0",
            ),
            (
                149,
                "000000000000000000000000000000000000000000006d8074912a6737d3d380",
            ),
            (
                150,
                "0000000000000000000000000000000000000000000080ac4e0f3e76ba089b80",
            ),
            (
                151,
                "00000000000000000000000000000000000000000000963ac1bd3bc314c0d7a0",
            ),
            (
                152,
                "00000000000000000000000000000000000000000000aeea01f39ddc8c90f040",
            ),
            (
                153,
                "00000000000000000000000000000000000000000000cdc07cf49ac256735280",
            ),
            (
                154,
                "00000000000000000000000000000000000000000000ed8a0bf93786bc4ea1c0",
            ),
            (
                155,
                "000000000000000000000000000000000000000000010fe4d0ad93ec88d58a20",
            ),
            (
                156,
                "000000000000000000000000000000000000000000013411c99602e0779512c0",
            ),
            (
                157,
                "000000000000000000000000000000000000000000015fca5387f865e1609380",
            ),
            (
                158,
                "00000000000000000000000000000000000000000001921527684f8e18e0f120",
            ),
            (
                159,
                "00000000000000000000000000000000000000000001c8c70b3ef33636f10d20",
            ),
            (
                160,
                "000000000000000000000000000000000000000000020854e6788dc151fee520",
            ),
            (
                161,
                "000000000000000000000000000000000000000000024882d8a223b780bebf20",
            ),
            (
                162,
                "000000000000000000000000000000000000000000028a7e47ce725d7d426340",
            ),
            (
                163,
                "00000000000000000000000000000000000000000002d31bfe56e2b1739d6bc0",
            ),
            (
                164,
                "000000000000000000000000000000000000000000031d00935207d1ab495d20",
            ),
            (
                165,
                "00000000000000000000000000000000000000000003665bd4e1aba42c7dd8c0",
            ),
            (
                166,
                "00000000000000000000000000000000000000000003aeb503f622705470cc20",
            ),
            (
                167,
                "00000000000000000000000000000000000000000003f939a016b21b1b395760",
            ),
            (
                168,
                "0000000000000000000000000000000000000000000449d9a5f3dbacdbb93960",
            ),
            (
                169,
                "000000000000000000000000000000000000000000049586e07bd6f20810b960",
            ),
            (
                170,
                "00000000000000000000000000000000000000000004e709f889ae74fa318c40",
            ),
            (
                171,
                "000000000000000000000000000000000000000000053ca35329505af64851c0",
            ),
            (
                172,
                "00000000000000000000000000000000000000000005939985b1e73e86585920",
            ),
            (
                173,
                "00000000000000000000000000000000000000000005e9427295b0327510f160",
            ),
            (
                174,
                "0000000000000000000000000000000000000000000643ec461b119e93fa0120",
            ),
            (
                175,
                "000000000000000000000000000000000000000000069b385ff2430bd50d39c0",
            ),
            (
                176,
                "00000000000000000000000000000000000000000006f293e337e48534b58620",
            ),
            (
                177,
                "000000000000000000000000000000000000000000074c11d1095634524084a0",
            ),
            (
                178,
                "00000000000000000000000000000000000000000007a354129e16951771cac0",
            ),
            (
                179,
                "00000000000000000000000000000000000000000007fe715e2872e96c5294a0",
            ),
            (
                180,
                "0000000000000000000000000000000000000000000859065d467171f99cd620",
            ),
            (
                181,
                "00000000000000000000000000000000000000000008b6ad4a7c5e93761ed960",
            ),
            (
                182,
                "0000000000000000000000000000000000000000000916886665dd85cb9e37c0",
            ),
            (
                183,
                "00000000000000000000000000000000000000000009772960493504b307b5c0",
            ),
            (
                184,
                "00000000000000000000000000000000000000000009daa5194766250ba1e4e0",
            ),
            (
                185,
                "0000000000000000000000000000000000000000000a4314a99165a339d76940",
            ),
            (
                186,
                "0000000000000000000000000000000000000000000aafe04e07a0cc76908780",
            ),
            (
                187,
                "0000000000000000000000000000000000000000000b1f61a6c72823bc6f7cc0",
            ),
            (
                188,
                "0000000000000000000000000000000000000000000b8f0423557c7834c9c440",
            ),
            (
                189,
                "0000000000000000000000000000000000000000000c0129c4864d86d6937540",
            ),
            (
                190,
                "0000000000000000000000000000000000000000000c79e686c513ee1711d700",
            ),
            (
                191,
                "0000000000000000000000000000000000000000000cff3e24f98a31a9513bc0",
            ),
            (
                192,
                "0000000000000000000000000000000000000000000d90484e8d690d207cb3e0",
            ),
            (
                193,
                "0000000000000000000000000000000000000000000e3ba087263ab2bf5acbe0",
            ),
            (
                194,
                "0000000000000000000000000000000000000000000efa194f42d4866a387da0",
            ),
            (
                195,
                "0000000000000000000000000000000000000000000fc9f11bbc39959b21b000",
            ),
            (
                196,
                "00000000000000000000000000000000000000000010a60801ccdc23faa49280",
            ),
            (
                197,
                "00000000000000000000000000000000000000000011ae475d9025c6286edae0",
            ),
            (
                198,
                "00000000000000000000000000000000000000000012da0d5328636c44f7bb20",
            ),
            (
                199,
                "00000000000000000000000000000000000000000013fc8a1001c47b4dec7d80",
            ),
            (
                200,
                "000000000000000000000000000000000000000000152bfd3dacde2eb7fd1260",
            ),
            (
                201,
                "000000000000000000000000000000000000000000165dec4bf88a5938102cc0",
            ),
            (
                202,
                "00000000000000000000000000000000000000000017a58ac69e578aeff74d60",
            ),
            (
                203,
                "00000000000000000000000000000000000000000018ed2050238fb72a6adb60",
            ),
            (
                204,
                "0000000000000000000000000000000000000000001a514e4f44f2f7b58cce20",
            ),
            (
                205,
                "0000000000000000000000000000000000000000001bbec2257da9ba542e3dc0",
            ),
            (
                206,
                "0000000000000000000000000000000000000000001d264026c89fc3a561ff20",
            ),
            (
                207,
                "0000000000000000000000000000000000000000001ea64c2728a2c3bd62bf20",
            ),
            (
                208,
                "000000000000000000000000000000000000000000202d9445cb5993709c9940",
            ),
            (
                209,
                "00000000000000000000000000000000000000000021b50850f1b264bd8ee400",
            ),
            (
                210,
                "000000000000000000000000000000000000000000232737b9bae704d658e980",
            ),
            (
                211,
                "00000000000000000000000000000000000000000024b5ca6a95511e529b9a60",
            ),
            (
                212,
                "000000000000000000000000000000000000000000264a8fdb9737cec5270360",
            ),
            (
                213,
                "00000000000000000000000000000000000000000027e8a464ee3e6441e33ba0",
            ),
            (
                214,
                "00000000000000000000000000000000000000000029a2f2ee951b390851d020",
            ),
            (
                215,
                "0000000000000000000000000000000000000000002b7cf7e446f67a01521e40",
            ),
            (
                216,
                "0000000000000000000000000000000000000000002d4dfeb582d570cb6ec4c0",
            ),
            (
                217,
                "0000000000000000000000000000000000000000002f20dbd4bde0279e863f60",
            ),
            (
                218,
                "00000000000000000000000000000000000000000031258f6adfa6b4147044c0",
            ),
            (
                219,
                "00000000000000000000000000000000000000000033335d7927c4d1cc706340",
            ),
            (
                220,
                "000000000000000000000000000000000000000000356c0dc0666c9a25e31d60",
            ),
            (
                221,
                "00000000000000000000000000000000000000000037b28eb2ad32e4eb0725a0",
            ),
            (
                222,
                "0000000000000000000000000000000000000000003a1c496adb7a0fa510f440",
            ),
            (
                223,
                "0000000000000000000000000000000000000000003ceccfe9ad4acc1bac8580",
            ),
            (
                224,
                "0000000000000000000000000000000000000000003ff2e4225485aa755b79a0",
            ),
            (
                225,
                "000000000000000000000000000000000000000000431b177600a43a49c8ff20",
            ),
            (
                226,
                "0000000000000000000000000000000000000000004667f1b695192e96aa5e00",
            ),
            (
                227,
                "00000000000000000000000000000000000000000049d02ec230291e1ed89fe0",
            ),
            (
                228,
                "0000000000000000000000000000000000000000004d644cbc7c8dac48b042e0",
            ),
            (
                229,
                "000000000000000000000000000000000000000000511f3d1a5d2ee6dddf2c60",
            ),
            (
                230,
                "00000000000000000000000000000000000000000054dc50acc5ee22163a87e0",
            ),
            (
                231,
                "00000000000000000000000000000000000000000058df0f81b00e65e31d9fc0",
            ),
            (
                232,
                "0000000000000000000000000000000000000000005d23b986246a80e2a66160",
            ),
            (
                233,
                "0000000000000000000000000000000000000000006200474547413007eb54e0",
            ),
            (
                234,
                "0000000000000000000000000000000000000000006719397aeed92cea73c0c0",
            ),
            (
                235,
                "0000000000000000000000000000000000000000006c2c99cc24de404ac4f6c0",
            ),
            (
                236,
                "00000000000000000000000000000000000000000071efc0e32e8d53c3437520",
            ),
            (
                237,
                "000000000000000000000000000000000000000000781907b3b129168140d360",
            ),
            (
                238,
                "0000000000000000000000000000000000000000007eb5d786594edfb7192580",
            ),
            (
                239,
                "00000000000000000000000000000000000000000085125dd58b787822420060",
            ),
            (
                240,
                "0000000000000000000000000000000000000000008bae3f082d510ef55e75a0",
            ),
            (
                241,
                "00000000000000000000000000000000000000000093956885c724768b3e4220",
            ),
            (
                242,
                "0000000000000000000000000000000000000000009ba216e9c83e948399d3e0",
            ),
            (
                243,
                "000000000000000000000000000000000000000000a4347de9712a3d299897c0",
            ),
            (
                244,
                "000000000000000000000000000000000000000000ae9c5fcf35f61f498146e0",
            ),
            (
                245,
                "000000000000000000000000000000000000000000b86222fe3501a784060ac0",
            ),
            (
                246,
                "000000000000000000000000000000000000000000c207f50841bc71fbf34200",
            ),
            (
                247,
                "000000000000000000000000000000000000000000cd6cfa174358d251800c40",
            ),
            (
                248,
                "000000000000000000000000000000000000000000dad77213452f0444c351e0",
            ),
            (
                249,
                "000000000000000000000000000000000000000000e8ac5170255ea89b74f900",
            ),
            (
                250,
                "000000000000000000000000000000000000000000f8a13b2c589aeeb23ffba0",
            ),
            (
                251,
                "0000000000000000000000000000000000000000010b46275cd6a0d8d647dcc0",
            ),
            (
                252,
                "0000000000000000000000000000000000000000011fdd1173e9b175a204fbc0",
            ),
            (
                253,
                "0000000000000000000000000000000000000000013567509d0940b8bba28240",
            ),
            (
                254,
                "0000000000000000000000000000000000000000014cf8de771e406fcb574e00",
            ),
            (
                255,
                "00000000000000000000000000000000000000000165c5ae302bc30be69eb9a0",
            ),
            (
                256,
                "0000000000000000000000000000000000000000017eeb74084c207738949880",
            ),
            (
                257,
                "0000000000000000000000000000000000000000019a6b1b59c384990c32ece0",
            ),
            (
                258,
                "000000000000000000000000000000000000000001b739d4c259343246ef1ee0",
            ),
            (
                259,
                "000000000000000000000000000000000000000001d4e7eb5fde62f143663aa0",
            ),
            (
                260,
                "000000000000000000000000000000000000000001f3c1028afece7ae8982120",
            ),
            (
                261,
                "0000000000000000000000000000000000000000021724227cc1eca0a316fde0",
            ),
            (
                262,
                "0000000000000000000000000000000000000000023b8214bfc487e587047c20",
            ),
            (
                263,
                "00000000000000000000000000000000000000000261ecc1d79b256c651d81c0",
            ),
            (
                264,
                "0000000000000000000000000000000000000000028704359f9c7d6769226240",
            ),
            (
                265,
                "000000000000000000000000000000000000000002b1a0ea483b571304264320",
            ),
            (
                266,
                "000000000000000000000000000000000000000002df642ba14be8dd6aa4de80",
            ),
            (
                267,
                "0000000000000000000000000000000000000000030f9301272cdfb2ac437b80",
            ),
            (
                268,
                "00000000000000000000000000000000000000000341d93154f4bdb6a5c457a0",
            ),
            (
                269,
                "00000000000000000000000000000000000000000375140aa6d3469564e40d20",
            ),
            (
                270,
                "000000000000000000000000000000000000000003aa793e4456d51fee079d20",
            ),
            (
                271,
                "000000000000000000000000000000000000000003ddeb802da8e6b18d7f2440",
            ),
            (
                272,
                "00000000000000000000000000000000000000000411609ae24d1bf31e937fa0",
            ),
            (
                273,
                "0000000000000000000000000000000000000000044107e5ba926026f20196c0",
            ),
            (
                274,
                "0000000000000000000000000000000000000000046978f859a2d324a4f423a0",
            ),
            (
                275,
                "0000000000000000000000000000000000000000048e0bf34e00b79c6e0c9cc0",
            ),
            (
                276,
                "000000000000000000000000000000000000000004b64a09060ec73d90f77520",
            ),
            (
                277,
                "000000000000000000000000000000000000000004e06ebc5bfb6b016e590e80",
            ),
            (
                278,
                "0000000000000000000000000000000000000000050a145245ab90a8067ccd40",
            ),
            (
                279,
                "000000000000000000000000000000000000000005357e89442872e853f88fe0",
            ),
            (
                280,
                "00000000000000000000000000000000000000000560fbafcacfef7b2141bde0",
            ),
            (
                281,
                "0000000000000000000000000000000000000000058c736b7d94f11ac4af8820",
            ),
            (
                282,
                "000000000000000000000000000000000000000005ba243ec2581be932e72bc0",
            ),
            (
                283,
                "000000000000000000000000000000000000000005e7ee4c12541090941dbe60",
            ),
            (
                284,
                "000000000000000000000000000000000000000006156f04d90982240b8b39c0",
            ),
            (
                285,
                "000000000000000000000000000000000000000006456fe96f932a6a69ce1de0",
            ),
            (
                286,
                "0000000000000000000000000000000000000000067575520b861045f8089f80",
            ),
            (
                287,
                "000000000000000000000000000000000000000006aae3297a3f9d93d55e9ce0",
            ),
            (
                288,
                "000000000000000000000000000000000000000006dff4cf1a2437365611d5c0",
            ),
            (
                289,
                "00000000000000000000000000000000000000000718c9a7d0e51cfd930a0b20",
            ),
            (
                290,
                "00000000000000000000000000000000000000000759b56bb260925290180080",
            ),
            (
                291,
                "0000000000000000000000000000000000000000079a44d2dcddadcd50c16380",
            ),
            (
                292,
                "000000000000000000000000000000000000000007e1c9a6b59653827fadcba0",
            ),
            (
                293,
                "0000000000000000000000000000000000000000082ab9c86e527cfd7dffdc40",
            ),
            (
                294,
                "00000000000000000000000000000000000000000877e0fc3b665d3187c61ce0",
            ),
            (
                295,
                "000000000000000000000000000000000000000008cd0b371205d869e58815e0",
            ),
            (
                296,
                "000000000000000000000000000000000000000009286f3a6c1469a93569fda0",
            ),
            (
                297,
                "000000000000000000000000000000000000000009859a773846d18d99e33c40",
            ),
            (
                298,
                "000000000000000000000000000000000000000009e7aabe3dbb65d04b436960",
            ),
            (
                299,
                "00000000000000000000000000000000000000000a42c5c116143a6675fe4c40",
            ),
            (
                300,
                "00000000000000000000000000000000000000000a9fb114d65d94f00168f6a0",
            ),
            (
                301,
                "00000000000000000000000000000000000000000afbeba9e7b19fc8c09584c0",
            ),
            (
                302,
                "00000000000000000000000000000000000000000b58a9ce9935920487232a80",
            ),
            (
                303,
                "00000000000000000000000000000000000000000bbb7ed558b66d4d2e1c0d60",
            ),
            (
                304,
                "00000000000000000000000000000000000000000c255453c47c551c36aa3540",
            ),
            (
                305,
                "00000000000000000000000000000000000000000c941a7dca358fb9521e03e0",
            ),
            (
                306,
                "00000000000000000000000000000000000000000d037486edebab30d3c6c0e0",
            ),
            (
                307,
                "00000000000000000000000000000000000000000d7260db2663c608c7f7a7c0",
            ),
            (
                308,
                "00000000000000000000000000000000000000000de8efca09e80642843d4be0",
            ),
            (
                309,
                "00000000000000000000000000000000000000000e4c955dbc140174f247f260",
            ),
            (
                310,
                "00000000000000000000000000000000000000000eb5fabb18e954747a74b000",
            ),
            (
                311,
                "00000000000000000000000000000000000000000f284806995597f3cd0bfd80",
            ),
            (
                312,
                "00000000000000000000000000000000000000000f9ba14e6a962918bf2127c0",
            ),
            (
                313,
                "000000000000000000000000000000000000000010080df526f4ff21960f1a40",
            ),
            (
                314,
                "0000000000000000000000000000000000000000106a692d441a6aad1cace9e0",
            ),
            (
                315,
                "000000000000000000000000000000000000000010db77996e285750cd8b9c80",
            ),
            (
                316,
                "0000000000000000000000000000000000000000114c850e564cfaa41534e5a0",
            ),
            (
                317,
                "000000000000000000000000000000000000000011c8c20e26e90338310d8b40",
            ),
            (
                318,
                "000000000000000000000000000000000000000012416d3a1b42c5f9e33e93e0",
            ),
            (
                319,
                "000000000000000000000000000000000000000012bad0326db68dfbabe3a0a0",
            ),
            (
                320,
                "0000000000000000000000000000000000000000133891fe722cd8f8d46b71e0",
            ),
            (
                321,
                "000000000000000000000000000000000000000013b4cf153adbbd38ac356200",
            ),
            (
                322,
                "0000000000000000000000000000000000000000143f25d8093643758a467060",
            ),
            (
                323,
                "000000000000000000000000000000000000000014c95e395adc5f2947c38f60",
            ),
            (
                324,
                "0000000000000000000000000000000000000000155898b9afe71b5bc6234aa0",
            ),
            (
                325,
                "000000000000000000000000000000000000000015d0d64858237f52b67fbd80",
            ),
            (
                326,
                "0000000000000000000000000000000000000000164edf3c9afdff38aca62a40",
            ),
            (
                327,
                "000000000000000000000000000000000000000016d815351bf2448270b26bc0",
            ),
            (
                328,
                "0000000000000000000000000000000000000000175dce415adf182a317efee0",
            ),
            (
                329,
                "000000000000000000000000000000000000000017e305e5e5ebe1b42a2283c0",
            ),
            (
                330,
                "000000000000000000000000000000000000000018769f070c2824c962eee160",
            ),
            (
                331,
                "0000000000000000000000000000000000000000190bc46a36b8e7956e861a40",
            ),
            (
                332,
                "000000000000000000000000000000000000000019a549dd7f975730622fb1e0",
            ),
            (
                333,
                "00000000000000000000000000000000000000001a40e2926d569536de587200",
            ),
            (
                334,
                "00000000000000000000000000000000000000001ada8179bddb7efbe43bb160",
            ),
            (
                335,
                "00000000000000000000000000000000000000001b771d7dcf1fac50373e6440",
            ),
            (
                336,
                "00000000000000000000000000000000000000001c1cd59725d81e6e21d5cae0",
            ),
            (
                337,
                "00000000000000000000000000000000000000001cc5bcc99d2c4a90357ad360",
            ),
            (
                338,
                "00000000000000000000000000000000000000001d595888caa6d458e6efa260",
            ),
            (
                339,
                "00000000000000000000000000000000000000001e0cbd014668d1e4d9ba8e40",
            ),
            (
                340,
                "00000000000000000000000000000000000000001ea37d7a3f2552a2f909f620",
            ),
            (
                341,
                "00000000000000000000000000000000000000001f3241a19347d4dd02c83d00",
            ),
            (
                342,
                "00000000000000000000000000000000000000001f99213be9ee53bddf9ee5c0",
            ),
            (
                343,
                "00000000000000000000000000000000000000001ffb0ee21327a85c0b6cd6c0",
            ),
            (
                344,
                "00000000000000000000000000000000000000002062e31d9a89a510058f0680",
            ),
            (
                345,
                "000000000000000000000000000000000000000020d24e4a9d0743295882b380",
            ),
            (
                346,
                "0000000000000000000000000000000000000000215078acda07c153babfb140",
            ),
            (
                347,
                "000000000000000000000000000000000000000021d45e243085daf592b0bbe0",
            ),
            (
                348,
                "0000000000000000000000000000000000000000225c6fa2067f24b11235b6a0",
            ),
            (
                349,
                "000000000000000000000000000000000000000022eaeae8d7274e795d554f80",
            ),
            (
                350,
                "0000000000000000000000000000000000000000237ac17de8cd15067a6a0fc0",
            ),
            (
                351,
                "00000000000000000000000000000000000000002415e366c94c1e34c7f72b20",
            ),
            (
                352,
                "000000000000000000000000000000000000000024b84a0606d0a6eff7d24240",
            ),
            (
                353,
                "000000000000000000000000000000000000000025584400aa7a24ab60f95da0",
            ),
            (
                354,
                "000000000000000000000000000000000000000026058fbce96b8fd898fb4440",
            ),
            (
                355,
                "000000000000000000000000000000000000000026b368bd9b25fad76f8f80e0",
            ),
            (
                356,
                "00000000000000000000000000000000000000002761f842fb541ec705fbab80",
            ),
            (
                357,
                "00000000000000000000000000000000000000002820cc635abe2ef6bb03bfa0",
            ),
            (
                358,
                "000000000000000000000000000000000000000028dff750d76099ef8067b5e0",
            ),
            (
                359,
                "000000000000000000000000000000000000000029a847072a5004727d7bb6c0",
            ),
            (
                360,
                "00000000000000000000000000000000000000002a6d9a7894891e6c8d042a60",
            ),
            (
                361,
                "00000000000000000000000000000000000000002b323ae9b7f6eaaec69c08a0",
            ),
            (
                362,
                "00000000000000000000000000000000000000002bfefb71afd13545bc2444e0",
            ),
            (
                363,
                "00000000000000000000000000000000000000002cc925a3aa907374b5f0b6c0",
            ),
            (
                364,
                "00000000000000000000000000000000000000002d9e8bc0134624c9d3ce88c0",
            ),
            (
                365,
                "00000000000000000000000000000000000000002e7e60cf6c8d3d2643d9ed00",
            ),
        ];

        let spv_client =
            SpvClient::new(db_path, 0, None, BitcoinNetworkType::Mainnet, false, false).unwrap();
        for (interval, work_str) in chain_work.iter() {
            let calculated_work = spv_client.find_interval_work(*interval).unwrap().unwrap();
            let expected_work = Uint256::from_hex_be(work_str).unwrap();
            assert_eq!(calculated_work, expected_work);
        }
    }

    #[test]
    fn test_spv_check_work_reorg_ignored() {
        if !env::var("BLOCKSTACK_SPV_HEADERS_DB").is_ok() {
            eprintln!("Skipping test_spv_check_work_reorg_ignored -- no BLOCKSTACK_SPV_HEADERS_DB envar set");
            return;
        }
        let db_path_source = env::var("BLOCKSTACK_SPV_HEADERS_DB").unwrap();
        let db_path = "/tmp/test_spv_check_work_reorg_ignored.dat".to_string();
        let reorg_db_path = "/tmp/test_spv_check_work_ignored.dat.reorg".to_string();

        if fs::metadata(&db_path).is_ok() {
            fs::remove_file(&db_path).unwrap();
        }

        if fs::metadata(&reorg_db_path).is_ok() {
            fs::remove_file(&reorg_db_path).unwrap();
        }

        fs::copy(&db_path_source, &db_path).unwrap();

        {
            // set up SPV client so we don't have chain work at first
            let mut spv_client = SpvClient::new_without_migration(
                &db_path,
                0,
                None,
                BitcoinNetworkType::Mainnet,
                true,
                false,
            )
            .unwrap();

            assert!(
                spv_client.get_headers_height().unwrap() >= 40322,
                "This test needs headers up to 40320"
            );
            spv_client.drop_headers(40320).unwrap();
        }

        let mut spv_client =
            SpvClient::new(&db_path, 0, None, BitcoinNetworkType::Mainnet, true, false).unwrap();

        assert_eq!(spv_client.get_headers_height().unwrap(), 40321);
        let total_work_before = spv_client.update_chain_work().unwrap();
        assert_eq!(total_work_before, spv_client.get_chain_work().unwrap());

        let total_work_before_idempotent = spv_client.update_chain_work().unwrap();
        assert_eq!(total_work_before, total_work_before_idempotent);

        // fake block headers for mainnet 40319-40320, which is on a difficulty adjustment boundary
        let bad_headers = [
            LoneBlockHeader {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "000000000683a474ef810000fd22f0edde4cf33ae76ae506b220e57aeeafeaa4",
                    )
                    .unwrap(),
                    merkle_root: Sha256dHash::from_hex(
                        "b4d736ca74838036ebd19b085c3eeb9ffec2307f6452347cdd8ddaa249686f39",
                    )
                    .unwrap(),
                    time: 1716199659,
                    bits: 486575299,
                    nonce: 201337507,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "000000006f403731d720174cd6875e331ac079b438cf53aa685f9cd068fd4ca8",
                    )
                    .unwrap(),
                    merkle_root: Sha256dHash::from_hex(
                        "a86b3c149f204d4cb47c67bf9bfeea2719df101dd6e6fc3f0e60d86efeba22a8",
                    )
                    .unwrap(),
                    time: 1716161259,
                    bits: 486604799,
                    nonce: 144574511,
                },
                tx_count: VarInt(0),
            },
        ];

        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(db_path.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Mainnet),
            None,
        );

        let mut inserted_bad_header = false;

        let new_tip = indexer
            .find_bitcoin_reorg(
                &db_path,
                &reorg_db_path,
                |ref mut indexer, ref mut reorg_spv_client, start_block, end_block_opt| {
                    let end_block =
                        end_block_opt.unwrap_or(start_block + BLOCK_DIFFICULTY_CHUNK_SIZE);

                    let mut ret = vec![];
                    for block_height in start_block..end_block {
                        if block_height > 40320 {
                            break;
                        }
                        if block_height >= 40319 && block_height <= 40320 {
                            test_debug!("insert bad header {}", block_height);
                            ret.push(bad_headers[(block_height - 40319) as usize].clone());
                            inserted_bad_header = true;
                        } else {
                            let orig_spv_client = SpvClient::new_without_migration(
                                &db_path,
                                0,
                                None,
                                BitcoinNetworkType::Mainnet,
                                true,
                                false,
                            )
                            .unwrap();
                            let hdr = orig_spv_client.read_block_header(block_height)?.unwrap();
                            ret.push(hdr);
                        }
                    }

                    test_debug!(
                        "add headers after {} (bad header: {})",
                        start_block,
                        inserted_bad_header
                    );
                    reorg_spv_client
                        .insert_block_headers_after(start_block - 1, ret)
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();

        assert!(inserted_bad_header);

        // reorg is ignored
        assert_eq!(new_tip, 40321);
        let total_work_after = spv_client.update_chain_work().unwrap();
        assert_eq!(total_work_after, total_work_before);
    }

    #[test]
    fn test_spv_check_work_reorg_accepted() {
        if !env::var("BLOCKSTACK_SPV_HEADERS_DB").is_ok() {
            eprintln!("Skipping test_spv_check_work_reorg_accepted -- no BLOCKSTACK_SPV_HEADERS_DB envar set");
            return;
        }
        let db_path_source = env::var("BLOCKSTACK_SPV_HEADERS_DB").unwrap();
        let db_path = "/tmp/test_spv_check_work_reorg_accepted.dat".to_string();
        let reorg_db_path = "/tmp/test_spv_check_work_reorg_accepted.dat.reorg".to_string();

        if fs::metadata(&db_path).is_ok() {
            fs::remove_file(&db_path).unwrap();
        }

        if fs::metadata(&reorg_db_path).is_ok() {
            fs::remove_file(&reorg_db_path).unwrap();
        }

        fs::copy(&db_path_source, &db_path).unwrap();

        // set up SPV client so we don't have chain work at first
        let mut spv_client = SpvClient::new_without_migration(
            &db_path,
            0,
            None,
            BitcoinNetworkType::Mainnet,
            true,
            false,
        )
        .unwrap();

        assert!(
            spv_client.get_headers_height().unwrap() >= 40322,
            "This test needs headers up to 40320"
        );
        spv_client.drop_headers(40320).unwrap();

        assert_eq!(spv_client.get_headers_height().unwrap(), 40321);

        // fake block headers for mainnet 40319-40320, which is on a difficulty adjustment boundary
        let bad_headers = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "000000000683a474ef810000fd22f0edde4cf33ae76ae506b220e57aeeafeaa4",
                    )
                    .unwrap(),
                    merkle_root: Sha256dHash::from_hex(
                        "b4d736ca74838036ebd19b085c3eeb9ffec2307f6452347cdd8ddaa249686f39",
                    )
                    .unwrap(),
                    time: 1716199659,
                    bits: 486575299,
                    nonce: 201337507,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "000000006f403731d720174cd6875e331ac079b438cf53aa685f9cd068fd4ca8",
                    )
                    .unwrap(),
                    merkle_root: Sha256dHash::from_hex(
                        "a86b3c149f204d4cb47c67bf9bfeea2719df101dd6e6fc3f0e60d86efeba22a8",
                    )
                    .unwrap(),
                    time: 1716161259,
                    bits: 486604799,
                    nonce: 144574511,
                },
                tx_count: VarInt(0),
            },
        ];

        // get the canonical chain's headers for this range
        let good_headers = spv_client.read_block_headers(40319, 40321).unwrap();
        assert_eq!(good_headers.len(), 2);
        assert_eq!(
            good_headers[0].header.prev_blockhash,
            bad_headers[0].header.prev_blockhash
        );
        assert!(good_headers[0].header != bad_headers[0].header);
        assert!(good_headers[1].header != bad_headers[1].header);

        // put these bad headers into the "main" chain
        spv_client
            .insert_block_headers_after(40318, bad_headers.clone())
            .unwrap();

        // *now* calculate main chain work
        SpvClient::test_db_migrate(spv_client.conn_mut()).unwrap();
        let total_work_before = spv_client.update_chain_work().unwrap();
        assert_eq!(total_work_before, spv_client.get_chain_work().unwrap());

        let total_work_before_idempotent = spv_client.update_chain_work().unwrap();
        assert_eq!(total_work_before, total_work_before_idempotent);

        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(db_path.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Mainnet),
            None,
        );

        let mut inserted_good_header = false;

        let new_tip = indexer
            .find_bitcoin_reorg(
                &db_path,
                &reorg_db_path,
                |ref mut indexer, ref mut reorg_spv_client, start_block, end_block_opt| {
                    let end_block =
                        end_block_opt.unwrap_or(start_block + BLOCK_DIFFICULTY_CHUNK_SIZE);

                    let mut ret = vec![];
                    for block_height in start_block..end_block {
                        if block_height > 40320 {
                            break;
                        }
                        if block_height >= 40319 && block_height <= 40320 {
                            test_debug!("insert good header {}", block_height);
                            ret.push(good_headers[(block_height - 40319) as usize].clone());
                            inserted_good_header = true;
                        } else {
                            let orig_spv_client = SpvClient::new_without_migration(
                                &db_path,
                                0,
                                None,
                                BitcoinNetworkType::Mainnet,
                                true,
                                false,
                            )
                            .unwrap();
                            let hdr = orig_spv_client.read_block_header(block_height)?.unwrap();
                            ret.push(hdr);
                        }
                    }

                    test_debug!(
                        "add headers after {} (good header: {})",
                        start_block,
                        inserted_good_header
                    );
                    reorg_spv_client
                        .insert_block_headers_after(start_block - 1, ret)
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();

        assert!(inserted_good_header);

        // chain reorg detected!
        assert_eq!(new_tip, 40318);

        // total work increased
        let total_work_after = spv_client.update_chain_work().unwrap();
        assert!(total_work_after > total_work_before);
    }

    #[test]
    fn test_check_header_timestamp() {
        let db_path = "/tmp/test-indexer-check-header-timestamp.dat";

        if fs::metadata(db_path).is_ok() {
            fs::remove_file(db_path).unwrap();
        }

        let headers = vec![
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "20bee96458517fc5082a9720ce6207b5742f2b18e4e0a7e7373342725d80f88c",
                    )
                    .unwrap(),
                    nonce: 2,
                    prev_blockhash: Sha256dHash::from_hex(
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
                    )
                    .unwrap(),
                    time: (get_epoch_time_secs() - 1) as u32,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "39d1a6f1ee7a5903797f92ec89e4c58549013f38114186fc2eb6e5218cb2d0ac",
                    )
                    .unwrap(),
                    nonce: 1,
                    prev_blockhash: Sha256dHash::from_hex(
                        "606d31daaaa5919f3720d8440dd99d31f2a4e4189c65879f19ae43268425e74b",
                    )
                    .unwrap(),
                    time: (get_epoch_time_secs() - 1) as u32,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
            LoneBlockHeader {
                header: BlockHeader {
                    bits: 545259519,
                    merkle_root: Sha256dHash::from_hex(
                        "a7e04ed25f589938eb5627abb7b5913dd77b8955bcdf72d7f111d0a71e346e47",
                    )
                    .unwrap(),
                    nonce: 4,
                    prev_blockhash: Sha256dHash::from_hex(
                        "2fa2f451ac27f0e5cd3760ba6cdf34ef46adb76a44d96bc0f3bf3e713dd955f0",
                    )
                    .unwrap(),
                    time: 1587626882,
                    version: 0x20000000,
                },
                tx_count: VarInt(0),
            },
        ];

        // set up SPV client so we don't have chain work at first
        let mut spv_client = SpvClient::new_without_migration(
            &db_path,
            0,
            None,
            BitcoinNetworkType::Regtest,
            true,
            false,
        )
        .unwrap();

        spv_client
            .test_write_block_headers(0, headers.clone())
            .unwrap();
        assert_eq!(spv_client.get_highest_header_height().unwrap(), 2);

        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(db_path.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest),
            None,
        );

        if let Err(burnchain_error::TrySyncAgain) = indexer.check_chain_tip_timestamp() {
        } else {
            panic!("stale tip not detected");
        }

        // peeled
        assert_eq!(spv_client.get_highest_header_height().unwrap(), 1);
        assert!(indexer.check_chain_tip_timestamp().is_ok());
        assert_eq!(spv_client.get_highest_header_height().unwrap(), 1);
    }

    /// This test ensures that setting `should_keep_running` to false halts the handshake function.
    #[test]
    fn test_should_keep_running_halts_handshake() {
        let db_path = "/tmp/test_should_keep_running.dat".to_string();

        if fs::metadata(&db_path).is_ok() {
            fs::remove_file(&db_path).unwrap();
        }

        let should_keep_running = Arc::new(AtomicBool::new(true));
        let mut indexer = BitcoinIndexer::new(
            BitcoinIndexerConfig::test_default(db_path.to_string()),
            BitcoinIndexerRuntime::new(BitcoinNetworkType::Mainnet),
            Some(should_keep_running.clone()),
        );

        thread::spawn(move || indexer.connect_handshake_backoff());
        thread::sleep(Duration::from_millis(10_000));

        should_keep_running.store(false, Ordering::SeqCst);
    }
}
