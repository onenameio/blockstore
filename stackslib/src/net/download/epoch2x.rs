// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{
    sync_channel, Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};

use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{BlockHeaderHash, PoxId, SortitionId, StacksBlockId};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log};

use crate::burnchains::{Burnchain, BurnchainView};
use crate::chainstate::burn::db::sortdb::{BlockHeaderCache, SortitionDB, SortitionDBConn};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{Error as chainstate_error, StacksBlockHeader};
use crate::core::{
    EMPTY_MICROBLOCK_PARENT_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::net::asn::ASEntry4;
use crate::net::atlas::AttachmentsDownloader;
use crate::net::codec::*;
use crate::net::connection::{ConnectionOptions, ReplyHandleHttp};
use crate::net::db::{PeerDB, *};
use crate::net::dns::*;
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::inv::epoch2x::InvState;
use crate::net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;
use crate::net::p2p::PeerNetwork;
use crate::net::rpc::*;
use crate::net::server::HttpPeer;
use crate::net::{
    Error as net_error, GetBlocksInv, Neighbor, NeighborKey, StacksMessage, StacksP2P, *,
};
use crate::util_lib::db::{DBConn, Error as db_error};

#[cfg(not(test))]
pub const BLOCK_DOWNLOAD_INTERVAL: u64 = 180;
#[cfg(test)]
pub const BLOCK_DOWNLOAD_INTERVAL: u64 = 0;

/// If a URL never connects, don't use it again for this many seconds
#[cfg(not(test))]
pub const BLOCK_DOWNLOAD_BAN_URL: u64 = 300;
#[cfg(test)]
pub const BLOCK_DOWNLOAD_BAN_URL: u64 = 60;

/// If we created a request to download a block or microblock, don't do so again until this many
/// seconds have passed.
#[cfg(not(test))]
pub const BLOCK_REREQUEST_INTERVAL: u64 = 60;
#[cfg(test)]
pub const BLOCK_REREQUEST_INTERVAL: u64 = 30;

/// This module is responsible for downloading blocks and microblocks from other peers, using block
/// inventory state (see src/net/inv.rs)

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum BlockRequestKeyKind {
    Block,
    ConfirmedMicroblockStream,
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct BlockRequestKey {
    pub neighbor: NeighborKey,
    pub data_url: UrlString,
    pub consensus_hash: ConsensusHash,
    pub anchor_block_hash: BlockHeaderHash,
    pub index_block_hash: StacksBlockId,
    pub parent_block_header: Option<StacksBlockHeader>, // only used if asking for a microblock; used to confirm the stream's continuity
    pub parent_consensus_hash: Option<ConsensusHash>,   // ditto
    pub sortition_height: u64,
    pub download_start: u64,
    pub kind: BlockRequestKeyKind,
    pub canonical_stacks_tip_height: u64,
}

impl BlockRequestKey {
    pub fn new(
        neighbor: NeighborKey,
        data_url: UrlString,
        consensus_hash: ConsensusHash,
        anchor_block_hash: BlockHeaderHash,
        index_block_hash: StacksBlockId,
        parent_block_header: Option<StacksBlockHeader>,
        parent_consensus_hash: Option<ConsensusHash>,
        sortition_height: u64,
        kind: BlockRequestKeyKind,
        canonical_stacks_tip_height: u64,
    ) -> BlockRequestKey {
        BlockRequestKey {
            neighbor,
            data_url,
            consensus_hash,
            anchor_block_hash,
            index_block_hash,
            parent_block_header,
            parent_consensus_hash,
            sortition_height,
            download_start: get_epoch_time_secs(),
            kind,
            canonical_stacks_tip_height,
        }
    }

    /// Make a request for a block
    fn make_getblock_request(&self, peer_host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            peer_host,
            "GET".into(),
            format!("/v2/blocks/{}", &self.index_block_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to create HTTP request for infallible data")
    }

    /// Make a request for a stream of confirmed microblocks
    fn make_confirmed_microblocks_request(&self, peer_host: PeerHost) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            peer_host,
            "GET".into(),
            format!("/v2/microblocks/confirmed/{}", &self.index_block_hash),
            HttpRequestContents::new(),
        )
        .expect("FATAL: failed to create HTTP request for infallible data")
    }
}

impl Requestable for BlockRequestKey {
    fn get_url(&self) -> &UrlString {
        &self.data_url
    }

    fn make_request_type(&self, peer_host: PeerHost) -> StacksHttpRequest {
        match self.kind {
            BlockRequestKeyKind::Block => self.make_getblock_request(peer_host),
            BlockRequestKeyKind::ConfirmedMicroblockStream => {
                self.make_confirmed_microblocks_request(peer_host)
            }
        }
    }
}

impl std::fmt::Display for BlockRequestKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "<Request<{:?}>: {} {} {:?}>",
            self.kind, self.index_block_hash, self.neighbor, self.data_url
        )
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum BlockDownloaderState {
    DNSLookupBegin,
    DNSLookupFinish,
    GetBlocksBegin,
    GetBlocksFinish,
    GetMicroblocksBegin,
    GetMicroblocksFinish,
    Done,
}

#[derive(Debug)]
pub struct BlockDownloader {
    state: BlockDownloaderState,
    pox_id: PoxId,

    /// Sortition height at which to attempt to fetch blocks
    block_sortition_height: u64,
    microblock_sortition_height: u64,
    next_block_sortition_height: u64,
    next_microblock_sortition_height: u64,

    /// How many blocks downloaded since we re-scanned the chain?
    num_blocks_downloaded: u64,
    num_microblocks_downloaded: u64,

    /// How many times have we tried to download blocks, only to find nothing?
    empty_block_download_passes: u64,
    empty_microblock_download_passes: u64,

    /// When was the last time we did a full scan of the inv state?  when was the last time the inv
    /// state was updated?
    pub finished_scan_at: u64,
    last_inv_update_at: u64,

    /// Maximum number of concurrent requests
    max_inflight_requests: u64,

    /// Block requests to try, grouped by block, keyed by sortition height
    blocks_to_try: HashMap<u64, VecDeque<BlockRequestKey>>,

    /// Microblock requests to try, grouped by block, keyed by sortition height
    microblocks_to_try: HashMap<u64, VecDeque<BlockRequestKey>>,

    /// In-flight requests for DNS names
    parsed_urls: HashMap<UrlString, DNSRequest>,
    dns_lookups: HashMap<UrlString, Option<Vec<SocketAddr>>>,
    dns_timeout: u128,

    /// In-flight requests for blocks and confirmed microblocks
    /// The key for each of these is the sortition height and _index_ block hash.
    getblock_requests: HashMap<BlockRequestKey, usize>,
    getmicroblocks_requests: HashMap<BlockRequestKey, usize>,
    blocks: HashMap<BlockRequestKey, StacksBlock>,
    microblocks: HashMap<BlockRequestKey, Vec<StacksMicroblock>>,

    /// statistics on peers' data-plane endpoints
    pub(crate) dead_peers: Vec<usize>,
    pub(crate) broken_peers: Vec<usize>,
    broken_neighbors: Vec<NeighborKey>, // disconnect peers who report invalid block inventories too

    pub(crate) blocked_urls: HashMap<UrlString, u64>, // URLs that chronically don't work, and when we can try them again

    /// how often to download
    download_interval: u64,

    /// when did we last request a given block hash
    requested_blocks: HashMap<StacksBlockId, u64>,
    requested_microblocks: HashMap<StacksBlockId, u64>,
}

impl BlockDownloader {
    pub fn new(
        dns_timeout: u128,
        download_interval: u64,
        max_inflight_requests: u64,
    ) -> BlockDownloader {
        BlockDownloader {
            state: BlockDownloaderState::DNSLookupBegin,
            pox_id: PoxId::initial(),

            block_sortition_height: 0,
            microblock_sortition_height: 0,
            next_block_sortition_height: 0,
            next_microblock_sortition_height: 0,

            num_blocks_downloaded: 0,
            num_microblocks_downloaded: 0,
            empty_block_download_passes: 0,
            empty_microblock_download_passes: 0,
            finished_scan_at: 0,
            last_inv_update_at: 0,

            max_inflight_requests,
            blocks_to_try: HashMap::new(),
            microblocks_to_try: HashMap::new(),

            parsed_urls: HashMap::new(),
            dns_lookups: HashMap::new(),
            dns_timeout,

            getblock_requests: HashMap::new(),
            getmicroblocks_requests: HashMap::new(),
            blocks: HashMap::new(),
            microblocks: HashMap::new(),

            dead_peers: vec![],
            broken_peers: vec![],
            broken_neighbors: vec![],
            blocked_urls: HashMap::new(),

            download_interval,
            requested_blocks: HashMap::new(),
            requested_microblocks: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        debug!("Downloader reset");
        self.state = BlockDownloaderState::DNSLookupBegin;

        self.dns_lookups.clear();
        self.parsed_urls.clear();

        self.getblock_requests.clear();
        self.getmicroblocks_requests.clear();
        self.blocks_to_try.clear();
        self.microblocks_to_try.clear();
        self.blocks.clear();
        self.microblocks.clear();

        self.dead_peers.clear();
        self.broken_peers.clear();
        self.broken_neighbors.clear();

        // perserve sortition height
        // preserve download accounting
    }

    pub fn restart_scan(&mut self, sortition_start: u64) {
        // prepare to restart a full-chain scan for block downloads
        self.block_sortition_height = sortition_start;
        self.microblock_sortition_height = sortition_start;
        self.next_block_sortition_height = sortition_start;
        self.next_microblock_sortition_height = sortition_start;
        self.empty_block_download_passes = 0;
        self.empty_microblock_download_passes = 0;
    }

    pub fn dns_lookups_begin(
        &mut self,
        pox_id: &PoxId,
        dns_client: &mut DNSClient,
        urls: Vec<UrlString>,
    ) -> Result<(), net_error> {
        assert_eq!(self.state, BlockDownloaderState::DNSLookupBegin);

        // optimistic concurrency control: remember the current PoX Id
        self.pox_id = pox_id.clone();
        self.dns_lookups.clear();
        for url_str in urls.into_iter() {
            if url_str.is_empty() {
                continue;
            }
            let url = url_str.parse_to_block_url()?; // NOTE: should always succeed, since a UrlString shouldn't decode unless it's a valid URL or the empty string
            let port = match url.port_or_known_default() {
                Some(p) => p,
                None => {
                    warn!("Unsupported URL {:?}: unknown port", &url);
                    continue;
                }
            };
            match url.host() {
                Some(url::Host::Domain(domain)) => {
                    match dns_client.queue_lookup(
                        domain,
                        port,
                        get_epoch_time_ms() + self.dns_timeout,
                    ) {
                        Ok(_) => {}
                        Err(_) => continue,
                    }
                    self.dns_lookups.insert(url_str.clone(), None);
                    self.parsed_urls
                        .insert(url_str, DNSRequest::new(domain.to_string(), port, 0));
                }
                Some(url::Host::Ipv4(addr)) => {
                    self.dns_lookups
                        .insert(url_str, Some(vec![SocketAddr::new(IpAddr::V4(addr), port)]));
                }
                Some(url::Host::Ipv6(addr)) => {
                    self.dns_lookups
                        .insert(url_str, Some(vec![SocketAddr::new(IpAddr::V6(addr), port)]));
                }
                None => {
                    warn!("Unsupported URL {:?}", &url_str);
                }
            }
        }

        self.state = BlockDownloaderState::DNSLookupFinish;
        Ok(())
    }

    pub fn dns_lookups_try_finish(
        &mut self,
        dns_client: &mut DNSClient,
    ) -> Result<bool, net_error> {
        dns_client.try_recv()?;

        let mut inflight = 0;
        for (url_str, request) in self.parsed_urls.iter() {
            match dns_client.poll_lookup(&request.host, request.port) {
                Ok(Some(query_result)) => {
                    if let Some(dns_result) = self.dns_lookups.get_mut(url_str) {
                        // solicited
                        match query_result.result {
                            Ok(addrs) => {
                                *dns_result = Some(addrs);
                            }
                            Err(msg) => {
                                warn!("DNS failed to look up {:?}: {}", &url_str, msg);
                            }
                        }
                    }
                }
                Ok(None) => {
                    inflight += 1;
                }
                Err(e) => {
                    warn!("DNS lookup failed on {:?}: {:?}", url_str, &e);
                }
            }
        }

        if inflight == 0 {
            // done with DNS
            dns_client.clear_all_requests();
            self.state = BlockDownloaderState::GetBlocksBegin;
        }

        Ok(inflight == 0)
    }

    pub fn getblocks_begin(&mut self, requests: HashMap<BlockRequestKey, usize>) {
        assert_eq!(self.state, BlockDownloaderState::GetBlocksBegin);

        // don't touch blocks-to-try -- that's managed by the peer network directly.
        self.getblock_requests = requests;
        self.state = BlockDownloaderState::GetBlocksFinish;
    }

    /// Finish fetching blocks.  Return true once all reply handles have been fulfilled (either
    /// with data, or with an error).
    /// Store blocks as we get them.
    pub fn getblocks_try_finish(&mut self, network: &mut PeerNetwork) -> Result<bool, net_error> {
        assert_eq!(self.state, BlockDownloaderState::GetBlocksFinish);

        // requests that are still pending
        let mut pending_block_requests = HashMap::new();

        PeerNetwork::with_http(network, |ref mut network, ref mut http| {
            for (block_key, event_id) in self.getblock_requests.drain() {
                match http.get_conversation(event_id) {
                    None => {
                        if http.is_connecting(event_id) {
                            debug!(
                                "Event {} ({:?}, {:?} for block {} is not connected yet",
                                event_id,
                                &block_key.neighbor,
                                &block_key.data_url,
                                &block_key.index_block_hash
                            );
                            pending_block_requests.insert(block_key, event_id);
                        } else {
                            self.dead_peers.push(event_id);

                            // try again
                            self.requested_blocks.remove(&block_key.index_block_hash);

                            let is_always_allowed = match PeerDB::get_peer(
                                &network.peerdb.conn(),
                                block_key.neighbor.network_id,
                                &block_key.neighbor.addrbytes,
                                block_key.neighbor.port,
                            ) {
                                Ok(Some(neighbor)) => neighbor.is_always_allowed(),
                                _ => false,
                            };

                            if !is_always_allowed {
                                debug!("Event {} ({:?}, {:?}) for block {} failed to connect. Temporarily blocking URL", event_id, &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash);

                                // don't try this again for a while
                                self.blocked_urls.insert(
                                    block_key.data_url,
                                    get_epoch_time_secs() + BLOCK_DOWNLOAD_BAN_URL,
                                );
                            } else {
                                debug!("Event {} ({:?}, {:?}, always-allowed) for block {} failed to connect", event_id, &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash);

                                if cfg!(test) {
                                    // just mark that we would have blocked it
                                    self.blocked_urls
                                        .insert(block_key.data_url, get_epoch_time_secs() + 10);
                                }
                            }
                        }
                    }
                    Some(ref mut convo) => {
                        match convo.try_get_response() {
                            None => {
                                // still waiting
                                debug!("Event {} ({:?}, {:?} for block {}) is still waiting for a response", event_id, &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash);
                                pending_block_requests.insert(block_key, event_id);
                            }
                            Some(http_response) => {
                                match StacksHttpResponse::decode_block(http_response) {
                                    Ok(block) => {
                                        if StacksBlockHeader::make_index_block_hash(
                                            &block_key.consensus_hash,
                                            &block.block_hash(),
                                        ) != block_key.index_block_hash
                                        {
                                            info!("Invalid block from {:?} ({:?}): did not ask for block {}/{}", &block_key.neighbor, &block_key.data_url, block_key.consensus_hash, block.block_hash());
                                            self.broken_peers.push(event_id);
                                            self.broken_neighbors.push(block_key.neighbor.clone());
                                        } else {
                                            // got the block
                                            debug!(
                                                "Got block {}: {}/{}",
                                                &block_key.sortition_height,
                                                &block_key.consensus_hash,
                                                block.block_hash()
                                            );
                                            self.blocks.insert(block_key, block);
                                        }
                                    }
                                    Err(net_error::NotFoundError) => {
                                        // remote peer didn't have the block
                                        info!("Remote neighbor {:?} ({:?}) does not actually have block {} indexed at {} ({})", &block_key.neighbor, &block_key.data_url, block_key.sortition_height, &block_key.index_block_hash, &block_key.consensus_hash);

                                        // the fact that we asked this peer means that it's block inv indicated
                                        // it was present, so the absence is the mark of a broken peer
                                        self.broken_peers.push(event_id);
                                        self.broken_neighbors.push(block_key.neighbor.clone());
                                    }
                                    Err(e) => {
                                        info!("Error decoding response from remote neighbor {:?} (at {}): {:?}", &block_key.neighbor, &block_key.data_url, &e;
                                            "consensus_hash" => %block_key.consensus_hash
                                        );
                                        self.broken_peers.push(event_id);
                                        self.broken_neighbors.push(block_key.neighbor.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // are we done?
        if pending_block_requests.is_empty() {
            self.state = BlockDownloaderState::GetMicroblocksBegin;
            return Ok(true);
        }

        // still have more to go
        for (block_key, event_id) in pending_block_requests.drain() {
            self.getblock_requests.insert(block_key, event_id);
        }
        return Ok(false);
    }

    /// Start fetching microblocks
    pub fn getmicroblocks_begin(&mut self, requests: HashMap<BlockRequestKey, usize>) {
        assert_eq!(self.state, BlockDownloaderState::GetMicroblocksBegin);

        self.getmicroblocks_requests = requests;
        self.state = BlockDownloaderState::GetMicroblocksFinish;
    }

    pub fn getmicroblocks_try_finish(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Result<bool, net_error> {
        assert_eq!(self.state, BlockDownloaderState::GetMicroblocksFinish);

        // requests that are still pending
        let mut pending_microblock_requests = HashMap::new();

        PeerNetwork::with_http(network, |ref mut network, ref mut http| {
            for (block_key, event_id) in self.getmicroblocks_requests.drain() {
                let rh_block_key = block_key.clone();
                match http.get_conversation(event_id) {
                    None => {
                        if http.is_connecting(event_id) {
                            debug!("Event {} ({:?}, {:?} for microblocks built by ({}) is not connected yet", &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash, event_id);
                            pending_microblock_requests.insert(block_key, event_id);
                        } else {
                            self.dead_peers.push(event_id);

                            // try again
                            self.requested_microblocks
                                .remove(&block_key.index_block_hash);

                            let is_always_allowed = match PeerDB::get_peer(
                                &network.peerdb.conn(),
                                block_key.neighbor.network_id,
                                &block_key.neighbor.addrbytes,
                                block_key.neighbor.port,
                            ) {
                                Ok(Some(neighbor)) => neighbor.is_always_allowed(),
                                _ => false,
                            };

                            if !is_always_allowed {
                                debug!(
                                    "Event {} ({:?}, {:?} for microblocks built by ({}) failed to connect.  Temporarily blocking URL.",
                                    event_id,
                                    &block_key.neighbor,
                                    &block_key.data_url,
                                    &block_key.index_block_hash,
                                );

                                // don't try this again for a while
                                self.blocked_urls.insert(
                                    block_key.data_url,
                                    get_epoch_time_secs() + BLOCK_DOWNLOAD_BAN_URL,
                                );
                            } else {
                                debug!(
                                    "Event {} ({:?}, {:?} for microblocks built by ({}) failed to connect to always-allowed peer",
                                    event_id,
                                    &block_key.neighbor,
                                    &block_key.data_url,
                                    &block_key.index_block_hash,
                                );
                            }
                        }
                    }
                    Some(ref mut convo) => {
                        match convo.try_get_response() {
                            None => {
                                // still waiting
                                debug!("Event {} ({:?}, {:?} for microblocks built by {:?}) is still waiting for a response", event_id, &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash);
                                pending_microblock_requests.insert(rh_block_key, event_id);
                            }
                            Some(http_response) => {
                                match StacksHttpResponse::decode_microblocks(http_response) {
                                    Ok(microblocks) => {
                                        if microblocks.is_empty() {
                                            // we wouldn't have asked for a 0-length stream
                                            info!("Got unexpected zero-length microblock stream from {:?} ({:?})", &block_key.neighbor, &block_key.data_url;
                                                "consensus_hash" => %block_key.consensus_hash
                                            );
                                            self.broken_peers.push(event_id);
                                            self.broken_neighbors.push(block_key.neighbor.clone());
                                        } else {
                                            // have microblocks (but we don't know yet if they're well-formed)
                                            debug!(
                                                "Got (tentative) microblocks {}: {}/{}-{}",
                                                block_key.sortition_height,
                                                &block_key.consensus_hash,
                                                &block_key.index_block_hash,
                                                microblocks[0].block_hash()
                                            );
                                            self.microblocks.insert(block_key, microblocks);
                                        }
                                    }
                                    Err(net_error::NotFoundError) => {
                                        // remote peer didn't have the microblock, even though their blockinv said
                                        // they did.
                                        info!("Remote neighbor {:?} ({:?}) does not have microblock stream indexed at {}", &block_key.neighbor, &block_key.data_url, &block_key.index_block_hash;
                                            "consensus_hash" => %block_key.consensus_hash
                                        );

                                        // the fact that we asked this peer means that it's block inv indicated
                                        // it was present, so the absence is the mark of a broken peer.
                                        // HOWEVER, there has been some bugs recently about nodes reporting
                                        // invalid microblock streams as present, even though they are
                                        // truly absent.  Don't punish these peers with a ban; just don't
                                        // talk to them for a while.
                                    }
                                    Err(e) => {
                                        info!("Error decoding response from remote neighbor {:?} (at {}): {:?}", &block_key.neighbor, &block_key.data_url, &e;
                                            "consensus_hash" => %block_key.consensus_hash
                                        );
                                        self.broken_peers.push(event_id);
                                        self.broken_neighbors.push(block_key.neighbor.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // are we done?
        if pending_microblock_requests.is_empty() {
            self.state = BlockDownloaderState::Done;
            return Ok(true);
        }

        // still have more to go
        for (block_key, event_id) in pending_microblock_requests.drain() {
            self.getmicroblocks_requests.insert(block_key, event_id);
        }
        return Ok(false);
    }

    /// Get the availability of each block in the given sortition range, using the inv state.
    /// Return the local block headers, paired with the list of peers that can serve them.
    /// Possibly less than the given range request.
    pub fn get_block_availability(
        _local_peer: &LocalPeer,
        inv_state: &InvState,
        sortdb: &SortitionDB,
        header_cache: &mut BlockHeaderCache,
        sortition_height_start: u64,
        mut sortition_height_end: u64,
    ) -> Result<Vec<(ConsensusHash, Option<BlockHeaderHash>, Vec<NeighborKey>)>, net_error> {
        let first_block_height = sortdb.first_block_height;

        // what blocks do we have in this range?
        let local_blocks = {
            let ic = sortdb.index_conn();
            let tip = SortitionDB::get_canonical_burn_chain_tip(&ic)?;

            if tip.block_height < first_block_height + sortition_height_start {
                test_debug!(
                    "Tip height {} < {}",
                    tip.block_height,
                    first_block_height + sortition_height_start
                );
                return Ok(vec![]);
            }

            if tip.block_height < first_block_height + sortition_height_end {
                test_debug!(
                    "Truncate end sortition {} down to {}",
                    sortition_height_end,
                    tip.block_height - first_block_height
                );
                sortition_height_end = tip.block_height - first_block_height;
            }

            if sortition_height_end <= sortition_height_start {
                test_debug!(
                    "sortition end {} <= sortition start {}",
                    sortition_height_end,
                    sortition_height_start
                );
                return Ok(vec![]);
            }

            debug!("Begin headers load");
            let begin_ts = get_epoch_time_ms();
            let last_ancestor = SortitionDB::get_ancestor_snapshot(
                &ic,
                first_block_height + sortition_height_end,
                &tip.sortition_id,
            )?
            .ok_or_else(|| net_error::DBError(db_error::NotFoundError))?;

            debug!(
                "Load {} headers off of {} ({})",
                sortition_height_end - sortition_height_start,
                last_ancestor.block_height,
                &last_ancestor.consensus_hash
            );
            let local_blocks = ic
                .get_stacks_header_hashes(
                    sortition_height_end - sortition_height_start,
                    &last_ancestor.consensus_hash,
                    header_cache,
                )
                .map_err(|e| {
                    if let db_error::InvalidPoxSortition = e {
                        net_error::Transient("Invalid PoX sortition; try again".to_string())
                    } else {
                        net_error::DBError(e)
                    }
                })?;

            for (_i, (_consensus_hash, _block_hash_opt)) in local_blocks.iter().enumerate() {
                test_debug!(
                    "  Loaded {} ({}): {:?}/{:?}",
                    (_i as u64) + sortition_height_start,
                    (_i as u64) + sortition_height_start + first_block_height,
                    _consensus_hash,
                    _block_hash_opt
                );
            }
            let end_ts = get_epoch_time_ms();
            debug!("End headers load ({} ms)", end_ts.saturating_sub(begin_ts));

            // update cache
            SortitionDB::merge_block_header_cache(header_cache, &local_blocks);

            local_blocks
        };

        let mut ret = vec![];
        for (i, (consensus_hash, block_hash_opt)) in local_blocks.into_iter().enumerate() {
            let sortition_bit = sortition_height_start + (i as u64) + 1;
            match block_hash_opt {
                Some(block_hash) => {
                    // a sortition happened at this height
                    let mut neighbors = vec![];
                    for (nk, stats) in inv_state.block_stats.iter() {
                        test_debug!(
                            "{:?}: stats for {:?}: {:?}; testing block bit {}",
                            _local_peer,
                            &nk,
                            &stats,
                            sortition_bit + first_block_height
                        );
                        if stats.inv.has_ith_block(sortition_bit + first_block_height) {
                            neighbors.push(nk.clone());
                        }
                    }
                    test_debug!(
                        "{:?}: At sortition height {} (block bit {}): {:?}/{:?} blocks available from {:?}",
                        _local_peer,
                        sortition_bit - 1,
                        sortition_bit + first_block_height,
                        &consensus_hash,
                        &block_hash,
                        &neighbors
                    );
                    ret.push((consensus_hash, Some(block_hash), neighbors));
                }
                None => {
                    // no sortition
                    test_debug!(
                        "{:?}: At sortition height {} (block bit {}): {:?}/(no sortition)",
                        _local_peer,
                        sortition_bit - 1,
                        sortition_bit + first_block_height,
                        &consensus_hash
                    );
                    ret.push((consensus_hash, None, vec![]));

                    if cfg!(test) {
                        for (_nk, stats) in inv_state.block_stats.iter() {
                            if stats.inv.has_ith_block(sortition_bit + first_block_height) {
                                debug!(
                                    "{:?}: BUT! Neighbor {:?} has block bit {} set!: {:?}",
                                    _local_peer,
                                    &_nk,
                                    sortition_bit + first_block_height,
                                    &stats
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(ret)
    }

    /// Find out which neighbors can serve a confirmed microblock stream, given the
    /// burn/block-header-hashes of the sortition that _produced_ them.
    fn get_microblock_stream_availability(
        _local_peer: &LocalPeer,
        inv_state: &InvState,
        sortdb: &SortitionDB,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<Vec<NeighborKey>, net_error> {
        let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), consensus_hash)?
            .ok_or_else(|| net_error::DBError(db_error::NotFoundError))?;

        let block_height = sn.block_height;

        if sn.winning_stacks_block_hash != *block_hash {
            test_debug!(
                "Snapshot of {} (height {}) does not have winning block hash {}",
                consensus_hash,
                block_height,
                block_hash
            );
            return Err(net_error::DBError(db_error::NotFoundError));
        }

        let mut neighbors = vec![];
        for (nk, stats) in inv_state.block_stats.iter() {
            test_debug!(
                "{:?}: stats for {:?}: {:?}; testing block {}",
                _local_peer,
                &nk,
                &stats,
                block_height
            );
            if stats.inv.has_ith_microblock_stream(block_height) {
                neighbors.push(nk.clone());
            }
        }
        debug!(
            "{:?}: At sortition height {} (block {}): {:?}/{:?} microblocks available from {:?}",
            _local_peer,
            block_height - sortdb.first_block_height + 1,
            block_height,
            consensus_hash,
            block_hash,
            &neighbors
        );
        Ok(neighbors)
    }

    /// Clear out broken peers that told us they had blocks, but didn't serve them.
    fn clear_broken_peers(&mut self) -> (Vec<usize>, Vec<NeighborKey>) {
        // remove dead/broken peers
        let mut disconnect = vec![];
        let mut disconnect_neighbors = vec![];

        disconnect.append(&mut self.broken_peers);
        disconnect.append(&mut self.dead_peers);
        disconnect_neighbors.append(&mut self.broken_neighbors);

        (disconnect, disconnect_neighbors)
    }

    /// Set a hint that a block is now available from a remote peer, if we're idling or we're ahead
    /// of the given height.  If force is true, then always restart the download scan at the target
    /// sortition, even if we're in the middle of downloading.
    pub fn hint_block_sortition_height_available(
        &mut self,
        block_sortition_height: u64,
        ibd: bool,
        force: bool,
    ) {
        if force
            || (ibd && self.state == BlockDownloaderState::DNSLookupBegin)
            || (self.empty_block_download_passes > 0
                || block_sortition_height < self.block_sortition_height + 1)
        {
            // idling on new blocks to fetch
            self.empty_block_download_passes = 0;
            self.empty_microblock_download_passes = 0;
            self.block_sortition_height = block_sortition_height.saturating_sub(1);
            self.next_block_sortition_height = block_sortition_height.saturating_sub(1);

            debug!(
                "Awaken downloader to start scanning at block sortiton height {}",
                block_sortition_height.saturating_sub(1)
            );
        }
        if ibd && self.state != BlockDownloaderState::DNSLookupBegin {
            debug!(
                "Will NOT awaken downloader to start scanning at block sortiton height {}, because it is busy at {} in state {:?}",
                block_sortition_height.saturating_sub(1),
                self.block_sortition_height,
                self.state
            );
        }
    }

    /// Set a hint that a confirmed microblock stream is now available from a remote peer, if we're idling or we're ahead
    /// of the given height.  If force is true, then always restart the download scan at the target
    /// sortition, even if we're in the middle of downloading.
    pub fn hint_microblock_sortition_height_available(
        &mut self,
        mblock_sortition_height: u64,
        ibd: bool,
        force: bool,
    ) {
        if force
            || (ibd && self.state == BlockDownloaderState::DNSLookupBegin)
            || (self.empty_microblock_download_passes > 0
                || mblock_sortition_height < self.microblock_sortition_height + 1)
        {
            // idling on new blocks to fetch
            self.empty_microblock_download_passes = 0;
            self.microblock_sortition_height = mblock_sortition_height.saturating_sub(1);
            self.next_microblock_sortition_height = mblock_sortition_height.saturating_sub(1);

            debug!(
                "Awaken downloader to start scanning at microblock sortiton height {}",
                mblock_sortition_height.saturating_sub(1)
            );
        }
        if ibd && self.state != BlockDownloaderState::DNSLookupBegin {
            debug!(
                "Will NOT awaken downloader to start scanning at microblock sortiton height {}, because it is busy at {} in state {:?}",
                mblock_sortition_height.saturating_sub(1),
                self.microblock_sortition_height,
                self.state
            );
        }
    }

    /// Set a hint that we should re-scan for blocks
    pub fn hint_download_rescan(&mut self, target_sortition_height: u64, ibd: bool) {
        self.hint_block_sortition_height_available(target_sortition_height, ibd, false);
        self.hint_microblock_sortition_height_available(target_sortition_height, ibd, false);
    }

    // are we doing the initial block download?
    pub fn is_initial_download(&self) -> bool {
        self.finished_scan_at == 0
    }

    // how many requests inflight?
    pub fn num_requests_inflight(&self) -> usize {
        self.microblocks_to_try.len() + self.blocks_to_try.len()
    }

    // is the downloader idle? i.e. did we already do a scan?
    pub fn is_download_idle(&self) -> bool {
        self.empty_block_download_passes > 0 && self.empty_microblock_download_passes > 0
    }

    /// Is a request in-flight for a given block or microblock stream?
    fn is_inflight(&self, index_hash: &StacksBlockId, microblocks: bool) -> bool {
        if microblocks {
            // being requested now?
            for (_, reqs) in self.microblocks_to_try.iter() {
                if !reqs.is_empty() && reqs[0].index_block_hash == *index_hash {
                    return true;
                }
            }

            // was recently requested?  could still be buffered up for storage
            if let Some(fetched_ts) = self.requested_microblocks.get(index_hash) {
                if get_epoch_time_secs() < fetched_ts + BLOCK_REREQUEST_INTERVAL {
                    return true;
                }
            }
        } else {
            for (_, reqs) in self.blocks_to_try.iter() {
                if !reqs.is_empty() && reqs[0].index_block_hash == *index_hash {
                    return true;
                }
            }

            // was recently requested?  could still be buffered up for storage
            if let Some(fetched_ts) = self.requested_blocks.get(index_hash) {
                if get_epoch_time_secs() < fetched_ts + BLOCK_REREQUEST_INTERVAL {
                    return true;
                }
            }
        }
        return false;
    }
}

impl PeerNetwork {
    pub fn with_downloader_state<F, R>(&mut self, handler: F) -> Result<R, net_error>
    where
        F: FnOnce(&mut PeerNetwork, &mut BlockDownloader) -> Result<R, net_error>,
    {
        let mut downloader = self.block_downloader.take();
        let res = match downloader {
            None => {
                debug!("{:?}: downloader not connected", &self.local_peer);
                Err(net_error::NotConnected)
            }
            Some(ref mut dl) => handler(self, dl),
        };
        self.block_downloader = downloader;
        res
    }

    /// Pass a hint to the downloader to re-scan
    pub fn hint_download_rescan(&mut self, target_height: u64, ibd: bool) {
        match self.block_downloader {
            Some(ref mut dl) => dl.hint_download_rescan(target_height, ibd),
            None => {}
        }
    }

    /// Get the data URL for a neighbor
    pub fn get_data_url(&self, neighbor_key: &NeighborKey) -> Option<UrlString> {
        match self.events.get(neighbor_key) {
            Some(ref event_id) => match self.peers.get(event_id) {
                Some(ref convo) => {
                    if convo.data_url.is_empty() {
                        None
                    } else {
                        Some(convo.data_url.clone())
                    }
                }
                None => None,
            },
            None => None,
        }
    }

    /// Do we need to download an anchored block?
    /// already have an anchored block?
    fn need_anchored_block(
        _local_peer: &LocalPeer,
        chainstate: &StacksChainState,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<bool, net_error> {
        // already in queue or already processed?
        let index_block_hash = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        if StacksChainState::has_block_indexed(&chainstate.blocks_path, &index_block_hash)? {
            test_debug!(
                "{:?}: Block already stored to chunk store: {}/{} ({})",
                _local_peer,
                consensus_hash,
                block_hash,
                &index_block_hash
            );
            return Ok(false);
        }
        Ok(true)
    }

    /// Are we able to download a microblock stream between two blocks at this time?
    pub fn can_download_microblock_stream(
        _local_peer: &LocalPeer,
        chainstate: &StacksChainState,
        parent_consensus_hash: &ConsensusHash,
        parent_block_hash: &BlockHeaderHash,
        child_consensus_hash: &ConsensusHash,
        child_block_hash: &BlockHeaderHash,
    ) -> Result<bool, net_error> {
        // if the child is processed, then we have all the microblocks we need.
        // this is the overwhelmingly likely case.
        if let Ok(Some(true)) = StacksChainState::get_staging_block_status(
            &chainstate.db(),
            &child_consensus_hash,
            &child_block_hash,
        ) {
            test_debug!(
                "{:?}: Already processed block {}/{}, so must have stream between it and {}/{}",
                _local_peer,
                child_consensus_hash,
                child_block_hash,
                parent_consensus_hash,
                parent_block_hash,
            );
            return Ok(false);
        }

        // block not processed for some reason.  Do we have the parent and child anchored blocks at
        // least?

        let _parent_header = match StacksChainState::load_block_header(
            &chainstate.blocks_path,
            parent_consensus_hash,
            parent_block_hash,
        ) {
            Ok(Some(hdr)) => hdr,
            _ => {
                test_debug!(
                    "{:?}: No parent block {}/{}, so cannot load microblock stream it produced",
                    _local_peer,
                    parent_consensus_hash,
                    parent_block_hash
                );
                return Ok(false);
            }
        };

        let child_header = match StacksChainState::load_block_header(
            &chainstate.blocks_path,
            child_consensus_hash,
            child_block_hash,
        ) {
            Ok(Some(hdr)) => hdr,
            _ => {
                test_debug!(
                    "{:?}: No child block {}/{}, so cannot load microblock stream it confirms",
                    _local_peer,
                    child_consensus_hash,
                    child_block_hash
                );
                return Ok(false);
            }
        };

        debug!(
            "EXPENSIVE check stream between {}/{} and {}/{}",
            parent_consensus_hash, parent_block_hash, child_consensus_hash, child_block_hash
        );

        // try and load the connecting stream.  If we have it, then we're good to go.
        // SLOW
        match StacksChainState::load_microblock_stream_fork(
            &chainstate.db(),
            parent_consensus_hash,
            parent_block_hash,
            &child_header.parent_microblock,
        )? {
            Some(_) => {
                test_debug!(
                    "{:?}: Already have stream between {}/{} and {}/{}",
                    _local_peer,
                    parent_consensus_hash,
                    parent_block_hash,
                    child_consensus_hash,
                    child_block_hash
                );
                return Ok(false);
            }
            None => {
                return Ok(true);
            }
        }
    }

    /// Create block request keys for a range of blocks that are available but that we don't have in a given range of
    /// sortitions.  The same keys can be used to fetch confirmed microblock streams.
    fn make_requests(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        downloader: &BlockDownloader,
        start_sortition_height: u64,
        microblocks: bool,
    ) -> Result<HashMap<u64, VecDeque<BlockRequestKey>>, net_error> {
        let scan_batch_size = self.burnchain.pox_constants.reward_cycle_length as u64;
        let mut blocks_to_try: HashMap<u64, VecDeque<BlockRequestKey>> = HashMap::new();

        debug!(
            "{:?}: find {} availability over sortitions ({}-{})...",
            &self.local_peer,
            if microblocks {
                "microblocks"
            } else {
                "anchored blocks"
            },
            start_sortition_height,
            start_sortition_height + scan_batch_size
        );

        let availability =
            PeerNetwork::with_inv_state(self, |ref mut network, ref mut inv_state| {
                BlockDownloader::get_block_availability(
                    &network.local_peer,
                    inv_state,
                    sortdb,
                    &mut network.header_cache,
                    start_sortition_height,
                    start_sortition_height + scan_batch_size,
                )
            })??;

        debug!(
            "{:?}: {} availability calculated over {} sortitions ({}-{})",
            &self.local_peer,
            if microblocks {
                "microblocks"
            } else {
                "anchored blocks"
            },
            availability.len(),
            start_sortition_height,
            start_sortition_height + scan_batch_size
        );

        for (i, (consensus_hash, block_hash_opt, mut neighbors)) in
            availability.into_iter().enumerate()
        {
            test_debug!(
                "{:?}: consider availability of {}/{:?}",
                &self.local_peer,
                &consensus_hash,
                &block_hash_opt
            );

            if (i as u64) >= scan_batch_size {
                // we may have loaded scan_batch_size + 1 so we can find the child block for
                // microblocks, but we don't have to request this block's data either way.
                break;
            }

            let Some(block_hash) = block_hash_opt else {
                continue;
            };

            let mut parent_block_header_opt = None;
            let mut parent_consensus_hash_opt = None;

            let index_block_hash =
                StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_hash);
            if downloader.is_inflight(&index_block_hash, microblocks) {
                // we already asked for this block or microblock stream
                debug!(
                    "{:?}: Already in-flight: {}/{}",
                    &self.local_peer, &consensus_hash, &block_hash
                );
                continue;
            }

            let (target_consensus_hash, target_block_hash) = if !microblocks {
                // asking for a block
                if !PeerNetwork::need_anchored_block(
                    &self.local_peer,
                    chainstate,
                    &consensus_hash,
                    &block_hash,
                )? {
                    // we already have this block stored to disk
                    test_debug!(
                        "{:?}: Already have anchored block {}/{}",
                        &self.local_peer,
                        &consensus_hash,
                        &block_hash
                    );
                    continue;
                }

                debug!(
                    "{:?}: Do not have anchored block {}/{} ({})",
                    &self.local_peer, &consensus_hash, &block_hash, &index_block_hash
                );

                (consensus_hash, block_hash)
            } else {
                // asking for microblocks
                let block_header = match StacksChainState::load_block_header(
                    &chainstate.blocks_path,
                    &consensus_hash,
                    &block_hash,
                ) {
                    Ok(Some(header)) => header,
                    Ok(None) => {
                        // we don't have this anchored block confirmed yet, so we can't ask for
                        // microblocks.
                        test_debug!("{:?}: Do not have anchored block {}/{} yet, so cannot ask for the microblocks it confirmed", &self.local_peer, &consensus_hash, &block_hash);
                        continue;
                    }
                    Err(chainstate_error::DBError(db_error::NotFoundError)) => {
                        // we can't fetch this microblock stream because we don't yet know
                        // about this block
                        test_debug!("{:?}: Do not have anchored block {}/{} yet, so cannot ask for the microblocks it confirmed", &self.local_peer, &consensus_hash, &block_hash);
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                if block_header.parent_microblock == EMPTY_MICROBLOCK_PARENT_HASH
                    && block_header.parent_microblock_sequence == 0
                {
                    // this block doesn't confirm a microblock stream
                    test_debug!(
                        "Block {}/{} does not confirm a microblock stream",
                        &consensus_hash,
                        &block_hash
                    );
                    continue;
                }

                // does this anchor block _confirm_ a microblock stream that we don't know about?
                let parent_header_opt = {
                    let child_block_info = match StacksChainState::load_staging_block_info(
                        &chainstate.db(),
                        &index_block_hash,
                    )? {
                        Some(hdr) => hdr,
                        None => {
                            test_debug!(
                                "{:?}: No such parent block: {:?}",
                                &self.local_peer,
                                &index_block_hash
                            );
                            continue;
                        }
                    };

                    match StacksChainState::load_block_header(
                        &chainstate.blocks_path,
                        &child_block_info.parent_consensus_hash,
                        &child_block_info.parent_anchored_block_hash,
                    ) {
                        Ok(header_opt) => {
                            header_opt.map(|hdr| (hdr, child_block_info.parent_consensus_hash))
                        }
                        Err(chainstate_error::DBError(db_error::NotFoundError)) => {
                            // we don't know about this parent block yet
                            test_debug!("{:?}: Do not have parent of anchored block {}/{} yet, so cannot ask for the microblocks it produced", &self.local_peer, &consensus_hash, &block_hash);
                            continue;
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                };

                if let Some((parent_header, parent_consensus_hash)) = parent_header_opt {
                    if !PeerNetwork::can_download_microblock_stream(
                        &self.local_peer,
                        chainstate,
                        &parent_consensus_hash,
                        &parent_header.block_hash(),
                        &consensus_hash,
                        &block_hash,
                    )? {
                        test_debug!("{:?}: Cannot (or will not) download microblock stream confirmed by {}/{} (built by {}/{})", &self.local_peer, &consensus_hash, &block_hash, &parent_consensus_hash, &parent_header.block_hash());
                        continue;
                    }

                    // ask for the microblocks _confirmed_ by this block (by asking for the
                    // microblocks built off of this block's _parent_)
                    let mut microblock_stream_neighbors = match self.inv_state {
                        Some(ref inv_state) => BlockDownloader::get_microblock_stream_availability(
                            &self.local_peer,
                            inv_state,
                            sortdb,
                            &consensus_hash,
                            &block_hash,
                        )?,
                        None => vec![],
                    };

                    // use these neighbors instead
                    neighbors.clear();
                    neighbors.append(&mut microblock_stream_neighbors);

                    debug!(
                        "{:?}: Get microblocks produced by {}/{}, confirmed by {}/{}, from up to {} neighbors",
                        &self.local_peer,
                        &parent_consensus_hash,
                        &parent_header.block_hash(),
                        &consensus_hash,
                        &block_hash,
                        neighbors.len()
                    );

                    parent_block_header_opt = Some(parent_header);
                    parent_consensus_hash_opt = Some(parent_consensus_hash);
                    (consensus_hash, block_hash)
                } else {
                    // we don't have the block that produced this stream
                    test_debug!(
                        "{:?}: Do not have parent anchored block of {}/{}",
                        &self.local_peer,
                        &consensus_hash,
                        &block_hash
                    );
                    continue;
                }
            };

            let target_index_block_hash = StacksBlockHeader::make_index_block_hash(
                &target_consensus_hash,
                &target_block_hash,
            );

            debug!(
                "{:?}: Consider {} sortition {} {}/{} from {} neighbors",
                &self.local_peer,
                if microblocks {
                    "microblock stream"
                } else {
                    "anchored block"
                },
                start_sortition_height + (i as u64),
                &target_consensus_hash,
                &target_block_hash,
                neighbors.len()
            );

            (&mut neighbors[..]).shuffle(&mut thread_rng());

            let mut requests = VecDeque::new();
            for nk in neighbors.into_iter() {
                let Some(data_url) = self.get_data_url(&nk) else {
                    debug!(
                        "{:?}: Unable to request {} from {}: no data URL",
                        &self.local_peer, &target_index_block_hash, &nk
                    );
                    continue;
                };
                if data_url.is_empty() {
                    // peer doesn't yet know its public IP address, and isn't given a data URL
                    // directly
                    debug!(
                        "{:?}: Unable to request {} from {}: no data URL",
                        &self.local_peer, &target_index_block_hash, &nk
                    );
                    continue;
                }

                let prev_blocked = match downloader.blocked_urls.get(&data_url) {
                    Some(deadline) if get_epoch_time_secs() < *deadline => {
                        debug!(
                            "{:?}: Will not request {} {}/{} from {:?} (of {:?}) until after {}",
                            &self.local_peer,
                            if microblocks {
                                "microblock stream"
                            } else {
                                "anchored block"
                            },
                            &target_consensus_hash,
                            &target_block_hash,
                            &data_url,
                            &nk,
                            deadline
                        );
                        true
                    }
                    _ => false,
                };

                if prev_blocked {
                    continue;
                }

                debug!(
                    "{:?}: Make request for {} at sortition height {} to {:?}: {:?}/{:?}",
                    &self.local_peer,
                    if microblocks {
                        "microblock stream"
                    } else {
                        "anchored block"
                    },
                    (i as u64) + start_sortition_height,
                    &nk,
                    &target_consensus_hash,
                    &target_block_hash
                );

                let request = BlockRequestKey::new(
                    nk,
                    data_url,
                    target_consensus_hash.clone(),
                    target_block_hash.clone(),
                    target_index_block_hash.clone(),
                    parent_block_header_opt.clone(),
                    parent_consensus_hash_opt.clone(),
                    (i as u64) + start_sortition_height,
                    if microblocks {
                        BlockRequestKeyKind::ConfirmedMicroblockStream
                    } else {
                        BlockRequestKeyKind::Block
                    },
                    self.burnchain_tip.canonical_stacks_tip_height,
                );
                requests.push_back(request);
            }

            blocks_to_try.insert((i as u64) + start_sortition_height, requests);
        }

        Ok(blocks_to_try)
    }

    /// Make requests for missing anchored blocks
    fn make_block_requests(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        downloader: &BlockDownloader,
        start_sortition_height: u64,
    ) -> Result<HashMap<u64, VecDeque<BlockRequestKey>>, net_error> {
        self.make_requests(
            sortdb,
            chainstate,
            downloader,
            start_sortition_height,
            false,
        )
    }

    /// Make requests for missing confirmed microblocks
    fn make_confirmed_microblock_requests(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        downloader: &BlockDownloader,
        start_sortition_height: u64,
    ) -> Result<HashMap<u64, VecDeque<BlockRequestKey>>, net_error> {
        self.make_requests(sortdb, chainstate, downloader, start_sortition_height, true)
    }

    /// Prioritize block requests -- ask for the rarest blocks first
    fn prioritize_requests(requests: &HashMap<u64, VecDeque<BlockRequestKey>>) -> Vec<u64> {
        let mut ordered = vec![];
        for (block_height, requests) in requests.iter() {
            ordered.push((*block_height, requests.len()));
        }
        ordered.sort_by(|(_, ref l1), (_, ref l2)| l1.cmp(l2));
        ordered.iter().map(|(ref h, _)| *h).collect()
    }

    /// Go start resolving block URLs to their IP addresses
    pub fn block_dns_lookups_begin(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        dns_client: &mut DNSClient,
    ) -> Result<(), net_error> {
        test_debug!("{:?}: block_dns_lookups_begin", &self.local_peer);
        let (need_blocks, block_sortition_height, microblock_sortition_height) =
            match self.block_downloader {
                Some(ref mut downloader) => (
                    downloader.blocks_to_try.is_empty(),
                    downloader.block_sortition_height,
                    downloader.microblock_sortition_height,
                ),
                None => {
                    test_debug!("{:?}: downloader not connected", &self.local_peer);
                    return Err(net_error::NotConnected);
                }
            };

        let scan_batch_size = self.burnchain.pox_constants.reward_cycle_length as u64;

        if need_blocks {
            PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
                test_debug!("{:?}: needs blocks", &network.local_peer);

                let mut next_block_sortition_height = block_sortition_height;
                let mut next_microblock_sortition_height = microblock_sortition_height;

                debug!(
                    "{:?}: Look for blocks at sortition {}, microblocks at sortition {}",
                    &network.local_peer,
                    next_block_sortition_height,
                    next_microblock_sortition_height
                );

                // fetch as many blocks and microblocks as we can -- either
                // downloader.max_inflight_requests, or however many blocks remain between the
                // downloader's sortition height and the chain tip's sortition height (whichever is
                // smaller).
                while next_block_sortition_height
                    <= network.chain_view.burn_block_height - sortdb.first_block_height
                    || next_microblock_sortition_height
                        <= network.chain_view.burn_block_height - sortdb.first_block_height
                {
                    debug!(
                        "{:?}: Make block requests from sortition height {}",
                        &network.local_peer, next_block_sortition_height
                    );
                    let mut next_blocks_to_try = network.make_block_requests(
                        sortdb,
                        chainstate,
                        downloader,
                        next_block_sortition_height,
                    )?;

                    debug!(
                        "{:?}: Make microblock requests from sortition height {}",
                        &network.local_peer, next_microblock_sortition_height
                    );
                    let mut next_microblocks_to_try = network.make_confirmed_microblock_requests(
                        sortdb,
                        chainstate,
                        downloader,
                        next_microblock_sortition_height,
                    )?;

                    let mut height = next_block_sortition_height;
                    let mut mblock_height = next_microblock_sortition_height;

                    let mut max_height = 0;
                    let mut max_mblock_height = 0;

                    for h in next_blocks_to_try.keys() {
                        if *h > max_height {
                            max_height = *h;
                        }
                    }

                    for h in next_microblocks_to_try.keys() {
                        if *h > max_mblock_height {
                            max_mblock_height = *h;
                        }
                    }

                    if next_microblocks_to_try.is_empty() {
                        // have no microblocks to try in the first place, so just advance to the
                        // next batch
                        debug!(
                            "No microblocks to try; advance max_mblock_height to {}",
                            mblock_height
                        );
                        max_mblock_height = mblock_height;
                        mblock_height += scan_batch_size;
                    }

                    test_debug!("{:?}: at {},{}: {} blocks to get, {} microblock streams to get (up to {},{})", 
                                &network.local_peer, next_block_sortition_height, next_microblock_sortition_height, next_blocks_to_try.len(), next_microblocks_to_try.len(), max_height, max_mblock_height);

                    test_debug!("{:?}: Begin block requests", &network.local_peer);
                    for (_key, _requests) in next_blocks_to_try.iter() {
                        test_debug!("   {:?}: {:?}", _key, _requests);
                    }
                    test_debug!("{:?}: End block requests", &network.local_peer);

                    test_debug!("{:?}: Begin microblock requests", &network.local_peer);
                    for (_key, _requests) in next_microblocks_to_try.iter() {
                        test_debug!("   {:?}: {:?}", _key, _requests);
                    }
                    test_debug!("{:?}: End microblock requests", &network.local_peer);

                    debug!(
                        "{:?}: create block, microblock requests from heights ({},{}) up to heights ({},{}) (so far: {} blocks, {} microblocks queued)",
                        &network.local_peer, height, mblock_height, max_height, max_mblock_height, downloader.blocks_to_try.len(), downloader.microblocks_to_try.len()
                    );

                    let now = get_epoch_time_secs();

                    // queue up block requests in order by sortition height
                    while height <= max_height
                        && (downloader.blocks_to_try.len() as u64)
                            < downloader.max_inflight_requests
                    {
                        if !next_blocks_to_try.contains_key(&height) {
                            height += 1;
                            continue;
                        }

                        if downloader.blocks_to_try.contains_key(&height) {
                            debug!("Block download already in-flight for {}", height);
                            height += 1;
                            continue;
                        }

                        let requests = next_blocks_to_try.remove(&height).expect(
                            "BUG: hashmap both contains and does not contain sortition height",
                        );
                        if requests.is_empty() {
                            height += 1;
                            continue;
                        }
                        assert_eq!(height, requests.front().as_ref().unwrap().sortition_height);

                        let index_block_hash =
                            requests.front().as_ref().unwrap().index_block_hash.clone();
                        if let Some(deadline) = downloader.requested_blocks.get(&index_block_hash) {
                            if now < *deadline {
                                debug!(
                                    "{:?}: already inflight: {}",
                                    &network.local_peer, &index_block_hash
                                );
                                height += 1;
                                continue;
                            }
                        }

                        debug!(
                            "{:?}: will request anchored block for sortition {}: {}/{} ({}) from {:?}",
                            &network.local_peer,
                            height,
                            &requests.front().as_ref().unwrap().consensus_hash,
                            &requests.front().as_ref().unwrap().anchor_block_hash,
                            &index_block_hash,
                            requests.iter().map(|ref r| &r.data_url).collect::<Vec<_>>()
                        );

                        downloader.blocks_to_try.insert(height, requests);
                        downloader
                            .requested_blocks
                            .insert(index_block_hash, now + BLOCK_REREQUEST_INTERVAL);

                        height += 1;
                    }

                    // queue up microblock requests in order by sortition height.
                    // Note that we use a different sortition height scan point for microblocks,
                    // since we can only get microblocks once we have both the block that produced
                    // them as well as the block that confirms them.
                    while mblock_height <= max_mblock_height
                        && (downloader.microblocks_to_try.len() as u64)
                            < downloader.max_inflight_requests
                    {
                        if !next_microblocks_to_try.contains_key(&mblock_height) {
                            mblock_height += 1;
                            continue;
                        }

                        if downloader.microblocks_to_try.contains_key(&mblock_height) {
                            mblock_height += 1;
                            debug!(
                                "Microblocks download already in-flight for {}",
                                mblock_height
                            );
                            continue;
                        }

                        let requests = next_microblocks_to_try.remove(&mblock_height).expect(
                            "BUG: hashmap both contains and does not contain sortition height",
                        );
                        if requests.is_empty() {
                            debug!("No microblock requests for {}", mblock_height);
                            mblock_height += 1;
                            continue;
                        }

                        assert_eq!(
                            mblock_height,
                            requests.front().as_ref().unwrap().sortition_height
                        );

                        let index_block_hash =
                            requests.front().as_ref().unwrap().index_block_hash.clone();
                        if let Some(deadline) =
                            downloader.requested_microblocks.get(&index_block_hash)
                        {
                            if now < *deadline {
                                debug!(
                                    "{:?}: already inflight: {}",
                                    &network.local_peer, &index_block_hash
                                );
                                mblock_height += 1;
                                continue;
                            }
                        }

                        debug!("{:?}: will request microblock stream confirmed by sortition {}: {}/{} ({}) from {:?}", 
                               &network.local_peer, mblock_height, &requests.front().as_ref().unwrap().consensus_hash, &requests.front().as_ref().unwrap().anchor_block_hash, &index_block_hash,
                                requests.iter().map(|ref r| &r.data_url).collect::<Vec<_>>()
                               );

                        downloader
                            .microblocks_to_try
                            .insert(mblock_height, requests);
                        downloader
                            .requested_microblocks
                            .insert(index_block_hash, now + BLOCK_REREQUEST_INTERVAL);

                        mblock_height += 1;
                    }

                    debug!(
                        "{:?}: block download scan now at ({},{}) (was ({},{})), trying {} blocks and {} microblocks",
                        &network.local_peer,
                        height,
                        mblock_height,
                        block_sortition_height,
                        microblock_sortition_height,
                        downloader.blocks_to_try.len(),
                        downloader.microblocks_to_try.len(),
                    );

                    if max_height <= next_block_sortition_height
                        && max_mblock_height <= next_microblock_sortition_height
                    {
                        debug!(
                            "{:?}: no more download requests to make",
                            &network.local_peer
                        );
                        break;
                    }

                    // restart next scan at this height
                    next_block_sortition_height = height;
                    next_microblock_sortition_height = mblock_height;

                    // at capacity?
                    if (downloader.blocks_to_try.len() as u64) >= downloader.max_inflight_requests
                        || (downloader.microblocks_to_try.len() as u64)
                            >= downloader.max_inflight_requests
                    {
                        debug!("{:?}: queued up {} requests (blocks so far: {}, microblocks so far: {})", &network.local_peer, downloader.blocks_to_try.len(), downloader.blocks_to_try.len(), downloader.microblocks_to_try.len());
                        break;
                    }
                }

                if downloader.blocks_to_try.is_empty() {
                    // nothing in this range, so advance sortition range to try for next time
                    next_block_sortition_height = next_block_sortition_height
                        + (network.burnchain.pox_constants.reward_cycle_length as u64);
                    debug!(
                        "{:?}: Pessimistically increase block sortition height to ({})",
                        &network.local_peer, next_block_sortition_height
                    );
                }
                if downloader.microblocks_to_try.is_empty() {
                    // nothing in this range, so advance sortition range to try for next time
                    next_microblock_sortition_height = next_microblock_sortition_height
                        + (network.burnchain.pox_constants.reward_cycle_length as u64);
                    debug!(
                        "{:?}: Pessimistically increase microblock sortition height to ({})",
                        &network.local_peer, next_microblock_sortition_height
                    );
                }

                downloader.next_block_sortition_height = next_block_sortition_height;
                downloader.next_microblock_sortition_height = next_microblock_sortition_height;

                debug!("{:?}: Will try for {} blocks and {} microblocks (next sortition heights are {},{}, chain tip is {})", 
                        &network.local_peer, downloader.blocks_to_try.len(), downloader.microblocks_to_try.len(), next_block_sortition_height, next_microblock_sortition_height, network.chain_view.burn_block_height - sortdb.first_block_height);
                Ok(())
            })?;
        } else {
            test_debug!("{:?}: does NOT need blocks", &self.local_peer);
        }

        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            let mut urlset = HashSet::new();
            for (_, requests) in downloader.blocks_to_try.iter() {
                for request in requests.iter() {
                    urlset.insert(request.data_url.clone());
                }
            }

            for (_, requests) in downloader.microblocks_to_try.iter() {
                for request in requests.iter() {
                    urlset.insert(request.data_url.clone());
                }
            }

            let mut urls = vec![];
            for url in urlset.drain() {
                urls.push(url);
            }

            downloader.dns_lookups_begin(&network.pox_id, dns_client, urls)
        })
    }

    /// Finish resolving URLs to their IP addresses
    pub fn block_dns_lookups_try_finish(
        &mut self,
        dns_client: &mut DNSClient,
    ) -> Result<bool, net_error> {
        test_debug!("{:?}: block_dns_lookups_try_finish", &self.local_peer);
        PeerNetwork::with_downloader_state(self, |ref mut _network, ref mut downloader| {
            downloader.dns_lookups_try_finish(dns_client)
        })
    }

    /// Start a request, given the list of request keys to consider.  Use the given request_factory to
    /// create the HTTP request.  Pops requests off the front of request_keys, and returns once it successfully
    /// sends out a request via the HTTP peer.  Returns the event ID in the http peer that's
    /// handling the request.
    pub fn begin_request<T: Requestable>(
        network: &mut PeerNetwork,
        dns_lookups: &HashMap<UrlString, Option<Vec<SocketAddr>>>,
        requestables: &mut VecDeque<T>,
    ) -> Option<(T, usize)> {
        loop {
            match requestables.pop_front() {
                Some(requestable) => {
                    if let Some(Some(ref sockaddrs)) = dns_lookups.get(requestable.get_url()) {
                        assert!(!sockaddrs.is_empty());

                        let peerhost = match PeerHost::try_from_url(requestable.get_url()) {
                            Some(ph) => ph,
                            None => {
                                warn!("Unparseable URL {:?}", requestable.get_url());
                                continue;
                            }
                        };

                        for addr in sockaddrs.iter() {
                            let request = requestable.make_request_type(peerhost.clone());
                            match network.connect_or_send_http_request(
                                requestable.get_url().clone(),
                                addr.clone(),
                                request,
                            ) {
                                Ok(handle) => {
                                    debug!(
                                        "{:?}: Begin HTTP request {}",
                                        &network.local_peer, requestable
                                    );
                                    return Some((requestable, handle));
                                }
                                Err(e) => {
                                    debug!(
                                        "{:?}: Failed to connect or send HTTP request {}: {:?}",
                                        &network.local_peer, requestable, &e
                                    );
                                }
                            }
                        }

                        debug!(
                            "{:?}: Failed request for {} from {:?}",
                            &network.local_peer, requestable, sockaddrs
                        );
                    } else {
                        debug!(
                            "{:?}: Will not request {}: failed to look up DNS name",
                            &network.local_peer, requestable
                        );
                    }
                }
                None => {
                    debug!("{:?}: No more requests keys", &network.local_peer);
                    break;
                }
            }
        }
        None
    }

    /// Start fetching blocks
    pub fn block_getblocks_begin(&mut self) -> Result<(), net_error> {
        test_debug!("{:?}: block_getblocks_begin", &self.local_peer);
        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            let priority = PeerNetwork::prioritize_requests(&downloader.blocks_to_try);
            let mut requests = HashMap::new();
            for sortition_height in priority.into_iter() {
                match downloader.blocks_to_try.get_mut(&sortition_height) {
                    Some(ref mut keys) => {
                        match PeerNetwork::begin_request(network, &downloader.dns_lookups, keys) {
                            Some((key, handle)) => {
                                requests.insert(key.clone(), handle);
                            }
                            None => {}
                        }
                    }
                    None => {
                        debug!(
                            "{:?}: No block at sortition height {}",
                            &network.local_peer, sortition_height
                        );
                    }
                }
            }

            downloader.getblocks_begin(requests);
            Ok(())
        })
    }

    /// Try to see if all blocks are finished downloading
    pub fn block_getblocks_try_finish(&mut self) -> Result<bool, net_error> {
        test_debug!("{:?}: block_getblocks_try_finish", &self.local_peer);
        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            downloader.getblocks_try_finish(network)
        })
    }

    /// Proceed to get microblocks
    pub fn block_getmicroblocks_begin(&mut self) -> Result<(), net_error> {
        test_debug!("{:?}: block_getmicroblocks_begin", &self.local_peer);
        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            let priority = PeerNetwork::prioritize_requests(&downloader.microblocks_to_try);
            let mut requests = HashMap::new();
            for sortition_height in priority.into_iter() {
                match downloader.microblocks_to_try.get_mut(&sortition_height) {
                    Some(ref mut keys) => {
                        match PeerNetwork::begin_request(network, &downloader.dns_lookups, keys) {
                            Some((key, handle)) => {
                                requests.insert(key.clone(), handle);
                            }
                            None => {}
                        }
                    }
                    None => {
                        debug!(
                            "{:?}: No microblocks at sortition height {}",
                            &network.local_peer, sortition_height
                        );
                    }
                }
            }

            downloader.getmicroblocks_begin(requests);
            Ok(())
        })
    }

    /// Try to see if all microblocks are finished downloading
    pub fn block_getmicroblocks_try_finish(&mut self) -> Result<bool, net_error> {
        test_debug!("{:?}: block_getmicroblocks_try_finish", &self.local_peer);
        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            downloader.getmicroblocks_try_finish(network)
        })
    }

    /// Process newly-fetched blocks and microblocks.
    /// Returns true if we've completed all requests.
    /// Returns (done?, at-chain-tip?, blocks-we-got, microblocks-we-got) on success
    fn finish_downloads(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
    ) -> Result<
        (
            bool,
            bool,
            Option<PoxId>,
            Vec<(ConsensusHash, StacksBlock, u64)>,
            Vec<(ConsensusHash, Vec<StacksMicroblock>, u64)>,
        ),
        net_error,
    > {
        let mut blocks = vec![];
        let mut microblocks = vec![];
        let mut done = false;
        let mut at_chain_tip = false;
        let mut old_pox_id = None;

        let now = get_epoch_time_secs();

        let inv_sortition_start = self
            .inv_state
            .as_ref()
            .map(|inv_state| inv_state.block_sortition_start)
            .unwrap_or(0);

        PeerNetwork::with_downloader_state(self, |ref mut network, ref mut downloader| {
            // extract blocks and microblocks downloaded
            for (request_key, block) in downloader.blocks.drain() {
                debug!(
                    "Downloaded block {}/{} ({}) at sortition height {}",
                    &request_key.consensus_hash,
                    &request_key.anchor_block_hash,
                    &request_key.index_block_hash,
                    request_key.sortition_height
                );
                blocks.push((
                    request_key.consensus_hash.clone(),
                    block,
                    now.saturating_sub(request_key.download_start),
                ));
                downloader.num_blocks_downloaded += 1;

                // don't try this again
                downloader
                    .blocks_to_try
                    .remove(&request_key.sortition_height);
            }
            for (request_key, mut microblock_stream) in downloader.microblocks.drain() {
                // NOTE: microblock streams are served in reverse order, since they're forks
                microblock_stream.reverse();

                let block_header = match StacksChainState::load_block_header(
                    &chainstate.blocks_path,
                    &request_key.consensus_hash,
                    &request_key.anchor_block_hash,
                ) {
                    Ok(Some(hdr)) => hdr,
                    Ok(None) => {
                        warn!("Missing Stacks blcok header for {}/{}.  Possibly invalidated due to PoX reorg", &request_key.consensus_hash, &request_key.anchor_block_hash);

                        // don't try again
                        downloader
                            .microblocks_to_try
                            .remove(&request_key.sortition_height);
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };

                assert!(
                    request_key.parent_block_header.is_some()
                        && request_key.parent_consensus_hash.is_some(),
                    "BUG: requested a microblock but didn't set the child block header"
                );
                let parent_block_header = request_key.parent_block_header.unwrap();
                let parent_consensus_hash = request_key.parent_consensus_hash.unwrap();

                if StacksChainState::validate_parent_microblock_stream(
                    &parent_block_header,
                    &block_header,
                    &microblock_stream,
                    true,
                )
                .is_some()
                {
                    // stream is valid!
                    debug!(
                        "Downloaded valid microblock stream confirmed by {}/{} at sortition height {}",
                        &request_key.consensus_hash,
                        &request_key.anchor_block_hash,
                        request_key.sortition_height
                    );
                    microblocks.push((
                        parent_consensus_hash,
                        microblock_stream,
                        now.saturating_sub(request_key.download_start),
                    ));
                    downloader.num_microblocks_downloaded += 1;
                } else {
                    // stream is not well-formed
                    debug!(
                        "Microblock stream {:?}: confirmed by {}/{} is invalid",
                        request_key.sortition_height,
                        &request_key.consensus_hash,
                        &request_key.anchor_block_hash
                    );
                }

                // don't try again
                downloader
                    .microblocks_to_try
                    .remove(&request_key.sortition_height);
            }

            // clear empties
            let mut blocks_empty = vec![];
            let mut microblocks_empty = vec![];

            for (height, requests) in downloader.blocks_to_try.iter() {
                if requests.is_empty() {
                    blocks_empty.push(*height);
                }
            }
            for (height, requests) in downloader.microblocks_to_try.iter() {
                if requests.is_empty() {
                    microblocks_empty.push(*height);
                }
            }

            for height in blocks_empty.into_iter() {
                downloader.blocks_to_try.remove(&height);
            }

            for height in microblocks_empty.into_iter() {
                downloader.microblocks_to_try.remove(&height);
            }

            debug!(
                "Blocks to try: {}; Microblocks to try: {}",
                downloader.blocks_to_try.len(),
                downloader.microblocks_to_try.len(),
            );
            if downloader.blocks_to_try.is_empty() && downloader.microblocks_to_try.is_empty() {
                // advance downloader state
                done = true;

                debug!(
                    "{:?}: Advance downloader to start at sortition heights {},{}",
                    &network.local_peer,
                    downloader.next_block_sortition_height,
                    downloader.next_microblock_sortition_height
                );
                downloader.block_sortition_height = downloader.next_block_sortition_height;
                downloader.microblock_sortition_height =
                    downloader.next_microblock_sortition_height;

                if downloader.block_sortition_height + sortdb.first_block_height
                    > network.chain_view.burn_block_height
                {
                    debug!(
                        "{:?}: Downloader for blocks has reached the chain tip; wrapping around to {}",
                        &network.local_peer,
                        inv_sortition_start
                    );
                    downloader.block_sortition_height = inv_sortition_start;
                    downloader.next_block_sortition_height = inv_sortition_start;

                    if downloader.num_blocks_downloaded == 0 {
                        downloader.empty_block_download_passes += 1;
                    } else {
                        downloader.empty_block_download_passes = 0;
                    }

                    downloader.num_blocks_downloaded = 0;
                }
                if downloader.microblock_sortition_height + sortdb.first_block_height
                    > network.chain_view.burn_block_height
                {
                    debug!(
                        "{:?}: Downloader for microblocks has reached the chain tip; wrapping around to {}",
                        &network.local_peer,
                        inv_sortition_start
                    );
                    downloader.microblock_sortition_height = inv_sortition_start;
                    downloader.next_microblock_sortition_height = inv_sortition_start;

                    if downloader.num_microblocks_downloaded == 0 {
                        downloader.empty_microblock_download_passes += 1;
                    } else {
                        downloader.empty_microblock_download_passes = 0;
                    }

                    downloader.num_microblocks_downloaded = 0;
                }

                if downloader.empty_block_download_passes > 0
                    && downloader.empty_microblock_download_passes > 0
                {
                    // we scanned the entire chain and didn't download anything.
                    // Either we have everything already, or none of our peers have anything we don't have, or we can't reach any of our peers.
                    // Regardless, we can throttle back now.
                    debug!("Did a full pass over the burn chain sortitions and found no new data");
                    downloader.finished_scan_at = get_epoch_time_secs();

                    at_chain_tip = true;
                }

                // propagate PoX ID as it was when we started
                old_pox_id = Some(downloader.pox_id.clone());
            } else {
                // still have different URLs to try for failed blocks.
                done = false;
                debug!("Re-trying blocks:");
                for (height, requests) in downloader.blocks_to_try.iter() {
                    assert!(
                        !requests.is_empty(),
                        "Empty block requests at height {height}"
                    );
                    debug!(
                        "   Height {}: anchored block {} available from {} peers: {:?}",
                        height,
                        requests.front().unwrap().index_block_hash,
                        requests.len(),
                        requests
                            .iter()
                            .map(|r| r.data_url.clone())
                            .collect::<Vec<UrlString>>()
                    );
                }
                for (height, requests) in downloader.microblocks_to_try.iter() {
                    assert!(
                        !requests.is_empty(),
                        "Empty microblock requests at height {height}"
                    );
                    debug!(
                        "   Height {}: microblocks {} available from {} peers: {:?}",
                        height,
                        requests.front().unwrap().index_block_hash,
                        requests.len(),
                        requests
                            .iter()
                            .map(|r| r.data_url.clone())
                            .collect::<Vec<UrlString>>()
                    );
                }

                downloader.state = BlockDownloaderState::GetBlocksBegin;
            }

            Ok((done, at_chain_tip, old_pox_id, blocks, microblocks))
        })
    }

    /// Initialize the downloader
    pub fn init_block_downloader(&mut self) {
        self.block_downloader = Some(BlockDownloader::new(
            self.connection_opts.dns_timeout,
            self.connection_opts.download_interval,
            self.connection_opts.max_inflight_blocks,
        ));
    }

    /// Initialize the attachment downloader
    pub fn init_attachments_downloader(&mut self, initial_batch: Vec<AttachmentInstance>) {
        self.attachments_downloader = Some(AttachmentsDownloader::new(initial_batch));
    }

    /// Process block downloader lifetime.  Returns the new blocks and microblocks if we get
    /// anything.
    /// Returns:
    /// * are we done?
    /// * did we do a full pass up to the chain tip?
    /// * what's the local PoX ID when we started?  Will be Some(..) when we're done
    /// * List of blocks we downloaded
    /// * List of microblock streams we downloaded
    /// * List of broken HTTP event IDs to disconnect from
    /// * List of broken p2p neighbor keys to disconnect from
    pub fn download_blocks(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        dns_client: &mut DNSClient,
        ibd: bool,
    ) -> Result<
        (
            bool,
            bool,
            Option<PoxId>,
            Vec<(ConsensusHash, StacksBlock, u64)>,
            Vec<(ConsensusHash, Vec<StacksMicroblock>, u64)>,
            Vec<usize>,
            Vec<NeighborKey>,
        ),
        net_error,
    > {
        if let Some(ref inv_state) = self.inv_state {
            if !inv_state.has_inv_data_for_downloader(ibd) {
                debug!(
                    "{:?}: No inventory state tracked, so no download actions to take (ibd={})",
                    &self.local_peer, ibd
                );
                return Err(net_error::NotConnected);
            }
        } else {
            debug!("{:?}: Inv state not initialized yet", &self.local_peer);
            return Err(net_error::NotConnected);
        }

        if self.block_downloader.is_none() {
            self.init_block_downloader();
        }

        let mut last_inv_update_at = 0;
        let mut inv_start_sortition = 0;
        let mut num_inv_states = 0;
        if let Some(ref inv_state) = self.inv_state {
            last_inv_update_at = inv_state.last_change_at;
            inv_start_sortition = inv_state.block_sortition_start;
            num_inv_states = inv_state.block_stats.len();
        }

        match self.block_downloader {
            Some(ref mut downloader) => {
                debug!("{:?}: Have {} inventory state(s) tracked, so take download actions starting from ({},{}, next {},{}) (ibd={})",
                       &self.local_peer, num_inv_states, downloader.block_sortition_height, downloader.microblock_sortition_height,
                       downloader.next_block_sortition_height, downloader.next_microblock_sortition_height, ibd);

                if downloader.empty_block_download_passes > 0
                    && downloader.empty_microblock_download_passes > 0
                    && !ibd
                {
                    if downloader.last_inv_update_at == last_inv_update_at
                        && downloader.finished_scan_at + downloader.download_interval
                            >= get_epoch_time_secs()
                    {
                        // throttle ourselves
                        debug!(
                            "{:?}: Throttle block downloads until {}",
                            &self.local_peer,
                            downloader.finished_scan_at + downloader.download_interval
                        );
                        return Ok((true, true, None, vec![], vec![], vec![], vec![]));
                    } else {
                        // start a rescan -- we've waited long enough
                        debug!(
                            "{:?}: Noticed an inventory change; re-starting a download scan",
                            &self.local_peer
                        );
                        downloader.restart_scan(inv_start_sortition);

                        downloader.last_inv_update_at = last_inv_update_at;
                    }
                } else {
                    downloader.last_inv_update_at = last_inv_update_at;
                }
            }
            None => {
                unreachable!();
            }
        }

        let mut done = false;
        let mut at_chain_tip = false;

        let mut blocks = vec![];
        let mut microblocks = vec![];
        let mut old_pox_id = None;

        let mut done_cycle = false;
        while !done_cycle {
            let dlstate = self.block_downloader.as_ref().unwrap().state;

            debug!("{:?}: Download state is {:?}", &self.local_peer, &dlstate);
            match dlstate {
                BlockDownloaderState::DNSLookupBegin => {
                    self.block_dns_lookups_begin(sortdb, chainstate, dns_client)?;
                }
                BlockDownloaderState::DNSLookupFinish => {
                    self.block_dns_lookups_try_finish(dns_client)?;
                }
                BlockDownloaderState::GetBlocksBegin => {
                    self.block_getblocks_begin()?;
                }
                BlockDownloaderState::GetBlocksFinish => {
                    self.block_getblocks_try_finish()?;
                }
                BlockDownloaderState::GetMicroblocksBegin => {
                    self.block_getmicroblocks_begin()?;
                }
                BlockDownloaderState::GetMicroblocksFinish => {
                    self.block_getmicroblocks_try_finish()?;
                }
                BlockDownloaderState::Done => {
                    // did a pass.
                    // do we have more requests?
                    let (
                        blocks_done,
                        full_pass,
                        downloader_pox_id,
                        mut successful_blocks,
                        mut successful_microblocks,
                    ) = self.finish_downloads(sortdb, chainstate)?;

                    old_pox_id = downloader_pox_id;
                    blocks.append(&mut successful_blocks);
                    microblocks.append(&mut successful_microblocks);
                    done = blocks_done;
                    at_chain_tip = full_pass;

                    done_cycle = true;
                }
            }

            let new_dlstate = self.block_downloader.as_ref().unwrap().state;
            if new_dlstate == dlstate {
                done_cycle = true;
            }
        }

        // remove dead/broken peers
        let (broken_http_peers, broken_p2p_peers) = match self.block_downloader {
            Some(ref mut downloader) => downloader.clear_broken_peers(),
            None => (vec![], vec![]),
        };

        if done {
            // reset state if we're done
            match self.block_downloader {
                Some(ref mut downloader) => downloader.reset(),
                None => {}
            }
        }

        Ok((
            done,
            at_chain_tip,
            old_pox_id,
            blocks,
            microblocks,
            broken_http_peers,
            broken_p2p_peers,
        ))
    }
}
