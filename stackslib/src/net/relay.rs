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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::{cmp, mem};

use clarity::vm::ast::errors::{ParseError, ParseErrors};
use clarity::vm::ast::{ast_check_size, ASTRules};
use clarity::vm::costs::ExecutionCost;
use clarity::vm::errors::RuntimeErrorType;
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::ClarityVersion;
use rand::prelude::*;
use rand::{thread_rng, Rng};
use stacks_common::address::public_keys_to_address_hash;
use stacks_common::codec::MAX_PAYLOAD_LEN;
use stacks_common::types::chainstate::{BurnchainHeaderHash, PoxId, SortitionId, StacksBlockId};
use stacks_common::types::{MempoolCollectionBehavior, StacksEpochId};
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use crate::burnchains::{Burnchain, BurnchainView};
use crate::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionDBConn, SortitionHandle, SortitionHandleConn,
};
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::coordinator::comm::CoordinatorChannels;
use crate::chainstate::coordinator::{
    BlockEventDispatcher, Error as CoordinatorError, OnChainRewardSetProvider,
};
use crate::chainstate::nakamoto::coordinator::load_nakamoto_reward_set;
use crate::chainstate::nakamoto::staging_blocks::NakamotoBlockObtainMethod;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::unconfirmed::ProcessedUnconfirmedState;
use crate::chainstate::stacks::db::{StacksChainState, StacksEpochReceipt, StacksHeaderInfo};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::{StacksBlockHeader, TransactionPayload};
use crate::clarity_vm::clarity::Error as clarity_error;
use crate::core::mempool::{MemPoolDB, *};
use crate::monitoring::update_stacks_tip_height;
use crate::net::chat::*;
use crate::net::connection::*;
use crate::net::db::*;
use crate::net::httpcore::*;
use crate::net::p2p::*;
use crate::net::poll::*;
use crate::net::rpc::*;
use crate::net::stackerdb::{
    StackerDBConfig, StackerDBEventDispatcher, StackerDBSyncResult, StackerDBs,
};
use crate::net::{Error as net_error, *};

pub type BlocksAvailableMap = HashMap<BurnchainHeaderHash, (u64, ConsensusHash)>;

pub const MAX_RELAYER_STATS: usize = 4096;
pub const MAX_RECENT_MESSAGES: usize = 256;
pub const MAX_RECENT_MESSAGE_AGE: usize = 600; // seconds; equal to the expected epoch length
pub const RELAY_DUPLICATE_INFERENCE_WARMUP: usize = 128;

#[cfg(any(test, feature = "testing"))]
pub mod fault_injection {
    use std::path::Path;

    static IGNORE_BLOCK: std::sync::Mutex<Option<(u64, String)>> = std::sync::Mutex::new(None);

    pub fn ignore_block(height: u64, working_dir: &str) -> bool {
        if let Some((ignore_height, ignore_dir)) = &*IGNORE_BLOCK.lock().unwrap() {
            let working_dir_path = Path::new(working_dir);
            let ignore_dir_path = Path::new(ignore_dir);

            let ignore = *ignore_height == height && working_dir_path.starts_with(ignore_dir_path);
            if ignore {
                warn!("Fault injection: ignore block at height {}", height);
            }
            return ignore;
        }
        false
    }

    pub fn set_ignore_block(height: u64, working_dir: &str) {
        warn!(
            "Fault injection: set ignore block at height {} for working directory {}",
            height, working_dir
        );
        *IGNORE_BLOCK.lock().unwrap() = Some((height, working_dir.to_string()));
    }

    pub fn clear_ignore_block() {
        warn!("Fault injection: clear ignore block");
        *IGNORE_BLOCK.lock().unwrap() = None;
    }
}

#[cfg(not(any(test, feature = "testing")))]
pub mod fault_injection {
    pub fn ignore_block(_height: u64, _working_dir: &str) -> bool {
        false
    }

    pub fn set_ignore_block(_height: u64, _working_dir: &str) {}

    pub fn clear_ignore_block() {}
}

pub struct Relayer {
    /// Connection to the p2p thread
    p2p: NetworkHandle,
    /// connection options
    connection_opts: ConnectionOptions,
    /// StackerDB connection
    stacker_dbs: StackerDBs,
    /// Recently-sent Nakamoto blocks, so we don't keep re-sending them.
    /// Maps to tenure ID and timestamp, so we can garbage-collect.
    /// Timestamp is in milliseconds
    recently_sent_nakamoto_blocks: HashMap<StacksBlockId, (ConsensusHash, u128)>,
}

#[derive(Debug)]
pub struct RelayerStats {
    /// Relayer statistics for the p2p network's ongoing conversations.
    /// Note that we key on (addr, port), not the full NeighborAddress.
    /// (TODO: Nothing is done with this yet, but one day we'll use it to probe for network
    /// choke-points).
    pub(crate) relay_stats: HashMap<NeighborAddress, RelayStats>,
    pub(crate) relay_updates: BTreeMap<u64, NeighborAddress>,

    /// Messages sent from each neighbor recently (includes duplicates)
    pub(crate) recent_messages: HashMap<NeighborKey, VecDeque<(u64, Sha512Trunc256Sum)>>,
    pub(crate) recent_updates: BTreeMap<u64, NeighborKey>,

    next_priority: u64,
}

pub struct ProcessedNetReceipts {
    pub mempool_txs_added: Vec<StacksTransaction>,
    pub processed_unconfirmed_state: ProcessedUnconfirmedState,
    pub num_new_blocks: u64,
    pub num_new_confirmed_microblocks: u64,
    pub num_new_unconfirmed_microblocks: u64,
    pub num_new_nakamoto_blocks: u64,
}

/// A trait for implementing both mempool event observer methods and stackerdb methods.
/// This is required for event observers to fully report on newly-relayed data.
pub trait RelayEventDispatcher:
    MemPoolEventDispatcher
    + StackerDBEventDispatcher
    + AsMemPoolEventDispatcher
    + AsStackerDBEventDispatcher
{
}
impl<T: MemPoolEventDispatcher + StackerDBEventDispatcher> RelayEventDispatcher for T {}

/// Trait for upcasting to MemPoolEventDispatcher
pub trait AsMemPoolEventDispatcher {
    fn as_mempool_event_dispatcher(&self) -> &dyn MemPoolEventDispatcher;
}

/// Trait for upcasting to StackerDBEventDispatcher
pub trait AsStackerDBEventDispatcher {
    fn as_stackerdb_event_dispatcher(&self) -> &dyn StackerDBEventDispatcher;
}

impl<T: RelayEventDispatcher> AsMemPoolEventDispatcher for T {
    fn as_mempool_event_dispatcher(&self) -> &dyn MemPoolEventDispatcher {
        self
    }
}

impl<T: RelayEventDispatcher> AsStackerDBEventDispatcher for T {
    fn as_stackerdb_event_dispatcher(&self) -> &dyn StackerDBEventDispatcher {
        self
    }
}

/// Private trait for keeping track of messages that can be relayed, so we can identify the peers
/// who frequently send us duplicates.
pub trait RelayPayload {
    /// Get a representative digest of this message.
    /// m1.get_digest() == m2.get_digest() --> m1 == m2
    fn get_digest(&self) -> Sha512Trunc256Sum;
    fn get_id(&self) -> String;
}

impl RelayPayload for BlocksAvailableData {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize");
        let h = Sha512Trunc256Sum::from_data(&bytes);
        h
    }
    fn get_id(&self) -> String {
        format!("{:?}", &self)
    }
}

impl RelayPayload for StacksBlock {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        let h = self.block_hash();
        Sha512Trunc256Sum(h.0)
    }
    fn get_id(&self) -> String {
        format!("StacksBlock({})", self.block_hash())
    }
}

impl RelayPayload for StacksMicroblock {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        let h = self.block_hash();
        Sha512Trunc256Sum(h.0)
    }
    fn get_id(&self) -> String {
        format!("StacksMicroblock({})", self.block_hash())
    }
}

impl RelayPayload for NakamotoBlock {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        let h = self.block_id();
        Sha512Trunc256Sum(h.0)
    }
    fn get_id(&self) -> String {
        format!("NakamotoBlock({})", self.block_id())
    }
}

impl RelayPayload for StacksTransaction {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        let h = self.txid();
        Sha512Trunc256Sum(h.0)
    }
    fn get_id(&self) -> String {
        format!("Transaction({})", self.txid())
    }
}

impl RelayPayload for StackerDBPushChunkData {
    fn get_digest(&self) -> Sha512Trunc256Sum {
        self.chunk_data.data_hash()
    }
    fn get_id(&self) -> String {
        format!(
            "StackerDBPushChunk(id={},ver={},data_hash={})",
            &self.chunk_data.slot_id,
            self.chunk_data.slot_version,
            &self.chunk_data.data_hash()
        )
    }
}

impl RelayerStats {
    pub fn new() -> RelayerStats {
        RelayerStats {
            relay_stats: HashMap::new(),
            relay_updates: BTreeMap::new(),
            recent_messages: HashMap::new(),
            recent_updates: BTreeMap::new(),
            next_priority: 0,
        }
    }

    /// Add in new stats gleaned from the PeerNetwork's network result
    pub fn merge_relay_stats(&mut self, mut stats: HashMap<NeighborAddress, RelayStats>) {
        for (mut addr, new_stats) in stats.drain() {
            addr.clear_public_key();
            let inserted = if let Some(stats) = self.relay_stats.get_mut(&addr) {
                stats.merge(new_stats);
                false
            } else {
                // remove oldest relay memories if we have too many
                if self.relay_stats.len() > MAX_RELAYER_STATS - 1 {
                    let mut to_remove = vec![];
                    for (ts, old_addr) in self.relay_updates.iter() {
                        self.relay_stats.remove(old_addr);
                        if self.relay_stats.len() <= MAX_RELAYER_STATS - 1 {
                            break;
                        }
                        to_remove.push(*ts);
                    }
                    for ts in to_remove.into_iter() {
                        self.relay_updates.remove(&ts);
                    }
                }
                self.relay_stats.insert(addr.clone(), new_stats);
                true
            };

            if inserted {
                self.relay_updates.insert(self.next_priority, addr);
                self.next_priority += 1;
            }
        }
    }

    /// Record that we've seen a relayed message from one of our neighbors.
    pub fn add_relayed_message<R: RelayPayload>(&mut self, nk: NeighborKey, msg: &R) {
        let h = msg.get_digest();
        let now = get_epoch_time_secs();
        let inserted = if let Some(relayed) = self.recent_messages.get_mut(&nk) {
            relayed.push_back((now, h));

            // prune if too many
            while relayed.len() > MAX_RECENT_MESSAGES {
                relayed.pop_front();
            }

            // prune stale
            while !relayed.is_empty() {
                let head_ts = match relayed.front() {
                    Some((ts, _)) => *ts,
                    None => {
                        break;
                    }
                };
                if head_ts + (MAX_RECENT_MESSAGE_AGE as u64) < now {
                    relayed.pop_front();
                } else {
                    break;
                }
            }
            false
        } else {
            let mut relayed = VecDeque::new();
            relayed.push_back((now, h));

            // remove oldest neighbor memories if we have too many
            if self.recent_messages.len() > MAX_RELAYER_STATS {
                let mut to_remove = vec![];
                for (ts, old_nk) in self.recent_updates.iter() {
                    self.recent_messages.remove(old_nk);
                    if self.recent_messages.len() <= MAX_RELAYER_STATS - 1 {
                        break;
                    }
                    to_remove.push(*ts);
                }
                for ts in to_remove {
                    self.recent_updates.remove(&ts);
                }
            }

            self.recent_messages.insert(nk.clone(), relayed);
            true
        };

        if inserted {
            self.recent_updates.insert(self.next_priority, nk);
            self.next_priority += 1;
        }
    }

    /// Process a neighbor ban -- remove any state for this neighbor
    pub fn process_neighbor_ban(&mut self, nk: &NeighborKey) {
        let addr = NeighborAddress::from_neighbor_key((*nk).clone(), Hash160([0u8; 20]));
        self.recent_messages.remove(nk);
        self.relay_stats.remove(&addr);

        // old state in self.recent_updates and self.relay_updates will eventually be removed by
        // add_relayed_message() and merge_relay_stats()
    }

    /// See if anyone has sent this message to us already, and if so, return the set of neighbors
    /// that did so already (and how many times)
    pub fn count_relay_dups<R: RelayPayload>(&self, msg: &R) -> HashMap<NeighborKey, usize> {
        let h = msg.get_digest();
        let now = get_epoch_time_secs();
        let mut ret = HashMap::new();

        for (nk, relayed) in self.recent_messages.iter() {
            for (ts, msg_hash) in relayed.iter() {
                if ts + (MAX_RECENT_MESSAGE_AGE as u64) < now {
                    // skip old
                    continue;
                }
                if *msg_hash == h {
                    if let Some(count) = ret.get_mut(nk) {
                        *count += 1;
                    } else {
                        ret.insert((*nk).clone(), 1);
                    }
                }
            }
        }

        ret
    }

    /// Map neighbors to the frequency of their AS numbers in the given neighbors list
    pub(crate) fn count_ASNs(
        conn: &DBConn,
        neighbors: &[NeighborKey],
    ) -> Result<HashMap<NeighborKey, usize>, net_error> {
        // look up ASNs
        let mut asns = HashMap::new();
        for nk in neighbors.iter() {
            if !asns.contains_key(nk) {
                match PeerDB::asn_lookup(conn, &nk.addrbytes)? {
                    Some(asn) => asns.insert((*nk).clone(), asn),
                    None => asns.insert((*nk).clone(), 0),
                };
            }
        }

        let mut asn_dist = HashMap::new();

        // calculate ASN distribution
        for nk in neighbors.iter() {
            let asn = asns.get(nk).unwrap_or(&0);
            if let Some(asn_count) = asn_dist.get_mut(asn) {
                *asn_count += 1;
            } else {
                asn_dist.insert(*asn, 1);
            }
        }

        let mut ret = HashMap::new();

        // map neighbors to ASN counts
        for nk in neighbors.iter() {
            let asn = asns.get(nk).unwrap_or(&0);
            let count = *(asn_dist.get(asn).unwrap_or(&0));
            ret.insert((*nk).clone(), count);
        }

        Ok(ret)
    }

    /// Get the (non-normalized) probability distribution to use to sample inbound neighbors to
    /// relay messages to.  The probability of being selected is proportional to how rarely the
    /// neighbor sends us messages we've already seen before.  The intuition is that if an inbound
    /// neighbor (e.g. a client) sends us data that we've already seen, then it must be connected
    /// to some other peer that's already forwarding it data.  Thus, we don't need to do so.
    pub fn get_inbound_relay_rankings<R: RelayPayload>(
        &self,
        neighbors: &[NeighborKey],
        msg: &R,
        warmup_threshold: usize,
    ) -> HashMap<NeighborKey, usize> {
        let mut dup_counts = self.count_relay_dups(msg);
        let mut dup_total = dup_counts.values().sum::<usize>();

        if dup_total < warmup_threshold {
            // don't make inferences on small samples for total duplicates.
            // just assume uniform distribution.
            dup_total = warmup_threshold;
            dup_counts.clear();
        }

        let mut ret = HashMap::new();

        for nk in neighbors.iter() {
            let dup_count = *(dup_counts.get(nk).unwrap_or(&0));

            assert!(dup_total >= dup_count);

            // every peer should have a non-zero chance, hence the + 1
            ret.insert((*nk).clone(), dup_total - dup_count + 1);
        }

        ret
    }

    /// Get the (non-normalized) probability distribution to use to sample outbound neighbors to
    /// relay messages to.  The probability of being selected is proportional to how rare the
    /// neighbor's AS number is in our neighbor set.  The intution is that we should try to
    /// disseminate our data to as many different _networks_ as quickly as possible, so nodes in
    /// those networks can take care of forwarding them to their inbound peers.
    pub fn get_outbound_relay_rankings(
        &self,
        peerdb: &PeerDB,
        neighbors: &[NeighborKey],
    ) -> Result<HashMap<NeighborKey, usize>, net_error> {
        let asn_counts = RelayerStats::count_ASNs(peerdb.conn(), neighbors)?;
        let asn_total = asn_counts.values().sum::<usize>();

        let mut ret = HashMap::new();

        for nk in neighbors.iter() {
            let asn_count = *(asn_counts.get(nk).unwrap_or(&0));

            assert!(asn_total >= asn_count);

            // every peer should have a non-zero chance, hence the + 1
            ret.insert((*nk).clone(), asn_total - asn_count + 1);
        }

        Ok(ret)
    }

    /// Sample a set of neighbors according to our relay data.
    /// Sampling is done *without* replacement, so the resulting neighbors list will have length
    /// min(count, rankings.len())
    pub fn sample_neighbors(
        rankings: HashMap<NeighborKey, usize>,
        count: usize,
    ) -> Vec<NeighborKey> {
        let mut ret = HashSet::new();
        let mut rng = thread_rng();

        let mut norm = rankings.values().sum::<usize>();
        let mut rankings_vec: Vec<(NeighborKey, usize)> = rankings.into_iter().collect();
        let mut sampled = 0;

        if norm <= 1 {
            // there is one or zero options
            if rankings_vec.is_empty() {
                return vec![];
            } else {
                return vec![rankings_vec[0].0.clone()];
            }
        }

        for l in 0..count {
            if norm == 0 {
                // just one option
                break;
            }

            let target: usize = rng.gen::<usize>() % norm; // slightly biased, but it doesn't really matter
            let mut w = 0;

            for i in 0..rankings_vec.len() {
                if rankings_vec[i].1 == 0 {
                    continue;
                }

                w += rankings_vec[i].1;
                if w >= target {
                    ret.insert(rankings_vec[i].0.clone());
                    sampled += 1;

                    // sample without replacement
                    norm = norm.saturating_sub(rankings_vec[i].1);
                    rankings_vec[i].1 = 0;
                    break;
                }
            }

            assert_eq!(l + 1, sampled);
        }

        ret.into_iter().collect()
    }
}

/// Processed result of pushed Nakamoto blocks
pub struct AcceptedNakamotoBlocks {
    pub relayers: Vec<RelayData>,
    pub blocks: Vec<NakamotoBlock>,
}

/// Block processed result
#[derive(Debug, Clone, PartialEq)]
pub enum BlockAcceptResponse {
    /// block was accepted to the staging DB
    Accepted,
    /// we already had this block
    AlreadyStored,
    /// block was rejected for some reason
    Rejected(String),
}

impl BlockAcceptResponse {
    /// Does this response indicate that the block was accepted to the staging DB
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

impl Relayer {
    pub fn new(
        handle: NetworkHandle,
        connection_opts: ConnectionOptions,
        stacker_dbs: StackerDBs,
    ) -> Relayer {
        Relayer {
            p2p: handle,
            connection_opts,
            stacker_dbs,
            recently_sent_nakamoto_blocks: HashMap::new(),
        }
    }

    pub fn from_p2p(network: &mut PeerNetwork, stacker_dbs: StackerDBs) -> Relayer {
        let handle = network.new_handle(1024);
        Relayer::new(handle, network.connection_opts.clone(), stacker_dbs)
    }

    pub fn get_p2p_handle(&self) -> NetworkHandle {
        self.p2p.clone()
    }

    /// Given Stacks 2.x blocks pushed to us, verify that they correspond to expected block data.
    pub fn validate_blocks_push(
        conn: &SortitionDBConn,
        blocks_data: &BlocksData,
    ) -> Result<(), net_error> {
        for BlocksDatum(consensus_hash, block) in blocks_data.blocks.iter() {
            let block_hash = block.block_hash();

            // is this the right Stacks block for this sortition?
            let sn = match SortitionDB::get_block_snapshot_consensus(conn.conn(), consensus_hash)? {
                Some(sn) => {
                    if !sn.pox_valid {
                        info!(
                            "Pushed block from consensus hash {} corresponds to invalid PoX state",
                            consensus_hash
                        );
                        continue;
                    }
                    sn
                }
                None => {
                    // don't know about this yet
                    continue;
                }
            };

            if !sn.sortition || sn.winning_stacks_block_hash != block_hash {
                info!(
                    "No such sortition in block with consensus hash {}",
                    consensus_hash
                );
                return Err(net_error::InvalidMessage);
            }
        }
        Ok(())
    }

    /// Given Nakamoto blocks pushed to us, verify that they correspond to expected block data.
    pub fn validate_nakamoto_blocks_push(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        stacks_tip: &StacksBlockId,
        nakamoto_blocks_data: &NakamotoBlocksData,
    ) -> Result<(), net_error> {
        let conn = sortdb.index_conn();
        let mut loaded_reward_sets = HashMap::new();
        let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;

        for nakamoto_block in nakamoto_blocks_data.blocks.iter() {
            // is this the right Stacks block for this sortition?
            let Some(sn) = SortitionDB::get_block_snapshot_consensus(
                conn.conn(),
                &nakamoto_block.header.consensus_hash,
            )?
            else {
                // don't know this sortition yet
                continue;
            };

            if !sn.pox_valid {
                info!(
                    "Pushed block from consensus hash {} corresponds to invalid PoX state",
                    nakamoto_block.header.consensus_hash
                );
                continue;
            }

            if !sn.sortition {
                info!(
                    "No such sortition in block with consensus hash {}",
                    &nakamoto_block.header.consensus_hash
                );
                return Err(net_error::InvalidMessage);
            }

            // is the block signed by the active reward set?
            let sn_rc = burnchain
                .block_height_to_reward_cycle(sn.block_height)
                .expect("FATAL: sortition has no reward cycle");
            let reward_cycle_info = if let Some(rc_info) = loaded_reward_sets.get(&sn_rc) {
                rc_info
            } else {
                let Some((reward_set_info, _)) = load_nakamoto_reward_set(
                    sn_rc,
                    &tip_sn.sortition_id,
                    burnchain,
                    chainstate,
                    stacks_tip,
                    sortdb,
                    &OnChainRewardSetProvider::new(),
                )
                .map_err(|e| {
                    error!(
                        "Failed to load reward cycle info for cycle {}: {:?}",
                        sn_rc, &e
                    );
                    match e {
                        CoordinatorError::ChainstateError(e) => {
                            error!(
                                "No RewardCycleInfo loaded for tip {}: {:?}",
                                &sn.consensus_hash, &e
                            );
                            net_error::ChainstateError(format!("{:?}", &e))
                        }
                        CoordinatorError::DBError(e) => {
                            error!(
                                "No RewardCycleInfo loaded for tip {}: {:?}",
                                &sn.consensus_hash, &e
                            );
                            net_error::DBError(e)
                        }
                        _ => {
                            error!(
                                "Failed to load RewardCycleInfo for tip {}: {:?}",
                                &sn.consensus_hash, &e
                            );
                            net_error::NoPoXRewardSet(sn_rc)
                        }
                    }
                })?
                else {
                    error!("No reward set for reward cycle {}", &sn_rc);
                    return Err(net_error::NoPoXRewardSet(sn_rc));
                };

                loaded_reward_sets.insert(sn_rc, reward_set_info);
                loaded_reward_sets.get(&sn_rc).expect("FATAL: infallible")
            };

            let Some(reward_set) = reward_cycle_info.known_selected_anchor_block() else {
                error!("No reward set for reward cycle {}", &sn_rc);
                return Err(net_error::NoPoXRewardSet(sn_rc));
            };

            if let Err(e) = nakamoto_block.header.verify_signer_signatures(reward_set) {
                warn!(
                    "Signature verification failure for Nakamoto block";
                    "consensus_hash" => %nakamoto_block.header.consensus_hash,
                    "block_hash" => %nakamoto_block.header.block_hash(),
                    "reward_cycle" => sn_rc,
                    "error" => %e.to_string()
                );
                return Err(net_error::InvalidMessage);
            }
        }
        Ok(())
    }

    /// Get the snapshot of the parent of a given Stacks block
    pub fn get_parent_stacks_block_snapshot(
        sort_handle: &SortitionHandleConn,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> Result<BlockSnapshot, chainstate_error> {
        let parent_block_snapshot = match sort_handle
            .get_block_snapshot_of_parent_stacks_block(consensus_hash, block_hash)
        {
            Ok(Some((_, sn))) => {
                debug!(
                    "Parent of {}/{} is {}/{}",
                    consensus_hash, block_hash, sn.consensus_hash, sn.winning_stacks_block_hash
                );
                sn
            }
            Ok(None) => {
                debug!(
                    "Received block with unknown parent snapshot: {}/{}",
                    consensus_hash, block_hash
                );
                return Err(chainstate_error::NoSuchBlockError);
            }
            Err(db_error::InvalidPoxSortition) => {
                warn!(
                    "Received block {}/{} on a non-canonical PoX sortition",
                    consensus_hash, block_hash
                );
                return Err(chainstate_error::DBError(db_error::InvalidPoxSortition));
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        Ok(parent_block_snapshot)
    }

    /// Insert a staging block that got relayed to us somehow -- e.g. uploaded via http, downloaded
    /// by us, or pushed via p2p.
    /// Return Ok(true) if we stored it, Ok(false) if we didn't
    pub fn process_new_anchored_block(
        sort_ic: &SortitionDBConn,
        chainstate: &mut StacksChainState,
        consensus_hash: &ConsensusHash,
        block: &StacksBlock,
        download_time: u64,
    ) -> Result<BlockAcceptResponse, chainstate_error> {
        info!(
            "Handle incoming block {}/{}",
            consensus_hash,
            &block.block_hash()
        );

        let block_sn = SortitionDB::get_block_snapshot_consensus(sort_ic, consensus_hash)?
            .ok_or(chainstate_error::DBError(db_error::NotFoundError))?;

        if chainstate.fault_injection.hide_blocks
            && Self::fault_injection_is_block_hidden(&block.header, block_sn.block_height)
        {
            return Ok(BlockAcceptResponse::Rejected(
                "Fault injection: block is hidden".into(),
            ));
        }

        // find the snapshot of the parent of this block
        let parent_block_snapshot = match sort_ic
            .find_parent_snapshot_for_stacks_block(consensus_hash, &block.block_hash())?
        {
            Some(sn) => sn,
            None => {
                // doesn't correspond to a PoX-valid sortition
                return Ok(BlockAcceptResponse::Rejected(
                    "Block does not correspond to a known sortition".into(),
                ));
            }
        };

        // don't relay this block if it's using the wrong AST rules (this would render at least one of its
        // txs problematic).
        let ast_rules = SortitionDB::get_ast_rules(sort_ic, block_sn.block_height)?;
        let epoch_id = SortitionDB::get_stacks_epoch(sort_ic, block_sn.block_height)?
            .expect("FATAL: no epoch defined")
            .epoch_id;
        debug!(
            "Current AST rules for block {}/{} height {} sortitioned at {} is {:?}",
            consensus_hash,
            &block.block_hash(),
            block.header.total_work.work,
            &block_sn.block_height,
            &ast_rules
        );
        if !Relayer::static_check_problematic_relayed_block(
            chainstate.mainnet,
            epoch_id,
            block,
            ast_rules,
        ) {
            warn!(
                "Block is problematic; will not store or relay";
                "stacks_block_hash" => %block.block_hash(),
                "consensus_hash" => %consensus_hash,
                "burn_height" => block.header.total_work.work,
                "sortition_height" => block_sn.block_height,
                "ast_rules" => ?ast_rules,
            );
            return Ok(BlockAcceptResponse::Rejected("Block is problematic".into()));
        }

        let res = chainstate.preprocess_anchored_block(
            sort_ic,
            consensus_hash,
            block,
            &parent_block_snapshot.consensus_hash,
            download_time,
        )?;
        if res {
            debug!(
                "Stored incoming block {}/{}",
                consensus_hash,
                &block.block_hash()
            );
            return Ok(BlockAcceptResponse::Accepted);
        } else {
            return Ok(BlockAcceptResponse::AlreadyStored);
        }
    }

    /// Wrapper around inner_process_new_nakamoto_block
    pub fn process_new_nakamoto_block(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        sort_handle: &mut SortitionHandleConn,
        chainstate: &mut StacksChainState,
        stacks_tip: &StacksBlockId,
        block: &NakamotoBlock,
        coord_comms: Option<&CoordinatorChannels>,
        obtained_method: NakamotoBlockObtainMethod,
    ) -> Result<BlockAcceptResponse, chainstate_error> {
        Self::process_new_nakamoto_block_ext(
            burnchain,
            sortdb,
            sort_handle,
            chainstate,
            stacks_tip,
            block,
            coord_comms,
            obtained_method,
            false,
        )
    }

    /// Insert a staging Nakamoto block that got relayed to us somehow -- e.g. uploaded via http,
    /// downloaded by us, or pushed via p2p.
    /// Return Ok(true) if we should broadcast the block.  If force_broadcast is true, then this
    /// function will return Ok(true) even if we already have the block.
    /// Return Ok(false) if we should not broadcast it (e.g. we already have it, it was invalid,
    /// etc.)
    /// Return Err(..) in the following cases, beyond DB errors:
    /// * If the block is from a tenure we don't recognize
    /// * If we're not in the Nakamoto epoch
    /// * If the reward cycle info could not be determined
    /// * If there was an unrecognized signer
    /// * If the coordinator is closed, and `coord_comms` is Some(..)
    pub fn process_new_nakamoto_block_ext(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        sort_handle: &mut SortitionHandleConn,
        chainstate: &mut StacksChainState,
        stacks_tip: &StacksBlockId,
        block: &NakamotoBlock,
        coord_comms: Option<&CoordinatorChannels>,
        obtained_method: NakamotoBlockObtainMethod,
        force_broadcast: bool,
    ) -> Result<BlockAcceptResponse, chainstate_error> {
        info!(
            "Handle incoming Nakamoto block {}/{} obtained via {}",
            &block.header.consensus_hash,
            &block.header.block_hash(),
            &obtained_method;
            "block_id" => %block.header.block_id(),
        );
        if block.is_shadow_block() {
            // drop, since we can get these from ourselves when downloading a tenure that ends in
            // a shadow block.
            return Ok(BlockAcceptResponse::AlreadyStored);
        }

        if fault_injection::ignore_block(block.header.chain_length, &burnchain.working_dir) {
            return Ok(BlockAcceptResponse::Rejected(
                "Fault injection: ignoring block".into(),
            ));
        }

        // do we have this block?  don't lock the DB needlessly if so.
        if chainstate
            .nakamoto_blocks_db()
            .has_nakamoto_block_with_index_hash(&block.header.block_id())
            .map_err(|e| {
                warn!(
                    "Failed to determine if we have Nakamoto block {}/{}: {:?}",
                    &block.header.consensus_hash,
                    &block.header.block_hash(),
                    &e
                );
                e
            })?
        {
            if force_broadcast {
                // it's possible that the signer sent this block to us, in which case, we should
                // broadcast it
                debug!(
                    "Already have Nakamoto block {}, but treating a new anyway so we can broadcast it",
                    &block.header.block_id()
                );
                return Ok(BlockAcceptResponse::Accepted);
            } else {
                debug!("Already have Nakamoto block {}", &block.header.block_id());
                return Ok(BlockAcceptResponse::AlreadyStored);
            }
        }

        let block_sn =
            SortitionDB::get_block_snapshot_consensus(sort_handle, &block.header.consensus_hash)?
                .ok_or_else(|| {
                debug!(
                    "Failed to load snapshot for consensus hash {}",
                    &block.header.consensus_hash
                );
                chainstate_error::DBError(db_error::NotFoundError)
            })?;

        // NOTE: it's `+ 1` because the first Nakamoto block is built atop the last epoch 2.x
        // tenure, right after the last 2.x sortition
        // TODO: is this true?
        let epoch_id = SortitionDB::get_stacks_epoch(sort_handle, block_sn.block_height + 1)?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        if epoch_id < StacksEpochId::Epoch30 {
            error!("Nakamoto blocks are not supported in this epoch");
            return Err(chainstate_error::InvalidStacksBlock(format!(
                "Nakamoto blocks are not supported in this epoch: {epoch_id}"
            )));
        }

        // don't relay this block if it's using the wrong AST rules (this would render at least one of its
        // txs problematic).
        if !Relayer::static_check_problematic_relayed_nakamoto_block(
            chainstate.mainnet,
            epoch_id,
            &block,
            ASTRules::PrecheckSize,
        ) {
            warn!(
                "Nakamoto block is problematic; will not store or relay";
                "stacks_block_hash" => %block.header.block_hash(),
                "consensus_hash" => %block.header.consensus_hash,
                "burn_height" => block.header.chain_length,
                "sortition_height" => block_sn.block_height,
            );
            return Ok(BlockAcceptResponse::Rejected(
                "Nakamoto block is problematic".into(),
            ));
        }

        let accept_msg = format!(
            "Stored incoming Nakamoto block {}/{}",
            &block.header.consensus_hash,
            &block.header.block_hash()
        );
        let reject_msg = format!(
            "Rejected incoming Nakamoto block {}/{}",
            &block.header.consensus_hash,
            &block.header.block_hash()
        );

        let config = chainstate.config();
        let tip = block_sn.sortition_id;

        let reward_info = match load_nakamoto_reward_set(
            burnchain
                .block_height_to_reward_cycle(block_sn.block_height)
                .expect("FATAL: block snapshot has no reward cycle"),
            &tip,
            burnchain,
            chainstate,
            stacks_tip,
            sortdb,
            &OnChainRewardSetProvider::new(),
        ) {
            Ok(Some((reward_info, ..))) => reward_info,
            Ok(None) => {
                error!("No RewardCycleInfo found for tip {}", tip);
                return Err(chainstate_error::PoxNoRewardCycle);
            }
            Err(CoordinatorError::DBError(db_error::NotFoundError)) => {
                error!("No RewardCycleInfo found for tip {}", tip);
                return Err(chainstate_error::PoxNoRewardCycle);
            }
            Err(CoordinatorError::ChainstateError(e)) => {
                error!("No RewardCycleInfo loaded for tip {}: {:?}", tip, &e);
                return Err(e);
            }
            Err(CoordinatorError::DBError(e)) => {
                error!("No RewardCycleInfo loaded for tip {}: {:?}", tip, &e);
                return Err(chainstate_error::DBError(e));
            }
            Err(e) => {
                error!("Failed to load RewardCycleInfo for tip {}: {:?}", tip, &e);
                return Err(chainstate_error::PoxNoRewardCycle);
            }
        };
        let reward_cycle = reward_info.reward_cycle;

        let Some(reward_set) = reward_info.known_selected_anchor_block_owned() else {
            return Err(chainstate_error::NoRegisteredSigners(reward_cycle));
        };

        let (headers_conn, staging_db_tx) = chainstate.headers_conn_and_staging_tx_begin()?;
        let accepted = NakamotoChainState::accept_block(
            &config,
            block,
            sort_handle,
            &staging_db_tx,
            headers_conn,
            &reward_set,
            obtained_method,
        )?;
        staging_db_tx.commit()?;

        if accepted {
            info!("{}", &accept_msg);
            if let Some(coord_comms) = coord_comms {
                if !coord_comms.announce_new_stacks_block() {
                    return Err(chainstate_error::NetError(net_error::CoordinatorClosed));
                }
            }
            return Ok(BlockAcceptResponse::Accepted);
        } else {
            info!("{}", &reject_msg);
            return Ok(BlockAcceptResponse::AlreadyStored);
        }
    }

    #[cfg_attr(test, mutants::skip)]
    /// Process nakamoto blocks that we downloaded.
    /// Log errors but do not return them.
    /// Returns the list of blocks we accepted.
    pub fn process_downloaded_nakamoto_blocks(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        stacks_tip: &StacksBlockId,
        blocks: impl Iterator<Item = NakamotoBlock>,
        coord_comms: Option<&CoordinatorChannels>,
    ) -> Result<Vec<NakamotoBlock>, chainstate_error> {
        let mut accepted = vec![];
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
        let mut sort_handle = sortdb.index_handle(&tip.sortition_id);
        for block in blocks {
            let block_id = block.block_id();
            let accept = match Self::process_new_nakamoto_block(
                burnchain,
                sortdb,
                &mut sort_handle,
                chainstate,
                stacks_tip,
                &block,
                coord_comms,
                NakamotoBlockObtainMethod::Downloaded,
            ) {
                Ok(x) => x,
                Err(e) => {
                    warn!("Failed to process Nakamoto block {}: {:?}", &block_id, &e);
                    continue;
                }
            };
            if BlockAcceptResponse::Accepted == accept {
                accepted.push(block);
            }
        }
        Ok(accepted)
    }

    /// Coalesce a set of microblocks into relayer hints and MicroblocksData messages, as calculated by
    /// process_new_blocks().  Make sure the messages don't get too big.
    fn make_microblocksdata_messages(
        new_microblocks: HashMap<
            StacksBlockId,
            (Vec<RelayData>, HashMap<BlockHeaderHash, StacksMicroblock>),
        >,
    ) -> Vec<(Vec<RelayData>, MicroblocksData)> {
        let mut mblocks_data: HashMap<StacksBlockId, Vec<(Vec<RelayData>, MicroblocksData)>> =
            HashMap::new();
        let mut mblocks_sizes: HashMap<StacksBlockId, usize> = HashMap::new();

        for (anchored_block_hash, (relayers, mblocks_map)) in new_microblocks.into_iter() {
            for (_, mblock) in mblocks_map.into_iter() {
                if !mblocks_data.contains_key(&anchored_block_hash) {
                    mblocks_data.insert(anchored_block_hash.clone(), vec![]);
                }

                if let Some(mblocks_msgs) = mblocks_data.get_mut(&anchored_block_hash) {
                    // should always succeed, due to the above insert
                    let mblock_len = {
                        let mut mblocks_buf = vec![];
                        mblock
                            .consensus_serialize(&mut mblocks_buf)
                            .expect("BUG: failed to serialize microblock we received");
                        mblocks_buf.len()
                    };

                    assert!(mblock_len <= MAX_PAYLOAD_LEN as usize); // this should always be true, since otherwise we wouldn't have been able to parse it.

                    let sz = *(mblocks_sizes.get(&anchored_block_hash).unwrap_or(&0));
                    if sz + mblock_len < (MAX_PAYLOAD_LEN as usize) {
                        // enough space to include this block in this messaege
                        if let Some((_, mblock_msg)) = mblocks_msgs.last_mut() {
                            // append to last mblocks message
                            mblock_msg.microblocks.push(mblock);
                        } else {
                            // allocate the first microblocks message, and add this mblock to it
                            let mblocks_msg = MicroblocksData {
                                index_anchor_block: anchored_block_hash.clone(),
                                microblocks: vec![mblock],
                            };
                            mblocks_msgs.push((relayers.clone(), mblocks_msg));
                        }

                        // update size counter with this mblock's length
                        if let Some(sz) = mblocks_sizes.get_mut(&anchored_block_hash) {
                            *sz += mblock_len
                        } else {
                            mblocks_sizes.insert(anchored_block_hash.clone(), mblock_len);
                        }
                    } else {
                        // start a new microblocks message
                        let mblocks_msg = MicroblocksData {
                            index_anchor_block: anchored_block_hash.clone(),
                            microblocks: vec![mblock],
                        };
                        mblocks_msgs.push((relayers.clone(), mblocks_msg));

                        // reset size counter
                        mblocks_sizes.insert(anchored_block_hash.clone(), mblock_len);
                    }
                } else {
                    // shouldn't happen because we inserted into mblocks_data earlier
                    unreachable!();
                }
            }
        }

        let mut ret = vec![];
        for (_, mut v) in mblocks_data.drain() {
            ret.append(&mut v);
        }
        ret
    }

    /// Preprocess all our downloaded blocks.
    /// Does not fail on invalid blocks; just logs a warning.
    /// Returns the set of consensus hashes for the sortitions that selected these blocks, and the
    /// blocks themselves
    fn preprocess_downloaded_blocks(
        sort_ic: &SortitionDBConn,
        network_result: &mut NetworkResult,
        chainstate: &mut StacksChainState,
    ) -> HashMap<ConsensusHash, StacksBlock> {
        let mut new_blocks = HashMap::new();

        for (consensus_hash, block, download_time) in network_result.blocks.iter() {
            debug!(
                "Received downloaded block {}/{}",
                consensus_hash,
                &block.block_hash()
            );
            if chainstate.fault_injection.hide_blocks {
                if let Some(sn) =
                    SortitionDB::get_block_snapshot_consensus(sort_ic, &consensus_hash)
                        .expect("FATAL: failed to query downloaded block snapshot")
                {
                    if Self::fault_injection_is_block_hidden(&block.header, sn.block_height) {
                        continue;
                    }
                }
            }
            match Relayer::process_new_anchored_block(
                sort_ic,
                chainstate,
                consensus_hash,
                block,
                *download_time,
            ) {
                Ok(accept_response) => {
                    if BlockAcceptResponse::Accepted == accept_response {
                        debug!(
                            "Accepted downloaded block {}/{}",
                            consensus_hash,
                            &block.block_hash()
                        );
                        new_blocks.insert((*consensus_hash).clone(), block.clone());
                    } else {
                        debug!(
                            "Rejected downloaded block {}/{}: {:?}",
                            consensus_hash,
                            &block.block_hash(),
                            &accept_response
                        );
                    }
                }
                Err(chainstate_error::InvalidStacksBlock(msg)) => {
                    warn!("Downloaded invalid Stacks block: {}", msg);
                    // NOTE: we can't punish the neighbor for this, since we could have been
                    // MITM'ed in our download.
                    continue;
                }
                Err(e) => {
                    warn!(
                        "Could not process downloaded Stacks block {}/{}: {:?}",
                        consensus_hash,
                        block.block_hash(),
                        &e
                    );
                }
            };
        }

        new_blocks
    }

    // fault injection -- don't accept this block if we are to deliberatly ignore
    // it in a test
    #[cfg(any(test, feature = "testing"))]
    pub fn fault_injection_is_block_hidden(
        _header: &StacksBlockHeader,
        burn_block_height: u64,
    ) -> bool {
        if let Ok(heights_str) = std::env::var("STACKS_HIDE_BLOCKS_AT_HEIGHT") {
            use serde_json;
            if let Ok(serde_json::Value::Array(height_list_value)) =
                serde_json::from_str(&heights_str)
            {
                for height_value in height_list_value {
                    if let Some(fault_height) = height_value.as_u64() {
                        if fault_height == burn_block_height {
                            debug!(
                                "Fault injection: hide anchored block at burn block height {}",
                                fault_height
                            );
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    #[cfg(not(any(test, feature = "testing")))]
    pub fn fault_injection_is_block_hidden(
        _block: &StacksBlockHeader,
        _burn_block_height: u64,
    ) -> bool {
        false
    }

    /// Preprocess all pushed blocks
    /// Return consensus hashes for the sortitions that elected the blocks we got, as well as the
    /// list of peers that served us invalid data.
    /// Does not fail; just logs warnings.
    fn preprocess_pushed_blocks(
        sort_ic: &SortitionDBConn,
        network_result: &mut NetworkResult,
        chainstate: &mut StacksChainState,
    ) -> Result<(HashMap<ConsensusHash, StacksBlock>, Vec<NeighborKey>), net_error> {
        let mut new_blocks = HashMap::new();
        let mut bad_neighbors = vec![];

        // process blocks pushed to us.
        // If a neighbor sends us an invalid block, ban them.
        for (neighbor_key, blocks_datas) in network_result.pushed_blocks.iter() {
            for blocks_data in blocks_datas.iter() {
                match Relayer::validate_blocks_push(sort_ic, blocks_data) {
                    Ok(_) => {}
                    Err(_) => {
                        // punish this peer
                        bad_neighbors.push((*neighbor_key).clone());
                        break;
                    }
                }

                for BlocksDatum(consensus_hash, block) in blocks_data.blocks.iter() {
                    match SortitionDB::get_block_snapshot_consensus(
                        sort_ic.conn(),
                        &consensus_hash,
                    )? {
                        Some(sn) => {
                            if !sn.pox_valid {
                                warn!(
                                    "Consensus hash {} is not on the valid PoX fork",
                                    &consensus_hash
                                );
                                continue;
                            }
                            if chainstate.fault_injection.hide_blocks
                                && Self::fault_injection_is_block_hidden(
                                    &block.header,
                                    sn.block_height,
                                )
                            {
                                continue;
                            }
                        }
                        None => {
                            warn!("Consensus hash {} not known to this node", &consensus_hash);
                            continue;
                        }
                    };

                    debug!(
                        "Received pushed block {}/{} from {}",
                        &consensus_hash,
                        block.block_hash(),
                        neighbor_key
                    );
                    let bhh = block.block_hash();
                    match Relayer::process_new_anchored_block(
                        sort_ic,
                        chainstate,
                        &consensus_hash,
                        block,
                        0,
                    ) {
                        Ok(accept_response) => {
                            if BlockAcceptResponse::Accepted == accept_response {
                                debug!(
                                    "Accepted block {}/{} from {}",
                                    &consensus_hash, &bhh, &neighbor_key
                                );
                                new_blocks.insert(consensus_hash.clone(), block.clone());
                            } else {
                                debug!(
                                    "Rejected block {}/{} from {}: {:?}",
                                    &consensus_hash, &bhh, &neighbor_key, &accept_response
                                );
                            }
                        }
                        Err(chainstate_error::InvalidStacksBlock(msg)) => {
                            warn!(
                                "Invalid pushed Stacks block {}/{}: {}",
                                &consensus_hash,
                                block.block_hash(),
                                msg
                            );
                            bad_neighbors.push((*neighbor_key).clone());
                        }
                        Err(e) => {
                            warn!(
                                "Could not process pushed Stacks block {}/{}: {:?}",
                                &consensus_hash,
                                block.block_hash(),
                                &e
                            );
                        }
                    }
                }
            }
        }

        Ok((new_blocks, bad_neighbors))
    }

    /// Preprocess all downloaded, confirmed microblock streams.
    /// Does not fail on invalid blocks; just logs a warning.
    /// Returns the consensus hashes for the sortitions that elected the stacks anchored blocks that produced these streams.
    fn preprocess_downloaded_microblocks(
        sort_ic: &SortitionDBConn,
        network_result: &mut NetworkResult,
        chainstate: &mut StacksChainState,
    ) -> HashMap<ConsensusHash, (StacksBlockId, Vec<StacksMicroblock>)> {
        let mut ret = HashMap::new();
        for (consensus_hash, microblock_stream, _download_time) in
            network_result.confirmed_microblocks.iter()
        {
            if microblock_stream.is_empty() {
                continue;
            }
            let anchored_block_hash = microblock_stream[0].header.prev_block.clone();

            let block_snapshot =
                match SortitionDB::get_block_snapshot_consensus(sort_ic, consensus_hash) {
                    Ok(Some(sn)) => sn,
                    Ok(None) => {
                        warn!(
                            "Failed to load parent anchored block snapshot for {}/{}",
                            consensus_hash, &anchored_block_hash
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to load parent stacks block snapshot: {:?}", &e);
                        continue;
                    }
                };

            let ast_rules = match SortitionDB::get_ast_rules(sort_ic, block_snapshot.block_height) {
                Ok(rules) => rules,
                Err(e) => {
                    error!("Failed to load current AST rules: {:?}", &e);
                    continue;
                }
            };
            let epoch_id = match SortitionDB::get_stacks_epoch(sort_ic, block_snapshot.block_height)
            {
                Ok(Some(epoch)) => epoch.epoch_id,
                Ok(None) => {
                    panic!("FATAL: no epoch defined");
                }
                Err(e) => {
                    error!("Failed to load epoch: {:?}", &e);
                    continue;
                }
            };

            let mut stored = false;
            for mblock in microblock_stream.iter() {
                debug!(
                    "Preprocess downloaded microblock {}/{}-{}",
                    consensus_hash,
                    &anchored_block_hash,
                    &mblock.block_hash()
                );
                if !Relayer::static_check_problematic_relayed_microblock(
                    chainstate.mainnet,
                    epoch_id,
                    mblock,
                    ast_rules,
                ) {
                    info!("Microblock {} from {}/{} is problematic; will not store or relay it, nor its descendants", &mblock.block_hash(), consensus_hash, &anchored_block_hash);
                    break;
                }
                match chainstate.preprocess_streamed_microblock(
                    consensus_hash,
                    &anchored_block_hash,
                    mblock,
                ) {
                    Ok(s) => {
                        stored = s;
                    }
                    Err(e) => {
                        warn!(
                            "Invalid downloaded microblock {}/{}-{}: {:?}",
                            consensus_hash,
                            &anchored_block_hash,
                            mblock.block_hash(),
                            &e
                        );
                    }
                }
            }

            // if we did indeed store this microblock (i.e. we didn't have it), then we can relay it
            if stored {
                let index_block_hash =
                    StacksBlockHeader::make_index_block_hash(consensus_hash, &anchored_block_hash);
                ret.insert(
                    (*consensus_hash).clone(),
                    (index_block_hash, microblock_stream.clone()),
                );
            }
        }
        ret
    }

    /// Preprocess all unconfirmed microblocks pushed to us.
    /// Return the list of MicroblockData messages we need to broadcast to our neighbors, as well
    /// as the list of neighbors we need to ban because they sent us invalid microblocks.
    fn preprocess_pushed_microblocks(
        sort_ic: &SortitionDBConn,
        network_result: &mut NetworkResult,
        chainstate: &mut StacksChainState,
    ) -> Result<(Vec<(Vec<RelayData>, MicroblocksData)>, Vec<NeighborKey>), net_error> {
        let mut new_microblocks: HashMap<
            StacksBlockId,
            (Vec<RelayData>, HashMap<BlockHeaderHash, StacksMicroblock>),
        > = HashMap::new();
        let mut bad_neighbors = vec![];

        // process unconfirmed microblocks pushed to us.
        // If a neighbor sends us bad microblocks, ban them.
        // Remember which ones we _don't_ have, and remember the prior relay hints.
        for (neighbor_key, mblock_datas) in network_result.pushed_microblocks.iter() {
            for (mblock_relayers, mblock_data) in mblock_datas.iter() {
                let (consensus_hash, anchored_block_hash) =
                    match chainstate.get_block_header_hashes(&mblock_data.index_anchor_block)? {
                        Some((bhh, bh)) => (bhh, bh),
                        None => {
                            warn!(
                                "Missing anchored block whose index hash is {}",
                                &mblock_data.index_anchor_block
                            );
                            continue;
                        }
                    };
                let index_block_hash = mblock_data.index_anchor_block.clone();

                let block_snapshot =
                    SortitionDB::get_block_snapshot_consensus(sort_ic, &consensus_hash)?
                        .ok_or(net_error::DBError(db_error::NotFoundError))?;
                let ast_rules = SortitionDB::get_ast_rules(sort_ic, block_snapshot.block_height)?;
                let epoch_id = SortitionDB::get_stacks_epoch(sort_ic, block_snapshot.block_height)?
                    .expect("FATAL: no epoch defined")
                    .epoch_id;

                for mblock in mblock_data.microblocks.iter() {
                    debug!(
                        "Preprocess downloaded microblock {}/{}-{}",
                        &consensus_hash,
                        &anchored_block_hash,
                        &mblock.block_hash()
                    );
                    if !Relayer::static_check_problematic_relayed_microblock(
                        chainstate.mainnet,
                        epoch_id,
                        mblock,
                        ast_rules,
                    ) {
                        info!("Microblock {} from {}/{} is problematic; will not store or relay it, nor its descendants", &mblock.block_hash(), &consensus_hash, &anchored_block_hash);
                        continue;
                    }
                    let need_relay = !chainstate.has_descendant_microblock_indexed(
                        &index_block_hash,
                        &mblock.block_hash(),
                    )?;
                    match chainstate.preprocess_streamed_microblock(
                        &consensus_hash,
                        &anchored_block_hash,
                        mblock,
                    ) {
                        Ok(_) => {
                            if need_relay {
                                // we didn't have this block before, so relay it.
                                // Group by index block hash, so we can convert them into
                                // MicroblocksData messages later.  Group microblocks by block
                                // hash, so we don't send dups.
                                let index_hash = StacksBlockHeader::make_index_block_hash(
                                    &consensus_hash,
                                    &anchored_block_hash,
                                );
                                if let Some((_, mblocks_map)) = new_microblocks.get_mut(&index_hash)
                                {
                                    mblocks_map.insert(mblock.block_hash(), (*mblock).clone());
                                } else {
                                    let mut mblocks_map = HashMap::new();
                                    mblocks_map.insert(mblock.block_hash(), (*mblock).clone());
                                    new_microblocks.insert(
                                        index_hash,
                                        ((*mblock_relayers).clone(), mblocks_map),
                                    );
                                }
                            }
                        }
                        Err(chainstate_error::InvalidStacksMicroblock(msg, hash)) => {
                            warn!(
                                "Invalid pushed microblock {}/{}-{}: {:?}",
                                &consensus_hash, &anchored_block_hash, hash, msg
                            );
                            bad_neighbors.push((*neighbor_key).clone());
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "Could not process pushed microblock {}/{}-{}: {:?}",
                                &consensus_hash,
                                &anchored_block_hash,
                                &mblock.block_hash(),
                                &e
                            );
                            continue;
                        }
                    }
                }
            }
        }

        // process uploaded microblocks.  We may have already stored them, so just reconstruct the
        // data we need to forward them to neighbors.
        for uploaded_mblock in network_result.uploaded_microblocks.iter() {
            for mblock in uploaded_mblock.microblocks.iter() {
                // is this microblock actually stored? i.e. it wasn't problematic?
                let (consensus_hash, block_hash) =
                    match chainstate.get_block_header_hashes(&uploaded_mblock.index_anchor_block) {
                        Ok(Some((ch, bhh))) => (ch, bhh),
                        Ok(None) => {
                            warn!("No such block {}", &uploaded_mblock.index_anchor_block);
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to look up hashes for {}: {:?}",
                                &uploaded_mblock.index_anchor_block, &e
                            );
                            continue;
                        }
                    };
                if chainstate
                    .get_microblock_status(&consensus_hash, &block_hash, &mblock.block_hash())
                    .unwrap_or(None)
                    .is_some()
                {
                    // yup, stored!
                    debug!(
                        "Preprocessed uploaded microblock {}/{}-{}",
                        &consensus_hash,
                        &block_hash,
                        &mblock.block_hash()
                    );
                    if let Some((_, mblocks_map)) =
                        new_microblocks.get_mut(&uploaded_mblock.index_anchor_block)
                    {
                        mblocks_map.insert(mblock.block_hash(), (*mblock).clone());
                    } else {
                        let mut mblocks_map = HashMap::new();
                        mblocks_map.insert(mblock.block_hash(), (*mblock).clone());
                        new_microblocks.insert(
                            uploaded_mblock.index_anchor_block.clone(),
                            (vec![], mblocks_map),
                        );
                    }
                } else {
                    // nope
                    debug!(
                        "Did NOT preprocess uploaded microblock {}/{}-{}",
                        &consensus_hash,
                        &block_hash,
                        &mblock.block_hash()
                    );
                }
            }
        }

        let mblock_datas = Relayer::make_microblocksdata_messages(new_microblocks);
        Ok((mblock_datas, bad_neighbors))
    }

    #[cfg_attr(test, mutants::skip)]
    /// Preprocess all pushed Nakamoto blocks
    /// Return the Nakamoto blocks we can accept (and who relayed them), as well as the
    /// list of peers that served us invalid data.
    pub(crate) fn process_pushed_nakamoto_blocks(
        network_result: &mut NetworkResult,
        burnchain: &Burnchain,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        coord_comms: Option<&CoordinatorChannels>,
        reject_blocks_pushed: bool,
    ) -> Result<(Vec<AcceptedNakamotoBlocks>, Vec<NeighborKey>), net_error> {
        let mut pushed_blocks = vec![];
        let mut bad_neighbors = vec![];
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;

        // process Nakamoto blocks pushed to us.
        // If a neighbor sends us an invalid Nakamoto block, then ban them.
        for (neighbor_key, relayers_and_block_data) in
            network_result.pushed_nakamoto_blocks.iter_mut()
        {
            for (relayers, nakamoto_blocks_data) in relayers_and_block_data.iter_mut() {
                let mut accepted_blocks = vec![];
                if let Err(e) = Relayer::validate_nakamoto_blocks_push(
                    burnchain,
                    sortdb,
                    chainstate,
                    &network_result.stacks_tip,
                    nakamoto_blocks_data,
                ) {
                    info!(
                        "Failed to validate Nakamoto blocks pushed from {:?}: {:?}",
                        neighbor_key, &e
                    );
                    break;
                }

                for nakamoto_block in nakamoto_blocks_data.blocks.drain(..) {
                    let block_id = nakamoto_block.block_id();
                    if reject_blocks_pushed {
                        debug!(
                            "Received pushed Nakamoto block {} from {}, but configured to reject it.",
                            block_id, neighbor_key
                        );
                        continue;
                    }

                    debug!(
                        "Received pushed Nakamoto block {} from {}",
                        block_id, neighbor_key
                    );
                    let mut sort_handle = sortdb.index_handle(&tip.sortition_id);
                    match Self::process_new_nakamoto_block(
                        burnchain,
                        sortdb,
                        &mut sort_handle,
                        chainstate,
                        &network_result.stacks_tip,
                        &nakamoto_block,
                        coord_comms,
                        NakamotoBlockObtainMethod::Pushed,
                    ) {
                        Ok(accept_response) => match accept_response {
                            BlockAcceptResponse::Accepted => {
                                debug!(
                                    "Accepted Nakamoto block {} ({}) from {}",
                                    &block_id, &nakamoto_block.header.consensus_hash, neighbor_key
                                );
                                accepted_blocks.push(nakamoto_block);
                            }
                            BlockAcceptResponse::AlreadyStored => {
                                debug!(
                                    "Rejected Nakamoto block {} ({}) from {}: already stored",
                                    &block_id, &nakamoto_block.header.consensus_hash, &neighbor_key,
                                );
                            }
                            BlockAcceptResponse::Rejected(msg) => {
                                warn!(
                                    "Rejected Nakamoto block {} ({}) from {}: {:?}",
                                    &block_id,
                                    &nakamoto_block.header.consensus_hash,
                                    &neighbor_key,
                                    &msg
                                );
                            }
                        },
                        Err(chainstate_error::InvalidStacksBlock(msg)) => {
                            warn!("Invalid pushed Nakamoto block {}: {}", &block_id, msg);
                            bad_neighbors.push((*neighbor_key).clone());
                            break;
                        }
                        Err(e) => {
                            warn!(
                                "Could not process pushed Nakamoto block {}: {:?}",
                                &block_id, &e
                            );
                        }
                    }
                }

                if !accepted_blocks.is_empty() {
                    pushed_blocks.push(AcceptedNakamotoBlocks {
                        relayers: relayers.clone(),
                        blocks: accepted_blocks,
                    });
                }
            }
        }

        Ok((pushed_blocks, bad_neighbors))
    }

    /// Verify that a relayed transaction is not problematic.  This is a static check -- we only
    /// look at the tx contents.
    ///
    /// Return true if the check passes -- i.e. it's not problematic
    /// Return false if the check fails -- i.e. it is problematic
    pub fn static_check_problematic_relayed_tx(
        mainnet: bool,
        epoch_id: StacksEpochId,
        tx: &StacksTransaction,
        ast_rules: ASTRules,
    ) -> Result<(), Error> {
        debug!(
            "Check {} to see if it is problematic in {:?}",
            &tx.txid(),
            &ast_rules
        );
        match tx.payload {
            TransactionPayload::SmartContract(ref smart_contract, ref clarity_version_opt) => {
                let clarity_version =
                    clarity_version_opt.unwrap_or(ClarityVersion::default_for_epoch(epoch_id));

                if ast_rules == ASTRules::PrecheckSize {
                    let origin = tx.get_origin();
                    let issuer_principal = {
                        let addr = if mainnet {
                            origin.address_mainnet()
                        } else {
                            origin.address_testnet()
                        };
                        addr.to_account_principal()
                    };
                    let issuer_principal = if let PrincipalData::Standard(data) = issuer_principal {
                        data
                    } else {
                        // not possible
                        panic!("Transaction had a contract principal origin");
                    };

                    let contract_id = QualifiedContractIdentifier::new(
                        issuer_principal,
                        smart_contract.name.clone(),
                    );
                    let contract_code_str = smart_contract.code_body.to_string();

                    // make sure that the AST isn't unreasonably big
                    let ast_res =
                        ast_check_size(&contract_id, &contract_code_str, clarity_version, epoch_id);
                    match ast_res {
                        Ok(_) => {}
                        Err(parse_error) => match parse_error.err {
                            ParseErrors::ExpressionStackDepthTooDeep
                            | ParseErrors::VaryExpressionStackDepthTooDeep => {
                                // don't include this block
                                info!("Transaction {} is problematic and will not be included, relayed, or built upon", &tx.txid());
                                return Err(Error::ClarityError(parse_error.into()));
                            }
                            _ => {}
                        },
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Verify that a relayed block is not problematic -- i.e. it doesn't contain any problematic
    /// transactions.  This is a static check -- we only look at the block contents.
    ///
    /// Returns true if the check passed -- i.e. no problems.
    /// Returns false if not
    pub fn static_check_problematic_relayed_block(
        mainnet: bool,
        epoch_id: StacksEpochId,
        block: &StacksBlock,
        ast_rules: ASTRules,
    ) -> bool {
        for tx in block.txs.iter() {
            if !Relayer::static_check_problematic_relayed_tx(mainnet, epoch_id, tx, ast_rules)
                .is_ok()
            {
                info!(
                    "Block {} with tx {} will not be stored or relayed",
                    block.block_hash(),
                    tx.txid()
                );
                return false;
            }
        }
        true
    }

    /// Verify that a relayed block is not problematic -- i.e. it doesn't contain any problematic
    /// transactions.  This is a static check -- we only look at the block contents.
    ///
    /// Returns true if the check passed -- i.e. no problems.
    /// Returns false if not
    pub fn static_check_problematic_relayed_nakamoto_block(
        mainnet: bool,
        epoch_id: StacksEpochId,
        block: &NakamotoBlock,
        ast_rules: ASTRules,
    ) -> bool {
        for tx in block.txs.iter() {
            if !Relayer::static_check_problematic_relayed_tx(mainnet, epoch_id, tx, ast_rules)
                .is_ok()
            {
                info!(
                    "Nakamoto block {} with tx {} will not be stored or relayed",
                    block.header.block_hash(),
                    tx.txid()
                );
                return false;
            }
        }
        true
    }

    /// Verify that a relayed microblock is not problematic -- i.e. it doesn't contain any
    /// problematic transactions. This is a static check -- we only look at the microblock
    /// contents.
    ///
    /// Returns true if the check passed -- i.e. no problems.
    /// Returns false if not
    pub fn static_check_problematic_relayed_microblock(
        mainnet: bool,
        epoch_id: StacksEpochId,
        mblock: &StacksMicroblock,
        ast_rules: ASTRules,
    ) -> bool {
        for tx in mblock.txs.iter() {
            if !Relayer::static_check_problematic_relayed_tx(mainnet, epoch_id, tx, ast_rules)
                .is_ok()
            {
                info!(
                    "Microblock {} with tx {} will not be stored relayed",
                    mblock.block_hash(),
                    tx.txid()
                );
                return false;
            }
        }
        true
    }

    /// Should we apply static checks against problematic blocks and microblocks?
    #[cfg(any(test, feature = "testing"))]
    pub fn do_static_problematic_checks() -> bool {
        std::env::var("STACKS_DISABLE_TX_PROBLEMATIC_CHECK") != Ok("1".into())
    }

    /// Should we apply static checks against problematic blocks and microblocks?
    #[cfg(not(any(test, feature = "testing")))]
    pub fn do_static_problematic_checks() -> bool {
        true
    }

    /// Should we store and process problematic blocks and microblocks to staging that we mined?
    #[cfg(any(test, feature = "testing"))]
    pub fn process_mined_problematic_blocks(
        cur_ast_rules: ASTRules,
        processed_ast_rules: ASTRules,
    ) -> bool {
        std::env::var("STACKS_PROCESS_PROBLEMATIC_BLOCKS") != Ok("1".into())
            || cur_ast_rules != processed_ast_rules
    }

    /// Should we store and process problematic blocks and microblocks to staging that we mined?
    /// We should do this only if we used a different ruleset than the active one.  If it was
    /// problematic with the currently-active rules, then obviously it shouldn't be processed.
    #[cfg(not(any(test, feature = "testing")))]
    pub fn process_mined_problematic_blocks(
        cur_ast_rules: ASTRules,
        processed_ast_rules: ASTRules,
    ) -> bool {
        cur_ast_rules != processed_ast_rules
    }

    /// Process blocks and microblocks that we recieved, both downloaded (confirmed) and streamed
    /// (unconfirmed). Returns:
    /// * set of consensus hashes that elected the newly-discovered blocks, and the blocks, so we can turn them into BlocksAvailable / BlocksData messages
    /// * set of confirmed microblock consensus hashes for newly-discovered microblock streams, and the streams, so we can turn them into MicroblocksAvailable / MicroblocksData messages
    /// * list of unconfirmed microblocks that got pushed to us, as well as their relayers (so we can forward them)
    /// * list of neighbors that served us invalid data (so we can ban them)
    pub fn process_new_blocks(
        network_result: &mut NetworkResult,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        coord_comms: Option<&CoordinatorChannels>,
    ) -> Result<
        (
            HashMap<ConsensusHash, StacksBlock>,
            HashMap<ConsensusHash, (StacksBlockId, Vec<StacksMicroblock>)>,
            Vec<(Vec<RelayData>, MicroblocksData)>,
            Vec<NeighborKey>,
        ),
        net_error,
    > {
        let mut new_blocks = HashMap::new();
        let mut bad_neighbors = vec![];

        let sort_ic = sortdb.index_conn();

        // process blocks we downloaded
        let new_dled_blocks =
            Relayer::preprocess_downloaded_blocks(&sort_ic, network_result, chainstate);
        for (new_dled_block_ch, block_data) in new_dled_blocks.into_iter() {
            debug!(
                "Received downloaded block for {}/{}",
                &new_dled_block_ch,
                &block_data.block_hash();
                "consensus_hash" => %new_dled_block_ch,
                "block_hash" => %block_data.block_hash()
            );
            new_blocks.insert(new_dled_block_ch, block_data);
        }

        // process blocks pushed to us
        let (new_pushed_blocks, mut new_bad_neighbors) =
            Relayer::preprocess_pushed_blocks(&sort_ic, network_result, chainstate)?;
        for (new_pushed_block_ch, block_data) in new_pushed_blocks.into_iter() {
            debug!(
                "Received p2p-pushed block for {}/{}",
                &new_pushed_block_ch,
                &block_data.block_hash();
                "consensus_hash" => %new_pushed_block_ch,
                "block_hash" => %block_data.block_hash()
            );
            new_blocks.insert(new_pushed_block_ch, block_data);
        }
        bad_neighbors.append(&mut new_bad_neighbors);

        // process blocks uploaded to us.  They've already been stored, but we need to report them
        // as available anyway so the callers of this method can know that they have shown up (e.g.
        // so they can be relayed).
        for block_data in network_result.uploaded_blocks.drain(..) {
            for BlocksDatum(consensus_hash, block) in block_data.blocks.into_iter() {
                // did we actually store it?
                if StacksChainState::get_staging_block_status(
                    chainstate.db(),
                    &consensus_hash,
                    &block.block_hash(),
                )
                .unwrap_or(None)
                .is_some()
                {
                    // block stored
                    debug!(
                        "Received http-uploaded block for {}/{}",
                        &consensus_hash,
                        block.block_hash()
                    );
                    new_blocks.insert(consensus_hash, block);
                }
            }
        }

        // process microblocks we downloaded
        let new_confirmed_microblocks =
            Relayer::preprocess_downloaded_microblocks(&sort_ic, network_result, chainstate);

        // process microblocks pushed to us, as well as identify which ones were uploaded via http
        // (these ones will have already been processed, but we need to report them as
        // newly-available to the caller nevertheless)
        let (new_microblocks, mut new_bad_neighbors) =
            Relayer::preprocess_pushed_microblocks(&sort_ic, network_result, chainstate)?;
        bad_neighbors.append(&mut new_bad_neighbors);

        if !new_blocks.is_empty()
            || !new_microblocks.is_empty()
            || !new_confirmed_microblocks.is_empty()
        {
            info!(
                "Processing newly received Stacks blocks: {}, microblocks: {}, confirmed microblocks: {}",
                new_blocks.len(),
                new_microblocks.len(),
                new_confirmed_microblocks.len()
            );
            if let Some(coord_comms) = coord_comms {
                if !coord_comms.announce_new_stacks_block() {
                    return Err(net_error::CoordinatorClosed);
                }
            }
        }

        Ok((
            new_blocks,
            new_confirmed_microblocks,
            new_microblocks,
            bad_neighbors,
        ))
    }

    #[cfg_attr(test, mutants::skip)]
    /// Process new Nakamoto blocks, both pushed and downloaded.
    /// Returns the list of Nakamoto blocks we stored, as well as the list of bad neighbors that
    /// sent us invalid blocks.
    pub fn process_new_nakamoto_blocks(
        connection_opts: &ConnectionOptions,
        network_result: &mut NetworkResult,
        burnchain: &Burnchain,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        coord_comms: Option<&CoordinatorChannels>,
    ) -> Result<(Vec<AcceptedNakamotoBlocks>, Vec<NeighborKey>), net_error> {
        // process downloaded Nakamoto blocks.
        // We treat them as singleton blocks fetched via zero relayers
        let nakamoto_blocks =
            std::mem::replace(&mut network_result.nakamoto_blocks, HashMap::new());
        let mut accepted_nakamoto_blocks_and_relayers =
            match Self::process_downloaded_nakamoto_blocks(
                burnchain,
                sortdb,
                chainstate,
                &network_result.stacks_tip,
                nakamoto_blocks.into_values(),
                coord_comms,
            ) {
                Ok(accepted) => vec![AcceptedNakamotoBlocks {
                    relayers: vec![],
                    blocks: accepted,
                }],
                Err(e) => {
                    warn!("Failed to process downloaded Nakamoto blocks: {:?}", &e);
                    vec![]
                }
            };

        // process pushed Nakamoto blocks
        let (pushed_blocks_and_relayers, bad_neighbors) = match Self::process_pushed_nakamoto_blocks(
            network_result,
            burnchain,
            sortdb,
            chainstate,
            coord_comms,
            connection_opts.reject_blocks_pushed,
        ) {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to process pushed Nakamoto blocks: {:?}", &e);
                (vec![], vec![])
            }
        };

        let mut http_uploaded_blocks = vec![];
        for block in network_result.uploaded_nakamoto_blocks.drain(..) {
            let block_id = block.block_id();
            let have_block = chainstate
                .nakamoto_blocks_db()
                .has_nakamoto_block_with_index_hash(&block_id)
                .unwrap_or_else(|e| {
                    warn!(
                        "Failed to determine if we have Nakamoto block";
                        "stacks_block_id" => %block_id,
                        "err" => ?e
                    );
                    false
                });
            if have_block {
                debug!(
                    "Received http-uploaded nakamoto block";
                    "stacks_block_id" => %block_id,
                );
                http_uploaded_blocks.push(block);
            }
        }
        if !http_uploaded_blocks.is_empty() {
            coord_comms.inspect(|comm| {
                comm.announce_new_stacks_block();
            });
        }

        accepted_nakamoto_blocks_and_relayers.extend(pushed_blocks_and_relayers);
        accepted_nakamoto_blocks_and_relayers.push(AcceptedNakamotoBlocks {
            relayers: vec![],
            blocks: http_uploaded_blocks,
        });
        Ok((accepted_nakamoto_blocks_and_relayers, bad_neighbors))
    }

    /// Produce blocks-available messages from blocks we just got.
    pub fn load_blocks_available_data(
        sortdb: &SortitionDB,
        consensus_hashes: Vec<ConsensusHash>,
    ) -> Result<BlocksAvailableMap, net_error> {
        let mut ret = BlocksAvailableMap::new();
        for ch in consensus_hashes.into_iter() {
            let sn = match SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &ch)? {
                Some(sn) => sn,
                None => {
                    continue;
                }
            };

            ret.insert(sn.burn_header_hash, (sn.block_height, sn.consensus_hash));
        }
        Ok(ret)
    }

    /// Filter out problematic transactions from the network result.
    /// Modifies network_result in-place.
    fn filter_problematic_transactions(
        network_result: &mut NetworkResult,
        mainnet: bool,
        epoch_id: StacksEpochId,
    ) {
        // filter out transactions that prove problematic
        let mut filtered_pushed_transactions = HashMap::new();
        let mut filtered_uploaded_transactions = vec![];
        for (nk, tx_data) in network_result.pushed_transactions.drain() {
            let mut filtered_tx_data = vec![];
            for (relayers, tx) in tx_data.into_iter() {
                if Relayer::do_static_problematic_checks()
                    && !Relayer::static_check_problematic_relayed_tx(
                        mainnet,
                        epoch_id,
                        &tx,
                        ASTRules::PrecheckSize,
                    )
                    .is_ok()
                {
                    info!(
                        "Pushed transaction {} is problematic; will not store or relay",
                        &tx.txid()
                    );
                    continue;
                }
                filtered_tx_data.push((relayers, tx));
            }
            if !filtered_tx_data.is_empty() {
                filtered_pushed_transactions.insert(nk, filtered_tx_data);
            }
        }

        for tx in network_result.uploaded_transactions.drain(..) {
            if Relayer::do_static_problematic_checks()
                && !Relayer::static_check_problematic_relayed_tx(
                    mainnet,
                    epoch_id,
                    &tx,
                    ASTRules::PrecheckSize,
                )
                .is_ok()
            {
                info!(
                    "Uploaded transaction {} is problematic; will not store or relay",
                    &tx.txid()
                );
                continue;
            }
            filtered_uploaded_transactions.push(tx);
        }

        network_result
            .pushed_transactions
            .extend(filtered_pushed_transactions);
        network_result
            .uploaded_transactions
            .append(&mut filtered_uploaded_transactions);
    }

    /// Store all new transactions we received, and return the list of transactions that we need to
    /// forward (as well as their relay hints).  Also, garbage-collect the mempool.
    pub(crate) fn process_transactions(
        network_result: &mut NetworkResult,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Result<Vec<(Vec<RelayData>, StacksTransaction)>, net_error> {
        let chain_tip =
            match NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)? {
                Some(tip) => tip,
                None => {
                    debug!(
                        "No Stacks chain tip; dropping {} transaction(s)",
                        network_result.pushed_transactions.len()
                    );
                    return Ok(vec![]);
                }
            };
        let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), network_result.burn_height)?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        let chain_height = chain_tip.anchored_header.height();
        Relayer::filter_problematic_transactions(network_result, chainstate.mainnet, epoch_id);

        if let Err(e) = PeerNetwork::store_transactions(
            mempool,
            chainstate,
            sortdb,
            network_result,
            event_observer,
        ) {
            warn!("Failed to store transactions: {:?}", &e);
        }

        let mut ret = vec![];

        // messages pushed (and already stored) via the p2p network
        for (_nk, tx_data) in network_result.pushed_transactions.iter() {
            for (relayers, tx) in tx_data.iter() {
                ret.push((relayers.clone(), tx.clone()));
            }
        }

        // uploaded via HTTP, but already stored to the mempool.  If we get them here, it means we
        // have to forward them.
        for tx in network_result.uploaded_transactions.iter() {
            ret.push((vec![], tx.clone()));
        }

        mempool.garbage_collect(
            chain_height,
            &epoch_id.mempool_garbage_behavior(),
            event_observer,
        )?;

        Ok(ret)
    }

    pub fn advertize_blocks(
        &mut self,
        available: BlocksAvailableMap,
        blocks: HashMap<ConsensusHash, StacksBlock>,
    ) -> Result<(), net_error> {
        self.p2p.advertize_blocks(available, blocks)
    }

    pub fn broadcast_block(
        &mut self,
        consensus_hash: ConsensusHash,
        block: StacksBlock,
    ) -> Result<(), net_error> {
        let blocks_data = BlocksData {
            blocks: vec![BlocksDatum(consensus_hash, block)],
        };
        self.p2p
            .broadcast_message(vec![], StacksMessageType::Blocks(blocks_data))
    }

    pub fn broadcast_microblock(
        &mut self,
        block_consensus_hash: &ConsensusHash,
        block_header_hash: &BlockHeaderHash,
        microblock: StacksMicroblock,
    ) -> Result<(), net_error> {
        self.p2p.broadcast_message(
            vec![],
            StacksMessageType::Microblocks(MicroblocksData {
                index_anchor_block: StacksBlockHeader::make_index_block_hash(
                    block_consensus_hash,
                    block_header_hash,
                ),
                microblocks: vec![microblock],
            }),
        )
    }

    /// Set up the unconfirmed chain state off of the canonical chain tip.
    /// Only relevant in Stacks 2.x.  Nakamoto nodes should not call this.
    pub fn setup_unconfirmed_state(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
    ) -> Result<ProcessedUnconfirmedState, Error> {
        let (canonical_consensus_hash, canonical_block_hash) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())?;
        let canonical_tip = StacksBlockHeader::make_index_block_hash(
            &canonical_consensus_hash,
            &canonical_block_hash,
        );
        // setup unconfirmed state off of this tip
        debug!(
            "Reload unconfirmed state off of {}/{}",
            &canonical_consensus_hash, &canonical_block_hash
        );
        let processed_unconfirmed_state = chainstate.reload_unconfirmed_state(
            &sortdb.index_handle_at_block(chainstate, &canonical_tip)?,
            canonical_tip,
        )?;

        Ok(processed_unconfirmed_state)
    }

    /// Set up unconfirmed chain state in a read-only fashion.
    /// Only relevant in Stacks 2.x.  Nakamoto nodes should not call this.
    pub fn setup_unconfirmed_state_readonly(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
    ) -> Result<(), Error> {
        let (canonical_consensus_hash, canonical_block_hash) =
            SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())?;
        let canonical_tip = StacksBlockHeader::make_index_block_hash(
            &canonical_consensus_hash,
            &canonical_block_hash,
        );

        // setup unconfirmed state off of this tip
        debug!(
            "Reload read-only unconfirmed state off of {}/{}",
            &canonical_consensus_hash, &canonical_block_hash
        );
        chainstate.refresh_unconfirmed_readonly(canonical_tip)?;
        Ok(())
    }

    /// Reload unconfirmed microblock stream.
    /// Only call if we're in Stacks 2.x
    pub fn refresh_unconfirmed(
        chainstate: &mut StacksChainState,
        sortdb: &mut SortitionDB,
    ) -> ProcessedUnconfirmedState {
        match Relayer::setup_unconfirmed_state(chainstate, sortdb) {
            Ok(processed_unconfirmed_state) => processed_unconfirmed_state,
            Err(e) => {
                if let net_error::ChainstateError(ref err_msg) = e {
                    if err_msg == "Stacks chainstate error: NoSuchBlockError" {
                        trace!("Failed to instantiate unconfirmed state: {:?}", &e);
                    } else {
                        warn!("Failed to instantiate unconfirmed state: {:?}", &e);
                    }
                } else {
                    warn!("Failed to instantiate unconfirmed state: {:?}", &e);
                }
                Default::default()
            }
        }
    }

    /// Process HTTP-uploaded stackerdb chunks.
    /// They're already stored by the RPC handler, so all we have to do
    /// is forward events for them and rebroadcast them (i.e. the fact that we stored them and got
    /// this far at all means that they were novel, and thus potentially novel to our neighbors).
    pub fn process_uploaded_stackerdb_chunks(
        &mut self,
        rc_consensus_hash: &ConsensusHash,
        uploaded_chunks: Vec<StackerDBPushChunkData>,
        event_observer: Option<&dyn StackerDBEventDispatcher>,
    ) {
        if let Some(observer) = event_observer {
            let mut all_events: HashMap<QualifiedContractIdentifier, Vec<StackerDBChunkData>> =
                HashMap::new();
            for chunk in uploaded_chunks.into_iter() {
                if let Some(events) = all_events.get_mut(&chunk.contract_id) {
                    events.push(chunk.chunk_data.clone());
                } else {
                    all_events.insert(chunk.contract_id.clone(), vec![chunk.chunk_data.clone()]);
                }

                // forward if not stale
                if chunk.rc_consensus_hash != *rc_consensus_hash {
                    debug!("Drop stale uploaded StackerDB chunk";
                           "stackerdb_contract_id" => &format!("{}", &chunk.contract_id),
                           "slot_id" => chunk.chunk_data.slot_id,
                           "slot_version" => chunk.chunk_data.slot_version,
                           "chunk.rc_consensus_hash" => %chunk.rc_consensus_hash,
                           "network.rc_consensus_hash" => %rc_consensus_hash);
                    continue;
                }

                debug!("Got uploaded StackerDB chunk"; "stackerdb_contract_id" => &format!("{}", &chunk.contract_id), "slot_id" => chunk.chunk_data.slot_id, "slot_version" => chunk.chunk_data.slot_version);

                let msg = StacksMessageType::StackerDBPushChunk(chunk);
                if let Err(e) = self.p2p.broadcast_message(vec![], msg) {
                    warn!("Failed to broadcast Nakamoto blocks: {:?}", &e);
                }
            }
            for (contract_id, new_chunks) in all_events.into_iter() {
                observer.new_stackerdb_chunks(contract_id, new_chunks);
            }
        }
    }

    /// Process newly-arrived chunks obtained from a peer stackerdb replica.
    /// Chunks that we store will be broadcast, since successful storage implies that they were new
    /// to us (and thus might be new to our neighbors)
    pub fn process_stacker_db_chunks(
        &mut self,
        rc_consensus_hash: &ConsensusHash,
        stackerdb_configs: &HashMap<QualifiedContractIdentifier, StackerDBConfig>,
        sync_results: Vec<StackerDBSyncResult>,
        event_observer: Option<&dyn StackerDBEventDispatcher>,
    ) -> Result<(), Error> {
        // sort stacker results by contract, so as to minimize the number of transactions.
        let mut sync_results_map: HashMap<QualifiedContractIdentifier, Vec<StackerDBSyncResult>> =
            HashMap::new();
        for sync_result in sync_results.into_iter() {
            if let Some(result_list) = sync_results_map.get_mut(&sync_result.contract_id) {
                result_list.push(sync_result);
            } else {
                sync_results_map.insert(sync_result.contract_id.clone(), vec![sync_result]);
            }
        }

        let mut all_events: HashMap<QualifiedContractIdentifier, Vec<StackerDBChunkData>> =
            HashMap::new();

        for (sc, sync_results) in sync_results_map.into_iter() {
            if let Some(config) = stackerdb_configs.get(&sc) {
                let tx = self.stacker_dbs.tx_begin(config.clone())?;
                for sync_result in sync_results.into_iter() {
                    for chunk in sync_result.chunks_to_store.into_iter() {
                        let md = chunk.get_slot_metadata();
                        if let Err(e) = tx.try_replace_chunk(&sc, &md, &chunk.data) {
                            if matches!(e, Error::StaleChunk { .. }) {
                                // This is a common and expected message, so log it as a debug and with a sep message
                                // to distinguish it from other message types.
                                debug!(
                                    "Dropping stale StackerDB chunk";
                                    "stackerdb_contract_id" => &format!("{}", &sync_result.contract_id),
                                    "slot_id" => md.slot_id,
                                    "slot_version" => md.slot_version,
                                    "num_bytes" => chunk.data.len(),
                                    "error" => %e
                                );
                            } else {
                                warn!(
                                    "Failed to store chunk for StackerDB";
                                    "stackerdb_contract_id" => &format!("{}", &sync_result.contract_id),
                                    "slot_id" => md.slot_id,
                                    "slot_version" => md.slot_version,
                                    "num_bytes" => chunk.data.len(),
                                    "error" => %e
                                );
                            }
                            continue;
                        } else {
                            debug!("Stored chunk"; "stackerdb_contract_id" => &format!("{}", &sync_result.contract_id), "slot_id" => md.slot_id, "slot_version" => md.slot_version);
                        }

                        if let Some(event_list) = all_events.get_mut(&sync_result.contract_id) {
                            event_list.push(chunk.clone());
                        } else {
                            all_events.insert(sync_result.contract_id.clone(), vec![chunk.clone()]);
                        }
                        let msg = StacksMessageType::StackerDBPushChunk(StackerDBPushChunkData {
                            contract_id: sc.clone(),
                            rc_consensus_hash: rc_consensus_hash.clone(),
                            chunk_data: chunk,
                        });
                        if let Err(e) = self.p2p.broadcast_message(vec![], msg) {
                            warn!("Failed to broadcast StackerDB chunk: {:?}", &e);
                        }
                    }
                }
                tx.commit()?;
            } else {
                info!("Got chunks for unconfigured StackerDB replica"; "stackerdb_contract_id" => &format!("{}", &sc));
            }
        }

        if let Some(observer) = event_observer.as_ref() {
            for (contract_id, new_chunks) in all_events.into_iter() {
                observer.new_stackerdb_chunks(contract_id, new_chunks);
            }
        }
        Ok(())
    }

    /// Process StackerDB chunks pushed to us.
    /// extract all StackerDBPushChunk messages from `unhandled_messages`
    pub fn process_pushed_stacker_db_chunks(
        &mut self,
        rc_consensus_hash: &ConsensusHash,
        stackerdb_configs: &HashMap<QualifiedContractIdentifier, StackerDBConfig>,
        stackerdb_chunks: Vec<StackerDBPushChunkData>,
        event_observer: Option<&dyn StackerDBEventDispatcher>,
    ) -> Result<(), Error> {
        // synthesize StackerDBSyncResults from each chunk
        let sync_results = stackerdb_chunks
            .into_iter()
            .map(|chunk_data| {
                debug!("Received pushed StackerDB chunk {:?}", &chunk_data);
                let sync_result = StackerDBSyncResult::from_pushed_chunk(chunk_data);
                sync_result
            })
            .collect();

        self.process_stacker_db_chunks(
            rc_consensus_hash,
            stackerdb_configs,
            sync_results,
            event_observer,
        )
    }

    /// Relay epoch2 block data
    fn relay_epoch2_blocks(
        &mut self,
        _local_peer: &LocalPeer,
        sortdb: &SortitionDB,
        new_blocks: HashMap<ConsensusHash, StacksBlock>,
        new_confirmed_microblocks: HashMap<ConsensusHash, (StacksBlockId, Vec<StacksMicroblock>)>,
        new_microblocks: Vec<(Vec<RelayData>, MicroblocksData)>,
    ) {
        // have the p2p thread tell our neighbors about newly-discovered blocks
        let new_block_chs = new_blocks.iter().map(|(ch, _)| ch.clone()).collect();
        let available = Relayer::load_blocks_available_data(sortdb, new_block_chs)
            .unwrap_or(BlocksAvailableMap::new());
        if !available.is_empty() {
            debug!("{:?}: Blocks available: {}", &_local_peer, available.len());
            if let Err(e) = self.p2p.advertize_blocks(available, new_blocks) {
                warn!("Failed to advertize new blocks: {:?}", &e);
            }
        }

        // have the p2p thread tell our neighbors about newly-discovered confirmed microblock streams
        let new_mblock_chs = new_confirmed_microblocks
            .iter()
            .map(|(ch, _)| ch.clone())
            .collect();
        let mblocks_available = Relayer::load_blocks_available_data(sortdb, new_mblock_chs)
            .unwrap_or(BlocksAvailableMap::new());
        if !mblocks_available.is_empty() {
            debug!(
                "{:?}: Confirmed microblock streams available: {}",
                &_local_peer,
                mblocks_available.len()
            );
            if let Err(e) = self
                .p2p
                .advertize_microblocks(mblocks_available, new_confirmed_microblocks)
            {
                warn!("Failed to advertize new confirmed microblocks: {:?}", &e);
            }
        }

        // have the p2p thread forward all new unconfirmed microblocks
        if !new_microblocks.is_empty() {
            debug!(
                "{:?}: Unconfirmed microblocks: {}",
                &_local_peer,
                new_microblocks.len()
            );
            for (relayers, mblocks_msg) in new_microblocks.into_iter() {
                debug!(
                    "{:?}: Send {} microblocks for {}",
                    &_local_peer,
                    mblocks_msg.microblocks.len(),
                    &mblocks_msg.index_anchor_block
                );
                let msg = StacksMessageType::Microblocks(mblocks_msg);
                if let Err(e) = self.p2p.broadcast_message(relayers, msg) {
                    warn!("Failed to broadcast microblock: {:?}", &e);
                }
            }
        }
    }

    #[cfg_attr(test, mutants::skip)]
    /// Process epoch2 block data.
    /// Relays blocks and microblocks as needed
    /// Returns (num new blocks, num new confirmed microblocks, num new unconfirmed microblocks)
    fn process_new_epoch2_blocks(
        &mut self,
        _local_peer: &LocalPeer,
        network_result: &mut NetworkResult,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        ibd: bool,
        coord_comms: Option<&CoordinatorChannels>,
    ) -> (u64, u64, u64) {
        let mut num_new_blocks = 0;
        let mut num_new_confirmed_microblocks = 0;
        let mut num_new_unconfirmed_microblocks = 0;

        // Process epoch2 data
        match Self::process_new_blocks(network_result, sortdb, chainstate, coord_comms) {
            Ok((new_blocks, new_confirmed_microblocks, new_microblocks, bad_block_neighbors)) => {
                // report quantities of new data in the receipts
                num_new_blocks = new_blocks.len() as u64;
                num_new_confirmed_microblocks = new_confirmed_microblocks.len() as u64;
                num_new_unconfirmed_microblocks = new_microblocks.len() as u64;

                // attempt to relay messages (note that this is all best-effort).
                // punish bad peers
                if !bad_block_neighbors.is_empty() {
                    debug!(
                        "{:?}: Ban {} peers",
                        &_local_peer,
                        bad_block_neighbors.len()
                    );
                    if let Err(e) = self.p2p.ban_peers(bad_block_neighbors) {
                        warn!("Failed to ban bad-block peers: {:?}", &e);
                    }
                }

                // only relay if not ibd
                if !ibd {
                    self.relay_epoch2_blocks(
                        _local_peer,
                        sortdb,
                        new_blocks,
                        new_confirmed_microblocks,
                        new_microblocks,
                    );
                }
            }
            Err(e) => {
                warn!("Failed to process new blocks: {:?}", &e);
            }
        }
        (
            num_new_blocks,
            num_new_confirmed_microblocks,
            num_new_unconfirmed_microblocks,
        )
    }

    #[cfg_attr(test, mutants::skip)]
    /// Get the last N sortitions, in order from the sortition tip to the n-1st ancestor
    pub fn get_last_n_sortitions(
        sortdb: &SortitionDB,
        n: u64,
    ) -> Result<Vec<BlockSnapshot>, chainstate_error> {
        let mut ret = vec![];
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;
        ret.push(sort_tip);

        for _i in 0..(n.saturating_sub(1)) {
            let last_sn_parent_sortition_id = ret
                .last()
                .map(|sn| sn.parent_sortition_id.clone())
                .expect("Infallible -- ret is non-empty");
            let sn = SortitionDB::get_block_snapshot(sortdb.conn(), &last_sn_parent_sortition_id)?
                .ok_or(db_error::NotFoundError)?;
            ret.push(sn);
        }
        Ok(ret)
    }

    #[cfg_attr(test, mutants::skip)]
    /// Relay Nakamoto blocks.
    /// By default, only sends them if we don't have them yet.
    /// This can be overridden by setting `force_send` to true.
    pub fn relay_epoch3_blocks(
        &mut self,
        _local_peer: &LocalPeer,
        sortdb: &SortitionDB,
        accepted_blocks: Vec<AcceptedNakamotoBlocks>,
    ) {
        debug!(
            "{:?}: relay {} sets of Nakamoto blocks",
            _local_peer,
            accepted_blocks.len()
        );

        // the relay strategy is to only send blocks that are within
        // `connection_opts.max_nakamoto_block_relay_age`, which is the number of
        // burnchain sortitions that have happened since its tenure began.  The
        // intuition is that nodes that are in IBD will be downloading blocks anyway,
        // but nodes that are at or near the chain tip would benefit from having blocks
        // pushed to them.
        let Ok(relay_sortitions) =
            Self::get_last_n_sortitions(sortdb, self.connection_opts.max_nakamoto_block_relay_age)
                .map_err(|e| warn!("Failed to load last N sortitions: {:?}", &e))
        else {
            return;
        };

        let relay_tenures: HashSet<_> = relay_sortitions
            .into_iter()
            .map(|sn| sn.consensus_hash)
            .collect();

        for blocks_and_relayers in accepted_blocks.into_iter() {
            let AcceptedNakamotoBlocks { relayers, blocks } = blocks_and_relayers;
            if blocks.is_empty() {
                continue;
            }

            let relay_blocks_set: HashMap<_, _> = blocks
                .into_iter()
                .filter(|blk| {
                    // don't relay blocks for non-recent tenures
                    if !relay_tenures.contains(&blk.header.consensus_hash) {
                        test_debug!(
                            "Do not relay {} -- {} is not recent",
                            &blk.header.block_id(),
                            &blk.header.consensus_hash
                        );
                        return false;
                    }
                    // don't relay blocks we've recently sent
                    if let Some((_ch, ts)) = self.recently_sent_nakamoto_blocks.get(&blk.block_id())
                    {
                        if ts + self.connection_opts.nakamoto_push_interval_ms
                            >= get_epoch_time_ms()
                        {
                            // too soon
                            test_debug!("Sent {} too recently; will not relay", &blk.block_id());
                            return false;
                        }
                    }
                    true
                })
                .map(|blk| (blk.block_id(), blk))
                .collect();

            let relay_blocks: Vec<_> = relay_blocks_set.into_values().collect();

            debug!(
                "{:?}: Forward {} Nakamoto blocks from {:?}",
                _local_peer,
                relay_blocks.len(),
                &relayers
            );

            if relay_blocks.is_empty() {
                continue;
            }

            for block in relay_blocks.iter() {
                debug!(
                    "{:?}: Forward Nakamoto block {}/{}",
                    _local_peer,
                    &block.header.consensus_hash,
                    &block.header.block_hash()
                );
                self.recently_sent_nakamoto_blocks.insert(
                    block.block_id(),
                    (block.header.consensus_hash.clone(), get_epoch_time_ms()),
                );
            }

            let msg = StacksMessageType::NakamotoBlocks(NakamotoBlocksData {
                blocks: relay_blocks,
            });
            if let Err(e) = self.p2p.broadcast_message(relayers, msg) {
                warn!("Failed to broadcast Nakamoto blocks: {:?}", &e);
            }
        }

        // garbage-collect
        self.recently_sent_nakamoto_blocks
            .retain(|_blk_id, (ch, _ts)| relay_tenures.contains(ch));
    }

    #[cfg_attr(test, mutants::skip)]
    /// Process epoch3 data
    /// Relay new nakamoto blocks if not in ibd
    /// Returns number of new nakamoto blocks, up to u64::MAX
    pub fn process_new_epoch3_blocks(
        &mut self,
        local_peer: &LocalPeer,
        network_result: &mut NetworkResult,
        burnchain: &Burnchain,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        ibd: bool,
        coord_comms: Option<&CoordinatorChannels>,
    ) -> u64 {
        let (accepted_blocks, bad_neighbors) = match Self::process_new_nakamoto_blocks(
            &self.connection_opts,
            network_result,
            burnchain,
            sortdb,
            chainstate,
            coord_comms,
        ) {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to process new Nakamoto blocks: {:?}", &e);
                return 0;
            }
        };

        let num_new_nakamoto_blocks = accepted_blocks
            .iter()
            .fold(0, |acc, accepted| acc + accepted.blocks.len())
            .try_into()
            .unwrap_or(u64::MAX); // don't panic if we somehow receive more than u64::MAX blocks

        // punish bad peers
        if !bad_neighbors.is_empty() {
            debug!("{:?}: Ban {} peers", &local_peer, bad_neighbors.len());
            if let Err(e) = self.p2p.ban_peers(bad_neighbors) {
                warn!("Failed to ban bad-block peers: {:?}", &e);
            }
        }

        // relay if not IBD
        if !ibd && !accepted_blocks.is_empty() {
            self.relay_epoch3_blocks(local_peer, sortdb, accepted_blocks);
        }
        num_new_nakamoto_blocks
    }

    #[cfg_attr(test, mutants::skip)]
    /// Process new transactions
    /// Returns the list of accepted txs
    pub fn process_new_transactions(
        &mut self,
        _local_peer: &LocalPeer,
        network_result: &mut NetworkResult,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
        ibd: bool,
        event_observer: Option<&dyn RelayEventDispatcher>,
    ) -> Vec<StacksTransaction> {
        if ibd {
            // don't do anything
            return vec![];
        }

        // only care about transaction forwarding if not IBD.
        // store all transactions, and forward the novel ones to neighbors
        let mut mempool_txs_added = vec![];
        test_debug!(
            "{:?}: Process {} transaction(s)",
            &_local_peer,
            network_result.pushed_transactions.len()
        );
        let new_txs = Relayer::process_transactions(
            network_result,
            sortdb,
            chainstate,
            mempool,
            event_observer.map(|obs| obs.as_mempool_event_dispatcher()),
        )
        .unwrap_or(vec![]);

        if !new_txs.is_empty() {
            debug!(
                "{:?}: Send {} transactions to neighbors",
                &_local_peer,
                new_txs.len()
            );
        }

        for (relayers, tx) in new_txs.into_iter() {
            debug!("{:?}: Broadcast tx {}", &_local_peer, &tx.txid());
            mempool_txs_added.push(tx.clone());
            let msg = StacksMessageType::Transaction(tx);
            if let Err(e) = self.p2p.broadcast_message(relayers, msg) {
                warn!("Failed to broadcast transaction: {:?}", &e);
            }
        }
        mempool_txs_added
    }

    /// Given a network result, consume and store all data.
    /// * Add all blocks and microblocks to staging.
    /// * Forward BlocksAvailable messages to neighbors for newly-discovered anchored blocks
    /// * Forward MicroblocksAvailable messages to neighbors for newly-discovered confirmed microblock streams
    /// * Forward along unconfirmed microblocks that we didn't already have
    /// * Add all transactions to the mempool.
    /// * Forward transactions we didn't already have.
    /// * Reload the unconfirmed state, if necessary.
    /// Mask errors from invalid data -- all errors due to invalid blocks and invalid data should be captured, and
    /// turned into peer bans.
    pub fn process_network_result(
        &mut self,
        local_peer: &LocalPeer,
        network_result: &mut NetworkResult,
        burnchain: &Burnchain,
        sortdb: &mut SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
        ibd: bool,
        coord_comms: Option<&CoordinatorChannels>,
        event_observer: Option<&dyn RelayEventDispatcher>,
    ) -> Result<ProcessedNetReceipts, net_error> {
        // process epoch2 data
        let (num_new_blocks, num_new_confirmed_microblocks, num_new_unconfirmed_microblocks) = self
            .process_new_epoch2_blocks(
                local_peer,
                network_result,
                sortdb,
                chainstate,
                ibd,
                coord_comms,
            );

        // process epoch3 data
        let num_new_nakamoto_blocks = self.process_new_epoch3_blocks(
            local_peer,
            network_result,
            burnchain,
            sortdb,
            chainstate,
            ibd,
            coord_comms,
        );

        // process transactions
        let mempool_txs_added = self.process_new_transactions(
            local_peer,
            network_result,
            sortdb,
            chainstate,
            mempool,
            ibd,
            event_observer,
        );

        // finally, refresh the unconfirmed chainstate, if need be.
        // only bother if we're not in IBD; otherwise this is a waste of time
        let processed_unconfirmed_state = if network_result.has_microblocks() && !ibd {
            Relayer::refresh_unconfirmed(chainstate, sortdb)
        } else {
            Default::default()
        };

        // push events for HTTP-uploaded stacker DB chunks
        self.process_uploaded_stackerdb_chunks(
            &network_result.rc_consensus_hash,
            mem::replace(&mut network_result.uploaded_stackerdb_chunks, vec![]),
            event_observer.map(|obs| obs.as_stackerdb_event_dispatcher()),
        );

        // store downloaded stacker DB chunks
        self.process_stacker_db_chunks(
            &network_result.rc_consensus_hash,
            &network_result.stacker_db_configs,
            mem::replace(&mut network_result.stacker_db_sync_results, vec![]),
            event_observer.map(|obs| obs.as_stackerdb_event_dispatcher()),
        )?;

        // store pushed stacker DB chunks
        self.process_pushed_stacker_db_chunks(
            &network_result.rc_consensus_hash,
            &network_result.stacker_db_configs,
            mem::replace(&mut network_result.pushed_stackerdb_chunks, vec![]),
            event_observer.map(|obs| obs.as_stackerdb_event_dispatcher()),
        )?;

        update_stacks_tip_height(
            i64::try_from(network_result.stacks_tip_height).unwrap_or(i64::MAX),
        );

        let receipts = ProcessedNetReceipts {
            mempool_txs_added,
            processed_unconfirmed_state,
            num_new_blocks,
            num_new_confirmed_microblocks,
            num_new_unconfirmed_microblocks,
            num_new_nakamoto_blocks,
        };

        Ok(receipts)
    }
}

impl PeerNetwork {
    /// Find out which neighbors need at least one (micro)block from the availability set.
    /// For outbound neighbors (i.e. ones we have inv data for), send (Micro)BlocksData messages if
    /// we can; fall back to (Micro)BlocksAvailable messages if we can't.
    /// For inbound neighbors (i.e. ones we don't have inv data for), pick a random set and send them
    /// the full (Micro)BlocksAvailable message.
    fn find_block_recipients(
        &mut self,
        available: &BlocksAvailableMap,
    ) -> Result<(Vec<NeighborKey>, Vec<NeighborKey>), net_error> {
        let outbound_recipients_set = PeerNetwork::with_inv_state(self, |_network, inv_state| {
            let mut recipients = HashSet::new();
            for (neighbor, stats) in inv_state.block_stats.iter() {
                for (_, (block_height, _)) in available.iter() {
                    if !stats.inv.has_ith_block(*block_height) {
                        recipients.insert((*neighbor).clone());
                    }
                }
            }
            recipients
        })?;

        // make a normalized random sample of inbound recipients, but don't send to an inbound peer
        // if it's already represented in the outbound set, or its reciprocal conversation is
        // represented in the outbound set.
        let mut inbound_recipients_set = HashSet::new();
        for (event_id, convo) in self.peers.iter() {
            if !convo.is_authenticated() {
                continue;
            }
            if convo.is_outbound() {
                continue;
            }
            let nk = convo.to_neighbor_key();
            if outbound_recipients_set.contains(&nk) {
                continue;
            }

            if let Some(out_nk) = self.find_outbound_neighbor(*event_id) {
                if outbound_recipients_set.contains(&out_nk) {
                    continue;
                }
            }

            inbound_recipients_set.insert(nk);
        }

        let outbound_recipients: Vec<NeighborKey> = outbound_recipients_set.into_iter().collect();
        let mut inbound_recipients_unshuffled: Vec<NeighborKey> =
            inbound_recipients_set.into_iter().collect();

        let inbound_recipients =
            if inbound_recipients_unshuffled.len() > MAX_BROADCAST_INBOUND_RECEIVERS {
                let _ = &mut inbound_recipients_unshuffled[..].shuffle(&mut thread_rng());
                inbound_recipients_unshuffled[0..MAX_BROADCAST_INBOUND_RECEIVERS].to_vec()
            } else {
                inbound_recipients_unshuffled
            };

        Ok((outbound_recipients, inbound_recipients))
    }

    /// Announce the availability of a set of blocks or microblocks to a peer.
    /// Break the availability into (Micro)BlocksAvailable messages and queue them for transmission.
    fn advertize_to_peer<S>(
        &mut self,
        recipient: &NeighborKey,
        wanted: &[(ConsensusHash, BurnchainHeaderHash)],
        mut msg_builder: S,
    ) where
        S: FnMut(BlocksAvailableData) -> StacksMessageType,
    {
        for i in (0..wanted.len()).step_by(BLOCKS_AVAILABLE_MAX_LEN as usize) {
            let to_send = if i + (BLOCKS_AVAILABLE_MAX_LEN as usize) < wanted.len() {
                wanted[i..(i + (BLOCKS_AVAILABLE_MAX_LEN as usize))].to_vec()
            } else {
                wanted[i..].to_vec()
            };

            let num_blocks = to_send.len();
            let payload = BlocksAvailableData { available: to_send };
            let message = match self.sign_for_neighbor(recipient, msg_builder(payload)) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "{:?}: Failed to sign for {:?}: {:?}",
                        &self.local_peer, recipient, &e
                    );
                    continue;
                }
            };

            // absorb errors
            let _ = self.relay_signed_message(recipient, message).map_err(|e| {
                warn!(
                    "{:?}: Failed to announce {} entries to {:?}: {:?}",
                    &self.local_peer, num_blocks, recipient, &e
                );
                e
            });
        }
    }

    /// Try to push a block to a peer.
    /// Absorb and log errors.
    fn push_block_to_peer(
        &mut self,
        recipient: &NeighborKey,
        consensus_hash: ConsensusHash,
        block: StacksBlock,
    ) {
        let blk_hash = block.block_hash();
        let ch = consensus_hash.clone();
        let payload = BlocksData {
            blocks: vec![BlocksDatum(consensus_hash, block)],
        };
        let message = match self.sign_for_neighbor(recipient, StacksMessageType::Blocks(payload)) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    "{:?}: Failed to sign for {:?}: {:?}",
                    &self.local_peer, recipient, &e
                );
                return;
            }
        };

        debug!(
            "{:?}: Push block {}/{} to {:?}",
            &self.local_peer, &ch, &blk_hash, recipient
        );

        // absorb errors
        let _ = self.relay_signed_message(recipient, message).map_err(|e| {
            warn!(
                "{:?}: Failed to push block {}/{} to {:?}: {:?}",
                &self.local_peer, &ch, &blk_hash, recipient, &e
            );
            e
        });
    }

    /// Try to push a confirmed microblock stream to a peer.
    /// Absorb and log errors.
    fn push_microblocks_to_peer(
        &mut self,
        recipient: &NeighborKey,
        index_block_hash: StacksBlockId,
        microblocks: Vec<StacksMicroblock>,
    ) {
        let idx_bhh = index_block_hash.clone();
        let payload = MicroblocksData {
            index_anchor_block: index_block_hash,
            microblocks,
        };
        let message =
            match self.sign_for_neighbor(recipient, StacksMessageType::Microblocks(payload)) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        "{:?}: Failed to sign for {:?}: {:?}",
                        &self.local_peer, recipient, &e
                    );
                    return;
                }
            };

        debug!(
            "{:?}: Push microblocks for {} to {:?}",
            &self.local_peer, &idx_bhh, recipient
        );

        // absorb errors
        let _ = self.relay_signed_message(recipient, message).map_err(|e| {
            warn!(
                "{:?}: Failed to push microblocks for {} to {:?}: {:?}",
                &self.local_peer, &idx_bhh, recipient, &e
            );
            e
        });
    }

    /// Announce blocks that we have to an outbound peer that doesn't have them.
    /// If we were given the block, send the block itself.
    /// Otherwise, send a BlocksAvailable.
    fn advertize_or_push_blocks_to_outbound_peer(
        &mut self,
        recipient: &NeighborKey,
        available: &BlocksAvailableMap,
        blocks: &HashMap<ConsensusHash, StacksBlock>,
    ) -> Result<(), net_error> {
        PeerNetwork::with_inv_state(self, |network, inv_state| {
            if let Some(stats) = inv_state.block_stats.get(recipient) {
                for (bhh, (block_height, ch)) in available.iter() {
                    if !stats.inv.has_ith_block(*block_height) {
                        test_debug!(
                            "{:?}: Outbound neighbor {:?} wants block data for {}",
                            &network.local_peer,
                            recipient,
                            bhh
                        );

                        match blocks.get(ch) {
                            Some(block) => {
                                network.push_block_to_peer(
                                    recipient,
                                    (*ch).clone(),
                                    (*block).clone(),
                                );
                            }
                            None => {
                                network.advertize_to_peer(
                                    recipient,
                                    &[((*ch).clone(), (*bhh).clone())],
                                    StacksMessageType::BlocksAvailable,
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    /// Announce microblocks that we have to an outbound peer that doesn't have them.
    /// If we were given the microblock stream, send the stream itself.
    /// Otherwise, send a MicroblocksAvailable.
    fn advertize_or_push_microblocks_to_outbound_peer(
        &mut self,
        recipient: &NeighborKey,
        available: &BlocksAvailableMap,
        microblocks: &HashMap<ConsensusHash, (StacksBlockId, Vec<StacksMicroblock>)>,
    ) -> Result<(), net_error> {
        PeerNetwork::with_inv_state(self, |network, inv_state| {
            if let Some(stats) = inv_state.block_stats.get(recipient) {
                for (bhh, (block_height, ch)) in available.iter() {
                    if !stats.inv.has_ith_microblock_stream(*block_height) {
                        test_debug!(
                            "{:?}: Outbound neighbor {:?} wants microblock data for {}",
                            &network.local_peer,
                            recipient,
                            bhh
                        );

                        match microblocks.get(ch) {
                            Some((stacks_block_id, mblocks)) => {
                                network.push_microblocks_to_peer(
                                    recipient,
                                    stacks_block_id.clone(),
                                    mblocks.clone(),
                                );
                            }
                            None => {
                                network.advertize_to_peer(
                                    recipient,
                                    &[((*ch).clone(), (*bhh).clone())],
                                    StacksMessageType::MicroblocksAvailable,
                                );
                            }
                        }
                    }
                }
            }
        })
    }

    /// Announce blocks that we have to an inbound peer that might not have them.
    /// Send all available blocks and microblocks, since we don't know what the inbound peer has
    /// already.
    fn advertize_to_inbound_peer<S>(
        &mut self,
        recipient: &NeighborKey,
        available: &BlocksAvailableMap,
        msg_builder: S,
    ) -> Result<(), net_error>
    where
        S: FnMut(BlocksAvailableData) -> StacksMessageType,
    {
        let mut wanted: Vec<(ConsensusHash, BurnchainHeaderHash)> = vec![];
        for (burn_header_hash, (_, consensus_hash)) in available.iter() {
            wanted.push(((*consensus_hash).clone(), (*burn_header_hash).clone()));
        }

        self.advertize_to_peer(recipient, &wanted, msg_builder);
        Ok(())
    }

    /// Announce blocks that we have to a subset of inbound and outbound peers.
    /// * Outbound peers receive announcements for blocks that we know they don't have, based on
    /// the inv state we synchronized from them.  We send the blocks themselves, if we have them.
    /// * Inbound peers are chosen uniformly at random to receive a full announcement, since we
    /// don't track their inventory state.  We send blocks-available messages to them, since they
    /// can turn around and ask us for the block data.
    /// Return the number of inbound and outbound neighbors that have received it
    pub fn advertize_blocks(
        &mut self,
        availability_data: BlocksAvailableMap,
        blocks: HashMap<ConsensusHash, StacksBlock>,
    ) -> Result<(usize, usize), net_error> {
        let (outbound_recipients, inbound_recipients) =
            self.find_block_recipients(&availability_data)?;
        debug!(
            "{:?}: Advertize {} blocks to {} inbound peers, {} outbound peers",
            &self.local_peer,
            availability_data.len(),
            outbound_recipients.len(),
            inbound_recipients.len()
        );

        let num_inbound = inbound_recipients.len();
        let num_outbound = outbound_recipients.len();

        for recipient in outbound_recipients.into_iter() {
            debug!(
                "{:?}: Advertize {} blocks to outbound peer {}",
                &self.local_peer,
                availability_data.len(),
                &recipient
            );
            self.advertize_or_push_blocks_to_outbound_peer(
                &recipient,
                &availability_data,
                &blocks,
            )?;
        }
        for recipient in inbound_recipients.into_iter() {
            debug!(
                "{:?}: Advertize {} blocks to inbound peer {}",
                &self.local_peer,
                availability_data.len(),
                &recipient
            );
            self.advertize_to_inbound_peer(&recipient, &availability_data, |payload| {
                StacksMessageType::BlocksAvailable(payload)
            })?;
        }
        Ok((num_inbound, num_outbound))
    }

    /// Announce confirmed microblocks that we have to a subset of inbound and outbound peers.
    /// * Outbound peers receive announcements for confirmed microblocks that we know they don't have, based on
    /// the inv state we synchronized from them.
    /// * Inbound peers are chosen uniformly at random to receive a full announcement, since we
    /// don't track their inventory state.
    /// Return the number of inbound and outbound neighbors that have received it
    pub fn advertize_microblocks(
        &mut self,
        availability_data: BlocksAvailableMap,
        microblocks: HashMap<ConsensusHash, (StacksBlockId, Vec<StacksMicroblock>)>,
    ) -> Result<(usize, usize), net_error> {
        let (outbound_recipients, inbound_recipients) =
            self.find_block_recipients(&availability_data)?;
        debug!("{:?}: Advertize {} confirmed microblock streams to {} inbound peers, {} outbound peers", &self.local_peer, availability_data.len(), outbound_recipients.len(), inbound_recipients.len());

        let num_inbound = inbound_recipients.len();
        let num_outbound = outbound_recipients.len();

        for recipient in outbound_recipients.into_iter() {
            debug!(
                "{:?}: Advertize {} confirmed microblock streams to outbound peer {}",
                &self.local_peer,
                availability_data.len(),
                &recipient
            );
            self.advertize_or_push_microblocks_to_outbound_peer(
                &recipient,
                &availability_data,
                &microblocks,
            )?;
        }
        for recipient in inbound_recipients.into_iter() {
            debug!(
                "{:?}: Advertize {} confirmed microblock streams to inbound peer {}",
                &self.local_peer,
                availability_data.len(),
                &recipient
            );
            self.advertize_to_inbound_peer(&recipient, &availability_data, |payload| {
                StacksMessageType::MicroblocksAvailable(payload)
            })?;
        }
        Ok((num_inbound, num_outbound))
    }

    /// Update accounting information for relayed messages from a network result.
    /// This influences selecting next-hop neighbors to get data from us.
    pub fn update_relayer_stats(&mut self, network_result: &NetworkResult) {
        // synchronize
        for (_, convo) in self.peers.iter_mut() {
            let stats = convo.get_stats_mut().take_relayers();
            self.relayer_stats.merge_relay_stats(stats);
        }

        for (nk, blocks_data) in network_result.pushed_blocks.iter() {
            for block_msg in blocks_data.iter() {
                for BlocksDatum(_, block) in block_msg.blocks.iter() {
                    self.relayer_stats.add_relayed_message((*nk).clone(), block);
                }
            }
        }

        for (nk, microblocks_data) in network_result.pushed_microblocks.iter() {
            for (_, microblock_msg) in microblocks_data.iter() {
                for mblock in microblock_msg.microblocks.iter() {
                    self.relayer_stats
                        .add_relayed_message((*nk).clone(), mblock);
                }
            }
        }

        for (nk, nakamoto_data) in network_result.pushed_nakamoto_blocks.iter() {
            for (_, nakamoto_msg) in nakamoto_data.iter() {
                for nakamoto_block in nakamoto_msg.blocks.iter() {
                    self.relayer_stats
                        .add_relayed_message((*nk).clone(), nakamoto_block);
                }
            }
        }

        for (nk, txs) in network_result.pushed_transactions.iter() {
            for (_, tx) in txs.iter() {
                self.relayer_stats.add_relayed_message((*nk).clone(), tx);
            }
        }
    }
}
