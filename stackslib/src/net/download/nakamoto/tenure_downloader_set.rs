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

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log};

use crate::burnchains::{Burnchain, BurnchainView, PoxConstants};
use crate::chainstate::burn::db::sortdb::{
    BlockHeaderCache, SortitionDB, SortitionDBConn, SortitionHandleConn,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::coordinator::{PoxAnchorBlockStatus, RewardCycleInfo};
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::stacks::boot::RewardSet;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlockHeader, TenureChangePayload,
};
use crate::core::{
    EMPTY_MICROBLOCK_PARENT_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::chat::ConversationP2P;
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::download::nakamoto::{
    AvailableTenures, NakamotoTenureDownloadState, NakamotoTenureDownloader,
    NakamotoUnconfirmedTenureDownloader, TenureStartEnd, WantedTenure,
};
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::inv::epoch2x::InvState;
use crate::net::inv::nakamoto::{NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::rpc::NeighborRPC;
use crate::net::neighbors::NeighborComms;
use crate::net::p2p::{CurrentRewardSet, PeerNetwork};
use crate::net::server::HttpPeer;
use crate::net::{Error as NetError, Neighbor, NeighborAddress, NeighborKey};
use crate::util_lib::db::{DBConn, Error as DBError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CompletedTenure {
    tenure_id: ConsensusHash,
    start_block: StacksBlockId,
    end_block: StacksBlockId,
}

impl From<&TenureStartEnd> for CompletedTenure {
    fn from(tse: &TenureStartEnd) -> Self {
        Self {
            tenure_id: tse.tenure_id_consensus_hash.clone(),
            start_block: tse.start_block_id.clone(),
            end_block: tse.end_block_id.clone(),
        }
    }
}

impl From<&mut NakamotoTenureDownloader> for CompletedTenure {
    fn from(ntd: &mut NakamotoTenureDownloader) -> Self {
        Self {
            tenure_id: ntd.tenure_id_consensus_hash,
            start_block: ntd.tenure_start_block_id,
            end_block: ntd.tenure_end_block_id,
        }
    }
}

pub const PEER_DEPRIORITIZATION_TIME_SECS: u64 = 60;

/// A set of confirmed downloader state machines assigned to one or more neighbors.  The block
/// downloader runs tenure-downloaders in parallel, since the downloader for the N+1'st tenure
/// needs to feed data into the Nth tenure.  This struct is responsible for scheduling peer
/// connections to downloader state machines, such that each peer is assigned to at most one
/// downloader.  A peer is assigned a downloader for the duration of at most one RPC request, at
/// which point, it will be re-assigned a (possibly different) downloader.  As such, each machine
/// can make progress even if there is only one available peer (in which case, that peer will get
/// scheduled across multiple machines to drive their progress in the right sequence such that
/// tenures will be incrementally fetched and yielded by the p2p state machine to the relayer).
pub struct NakamotoTenureDownloaderSet {
    /// A list of instantiated downloaders that are in progress
    pub(crate) downloaders: Vec<Option<NakamotoTenureDownloader>>,
    /// An assignment of peers to downloader machines in the `downloaders` list.
    pub(crate) peers: HashMap<NeighborAddress, usize>,
    /// The set of tenures that have been successfully downloaded (but possibly not yet stored or
    /// processed)
    pub(crate) completed_tenures: HashSet<CompletedTenure>,
    /// Number of times a tenure download was attempted.  This counter is incremented before the
    /// downloader starts
    pub(crate) attempted_tenures: HashMap<ConsensusHash, u64>,
    /// Number of times a tenure download failed.  This counter is incremented after the downloader
    /// finishes in an error state.
    pub(crate) attempt_failed_tenures: HashMap<ConsensusHash, u64>,
    /// Peers that should be deprioritized because they're dead (maps to when they can be used
    /// again)
    pub(crate) deprioritized_peers: HashMap<NeighborAddress, u64>,
}

impl NakamotoTenureDownloaderSet {
    pub fn new() -> Self {
        Self {
            downloaders: vec![],
            peers: HashMap::new(),
            completed_tenures: HashSet::new(),
            attempted_tenures: HashMap::new(),
            attempt_failed_tenures: HashMap::new(),
            deprioritized_peers: HashMap::new(),
        }
    }

    /// Mark a tenure as having failed to download.
    /// Implemented statically to appease the borrow checker.
    fn mark_failure(attempt_failed_tenures: &mut HashMap<ConsensusHash, u64>, ch: &ConsensusHash) {
        if let Some(failures) = attempt_failed_tenures.get_mut(ch) {
            *failures = (*failures).saturating_add(1);
        } else {
            attempt_failed_tenures.insert(ch.clone(), 1);
        }
    }

    /// Mark a peer as deprioritized
    /// Implemented statically to appease the borrow checker.
    fn mark_deprioritized(
        deprioritized_peers: &mut HashMap<NeighborAddress, u64>,
        peer: &NeighborAddress,
    ) {
        deprioritized_peers.insert(
            peer.clone(),
            get_epoch_time_secs() + PEER_DEPRIORITIZATION_TIME_SECS,
        );
    }

    /// Mark a peer and its tenure as dead and failed
    fn mark_failed_and_deprioritize_peer(
        attempted_failed_tenures: &mut HashMap<ConsensusHash, u64>,
        deprioritized_peers: &mut HashMap<NeighborAddress, u64>,
        ch: &ConsensusHash,
        peer: &NeighborAddress,
    ) {
        Self::mark_failure(attempted_failed_tenures, ch);
        Self::mark_deprioritized(deprioritized_peers, peer);
    }

    /// Assign the given peer to the given downloader state machine.  Allocate a slot for it if
    /// needed.
    fn add_downloader(&mut self, naddr: NeighborAddress, downloader: NakamotoTenureDownloader) {
        debug!(
            "Add downloader for tenure {} driven by {naddr}",
            &downloader.tenure_id_consensus_hash
        );
        if let Some(idx) = self.peers.get(&naddr) {
            self.downloaders[*idx] = Some(downloader);
        } else {
            self.downloaders.push(Some(downloader));
            self.peers.insert(naddr, self.downloaders.len() - 1);
        }
    }

    /// Does the given neighbor have an assigned downloader state machine?
    pub(crate) fn has_downloader(&self, naddr: &NeighborAddress) -> bool {
        let Some(idx) = self.peers.get(naddr) else {
            return false;
        };
        let Some(downloader_opt) = self.downloaders.get(*idx) else {
            return false;
        };
        downloader_opt.is_some()
    }

    /// Drop the downloader associated with the given neighbor, if any.
    pub fn clear_downloader(&mut self, naddr: &NeighborAddress) {
        let Some(index) = self.peers.remove(naddr) else {
            return;
        };
        self.downloaders[index] = None;
    }

    /// How many downloaders are there?
    pub fn num_downloaders(&self) -> usize {
        self.downloaders
            .iter()
            .fold(0, |acc, dl| if dl.is_some() { acc + 1 } else { acc })
    }

    /// How many downloaders are there, which are scheduled?
    pub fn num_scheduled_downloaders(&self) -> usize {
        let mut cnt = 0;
        for (_, idx) in self.peers.iter() {
            if let Some(Some(_)) = self.downloaders.get(*idx) {
                cnt += 1;
            }
        }
        cnt
    }

    /// Add a sequence of (address, downloader) pairs to this downloader set.
    pub(crate) fn add_downloaders(
        &mut self,
        iter: impl IntoIterator<Item = (NeighborAddress, NakamotoTenureDownloader)>,
    ) {
        for (naddr, downloader) in iter {
            if self.has_downloader(&naddr) {
                debug!("Already have downloader for {naddr}");
                continue;
            }
            self.add_downloader(naddr, downloader);
        }
    }

    /// Count up the number of in-flight messages, based on the states of each instantiated
    /// downloader.
    pub fn inflight(&self) -> usize {
        let mut cnt = 0;
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if downloader.idle {
                continue;
            }
            if downloader.is_done() {
                continue;
            }
            cnt += 1;
        }
        cnt
    }

    /// Determine if this downloader set is empty -- i.e. there's no in-progress downloaders.
    pub fn is_empty(&self) -> bool {
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if downloader.is_done() {
                continue;
            }
            debug!("TenureDownloadSet::is_empty(): have downloader for tenure {:?} assigned to {} in state {}", &downloader.tenure_id_consensus_hash, &downloader.naddr, &downloader.state);
            return false;
        }
        true
    }

    /// Try to resume processing a download state machine with a given peer.  Since a peer is
    /// detached from the machine after a single RPC call, this call is needed to re-attach it to a
    /// (potentially different, unblocked) machine for the next RPC call to this peer.
    ///
    /// Returns true if the peer gets scheduled.
    /// Returns false if not.
    pub fn try_resume_peer(&mut self, naddr: NeighborAddress) -> bool {
        debug!("Try resume {}", &naddr);
        if let Some(idx) = self.peers.get(&naddr) {
            let Some(Some(_downloader)) = self.downloaders.get(*idx) else {
                return false;
            };

            debug!(
                "Peer {naddr} already bound to downloader for {}",
                &_downloader.tenure_id_consensus_hash
            );
            return true;
        }
        for (i, downloader_opt) in self.downloaders.iter_mut().enumerate() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if !downloader.idle {
                continue;
            }
            debug!(
                "Assign peer {naddr} to work on downloader for {} in state {}",
                &downloader.tenure_id_consensus_hash, &downloader.state
            );
            downloader.naddr = naddr.clone();
            self.peers.insert(naddr, i);
            return true;
        }
        return false;
    }

    /// Deschedule peers that are bound to downloader slots that are either vacant or correspond to
    /// blocked downloaders.
    pub fn clear_available_peers(&mut self) {
        let mut idled: Vec<NeighborAddress> = vec![];
        for (naddr, i) in self.peers.iter() {
            let Some(downloader_opt) = self.downloaders.get(*i) else {
                // should be unreachable
                idled.push(naddr.clone());
                continue;
            };
            let Some(downloader) = downloader_opt.as_ref() else {
                debug!("Remove peer {naddr} for null download {i}");
                idled.push(naddr.clone());
                continue;
            };
            if downloader.idle {
                debug!(
                    "Remove idled peer {naddr} for tenure download {}",
                    &downloader.tenure_id_consensus_hash
                );
                idled.push(naddr.clone());
            }
        }
        for naddr in idled.into_iter() {
            self.peers.remove(&naddr);
        }
    }

    /// Clear out downloaders (but not their peers) that have finished.  The caller should follow
    /// this up with a call to `clear_available_peers()`.
    pub fn clear_finished_downloaders(&mut self) {
        for downloader_opt in self.downloaders.iter_mut() {
            // clear the downloader if it's done by setting it to None
            if downloader_opt
                .as_ref()
                .map(|dl| dl.is_done())
                .unwrap_or(false)
            {
                *downloader_opt = None;
            }
        }
    }

    /// Find the downloaders that have obtained their tenure-start blocks, and extract them.  These
    /// will be fed into other downloaders which are blocked on needing their tenure-end blocks.
    pub(crate) fn find_new_tenure_start_blocks(&self) -> HashMap<StacksBlockId, NakamotoBlock> {
        let mut ret = HashMap::new();
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            let Some(block) = downloader.tenure_start_block.as_ref() else {
                continue;
            };
            ret.insert(block.block_id(), block.clone());
        }
        ret
    }

    /// Does there exist a downloader (possibly unscheduled) for the given tenure?
    pub(crate) fn has_downloader_for_tenure(&self, tenure_id: &ConsensusHash) -> bool {
        for downloader_opt in self.downloaders.iter() {
            let Some(downloader) = downloader_opt else {
                continue;
            };
            if &downloader.tenure_id_consensus_hash == tenure_id {
                debug!(
                    "Have downloader for tenure {tenure_id} already (idle={}, state={}, naddr={})",
                    downloader.idle, &downloader.state, &downloader.naddr
                );
                return true;
            }
        }
        false
    }

    /// Create a given number of downloads from a schedule and availability set.
    /// Removes items from the schedule, and neighbors from the availability set.
    /// A neighbor will be issued at most one request.
    pub(crate) fn make_tenure_downloaders(
        &mut self,
        schedule: &mut VecDeque<ConsensusHash>,
        available: &mut HashMap<ConsensusHash, Vec<NeighborAddress>>,
        tenure_block_ids: &HashMap<NeighborAddress, AvailableTenures>,
        count: usize,
        current_reward_cycles: &BTreeMap<u64, CurrentRewardSet>,
    ) {
        test_debug!("make_tenure_downloaders";
               "schedule" => ?schedule,
               "available" => ?available,
               "tenure_block_ids" => ?tenure_block_ids,
               "inflight" => %self.inflight(),
               "count" => count,
               "running" => self.num_downloaders(),
               "scheduled" => self.num_scheduled_downloaders());

        self.clear_finished_downloaders();
        self.clear_available_peers();
        while self.num_scheduled_downloaders() < count {
            let Some(ch) = schedule.front() else {
                break;
            };
            let Some(neighbors) = available.get_mut(ch) else {
                // not found on any neighbors, so stop trying this tenure
                debug!("No neighbors have tenure {ch}");
                schedule.pop_front();
                continue;
            };
            if neighbors.is_empty() {
                // no more neighbors to try
                debug!("No more neighbors can serve tenure {ch}");
                schedule.pop_front();
                continue;
            }
            let Some(naddr) = neighbors.pop() else {
                debug!("No more neighbors can serve tenure {ch}");
                schedule.pop_front();
                continue;
            };
            if get_epoch_time_secs() < *self.deprioritized_peers.get(&naddr).unwrap_or(&0) {
                debug!(
                    "Peer {} is deprioritized until {naddr}",
                    self.deprioritized_peers.get(&naddr).unwrap_or(&0)
                );
                continue;
            }

            if self.try_resume_peer(naddr.clone()) {
                continue;
            };
            if self.has_downloader_for_tenure(ch) {
                schedule.pop_front();
                continue;
            }

            let Some(available_tenures) = tenure_block_ids.get(&naddr) else {
                // this peer doesn't have any known tenures, so try the others
                debug!("No tenures available from {naddr}");
                continue;
            };
            let Some(tenure_info) = available_tenures.get(ch) else {
                // this peer does not have a tenure start/end block for this tenure, so try the
                // others.
                debug!("Neighbor {naddr} does not serve tenure {ch}");
                continue;
            };
            if tenure_info.processed {
                // we already have tried to download this tenure,
                // but do remove it from `self.completed_tenures` in order to (1) avoid a memory
                // leak, and (2) account for the chance that the end-block has changed due to a
                // Bitcoin reorg.  This way, a subsequent call with the same tenure in `schedule`
                // will succeed in starting a downloader.  Since `schedule` is derived from on-disk
                // state, the only way a "completed" tenure will show up in `schedule` again is if
                // it is later determined that the tenure we stored is incomplete or not canonical.
                debug!("Already have processed tenure {ch}");
                self.completed_tenures
                    .remove(&CompletedTenure::from(tenure_info));
                continue;
            }
            if self
                .completed_tenures
                .contains(&CompletedTenure::from(tenure_info))
            {
                debug!(
                    "Already successfully downloaded tenure {ch} ({}-{})",
                    &tenure_info.start_block_id, &tenure_info.end_block_id
                );
                schedule.pop_front();
                continue;
            }
            let Some(Some(start_reward_set)) = current_reward_cycles
                .get(&tenure_info.start_reward_cycle)
                .map(|cycle_info| cycle_info.reward_set())
            else {
                debug!(
                    "Cannot fetch tenure-start block due to no known start reward set for cycle {}: {tenure_info:?}",
                    tenure_info.start_reward_cycle,
                );
                schedule.pop_front();
                continue;
            };
            let Some(Some(end_reward_set)) = current_reward_cycles
                .get(&tenure_info.end_reward_cycle)
                .map(|cycle_info| cycle_info.reward_set())
            else {
                debug!(
                    "Cannot fetch tenure-end block due to no known end reward set for cycle {}: {tenure_info:?}",
                    tenure_info.end_reward_cycle,
                );
                schedule.pop_front();
                continue;
            };

            let attempt_count = *self.attempted_tenures.get(ch).unwrap_or(&0);
            self.attempted_tenures
                .insert(ch.clone(), attempt_count.saturating_add(1));

            let attempt_failed_count = *self.attempt_failed_tenures.get(ch).unwrap_or(&0);

            info!("Download tenure {ch}";
                "peer" => %naddr,
                "attempt" => attempt_count.saturating_add(1),
                "failed" => attempt_failed_count,
                "downloads_scheduled" => %self.num_scheduled_downloaders(),
                "downloads_total" => %self.num_downloaders(),
                "downloads_max_count" => count,
                "downloads_inflight" => self.inflight(),
                "tenure_start_block" => %tenure_info.start_block_id,
                "tenure_end_block" => %tenure_info.end_block_id,
                "tenure_start_reward_cycle" => tenure_info.start_reward_cycle,
                "tenure_end_reward_cycle" => tenure_info.end_reward_cycle,
                "tenure_burn_height" => tenure_info.tenure_id_burn_block_height);

            let tenure_download = NakamotoTenureDownloader::new(
                ch.clone(),
                tenure_info.start_block_snapshot_consensus_hash.clone(),
                tenure_info.start_block_id.clone(),
                tenure_info.end_block_snapshot_consensus_hash.clone(),
                tenure_info.end_block_id.clone(),
                naddr.clone(),
                start_reward_set.clone(),
                end_reward_set.clone(),
            );

            debug!("Request tenure {ch} from neighbor {naddr}");
            self.add_downloader(naddr, tenure_download);
            schedule.pop_front();
        }
    }

    /// Run all confirmed downloaders.
    /// * Identify neighbors for which we do not have an inflight request
    /// * Get each such neighbor's downloader, and generate its next HTTP reqeust. Send that
    /// request to the neighbor and begin driving the underlying socket I/O.
    /// * Get each HTTP reply, and pass it into the corresponding downloader's handler to advance
    /// its state.
    /// * Identify and remove misbehaving neighbors and neighbors whose connections have broken.
    ///
    /// Returns the set of downloaded blocks obtained for completed downloaders.  These will be
    /// full confirmed tenures.
    pub fn run(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_rpc: &mut NeighborRPC,
        chainstate: &mut StacksChainState,
    ) -> HashMap<ConsensusHash, Vec<NakamotoBlock>> {
        let addrs: Vec<_> = self.peers.keys().cloned().collect();
        let mut finished = vec![];
        let mut finished_tenures = vec![];
        let mut new_blocks = HashMap::new();

        // send requests
        for (naddr, index) in self.peers.iter() {
            if neighbor_rpc.has_inflight(naddr) {
                debug!("Peer {naddr} has an inflight request");
                continue;
            }
            let Some(Some(downloader)) = self.downloaders.get_mut(*index) else {
                debug!("No downloader for {naddr}");
                continue;
            };
            if downloader.is_done() {
                debug!(
                    "Downloader for {naddr} on tenure {} is finished",
                    &downloader.tenure_id_consensus_hash
                );
                finished.push(naddr.clone());
                finished_tenures.push(CompletedTenure::from(downloader));
                continue;
            }

            let _ = downloader
                .try_advance_from_chainstate(chainstate)
                .inspect_err(|e| {
                    warn!(
                        "Failed to advance downloader in state {} for {}: {e:?}",
                        &downloader.state, &downloader.naddr
                    );
                });

            debug!(
                "Send request to {naddr} for tenure {} (state {})",
                &downloader.tenure_id_consensus_hash, &downloader.state
            );
            let Ok(sent) = downloader.send_next_download_request(network, neighbor_rpc) else {
                info!(
                    "Downloader for tenure {} to {naddr} failed; this peer is dead",
                    &downloader.tenure_id_consensus_hash,
                );
                Self::mark_failed_and_deprioritize_peer(
                    &mut self.attempt_failed_tenures,
                    &mut self.deprioritized_peers,
                    &downloader.tenure_id_consensus_hash,
                    naddr,
                );
                neighbor_rpc.add_dead(network, naddr);
                continue;
            };
            if !sent {
                // this downloader is dead or broken
                finished.push(naddr.clone());
                continue;
            }
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                debug!("Remove dead/broken downloader for {naddr}");
                self.clear_downloader(naddr);
            }
        }
        for done_naddr in finished.drain(..) {
            debug!("Remove finished downloader for {done_naddr}");
            self.clear_downloader(&done_naddr);
        }
        for done_tenure in finished_tenures.drain(..) {
            self.completed_tenures.insert(done_tenure);
        }

        // handle responses
        for (naddr, response) in neighbor_rpc.collect_replies(network) {
            let Some(index) = self.peers.get(&naddr) else {
                debug!("No downloader for {naddr}");
                continue;
            };
            let Some(Some(downloader)) = self.downloaders.get_mut(*index) else {
                debug!("No downloader for {naddr}");
                continue;
            };
            debug!("Got response from {naddr}");

            let Ok(blocks_opt) = downloader
                .handle_next_download_response(response)
                .map_err(|e| {
                    info!(
                        "Failed to handle response from {naddr} on tenure {}: {e}",
                        &downloader.tenure_id_consensus_hash,
                    );
                    e
                })
            else {
                debug!(
                    "Failed to handle download response from {naddr} on tenure {}",
                    &downloader.tenure_id_consensus_hash
                );
                Self::mark_failed_and_deprioritize_peer(
                    &mut self.attempt_failed_tenures,
                    &mut self.deprioritized_peers,
                    &downloader.tenure_id_consensus_hash,
                    &naddr,
                );
                neighbor_rpc.add_dead(network, &naddr);
                continue;
            };

            let Some(blocks) = blocks_opt else {
                continue;
            };

            debug!(
                "Got {} blocks for tenure {}",
                blocks.len(),
                &downloader.tenure_id_consensus_hash
            );
            new_blocks.insert(downloader.tenure_id_consensus_hash.clone(), blocks);
            if downloader.is_done() {
                info!(
                    "Downloader for tenure {} is finished",
                    &downloader.tenure_id_consensus_hash
                );
                debug!(
                    "Downloader for tenure {} finished on {naddr}",
                    &downloader.tenure_id_consensus_hash,
                );
                finished.push(naddr.clone());
                finished_tenures.push(CompletedTenure::from(downloader));
                continue;
            }
        }

        // clear dead, broken, and done
        for naddr in addrs.iter() {
            if neighbor_rpc.is_dead_or_broken(network, naddr) {
                debug!("Remove dead/broken downloader for {naddr}");
                self.clear_downloader(naddr);
            }
        }
        for done_naddr in finished.into_iter() {
            debug!("Remove finished downloader for {done_naddr}");
            self.clear_downloader(&done_naddr);
        }
        for done_tenure in finished_tenures.into_iter() {
            self.completed_tenures.insert(done_tenure);
        }

        new_blocks
    }
}
