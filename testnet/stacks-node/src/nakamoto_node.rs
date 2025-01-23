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
use std::collections::HashSet;
use std::io::Write;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::{fs, thread};

use stacks::burnchains::{BurnchainSigner, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::BlockSnapshot;
use stacks::chainstate::stacks::Error as ChainstateError;
use stacks::libstackerdb::StackerDBChunkAckData;
use stacks::monitoring;
use stacks::monitoring::update_active_miners_count_gauge;
use stacks::net::atlas::AtlasConfig;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::StackerDBs;
use stacks::net::Error as NetError;
use stacks::util_lib::db::Error as DBError;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::StacksEpochId;

use super::{Config, EventDispatcher, Keychain};
use crate::burnchains::bitcoin_regtest_controller::addr2str;
use crate::burnchains::Error as BurnchainsError;
use crate::neon_node::{LeaderKeyRegistrationState, StacksNode as NeonNode};
use crate::run_loop::boot_nakamoto::Neon2NakaData;
use crate::run_loop::nakamoto::{Globals, RunLoop};
use crate::run_loop::RegisteredKey;

pub mod miner;
pub mod peer;
pub mod relayer;
pub mod signer_coordinator;
pub mod stackerdb_listener;

use self::peer::PeerThread;
use self::relayer::{RelayerDirective, RelayerThread};

pub const RELAYER_MAX_BUFFER: usize = 1;
const VRF_MOCK_MINER_KEY: u64 = 1;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

pub type BlockCommits = HashSet<Txid>;

/// Node implementation for both miners and followers.
/// This struct is used to set up the node proper and launch the p2p thread and relayer thread.
/// It is further used by the main thread to communicate with these two threads.
pub struct StacksNode {
    /// Atlas network configuration
    pub atlas_config: AtlasConfig,
    /// Global inter-thread communication handle
    pub globals: Globals,
    /// True if we're a miner
    is_miner: bool,
    /// handle to the p2p thread
    pub p2p_thread_handle: JoinHandle<()>,
    /// handle to the relayer thread
    pub relayer_thread_handle: JoinHandle<()>,
}

/// Types of errors that can arise during Nakamoto StacksNode operation
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Can't find the block sortition snapshot for the chain tip
    #[error("Can't find the block sortition snapshot for the chain tip")]
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    #[error("The burnchain tip changed while this operation was in progress")]
    BurnchainTipChanged,
    /// The Stacks tip changed while this operation was in progress
    #[error("The Stacks tip changed while this operation was in progress")]
    StacksTipChanged,
    /// Signers rejected a block
    #[error("Signers rejected a block")]
    SignersRejected,
    /// Error while spawning a subordinate thread
    #[error("Error while spawning a subordinate thread: {0}")]
    SpawnError(std::io::Error),
    /// Injected testing errors
    #[error("Injected testing errors")]
    FaultInjection,
    /// This miner was elected, but another sortition occurred before mining started
    #[error("This miner was elected, but another sortition occurred before mining started")]
    MissedMiningOpportunity,
    /// Attempted to mine while there was no active VRF key
    #[error("Attempted to mine while there was no active VRF key")]
    NoVRFKeyActive,
    /// The parent block or tenure could not be found
    #[error("The parent block or tenure could not be found")]
    ParentNotFound,
    /// Something unexpected happened (e.g., hash mismatches)
    #[error("Something unexpected happened (e.g., hash mismatches)")]
    UnexpectedChainState,
    /// A burnchain operation failed when submitting it to the burnchain
    #[error("A burnchain operation failed when submitting it to the burnchain: {0}")]
    BurnchainSubmissionFailed(BurnchainsError),
    /// A new parent has been discovered since mining started
    #[error("A new parent has been discovered since mining started")]
    NewParentDiscovered,
    /// A failure occurred while constructing a VRF Proof
    #[error("A failure occurred while constructing a VRF Proof")]
    BadVrfConstruction,
    #[error("A failure occurred while mining: {0}")]
    MiningFailure(#[from] ChainstateError),
    /// The miner didn't accept their own block
    #[error("The miner didn't accept their own block: {0}")]
    AcceptFailure(ChainstateError),
    #[error("A failure occurred while signing a miner's block: {0}")]
    MinerSignatureError(&'static str),
    #[error("A failure occurred while signing a signer's block: {0}")]
    SignerSignatureError(String),
    /// A failure occurred while configuring the miner thread
    #[error("A failure occurred while configuring the miner thread: {0}")]
    MinerConfigurationFailed(&'static str),
    /// An error occurred while operating as the signing coordinator
    #[error("An error occurred while operating as the signing coordinator: {0}")]
    SigningCoordinatorFailure(String),
    /// An error occurred on StackerDB post
    #[error("An error occurred while uploading data to StackerDB: {0}")]
    StackerDBUploadError(StackerDBChunkAckData),
    // The thread that we tried to send to has closed
    #[error("The thread that we tried to send to has closed")]
    ChannelClosed,
    /// DBError wrapper
    #[error("DBError: {0}")]
    DBError(#[from] DBError),
    /// NetError wrapper
    #[error("NetError: {0}")]
    NetError(#[from] NetError),
}

impl StacksNode {
    /// This function sets the global var `GLOBAL_BURNCHAIN_SIGNER`.
    ///
    /// This variable is used for prometheus monitoring (which only
    /// runs when the feature flag `monitoring_prom` is activated).
    /// The address is set using the single-signature BTC address
    /// associated with `keychain`'s public key. This address always
    /// assumes Epoch-2.1 rules for the miner address: if the
    /// node is configured for segwit, then the miner address generated
    /// is a segwit address, otherwise it is a p2pkh.
    ///
    fn set_monitoring_miner_address(keychain: &Keychain, relayer_thread: &RelayerThread) {
        let public_key = keychain.get_pub_key();
        let miner_addr = relayer_thread
            .bitcoin_controller
            .get_miner_address(StacksEpochId::Epoch21, &public_key);
        let miner_addr_str = addr2str(&miner_addr);
        let _ = monitoring::set_burnchain_signer(BurnchainSigner(miner_addr_str)).map_err(|e| {
            warn!("Failed to set global burnchain signer: {e:?}");
            e
        });
    }

    pub fn spawn(
        runloop: &RunLoop,
        globals: Globals,
        // relay receiver endpoint for the p2p thread, so the relayer can feed it data to push
        relay_recv: Receiver<RelayerDirective>,
        data_from_neon: Option<Neon2NakaData>,
    ) -> StacksNode {
        let config = runloop.config().clone();
        let is_miner = runloop.is_miner();
        let burnchain = runloop.get_burnchain();
        let atlas_config = config.atlas.clone();
        let mut keychain = Keychain::default(config.node.seed.clone());
        if let Some(mining_key) = config.miner.mining_key {
            keychain.set_nakamoto_sk(mining_key);
        }

        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sortition db");

        NeonNode::setup_ast_size_precheck(&config, &mut sortdb);

        let _ = config
            .connect_mempool_db()
            .expect("FATAL: database failure opening mempool");

        let data_from_neon = data_from_neon.unwrap_or_default();

        let mut p2p_net = data_from_neon
            .peer_network
            .unwrap_or_else(|| NeonNode::setup_peer_network(&config, &atlas_config, burnchain));

        let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");

        let relayer = Relayer::from_p2p(&mut p2p_net, stackerdbs);

        let local_peer = p2p_net.local_peer.clone();

        // setup initial key registration
        let leader_key_registration_state = if config.get_node_config(false).mock_mining {
            // mock mining, pretend to have a registered key
            let (vrf_public_key, _) = keychain.make_vrf_keypair(VRF_MOCK_MINER_KEY);
            LeaderKeyRegistrationState::Active(RegisteredKey {
                target_block_height: VRF_MOCK_MINER_KEY,
                block_height: 1,
                op_vtxindex: 1,
                vrf_public_key,
                memo: keychain.get_nakamoto_pkh().as_bytes().to_vec(),
            })
        } else {
            match &data_from_neon.leader_key_registration_state {
                LeaderKeyRegistrationState::Active(registered_key) => {
                    let pubkey_hash = keychain.get_nakamoto_pkh();
                    if pubkey_hash.as_ref() == registered_key.memo {
                        data_from_neon.leader_key_registration_state
                    } else {
                        LeaderKeyRegistrationState::Inactive
                    }
                }
                _ => LeaderKeyRegistrationState::Inactive,
            }
        };

        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread =
            RelayerThread::new(runloop, local_peer.clone(), relayer, keychain.clone());

        StacksNode::set_monitoring_miner_address(&keychain, &relayer_thread);

        let relayer_thread_handle = thread::Builder::new()
            .name(format!("relayer-{}", &local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                relayer_thread.main(relay_recv);
            })
            .expect("FATAL: failed to start relayer thread");

        let p2p_event_dispatcher = runloop.get_event_dispatcher();
        let p2p_thread = PeerThread::new(runloop, p2p_net);
        let p2p_thread_handle = thread::Builder::new()
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .name(format!(
                "p2p-({},{})",
                &config.node.p2p_bind, &config.node.rpc_bind
            ))
            .spawn(move || {
                p2p_thread.main(p2p_event_dispatcher);
            })
            .expect("FATAL: failed to start p2p thread");

        info!("Start HTTP server on: {}", &config.node.rpc_bind);
        info!("Start P2P server on: {}", &config.node.p2p_bind);

        StacksNode {
            atlas_config,
            globals,
            is_miner,
            p2p_thread_handle,
            relayer_thread_handle,
        }
    }

    /// Notify the relayer that a new burn block has been processed by the sortition db,
    ///  telling it to process the block and begin mining if this miner won.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    fn relayer_burnchain_notify(&self, snapshot: BlockSnapshot) -> Result<(), Error> {
        if !self.is_miner {
            // node is a follower, don't need to notify the relayer of these events.
            return Ok(());
        }

        info!(
            "Tenure: Notify burn block!";
            "consensus_hash" => %snapshot.consensus_hash,
            "burn_block_hash" => %snapshot.burn_header_hash,
            "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
            "burn_block_height" => &snapshot.block_height,
            "sortition_id" => %snapshot.sortition_id
        );

        // unlike in neon_node, the nakamoto node should *always* notify the relayer of
        //  a new burnchain block

        self.globals
            .relay_send
            .send(RelayerDirective::ProcessedBurnBlock(
                snapshot.consensus_hash,
                snapshot.parent_burn_header_hash,
                snapshot.winning_stacks_block_hash,
            ))
            .map_err(|_| Error::ChannelClosed)?;

        Ok(())
    }

    /// Process a state coming from the burnchain, by extracting the validated KeyRegisterOp
    /// and inspecting if a sortition was won.
    /// `ibd`: boolean indicating whether or not we are in the initial block download
    /// Called from the main thread.
    pub fn process_burnchain_state(
        &mut self,
        config: &Config,
        sortdb: &SortitionDB,
        sort_id: &SortitionId,
        ibd: bool,
    ) -> Result<(), Error> {
        let ic = sortdb.index_conn();

        let block_snapshot = SortitionDB::get_block_snapshot(&ic, sort_id)
            .expect("Failed to obtain block snapshot for processed burn block.")
            .expect("Failed to obtain block snapshot for processed burn block.");
        let block_height = block_snapshot.block_height;

        let block_commits =
            SortitionDB::get_block_commits_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching block commits");

        let num_block_commits = block_commits.len();

        update_active_miners_count_gauge(block_commits.len() as i64);

        for op in block_commits.into_iter() {
            if op.txid == block_snapshot.winning_block_txid {
                info!(
                    "Received burnchain block #{block_height} including block_commit_op (winning) - {} ({})",
                    op.apparent_sender, &op.block_header_hash
                );
            } else if self.is_miner {
                info!(
                    "Received burnchain block #{block_height} including block_commit_op - {} ({})",
                    op.apparent_sender, &op.block_header_hash
                );
            }
        }

        let key_registers =
            SortitionDB::get_leader_keys_by_block(&ic, &block_snapshot.sortition_id)
                .expect("Unexpected SortitionDB error fetching key registers");

        let num_key_registers = key_registers.len();

        let activated_key_opt = self
            .globals
            .try_activate_leader_key_registration(block_height, key_registers);

        // save the registered VRF key
        if let (Some(activated_key), Some(path)) = (
            activated_key_opt,
            config.miner.activated_vrf_key_path.as_ref(),
        ) {
            save_activated_vrf_key(path, &activated_key);
        }

        debug!(
            "Processed burnchain state";
            "burn_height" => block_height,
            "leader_keys_count" => num_key_registers,
            "block_commits_count" => num_block_commits,
            "in_initial_block_download?" => ibd,
        );

        self.globals.set_last_sortition(block_snapshot.clone());

        // notify the relayer thread of the new sortition state
        self.relayer_burnchain_notify(block_snapshot)
    }

    /// Join all inner threads
    pub fn join(self) {
        self.relayer_thread_handle.join().unwrap();
        self.p2p_thread_handle.join().unwrap();
    }
}

pub(crate) fn save_activated_vrf_key(path: &str, activated_key: &RegisteredKey) {
    info!("Activated VRF key; saving to {path}");

    let Ok(key_json) = serde_json::to_string(&activated_key) else {
        warn!("Failed to serialize VRF key");
        return;
    };

    let mut f = match fs::File::create(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Failed to create {path}: {e:?}");
            return;
        }
    };

    if let Err(e) = f.write_all(key_json.as_bytes()) {
        warn!("Failed to write activated VRF key to {path}: {e:?}");
        return;
    }

    info!("Saved activated VRF key to {path}");
}
