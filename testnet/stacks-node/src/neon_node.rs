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

/// Main body of code for the Stacks node and miner.
///
/// System schematic.
/// Legend:
///    |------|    Thread
///    /------\    Shared memory
///    @------@    Database
///    .------.    Code module
///
///
///                           |------------------|
///                           |  RunLoop thread  |   [1,7]
///                           |   .----------.   |--------------------------------------.
///                           |   .StacksNode.   |                                      |
///                           |---.----------.---|                                      |
///                    [1,12]     |     |    |     [1]                                  |
///              .----------------*     |    *---------------.                          |
///              |                  [3] |                    |                          |
///              V                      |                    V                          V
///      |----------------|             |    [9,10]   |---------------| [11] |--------------------------|
/// .--- | Relayer thread | <-----------|-----------> |   P2P Thread  | <--- | ChainsCoordinator thread | <--.
/// |    |----------------|             V             |---------------|      |--------------------------|    |
/// |            |     |          /-------------\    [2,3]    |    |              |          |               |
/// |        [1] |     *--------> /   Globals   \ <-----------*----|--------------*          | [4]           |
/// |            |     [2,3,7]    /-------------\                  |                         |               |
/// |            V                                                 V [5]                     V               |
/// |    |----------------|                                 @--------------@        @------------------@     |
/// |    |  Miner thread  | <------------------------------ @  Mempool DB  @        @  Chainstate DBs  @     |
/// |    |----------------|             [6]                 @--------------@        @------------------@     |
/// |                                                                                        ^               |
/// |                                               [8]                                      |               |
/// *----------------------------------------------------------------------------------------*               |
/// |                                               [7]                                                      |
/// *--------------------------------------------------------------------------------------------------------*
///
/// [1]  Spawns
/// [2]  Synchronize unconfirmed state
/// [3]  Enable/disable miner
/// [4]  Processes block data
/// [5]  Stores unconfirmed transactions
/// [6]  Reads unconfirmed transactions
/// [7]  Signals block arrival
/// [8]  Store blocks and microblocks
/// [9]  Pushes retrieved blocks and microblocks
/// [10] Broadcasts new blocks, microblocks, and transactions
/// [11] Notifies about new transaction attachment events
/// [12] Signals VRF key registration
///
/// When the node is running, there are 4-5 active threads at once. They are:
///
/// * **RunLoop Thread**:
///     This is the main thread, whose code body lives in `src/run_loop/neon.rs`.
///     This thread is responsible for:
///       * Bootup
///       * Running the burnchain indexer
///       * Notifying the ChainsCoordinator thread when there are new burnchain blocks to process
///
/// * **Relayer Thread**:
///     This is the thread that stores and relays blocks and microblocks. Both
///     it and the ChainsCoordinator thread are very I/O-heavy threads, and care has been taken to
///     ensure that neither one attempts to acquire a write-lock in the underlying databases.
///     Specifically, this thread directs the ChainsCoordinator thread when to process new Stacks
///     blocks, and it directs the miner thread (if running) to stop when either it or the
///     ChainsCoordinator thread needs to acquire the write-lock.
///     This thread is responsible for:
///       * Receiving new blocks and microblocks from the P2P thread via a shared channel
///       * (Synchronously) requesting the CoordinatorThread to process newly-stored Stacks blocks
///         and microblocks
///       * Building up the node's unconfirmed microblock stream state, and sharing it with the P2P
///         thread so it can answer queries about the unconfirmed microblock chain
///       * Pushing newly-discovered blocks and microblocks to the P2P thread for broadcast
///       * Registering the VRF public key for the miner
///       * Spawning the block and microblock miner threads, and stopping them if their continued
///         execution would inhibit block or microblock storage or processing.
///       * Submitting the burnchain operation to commit to a freshly-mined block
///
/// * **Miner Thread**:
///     This is the thread that actually produces new blocks and microblocks. It
///     is spawned only by the Relayer thread to carry out mining activity when the underlying
///     chainstate is not needed by either the Relayer or ChainsCoordinator threads.
///     This thread does the following:
///       * Walk the mempool DB to build a new block or microblock
///       * Return the block or microblock to the Relayer thread
///
/// * **P2P Thread**:
///     This is the thread that communicates with the rest of the P2P network, and
///     handles RPC requests. It is meant to do as little storage-write I/O as possible to avoid lock
///     contention with the Miner, Relayer, and ChainsCoordinator threads. In particular, it forwards
///     data it receives from the P2P thread to the Relayer thread for I/O-bound processing. At the
///     time of this writing, it still requires holding a write-lock to handle some RPC requests, but
///     future work will remove this so that this thread's execution will not interfere with the
///     others. This is the only thread that does socket I/O.
///     This thread runs the PeerNetwork state machines, which include the following:
///       * Learning the node's public IP address
///       * Discovering neighbor nodes
///       * Forwarding newly-discovered blocks, microblocks, and transactions from the Relayer thread
///         to other neighbors
///       * Synchronizing block and microblock inventory state with other neighbors
///       * Downloading blocks and microblocks, and passing them to the Relayer for storage and
///         processing
///       * Downloading transaction attachments as their hashes are discovered during block processing
///       * Synchronizing the local mempool database with other neighbors
///         (notifications for new attachments come from a shared channel in the ChainsCoordinator thread)
///       * Handling HTTP requests
///
/// * **ChainsCoordinator Thread**:
///     This thread processes sortitions and Stacks blocks and
///     microblocks, and handles PoX reorgs should they occur (this mainly happens in boot-up). It,
///     like the Relayer thread, is a very I/O-heavy thread, and it will hold a write-lock on the
///     chainstate DBs while it works. Its actions are controlled by a CoordinatorComms structure in
///     the Globals shared state, which the Relayer thread and RunLoop thread both drive (the former
///     drives Stacks blocks processing, the latter sortitions).
///     This thread is responsible for:
///       * Responding to requests from other threads to process sortitions
///       * Responding to requests from other threads to process Stacks blocks and microblocks
///       * Processing PoX chain reorgs, should they ever happen
///       * Detecting attachment creation events, and informing the P2P thread of them so it can go
///         and download them
///
/// In addition to the mempool and chainstate databases, these threads share access to a Globals
/// singleton that contains soft state shared between threads. Mainly, the Globals struct is meant
/// to store inter-thread shared singleton communication media all in one convenient struct. Each
/// thread has a handle to the struct's shared state handles. Global state includes:
///       * The global flag as to whether or not the miner thread can be running
///       * The global shutdown flag that, when set, causes all threads to terminate
///       * Sender channel endpoints that can be shared between threads
///       * Metrics about the node's behavior (e.g. number of blocks processed, etc.)
///
/// This file may be refactored in the future into a full-fledged module.
use std::cmp;
use std::cmp::Ordering as CmpOrdering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{fs, mem, thread};

use clarity::boot_util::boot_code_id;
use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use libsigner::v0::messages::{
    MessageSlotID, MinerSlotID, MockBlock, MockProposal, MockSignature, PeerInfo, SignerMessage,
};
use libsigner::{SignerSession, StackerDBSession};
use stacks::burnchains::bitcoin::address::{BitcoinAddress, LegacyBitcoinAddressType};
use stacks::burnchains::db::BurnchainHeaderReader;
use stacks::burnchains::{Burnchain, BurnchainSigner, PoxConstants, Txid};
use stacks::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use stacks::chainstate::burn::operations::leader_block_commit::{
    RewardSetInfo, BURN_BLOCK_MINED_AT_MODULUS,
};
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use stacks::chainstate::burn::{BlockSnapshot, ConsensusHash};
use stacks::chainstate::coordinator::{get_next_recipients, OnChainRewardSetProvider};
use stacks::chainstate::nakamoto::NakamotoChainState;
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::db::blocks::StagingBlock;
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY};
use stacks::chainstate::stacks::miner::{
    signal_mining_blocked, signal_mining_ready, AssembledAnchorBlock, BlockBuilderSettings,
    StacksMicroblockBuilder,
};
use stacks::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksBlock, StacksBlockBuilder, StacksBlockHeader,
    StacksMicroblock, StacksPublicKey, StacksTransaction, StacksTransactionSigner,
    TransactionAnchorMode, TransactionPayload, TransactionVersion,
};
use stacks::config::chain_data::MinerStats;
use stacks::config::NodeConfig;
use stacks::core::mempool::MemPoolDB;
use stacks::core::{EpochList, FIRST_BURNCHAIN_CONSENSUS_HASH, STACKS_EPOCH_3_0_MARKER};
use stacks::cost_estimates::metrics::{CostMetric, UnitMetric};
use stacks::cost_estimates::{CostEstimator, FeeEstimator, UnitEstimator};
use stacks::monitoring::{increment_stx_blocks_mined_counter, update_active_miners_count_gauge};
use stacks::net::atlas::{AtlasConfig, AtlasDB};
use stacks::net::db::{LocalPeer, PeerDB};
use stacks::net::dns::{DNSClient, DNSResolver};
use stacks::net::p2p::PeerNetwork;
use stacks::net::relay::Relayer;
use stacks::net::stackerdb::{StackerDBConfig, StackerDBSync, StackerDBs, MINER_SLOT_COUNT};
use stacks::net::{
    Error as NetError, NetworkResult, PeerNetworkComms, RPCHandlerArgs, ServiceFlags,
};
use stacks::util_lib::strings::{UrlString, VecDisplay};
use stacks::{monitoring, version_string};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksAddress, StacksBlockId,
    StacksPrivateKey, VRFSeed,
};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::{PublicKey, StacksEpochId};
use stacks_common::util::hash::{to_hex, Hash160, Sha256Sum};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use super::{BurnchainController, Config, EventDispatcher, Keychain};
use crate::burnchains::bitcoin_regtest_controller::{
    addr2str, burnchain_params_from_config, BitcoinRegtestController, OngoingBlockCommit,
};
use crate::burnchains::{make_bitcoin_indexer, Error as BurnchainControllerError};
use crate::globals::{NeonGlobals as Globals, RelayerDirective};
use crate::nakamoto_node::signer_coordinator::SignerCoordinator;
use crate::run_loop::neon::RunLoop;
use crate::run_loop::RegisteredKey;
use crate::ChainTip;

pub const RELAYER_MAX_BUFFER: usize = 100;
const VRF_MOCK_MINER_KEY: u64 = 1;

pub const BLOCK_PROCESSOR_STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

type MinedBlocks = HashMap<BlockHeaderHash, (AssembledAnchorBlock, Secp256k1PrivateKey)>;

/// Result of running the miner thread.  It could produce a Stacks block or a microblock.
#[allow(clippy::large_enum_variant)]
pub(crate) enum MinerThreadResult {
    Block(
        AssembledAnchorBlock,
        Secp256k1PrivateKey,
        Option<OngoingBlockCommit>,
    ),
    Microblock(
        Result<Option<(StacksMicroblock, ExecutionCost)>, NetError>,
        MinerTip,
    ),
}

/// Miner chain tip, on top of which to build microblocks
#[derive(Debug, Clone, PartialEq)]
pub struct MinerTip {
    /// tip's consensus hash
    consensus_hash: ConsensusHash,
    /// tip's Stacks block header hash
    block_hash: BlockHeaderHash,
    /// Microblock private key to use to sign microblocks
    microblock_privkey: Secp256k1PrivateKey,
    /// Stacks height
    stacks_height: u64,
    /// burnchain height
    burn_height: u64,
}

impl MinerTip {
    pub fn new(
        ch: ConsensusHash,
        bh: BlockHeaderHash,
        pk: Secp256k1PrivateKey,
        stacks_height: u64,
        burn_height: u64,
    ) -> MinerTip {
        MinerTip {
            consensus_hash: ch,
            block_hash: bh,
            microblock_privkey: pk,
            stacks_height,
            burn_height,
        }
    }
}

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
    pub p2p_thread_handle: JoinHandle<Option<PeerNetwork>>,
    /// handle to the relayer thread
    pub relayer_thread_handle: JoinHandle<()>,
}

/// Fault injection logic to artificially increase the length of a tenure.
/// Only used in testing
#[cfg(test)]
pub(crate) fn fault_injection_long_tenure() {
    // simulated slow block
    let Ok(tenure_str) = std::env::var("STX_TEST_SLOW_TENURE") else {
        return;
    };
    let Ok(tenure_time) = tenure_str.parse::<u64>() else {
        error!("Parse error for STX_TEST_SLOW_TENURE");
        panic!();
    };
    info!("Fault injection: sleeping for {tenure_time} milliseconds to simulate a long tenure");
    stacks_common::util::sleep_ms(tenure_time);
}

#[cfg(not(test))]
pub(crate) fn fault_injection_long_tenure() {}

/// Fault injection to skip mining in this bitcoin block height
/// Only used in testing
#[cfg(test)]
pub(crate) fn fault_injection_skip_mining(rpc_bind: &str, target_burn_height: u64) -> bool {
    let Ok(disable_heights) = std::env::var("STACKS_DISABLE_MINER") else {
        return false;
    };
    let disable_schedule: serde_json::Value = serde_json::from_str(&disable_heights).unwrap();
    let disable_schedule = disable_schedule.as_array().unwrap();
    for disabled in disable_schedule {
        let target_miner_rpc_bind = disabled.get("rpc_bind").unwrap().as_str().unwrap();
        if target_miner_rpc_bind != rpc_bind {
            continue;
        }
        let target_block_heights = disabled.get("blocks").unwrap().as_array().unwrap();
        for target_block_value in target_block_heights {
            let target_block = u64::try_from(target_block_value.as_i64().unwrap()).unwrap();
            if target_block == target_burn_height {
                return true;
            }
        }
    }
    false
}

#[cfg(not(test))]
pub(crate) fn fault_injection_skip_mining(_rpc_bind: &str, _target_burn_height: u64) -> bool {
    false
}

/// Open the chainstate, and inject faults from the config file
pub(crate) fn open_chainstate_with_faults(
    config: &Config,
) -> Result<StacksChainState, ChainstateError> {
    let stacks_chainstate_path = config.get_chainstate_path_str();
    let (mut chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &stacks_chainstate_path,
        Some(config.node.get_marf_opts()),
    )?;

    chainstate.fault_injection.hide_blocks = config.node.fault_injection_hide_blocks;
    Ok(chainstate)
}

/// Types of errors that can arise during mining
enum Error {
    /// Can't find the header record for the chain tip
    HeaderNotFoundForChainTip,
    /// Can't find the stacks block's offset in the burnchain block
    WinningVtxNotFoundForChainTip,
    /// Can't find the block sortition snapshot for the chain tip
    SnapshotNotFoundForChainTip,
    /// The burnchain tip changed while this operation was in progress
    BurnchainTipChanged,
    /// The coordinator channel closed
    CoordinatorClosed,
}

/// Metadata required for beginning a new tenure
struct ParentStacksBlockInfo {
    /// Header metadata for the Stacks block we're going to build on top of
    stacks_parent_header: StacksHeaderInfo,
    /// the consensus hash of the sortition that selected the Stacks block parent
    parent_consensus_hash: ConsensusHash,
    /// the burn block height of the sortition that selected the Stacks block parent
    parent_block_burn_height: u64,
    /// the total amount burned in the sortition that selected the Stacks block parent
    parent_block_total_burn: u64,
    /// offset in the burnchain block where the parent's block-commit was
    parent_winning_vtxindex: u16,
    /// nonce to use for this new block's coinbase transaction
    coinbase_nonce: u64,
}

#[derive(Clone, Default)]
pub enum LeaderKeyRegistrationState {
    /// Not started yet
    #[default]
    Inactive,
    /// Waiting for burnchain confirmation
    /// `u64` is the target block height in which we intend this key to land
    /// `txid` is the burnchain transaction ID
    Pending(u64, Txid),
    /// Ready to go!
    Active(RegisteredKey),
}

impl LeaderKeyRegistrationState {
    pub fn get_active(&self) -> Option<RegisteredKey> {
        if let Self::Active(registered_key) = self {
            Some(registered_key.clone())
        } else {
            None
        }
    }
}

/// Relayer thread
/// * accepts network results and stores blocks and microblocks
/// * forwards new blocks, microblocks, and transactions to the p2p thread
/// * processes burnchain state
/// * if mining, runs the miner and broadcasts blocks (via a subordinate MinerThread)
pub struct RelayerThread {
    /// Node config
    config: Config,
    /// Handle to the sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// Handle to the chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// Handle to the mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// Handle to global state and inter-thread communication channels
    globals: Globals,
    /// Authoritative copy of the keychain state
    keychain: Keychain,
    /// Burnchian configuration
    burnchain: Burnchain,
    /// height of last VRF key registration request
    last_vrf_key_burn_height: u64,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    last_mined_blocks: MinedBlocks,
    /// client to the burnchain (used only for sending block-commits)
    bitcoin_controller: BitcoinRegtestController,
    /// client to the event dispatcher
    event_dispatcher: EventDispatcher,
    /// copy of the local peer state
    local_peer: LocalPeer,
    /// last time we tried to mine a block (in millis)
    last_tenure_issue_time: u128,
    /// last observed burnchain block height from the p2p thread (obtained from network results)
    last_network_block_height: u64,
    /// time at which we observed a change in the network block height (epoch time in millis)
    last_network_block_height_ts: u128,
    /// last observed number of downloader state-machine passes from the p2p thread (obtained from
    /// network results)
    last_network_download_passes: u64,
    /// last observed number of inventory state-machine passes from the p2p thread (obtained from
    /// network results)
    last_network_inv_passes: u64,
    /// minimum number of downloader state-machine passes that must take place before mining (this
    /// is used to ensure that the p2p thread attempts to download new Stacks block data before
    /// this thread tries to mine a block)
    min_network_download_passes: u64,
    /// minimum number of inventory state-machine passes that must take place before mining (this
    /// is used to ensure that the p2p thread attempts to download new Stacks block data before
    /// this thread tries to mine a block)
    min_network_inv_passes: u64,
    /// consensus hash of the last sortition we saw, even if we weren't the winner
    last_tenure_consensus_hash: Option<ConsensusHash>,
    /// tip of last tenure we won (used for mining microblocks)
    miner_tip: Option<MinerTip>,
    /// last time we mined a microblock, in millis
    last_microblock_tenure_time: u128,
    /// when should we run the next microblock tenure, in millis
    microblock_deadline: u128,
    /// cost of the last-produced microblock stream
    microblock_stream_cost: ExecutionCost,

    /// Inner relayer instance for forwarding broadcasted data back to the p2p thread for dispatch
    /// to neighbors
    relayer: Relayer,

    /// handle to the subordinate miner thread
    miner_thread: Option<JoinHandle<Option<MinerThreadResult>>>,
    /// if true, then the last time the miner thread was launched, it was used to mine a Stacks
    /// block (used to alternate between mining microblocks and Stacks blocks that confirm them)
    mined_stacks_block: bool,
}

pub(crate) struct BlockMinerThread {
    /// node config struct
    config: Config,
    /// handle to global state
    globals: Globals,
    /// copy of the node's keychain
    keychain: Keychain,
    /// burnchain configuration
    burnchain: Burnchain,
    /// Set of blocks that we have mined, but are still potentially-broadcastable
    /// (copied from RelayerThread since we need the info to determine the strategy for mining the
    /// next block during this tenure).
    last_mined_blocks: MinedBlocks,
    /// Copy of the node's last ongoing block commit from the last time this thread was run
    ongoing_commit: Option<OngoingBlockCommit>,
    /// Copy of the node's registered VRF key
    registered_key: RegisteredKey,
    /// Burnchain block snapshot at the time this thread was initialized
    burn_block: BlockSnapshot,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
    /// Failed to submit last attempted block
    failed_to_submit_last_attempt: bool,
}

/// State representing the microblock miner.
struct MicroblockMinerThread {
    /// handle to global state
    globals: Globals,
    /// handle to chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// handle to sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// handle to mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// Handle to the node's event dispatcher
    event_dispatcher: EventDispatcher,
    /// Parent Stacks block's sortition's consensus hash
    parent_consensus_hash: ConsensusHash,
    /// Parent Stacks block's hash
    parent_block_hash: BlockHeaderHash,
    /// Microblock signing key
    miner_key: Secp256k1PrivateKey,
    /// How often to make microblocks, in milliseconds
    frequency: u64,
    /// Epoch timestamp, in milliseconds, when the last microblock was produced
    last_mined: u128,
    /// How many microblocks produced so far
    quantity: u64,
    /// Block budget consumed so far by this tenure (initialized to the cost of the Stacks block
    /// itself; microblocks fill up the remaining budget)
    cost_so_far: ExecutionCost,
    /// Block builder settings for the microblock miner.
    settings: BlockBuilderSettings,
}

impl MicroblockMinerThread {
    /// Instantiate the miner thread state from the relayer thread.
    /// May fail if:
    /// * we didn't win the last sortition
    /// * we couldn't open or read the DBs for some reason
    /// * we couldn't find the anchored block (i.e. it's not processed yet)
    pub fn from_relayer_thread(relayer_thread: &RelayerThread) -> Option<MicroblockMinerThread> {
        let globals = relayer_thread.globals.clone();
        let config = relayer_thread.config.clone();
        let burnchain = relayer_thread.burnchain.clone();
        let miner_tip = match relayer_thread.miner_tip.clone() {
            Some(tip) => tip,
            None => {
                debug!("Relayer: cannot instantiate microblock miner: did not win Stacks tip sortition");
                return None;
            }
        };

        let stacks_chainstate_path = config.get_chainstate_path_str();
        let burn_db_path = config.get_burn_db_file_path();
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let sortdb = SortitionDB::open(&burn_db_path, true, burnchain.pox_constants)
            .map_err(|e| {
                error!("Relayer: Could not open sortdb '{burn_db_path}' ({e:?}); skipping tenure");
                e
            })
            .ok()?;

        let mut chainstate = open_chainstate_with_faults(&config)
            .map_err(|e| {
                error!(
                    "Relayer: Could not open chainstate '{stacks_chainstate_path}' ({e:?}); skipping microblock tenure"
                );
                e
            })
            .ok()?;

        let mempool = MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let MinerTip {
            consensus_hash: ch,
            block_hash: bhh,
            microblock_privkey: miner_key,
            ..
        } = miner_tip;

        debug!("Relayer: Instantiate microblock mining state off of {ch}/{bhh}");

        // we won a block! proceed to build a microblock tail if we've stored it
        match StacksChainState::get_anchored_block_header_info(chainstate.db(), &ch, &bhh) {
            Ok(Some(_)) => {
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&ch, &bhh);
                let cost_so_far = if relayer_thread.microblock_stream_cost == ExecutionCost::ZERO {
                    // unknown cost, or this is idempotent.
                    StacksChainState::get_stacks_block_anchored_cost(
                        chainstate.db(),
                        &parent_index_hash,
                    )
                    .expect("FATAL: failed to get anchored block cost")
                    .expect("FATAL: no anchored block cost stored for processed anchored block")
                } else {
                    relayer_thread.microblock_stream_cost.clone()
                };

                let frequency = config.node.microblock_frequency;
                let settings =
                    config.make_block_builder_settings(0, true, globals.get_miner_status());

                // port over unconfirmed state to this thread
                chainstate.unconfirmed_state = if let Some(unconfirmed_state) =
                    relayer_thread.chainstate_ref().unconfirmed_state.as_ref()
                {
                    Some(unconfirmed_state.make_readonly_owned().ok()?)
                } else {
                    None
                };

                Some(MicroblockMinerThread {
                    globals,
                    chainstate: Some(chainstate),
                    sortdb: Some(sortdb),
                    mempool: Some(mempool),
                    event_dispatcher: relayer_thread.event_dispatcher.clone(),
                    parent_consensus_hash: ch,
                    parent_block_hash: bhh,
                    miner_key,
                    frequency,
                    last_mined: 0,
                    quantity: 0,
                    cost_so_far,
                    settings,
                })
            }
            Ok(None) => {
                warn!("Relayer: No such anchored block: {ch}/{bhh}.  Cannot mine microblocks");
                None
            }
            Err(e) => {
                warn!("Relayer: Failed to get anchored block cost for {ch}/{bhh}: {e:?}");
                None
            }
        }
    }

    /// Do something with the inner chainstate DBs (borrowed mutably).
    /// Used to fool the borrow-checker.
    /// NOT COMPOSIBLE - WILL PANIC IF CALLED FROM WITHIN ITSELF.
    fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut Self, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self.sortdb.take().expect("FATAL: already took sortdb");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: already took chainstate");
        let mut mempool = self.mempool.take().expect("FATAL: already took mempool");

        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);

        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);

        res
    }

    /// Unconditionally mine one microblock.
    /// Can fail if the miner thread gets cancelled (most likely cause), or if there's some kind of
    /// DB error.
    fn inner_mine_one_microblock(
        &mut self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mempool: &mut MemPoolDB,
    ) -> Result<StacksMicroblock, ChainstateError> {
        debug!(
            "Try to mine one microblock off of {}/{} (total: {})",
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            chainstate
                .unconfirmed_state
                .as_ref()
                .map(|us| us.num_microblocks())
                .unwrap_or(0)
        );

        let block_snapshot =
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &self.parent_consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {e}");
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?;
        let burn_height = block_snapshot.block_height;

        let ast_rules = SortitionDB::get_ast_rules(sortdb.conn(), burn_height).map_err(|e| {
            error!("Failed to get AST rules for microblock: {e}");
            e
        })?;

        let epoch_id = SortitionDB::get_stacks_epoch(sortdb.conn(), burn_height)
            .map_err(|e| {
                error!("Failed to get epoch for microblock: {e}");
                e
            })?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        let mint_result = {
            let ic = sortdb.index_handle_at_block(
                chainstate,
                &block_snapshot.get_canonical_stacks_block_id(),
            )?;
            let mut microblock_miner = match StacksMicroblockBuilder::resume_unconfirmed(
                chainstate,
                &ic,
                &self.cost_so_far,
                self.settings.clone(),
            ) {
                Ok(x) => x,
                Err(e) => {
                    let msg = format!(
                        "Failed to create a microblock miner at chaintip {}/{}: {e:?}",
                        &self.parent_consensus_hash, &self.parent_block_hash
                    );
                    error!("{msg}");
                    return Err(e);
                }
            };

            let t1 = get_epoch_time_ms();

            let mblock = microblock_miner.mine_next_microblock(
                mempool,
                &self.miner_key,
                &self.event_dispatcher,
            )?;
            let new_cost_so_far = microblock_miner.get_cost_so_far().expect("BUG: cannot read cost so far from miner -- indicates that the underlying Clarity Tx is somehow in use still.");
            let t2 = get_epoch_time_ms();

            info!(
                "Mined microblock {} ({}) with {} transactions in {}ms",
                mblock.block_hash(),
                mblock.header.sequence,
                mblock.txs.len(),
                t2.saturating_sub(t1)
            );

            Ok((mblock, new_cost_so_far))
        };

        let (mined_microblock, new_cost) = match mint_result {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to mine microblock: {e}");
                return Err(e);
            }
        };

        // failsafe
        if !Relayer::static_check_problematic_relayed_microblock(
            chainstate.mainnet,
            epoch_id,
            &mined_microblock,
            ASTRules::PrecheckSize,
        ) {
            // nope!
            warn!(
                "Our mined microblock {} was problematic",
                &mined_microblock.block_hash()
            );

            #[cfg(test)]
            {
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this microblock somewhere
                    if fs::metadata(&path).is_err() {
                        fs::create_dir_all(&path)
                            .unwrap_or_else(|_| panic!("FATAL: could not create '{path}'"));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &mined_microblock.block_hash())));
                    let mut file = fs::File::create(&path)
                        .unwrap_or_else(|_| panic!("FATAL: could not create '{path:?}'"));

                    let mblock_bits = mined_microblock.serialize_to_vec();
                    let mblock_bits_hex = to_hex(&mblock_bits);

                    let mblock_json = format!(
                        r#"{{"microblock":"{mblock_bits_hex}","parent_consensus":"{}","parent_block":"{}"}}"#,
                        &self.parent_consensus_hash, &self.parent_block_hash
                    );
                    file.write_all(mblock_json.as_bytes()).unwrap_or_else(|_| {
                        panic!("FATAL: failed to write microblock bits to '{path:?}'")
                    });
                    info!(
                        "Fault injection: bad microblock {} saved to {}",
                        &mined_microblock.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            if !Relayer::process_mined_problematic_blocks(ast_rules, ASTRules::PrecheckSize) {
                // don't process it
                warn!(
                    "Will NOT process our problematic mined microblock {}",
                    &mined_microblock.block_hash()
                );
                return Err(ChainstateError::NoTransactionsToMine);
            } else {
                warn!(
                    "Will process our problematic mined microblock {}",
                    &mined_microblock.block_hash()
                )
            }
        }

        // cancelled?
        let is_miner_blocked = self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked();
        if is_miner_blocked {
            return Err(ChainstateError::MinerAborted);
        }

        // preprocess the microblock locally
        chainstate.preprocess_streamed_microblock(
            &self.parent_consensus_hash,
            &self.parent_block_hash,
            &mined_microblock,
        )?;

        // update unconfirmed state cost
        self.cost_so_far = new_cost;
        self.quantity += 1;
        Ok(mined_microblock)
    }

    /// Can this microblock miner mine off of this given tip?
    pub fn can_mine_on_tip(
        &self,
        consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
    ) -> bool {
        self.parent_consensus_hash == *consensus_hash && self.parent_block_hash == *block_hash
    }

    /// Body of try_mine_microblock()
    fn inner_try_mine_microblock(
        &mut self,
        miner_tip: MinerTip,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        mem_pool: &mut MemPoolDB,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        if !self.can_mine_on_tip(&self.parent_consensus_hash, &self.parent_block_hash) {
            // not configured to mine on this tip
            return Ok(None);
        }
        if !self.can_mine_on_tip(&miner_tip.consensus_hash, &miner_tip.block_hash) {
            // this tip isn't what this miner is meant to mine on
            return Ok(None);
        }

        if self.last_mined + (self.frequency as u128) >= get_epoch_time_ms() {
            // too soon to mine
            return Ok(None);
        }

        let mut next_microblock_and_runtime = None;

        // opportunistically try and mine, but only if there are no attachable blocks in
        // recent history (i.e. in the last 10 minutes)
        let num_attachable = StacksChainState::count_attachable_staging_blocks(
            chainstate.db(),
            1,
            get_epoch_time_secs() - 600,
        )?;
        if num_attachable == 0 {
            match self.inner_mine_one_microblock(sortdb, chainstate, mem_pool) {
                Ok(microblock) => {
                    // will need to relay this
                    next_microblock_and_runtime = Some((microblock, self.cost_so_far.clone()));
                }
                Err(ChainstateError::NoTransactionsToMine) => {
                    info!("Will keep polling mempool for transactions to include in a microblock");
                }
                Err(e) => {
                    warn!("Failed to mine one microblock: {e:?}");
                }
            }
        } else {
            debug!("Will not mine microblocks yet -- have {num_attachable} attachable blocks that arrived in the last 10 minutes");
        }

        self.last_mined = get_epoch_time_ms();

        Ok(next_microblock_and_runtime)
    }

    /// Try to mine one microblock, given the current chain tip and access to the chain state DBs.
    /// If we succeed, return the microblock and log the tx events to the given event dispatcher.
    /// May return None if any of the following are true:
    /// * `miner_tip` does not match this miner's miner tip
    /// * it's been too soon (less than microblock_frequency milliseconds) since we tried this call
    /// * there are simply no transactions to mine
    /// * there are still stacks blocks to be processed in the staging db
    /// * the miner thread got cancelled
    pub fn try_mine_microblock(
        &mut self,
        cur_tip: MinerTip,
    ) -> Result<Option<(StacksMicroblock, ExecutionCost)>, NetError> {
        debug!("microblock miner thread ID is {:?}", thread::current().id());
        self.with_chainstate(|mblock_miner, sortdb, chainstate, mempool| {
            mblock_miner.inner_try_mine_microblock(cur_tip, sortdb, chainstate, mempool)
        })
    }
}

/// Candidate chain tip
#[derive(Debug, Clone, PartialEq)]
pub struct TipCandidate {
    pub stacks_height: u64,
    pub consensus_hash: ConsensusHash,
    pub anchored_block_hash: BlockHeaderHash,
    pub parent_consensus_hash: ConsensusHash,
    pub parent_anchored_block_hash: BlockHeaderHash,
    /// the block's sortition's burnchain height
    pub burn_height: u64,
    /// the number of Stacks blocks *at the same height* as this one, but from earlier sortitions
    /// than `burn_height`
    pub num_earlier_siblings: u64,
}

impl TipCandidate {
    pub fn id(&self) -> StacksBlockId {
        StacksBlockId::new(&self.consensus_hash, &self.anchored_block_hash)
    }

    pub fn parent_id(&self) -> StacksBlockId {
        StacksBlockId::new(
            &self.parent_consensus_hash,
            &self.parent_anchored_block_hash,
        )
    }

    pub fn new(tip: StagingBlock, burn_height: u64) -> Self {
        Self {
            stacks_height: tip.height,
            consensus_hash: tip.consensus_hash,
            anchored_block_hash: tip.anchored_block_hash,
            parent_consensus_hash: tip.parent_consensus_hash,
            parent_anchored_block_hash: tip.parent_anchored_block_hash,
            burn_height,
            num_earlier_siblings: 0,
        }
    }
}

impl BlockMinerThread {
    /// Instantiate the miner thread from its parent RelayerThread
    pub fn from_relayer_thread(
        rt: &RelayerThread,
        registered_key: RegisteredKey,
        burn_block: BlockSnapshot,
    ) -> BlockMinerThread {
        BlockMinerThread {
            config: rt.config.clone(),
            globals: rt.globals.clone(),
            keychain: rt.keychain.clone(),
            burnchain: rt.burnchain.clone(),
            last_mined_blocks: rt.last_mined_blocks.clone(),
            ongoing_commit: rt.bitcoin_controller.get_ongoing_commit(),
            registered_key,
            burn_block,
            event_dispatcher: rt.event_dispatcher.clone(),
            failed_to_submit_last_attempt: false,
        }
    }

    /// Get the coinbase recipient address, if set in the config and if allowed in this epoch
    fn get_coinbase_recipient(&self, epoch_id: StacksEpochId) -> Option<PrincipalData> {
        let miner_config = self.config.get_miner_config();
        if epoch_id < StacksEpochId::Epoch21 && miner_config.block_reward_recipient.is_some() {
            warn!("Coinbase pay-to-contract is not supported in the current epoch");
            None
        } else {
            miner_config.block_reward_recipient
        }
    }

    /// Create a coinbase transaction.
    fn inner_generate_coinbase_tx(
        &mut self,
        nonce: u64,
        epoch_id: StacksEpochId,
    ) -> StacksTransaction {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let recipient_opt = self.get_coinbase_recipient(epoch_id);
        let mut tx = StacksTransaction::new(
            version,
            tx_auth,
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), recipient_opt, None),
        );
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Create a poison microblock transaction.
    fn inner_generate_poison_microblock_tx(
        &mut self,
        nonce: u64,
        poison_payload: TransactionPayload,
    ) -> StacksTransaction {
        let is_mainnet = self.config.is_mainnet();
        let chain_id = self.config.burnchain.chain_id;
        let mut tx_auth = self.keychain.get_transaction_auth().unwrap();
        tx_auth.set_origin_nonce(nonce);

        let version = if is_mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let mut tx = StacksTransaction::new(version, tx_auth, poison_payload);
        tx.chain_id = chain_id;
        tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
        let mut tx_signer = StacksTransactionSigner::new(&tx);
        self.keychain.sign_as_origin(&mut tx_signer);

        tx_signer.get_tx().unwrap()
    }

    /// Constructs and returns a LeaderBlockCommitOp out of the provided params.
    #[allow(clippy::too_many_arguments)]
    fn inner_generate_block_commit_op(
        &self,
        block_header_hash: BlockHeaderHash,
        burn_fee: u64,
        key: &RegisteredKey,
        parent_burnchain_height: u32,
        parent_winning_vtx: u16,
        vrf_seed: VRFSeed,
        commit_outs: Vec<PoxAddress>,
        sunset_burn: u64,
        current_burn_height: u64,
    ) -> BlockstackOperationType {
        let (parent_block_ptr, parent_vtxindex) = (parent_burnchain_height, parent_winning_vtx);
        let burn_parent_modulus = (current_burn_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;
        let sender = self.keychain.get_burnchain_signer();
        BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn,
            block_header_hash,
            burn_fee,
            input: (Txid([0; 32]), 0),
            apparent_sender: sender,
            key_block_ptr: key.block_height as u32,
            key_vtxindex: key.op_vtxindex as u16,
            memo: vec![STACKS_EPOCH_3_0_MARKER],
            new_seed: vrf_seed,
            parent_block_ptr,
            parent_vtxindex,
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            burn_parent_modulus,
            commit_outs,
        })
    }

    /// Get references to the inner assembled anchor block data we've produced for a given burnchain block height
    fn find_inflight_mined_blocks(
        burn_height: u64,
        last_mined_blocks: &MinedBlocks,
    ) -> Vec<&AssembledAnchorBlock> {
        let mut ret = vec![];
        for (_, (assembled_block, _)) in last_mined_blocks.iter() {
            if assembled_block.burn_block_height >= burn_height {
                ret.push(assembled_block);
            }
        }
        ret
    }

    /// Is a given Stacks staging block on the canonical burnchain fork?
    pub(crate) fn is_on_canonical_burnchain_fork(
        candidate: &StagingBlock,
        sortdb_tip_handle: &SortitionHandleConn,
    ) -> bool {
        let candidate_ch = &candidate.consensus_hash;
        let candidate_burn_ht = match SortitionDB::get_block_snapshot_consensus(
            sortdb_tip_handle.conn(),
            candidate_ch,
        ) {
            Ok(Some(x)) => x.block_height,
            Ok(None) => {
                warn!("Tried to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate.anchored_block_hash);
                return false;
            }
            Err(e) => {
                warn!("Error while trying to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate.anchored_block_hash,
                      "err" => ?e);
                return false;
            }
        };
        let tip_ch = match sortdb_tip_handle.get_consensus_at(candidate_burn_ht) {
            Ok(Some(x)) => x,
            Ok(None) => {
                warn!("Tried to evaluate potential chain tip with a consensus hash ahead of canonical tip";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate.anchored_block_hash);
                return false;
            }
            Err(e) => {
                warn!("Error while trying to evaluate potential chain tip with an unknown consensus hash";
                      "consensus_hash" => %candidate_ch,
                      "stacks_block_hash" => %candidate.anchored_block_hash,
                      "err" => ?e);
                return false;
            }
        };
        &tip_ch == candidate_ch
    }

    /// Load all candidate tips upon which to build.  This is all Stacks blocks whose heights are
    /// less than or equal to at `at_stacks_height` (or the canonical chain tip height, if not given),
    /// but greater than or equal to this end height minus `max_depth`.
    /// Returns the list of all Stacks blocks up to max_depth blocks beneath it.
    /// The blocks will be sorted first by stacks height, and then by burnchain height
    pub(crate) fn load_candidate_tips(
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        max_depth: u64,
        at_stacks_height: Option<u64>,
    ) -> Vec<TipCandidate> {
        let stacks_tips = if let Some(start_height) = at_stacks_height {
            chain_state
                .get_stacks_chain_tips_at_height(start_height)
                .expect("FATAL: could not query chain tips at start height")
        } else {
            chain_state
                .get_stacks_chain_tips(burn_db)
                .expect("FATAL: could not query chain tips")
        };

        if stacks_tips.is_empty() {
            return vec![];
        }

        let sortdb_tip_handle = burn_db.index_handle_at_tip();

        let stacks_tips: Vec<_> = stacks_tips
            .into_iter()
            .filter(|candidate| Self::is_on_canonical_burnchain_fork(candidate, &sortdb_tip_handle))
            .collect();

        if stacks_tips.is_empty() {
            return vec![];
        }

        let mut considered = HashSet::new();
        let mut candidates = vec![];
        let end_height = stacks_tips[0].height;

        // process these tips
        for tip in stacks_tips.into_iter() {
            let index_block_hash =
                StacksBlockId::new(&tip.consensus_hash, &tip.anchored_block_hash);
            let burn_height = burn_db
                .get_consensus_hash_height(&tip.consensus_hash)
                .expect("FATAL: could not query burnchain block height")
                .expect("FATAL: no burnchain block height for Stacks tip");
            let candidate = TipCandidate::new(tip, burn_height);
            candidates.push(candidate);
            considered.insert(index_block_hash);
        }

        // process earlier tips, back to max_depth
        for cur_height in end_height.saturating_sub(max_depth)..end_height {
            let stacks_tips = chain_state
                .get_stacks_chain_tips_at_height(cur_height)
                .expect("FATAL: could not query chain tips at height")
                .into_iter()
                .filter(|candidate| {
                    Self::is_on_canonical_burnchain_fork(candidate, &sortdb_tip_handle)
                });

            for tip in stacks_tips {
                let index_block_hash =
                    StacksBlockId::new(&tip.consensus_hash, &tip.anchored_block_hash);

                if considered.insert(index_block_hash) {
                    let burn_height = burn_db
                        .get_consensus_hash_height(&tip.consensus_hash)
                        .expect("FATAL: could not query burnchain block height")
                        .expect("FATAL: no burnchain block height for Stacks tip");
                    let candidate = TipCandidate::new(tip, burn_height);
                    candidates.push(candidate);
                }
            }
        }
        Self::sort_and_populate_candidates(candidates)
    }

    /// Put all tip candidates in order by stacks height, breaking ties with burnchain height.
    /// Also, count up the number of earliersiblings each tip has -- i.e. the number of stacks
    /// blocks that have the same height, but a later burnchain sortition.
    pub(crate) fn sort_and_populate_candidates(
        mut candidates: Vec<TipCandidate>,
    ) -> Vec<TipCandidate> {
        if candidates.is_empty() {
            return candidates;
        }
        candidates.sort_by(|tip1, tip2| {
            // stacks block height, then burnchain block height
            let ord = tip1.stacks_height.cmp(&tip2.stacks_height);
            if ord == CmpOrdering::Equal {
                return tip1.burn_height.cmp(&tip2.burn_height);
            }
            ord
        });

        // calculate the number of earlier siblings for each block.
        // this is the number of stacks blocks at the same height, but later burnchain heights.
        let mut idx = 0;
        let mut cur_stacks_height = candidates[idx].stacks_height;
        let mut num_siblings = 0;
        loop {
            idx += 1;
            if idx >= candidates.len() {
                break;
            }
            if cur_stacks_height == candidates[idx].stacks_height {
                // same stacks height, so this block has one more earlier sibling than the last
                num_siblings += 1;
                candidates[idx].num_earlier_siblings = num_siblings;
            } else {
                // new stacks height, so no earlier siblings
                num_siblings = 0;
                cur_stacks_height = candidates[idx].stacks_height;
                candidates[idx].num_earlier_siblings = 0;
            }
        }

        candidates
    }

    /// Select the best tip to mine the next block on. Potential tips are all
    /// leaf nodes where the Stacks block height is <= the max height -
    /// max_reorg_depth. Each potential tip is then scored based on the amount
    /// of orphans that its chain has caused -- that is, the number of orphans
    /// that the tip _and all of its ancestors_ (up to `max_depth`) created.
    /// The tip with the lowest score is composed of blocks that collectively made the fewest
    /// orphans, and is thus the "nicest" chain with the least orphaning.  This is the tip that is
    /// selected.
    pub fn pick_best_tip(
        globals: &Globals,
        config: &Config,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        at_stacks_height: Option<u64>,
    ) -> Option<TipCandidate> {
        info!("Picking best Stacks tip");
        let miner_config = config.get_miner_config();
        let max_depth = miner_config.max_reorg_depth;

        // There could be more than one possible chain tip. Go find them.
        let stacks_tips =
            Self::load_candidate_tips(burn_db, chain_state, max_depth, at_stacks_height);

        let mut previous_best_tips = HashMap::new();
        for tip in stacks_tips.iter() {
            let Some(prev_best_tip) = globals.get_best_tip(tip.stacks_height) else {
                continue;
            };
            previous_best_tips.insert(tip.stacks_height, prev_best_tip);
        }

        let best_tip_opt = Self::inner_pick_best_tip(stacks_tips, previous_best_tips);
        if let Some(best_tip) = best_tip_opt.as_ref() {
            globals.add_best_tip(best_tip.stacks_height, best_tip.clone(), max_depth);
        } else {
            // no best-tip found; revert to old tie-breaker logic
            info!("No best-tips found; using old tie-breaking logic");
            return chain_state
                .get_stacks_chain_tip(burn_db)
                .expect("FATAL: could not load chain tip")
                .map(|staging_block| {
                    let burn_height = burn_db
                        .get_consensus_hash_height(&staging_block.consensus_hash)
                        .expect("FATAL: could not query burnchain block height")
                        .expect("FATAL: no burnchain block height for Stacks tip");
                    TipCandidate::new(staging_block, burn_height)
                });
        }
        best_tip_opt
    }

    /// Given a list of sorted candidate tips, pick the best one.  See `Self::pick_best_tip()`.
    /// Takes the list of stacks tips that are eligible to be built on, and a map of
    /// previously-chosen best tips (so if we chose a tip in the past, we keep confirming it, even
    /// if subsequent stacks blocks show up).  The previous best tips should be from recent Stacks
    /// heights; it's important that older best-tips are forgotten in order to ensure that miners
    /// will eventually (e.g. after `max_reorg_depth` Stacks blocks pass) stop trying to confirm a
    /// now-orphaned previously-chosen best-tip.  If there are multiple best-tips that conflict in
    /// `previosu_best_tips`, then only the highest one which the leaf could confirm will be
    /// considered (since the node updates its understanding of the best-tip on each RunTenure).
    pub(crate) fn inner_pick_best_tip(
        stacks_tips: Vec<TipCandidate>,
        previous_best_tips: HashMap<u64, TipCandidate>,
    ) -> Option<TipCandidate> {
        // identify leaf tips -- i.e. blocks with no children
        let parent_consensus_hashes: HashSet<_> = stacks_tips
            .iter()
            .map(|x| x.parent_consensus_hash)
            .collect();

        let mut leaf_tips: Vec<_> = stacks_tips
            .iter()
            .filter(|x| !parent_consensus_hashes.contains(&x.consensus_hash))
            .collect();

        if leaf_tips.is_empty() {
            return None;
        }

        // Make scoring deterministic in the case of a tie.
        // Prefer leafs that were mined earlier on the burnchain,
        // but which pass through previously-determined best tips.
        leaf_tips.sort_by(|tip1, tip2| {
            // stacks block height, then burnchain block height
            let ord = tip1.stacks_height.cmp(&tip2.stacks_height);
            if ord == CmpOrdering::Equal {
                return tip1.burn_height.cmp(&tip2.burn_height);
            }
            ord
        });

        let mut scores = BTreeMap::new();
        for (i, leaf_tip) in leaf_tips.iter().enumerate() {
            let leaf_id = leaf_tip.id();
            // Score each leaf tip as the number of preceding Stacks blocks that are _not_ an
            // ancestor.  Because stacks_tips are in order by stacks height, a linear scan of this
            // list will allow us to match all ancestors in the last max_depth Stacks blocks.
            // `ancestor_ptr` tracks the next expected ancestor.
            let mut ancestor_ptr = leaf_tip.parent_id();
            let mut score: u64 = 0;
            let mut score_summaries = vec![];

            // find the highest stacks_tip we must confirm
            let mut must_confirm = None;
            for tip in stacks_tips.iter().rev() {
                if let Some(prev_best_tip) = previous_best_tips.get(&tip.stacks_height) {
                    if leaf_id != prev_best_tip.id() {
                        // the `ancestor_ptr` must pass through this prior best-tip
                        must_confirm = Some(prev_best_tip.clone());
                        break;
                    }
                }
            }

            for tip in stacks_tips.iter().rev() {
                if let Some(required_ancestor) = must_confirm.as_ref() {
                    if tip.stacks_height < required_ancestor.stacks_height
                        && leaf_tip.stacks_height >= required_ancestor.stacks_height
                    {
                        // This leaf does not confirm a previous-best-tip, so assign it the
                        // worst-possible score.
                        info!("Tip #{i} {}/{} at {}:{} conflicts with a previous best-tip {}/{} at {}:{}",
                              &leaf_tip.consensus_hash,
                              &leaf_tip.anchored_block_hash,
                              leaf_tip.burn_height,
                              leaf_tip.stacks_height,
                              &required_ancestor.consensus_hash,
                              &required_ancestor.anchored_block_hash,
                              required_ancestor.burn_height,
                              required_ancestor.stacks_height
                        );
                        score = u64::MAX;
                        score_summaries.push(format!("{} (best-tip reorged)", u64::MAX));
                        break;
                    }
                }
                if tip.id() == leaf_id {
                    // we can't orphan ourselves
                    continue;
                }
                if leaf_tip.stacks_height < tip.stacks_height {
                    // this tip is further along than leaf_tip, so canonicalizing leaf_tip would
                    // orphan `tip.stacks_height - leaf_tip.stacks_height` blocks.
                    score = score.saturating_add(tip.stacks_height - leaf_tip.stacks_height);
                    score_summaries.push(format!(
                        "{} (stx height diff)",
                        tip.stacks_height - leaf_tip.stacks_height
                    ));
                } else if leaf_tip.stacks_height == tip.stacks_height
                    && leaf_tip.burn_height > tip.burn_height
                {
                    // this tip has the same stacks height as the leaf, but its sortition happened
                    // earlier. This means that the leaf is trying to orphan this block and all
                    // blocks sortition'ed up to this leaf.  The miner should have instead tried to
                    // confirm this existing tip, instead of mine a sibling.
                    score = score.saturating_add(tip.num_earlier_siblings + 1);
                    score_summaries.push(format!("{} (uncles)", tip.num_earlier_siblings + 1));
                }
                if tip.id() == ancestor_ptr {
                    // did we confirm a previous best-tip? If so, then clear this
                    if let Some(required_ancestor) = must_confirm.take() {
                        if required_ancestor.id() != tip.id() {
                            // did not confirm, so restoroe
                            must_confirm = Some(required_ancestor);
                        }
                    }

                    // this stacks tip is the next ancestor.  However, that ancestor may have
                    // earlier-sortition'ed siblings that confirming this tip would orphan, so count those.
                    ancestor_ptr = tip.parent_id();
                    score = score.saturating_add(tip.num_earlier_siblings);
                    score_summaries.push(format!("{} (earlier sibs)", tip.num_earlier_siblings));
                } else {
                    // this stacks tip is not an ancestor, and would be orphaned if leaf_tip is
                    // canonical.
                    score = score.saturating_add(1);
                    score_summaries.push(format!("{} (non-ancestor)", 1));
                }
            }

            info!(
                "Tip #{i} {}/{} at {}:{} has score {score} ({})",
                &leaf_tip.consensus_hash,
                &leaf_tip.anchored_block_hash,
                leaf_tip.burn_height,
                leaf_tip.stacks_height,
                score_summaries.join(" + ").to_string()
            );
            if score < u64::MAX {
                scores.insert(i, score);
            }
        }

        if scores.is_empty() {
            // revert to prior tie-breaking scheme
            return None;
        }

        // The lowest score is the "nicest" tip (least amount of orphaning)
        let best_tip_idx = scores
            .iter()
            .min_by_key(|(_, score)| *score)
            .expect("FATAL: candidates should not be empty here")
            .0;

        let best_tip = leaf_tips
            .get(*best_tip_idx)
            .expect("FATAL: candidates should not be empty");

        info!(
            "Best tip is #{best_tip_idx} {}/{}",
            &best_tip.consensus_hash, &best_tip.anchored_block_hash
        );
        Some((*best_tip).clone())
    }

    // TODO: add tests from mutation testing results #4870
    #[cfg_attr(test, mutants::skip)]
    /// Load up the parent block info for mining.
    /// If there's no parent because this is the first block, then return the genesis block's info.
    /// If we can't find the parent in the DB but we expect one, return None.
    fn load_block_parent_info(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
    ) -> (Option<ParentStacksBlockInfo>, bool) {
        if let Some(stacks_tip) = chain_state
            .get_stacks_chain_tip(burn_db)
            .expect("FATAL: could not query chain tip")
        {
            let best_stacks_tip =
                Self::pick_best_tip(&self.globals, &self.config, burn_db, chain_state, None)
                    .expect("FATAL: no best chain tip");
            let miner_address = self
                .keychain
                .origin_address(self.config.is_mainnet())
                .unwrap();
            let parent_info = match ParentStacksBlockInfo::lookup(
                chain_state,
                burn_db,
                &self.burn_block,
                miner_address,
                &best_stacks_tip.consensus_hash,
                &best_stacks_tip.anchored_block_hash,
            ) {
                Ok(parent_info) => Some(parent_info),
                Err(Error::BurnchainTipChanged) => {
                    self.globals.counters.bump_missed_tenures();
                    None
                }
                Err(..) => None,
            };
            if parent_info.is_none() {
                warn!(
                    "No parent for best-tip {}/{}",
                    &best_stacks_tip.consensus_hash, &best_stacks_tip.anchored_block_hash
                );
            }
            let canonical = best_stacks_tip.consensus_hash == stacks_tip.consensus_hash
                && best_stacks_tip.anchored_block_hash == stacks_tip.anchored_block_hash;
            (parent_info, canonical)
        } else {
            debug!("No Stacks chain tip known, will return a genesis block");
            let burnchain_params = burnchain_params_from_config(&self.config.burnchain);

            let chain_tip = ChainTip::genesis(
                &burnchain_params.first_block_hash,
                burnchain_params.first_block_height,
                burnchain_params.first_block_timestamp.into(),
            );

            (
                Some(ParentStacksBlockInfo {
                    stacks_parent_header: chain_tip.metadata,
                    parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH,
                    parent_block_burn_height: 0,
                    parent_block_total_burn: 0,
                    parent_winning_vtxindex: 0,
                    coinbase_nonce: 0,
                }),
                true,
            )
        }
    }

    /// Determine which attempt this will be when mining a block, and whether or not an attempt
    /// should even be made.
    /// Returns Some(attempt, max-txs) if we should attempt to mine (and what attempt it will be)
    /// Returns None if we should not mine.
    fn get_mine_attempt(
        &self,
        chain_state: &StacksChainState,
        parent_block_info: &ParentStacksBlockInfo,
        force: bool,
    ) -> Option<(u64, u64)> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &parent_block_info.stacks_parent_header;
        let parent_block_burn_height = parent_block_info.parent_block_burn_height;

        let last_mined_blocks =
            Self::find_inflight_mined_blocks(self.burn_block.block_height, &self.last_mined_blocks);

        // has the tip changed from our previously-mined block for this epoch?
        let should_unconditionally_mine = last_mined_blocks.is_empty()
            || (last_mined_blocks.len() == 1 && !self.failed_to_submit_last_attempt);
        let (attempt, max_txs) = if should_unconditionally_mine {
            // always mine if we've not mined a block for this epoch yet, or
            // if we've mined just one attempt, unconditionally try again (so we
            // can use `subsequent_miner_time_ms` in this attempt)
            if last_mined_blocks.len() == 1 {
                info!("Have only attempted one block; unconditionally trying again");
            }
            let attempt = last_mined_blocks.len() as u64 + 1;
            let mut max_txs = 0;
            for last_mined_block in last_mined_blocks.iter() {
                max_txs = cmp::max(max_txs, last_mined_block.anchored_block.txs.len());
            }
            (attempt, max_txs)
        } else {
            let mut best_attempt = 0;
            let mut max_txs = 0;
            info!(
                "Consider {} in-flight Stacks tip(s)",
                &last_mined_blocks.len()
            );
            for prev_block in last_mined_blocks.iter() {
                info!(
                    "Consider in-flight block {} on Stacks tip {}/{} in {} with {} txs",
                    &prev_block.anchored_block.block_hash(),
                    &prev_block.parent_consensus_hash,
                    &prev_block.anchored_block.header.parent_block,
                    &prev_block.burn_hash,
                    &prev_block.anchored_block.txs.len()
                );
                max_txs = cmp::max(max_txs, prev_block.anchored_block.txs.len());

                if prev_block.anchored_block.txs.len() == 1 && prev_block.attempt == 1 {
                    // Don't let the fact that we've built an empty block during this sortition
                    // prevent us from trying again.
                    best_attempt = 1;
                    continue;
                }
                if prev_block.parent_consensus_hash == *parent_consensus_hash
                    && prev_block.burn_hash == self.burn_block.burn_header_hash
                    && prev_block.anchored_block.header.parent_block
                        == stacks_parent_header.anchored_header.block_hash()
                {
                    // the anchored chain tip hasn't changed since we attempted to build a block.
                    // But, have discovered any new microblocks worthy of being mined?
                    if let Ok(Some(stream)) =
                        StacksChainState::load_descendant_staging_microblock_stream(
                            chain_state.db(),
                            &StacksBlockHeader::make_index_block_hash(
                                &prev_block.parent_consensus_hash,
                                &stacks_parent_header.anchored_header.block_hash(),
                            ),
                            0,
                            u16::MAX,
                        )
                    {
                        if (prev_block.anchored_block.header.parent_microblock
                            == BlockHeaderHash([0u8; 32])
                            && stream.is_empty())
                            || (prev_block.anchored_block.header.parent_microblock
                                != BlockHeaderHash([0u8; 32])
                                && stream.len()
                                    <= (prev_block.anchored_block.header.parent_microblock_sequence
                                        as usize)
                                        + 1)
                        {
                            if !force {
                                // the chain tip hasn't changed since we attempted to build a block.  Use what we
                                // already have.
                                info!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, and no new microblocks ({} <= {} + 1)",
                                       &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                       prev_block.anchored_block.txs.len(), prev_block.burn_hash, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                                return None;
                            }
                        } else {
                            // there are new microblocks!
                            // TODO: only consider rebuilding our anchored block if we (a) have
                            // time, and (b) the new microblocks are worth more than the new BTC
                            // fee minus the old BTC fee
                            info!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, but there are new microblocks ({} > {} + 1)",
                                   &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                   prev_block.anchored_block.txs.len(), prev_block.burn_hash, stream.len(), prev_block.anchored_block.header.parent_microblock_sequence);

                            best_attempt = cmp::max(best_attempt, prev_block.attempt);
                        }
                    } else if !force {
                        // no microblock stream to confirm, and the stacks tip hasn't changed
                        info!("Relayer: Stacks tip is unchanged since we last tried to mine a block off of {}/{} at height {} with {} txs, in {} at burn height {parent_block_burn_height}, and no microblocks present",
                                &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block, prev_block.anchored_block.header.total_work.work,
                                prev_block.anchored_block.txs.len(), prev_block.burn_hash);

                        return None;
                    }
                } else if self.burn_block.burn_header_hash == prev_block.burn_hash {
                    // only try and re-mine if there was no sortition since the last chain tip
                    info!("Relayer: Stacks tip has changed to {parent_consensus_hash}/{} since we last tried to mine a block in {} at burn height {parent_block_burn_height}; attempt was {} (for Stacks tip {}/{})",
                            stacks_parent_header.anchored_header.block_hash(), prev_block.burn_hash, prev_block.attempt, &prev_block.parent_consensus_hash, &prev_block.anchored_block.header.parent_block);
                    best_attempt = cmp::max(best_attempt, prev_block.attempt);
                    // Since the chain tip has changed, we should try to mine a new block, even
                    // if it has less transactions than the previous block we mined, since that
                    // previous block would now be a reorg.
                    max_txs = 0;
                } else {
                    info!("Relayer: Burn tip has changed to {} ({}) since we last tried to mine a block in {}",
                            &self.burn_block.burn_header_hash, self.burn_block.block_height, &prev_block.burn_hash);
                }
            }
            (best_attempt + 1, max_txs)
        };
        Some((attempt, u64::try_from(max_txs).expect("too many txs")))
    }

    /// Generate the VRF proof for the block we're going to build.
    /// Returns Some(proof) if we could make the proof
    /// Return None if we could not make the proof
    fn make_vrf_proof(&mut self) -> Option<VRFProof> {
        // if we're a mock miner, then make sure that the keychain has a keypair for the mocked VRF
        // key
        let vrf_proof = if self.config.get_node_config(false).mock_mining {
            self.keychain.generate_proof(
                VRF_MOCK_MINER_KEY,
                self.burn_block.sortition_hash.as_bytes(),
            )
        } else {
            self.keychain.generate_proof(
                self.registered_key.target_block_height,
                self.burn_block.sortition_hash.as_bytes(),
            )
        };

        debug!(
            "Generated VRF Proof: {} over {} ({},{}) with key {}",
            vrf_proof.to_hex(),
            &self.burn_block.sortition_hash,
            &self.burn_block.block_height,
            &self.burn_block.burn_header_hash,
            &self.registered_key.vrf_public_key.to_hex()
        );
        Some(vrf_proof)
    }

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key.
    ///
    /// In testing, we ignore the parent stacks block hash because we don't have an easy way to
    /// reproduce it in integration tests.
    #[cfg(not(test))]
    fn make_microblock_private_key(
        &mut self,
        parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        self.keychain
            .make_microblock_secret_key(self.burn_block.block_height, &parent_stacks_hash.0)
    }

    /// Get the microblock private key we'll be using for this tenure, should we win.
    /// Return the private key on success
    #[cfg(test)]
    fn make_microblock_private_key(
        &mut self,
        _parent_stacks_hash: &StacksBlockId,
    ) -> Secp256k1PrivateKey {
        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        warn!("test version of make_microblock_secret_key");
        self.keychain.make_microblock_secret_key(
            self.burn_block.block_height,
            &self.burn_block.block_height.to_be_bytes(),
        )
    }

    /// Load the parent microblock stream and vet it for the absence of forks.
    /// If there is a fork, then mine and relay a poison microblock transaction.
    /// Update stacks_parent_header's microblock tail to point to the end of the stream we load.
    /// Return the microblocks we'll confirm, if there are any.
    fn load_and_vet_parent_microblocks(
        &mut self,
        chain_state: &mut StacksChainState,
        sortdb: &SortitionDB,
        mem_pool: &mut MemPoolDB,
        parent_block_info: &mut ParentStacksBlockInfo,
    ) -> Option<Vec<StacksMicroblock>> {
        let parent_consensus_hash = &parent_block_info.parent_consensus_hash;
        let stacks_parent_header = &mut parent_block_info.stacks_parent_header;

        let microblock_info_opt =
            match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                chain_state.db(),
                &StacksBlockHeader::make_index_block_hash(
                    parent_consensus_hash,
                    &stacks_parent_header.anchored_header.block_hash(),
                ),
                0,
                u16::MAX,
            ) {
                Ok(x) => {
                    let num_mblocks = x.as_ref().map(|(mblocks, ..)| mblocks.len()).unwrap_or(0);
                    debug!(
                        "Loaded {num_mblocks} microblocks descending from {parent_consensus_hash}/{} (data: {})",
                        &stacks_parent_header.anchored_header.block_hash(),
                        x.is_some()
                    );
                    x
                }
                Err(e) => {
                    warn!(
                        "Failed to load descendant microblock stream from {parent_consensus_hash}/{}: {e:?}",
                        &stacks_parent_header.anchored_header.block_hash()
                    );
                    None
                }
            };

        if let Some((ref microblocks, ref poison_opt)) = &microblock_info_opt {
            if let Some(tail) = microblocks.last() {
                debug!(
                    "Confirm microblock stream tailed at {} (seq {})",
                    &tail.block_hash(),
                    tail.header.sequence
                );
            }

            // try and confirm as many microblocks as we can (but note that the stream itself may
            // be too long; we'll try again if that happens).
            stacks_parent_header.microblock_tail = microblocks.last().map(|blk| blk.header.clone());

            if let Some(poison_payload) = poison_opt {
                debug!("Detected poisoned microblock fork: {poison_payload:?}");

                // submit it multiple times with different nonces, so it'll have a good chance of
                // eventually getting picked up (even if the miner sends other transactions from
                // the same address)
                for i in 0..10 {
                    let poison_microblock_tx = self.inner_generate_poison_microblock_tx(
                        parent_block_info.coinbase_nonce + 1 + i,
                        poison_payload.clone(),
                    );

                    // submit the poison payload, privately, so we'll mine it when building the
                    // anchored block.
                    if let Err(e) = mem_pool.miner_submit(
                        chain_state,
                        sortdb,
                        parent_consensus_hash,
                        &stacks_parent_header.anchored_header.block_hash(),
                        &poison_microblock_tx,
                        Some(&self.event_dispatcher),
                        1_000_000_000.0, // prioritize this for inclusion
                    ) {
                        warn!("Detected but failed to mine poison-microblock transaction: {e:?}");
                    } else {
                        debug!("Submit poison-microblock transaction {poison_microblock_tx:?}");
                    }
                }
            }
        }

        microblock_info_opt.map(|(stream, _)| stream)
    }

    /// Get the list of possible burn addresses this miner is using
    pub fn get_miner_addrs(config: &Config, keychain: &Keychain) -> Vec<String> {
        let mut op_signer = keychain.generate_op_signer();
        let mut btc_addrs = vec![
            // legacy
            BitcoinAddress::from_bytes_legacy(
                config.burnchain.get_bitcoin_network().1,
                LegacyBitcoinAddressType::PublicKeyHash,
                &Hash160::from_data(&op_signer.get_public_key().to_bytes()).0,
            )
            .expect("FATAL: failed to construct legacy bitcoin address"),
        ];
        if config.miner.segwit {
            btc_addrs.push(
                // segwit p2wpkh
                BitcoinAddress::from_bytes_segwit_p2wpkh(
                    config.burnchain.get_bitcoin_network().1,
                    &Hash160::from_data(&op_signer.get_public_key().to_bytes_compressed()).0,
                )
                .expect("FATAL: failed to construct segwit p2wpkh address"),
            );
        }
        btc_addrs
            .into_iter()
            .map(|addr| format!("{addr}"))
            .collect()
    }

    /// Obtain the target burn fee cap, when considering how well this miner is performing.
    #[allow(clippy::too_many_arguments)]
    pub fn get_mining_spend_amount<F, G>(
        config: &Config,
        keychain: &Keychain,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        recipients: &[PoxAddress],
        start_mine_height: u64,
        at_burn_block: Option<u64>,
        mut get_prior_winning_prob: F,
        mut set_prior_winning_prob: G,
    ) -> u64
    where
        F: FnMut(u64) -> f64,
        G: FnMut(u64, f64),
    {
        let config_file_burn_fee_cap = config.get_burnchain_config().burn_fee_cap;
        let miner_config = config.get_miner_config();

        if miner_config.target_win_probability < 0.00001 {
            // this field is effectively zero
            return config_file_burn_fee_cap;
        }
        let Some(miner_stats) = config.get_miner_stats() else {
            return config_file_burn_fee_cap;
        };

        let Ok(tip) = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).map_err(|e| {
            warn!("Failed to load canonical burn chain tip: {e:?}");
            e
        }) else {
            return config_file_burn_fee_cap;
        };
        let tip = if let Some(at_burn_block) = at_burn_block.as_ref() {
            let ih = sortdb.index_handle(&tip.sortition_id);
            let Ok(Some(ancestor_tip)) = ih.get_block_snapshot_by_height(*at_burn_block) else {
                warn!("Failed to load ancestor tip at burn height {at_burn_block}");
                return config_file_burn_fee_cap;
            };
            ancestor_tip
        } else {
            tip
        };

        let Ok(active_miners_and_commits) = MinerStats::get_active_miners(sortdb, at_burn_block)
            .map_err(|e| {
                warn!("Failed to get active miners: {e:?}");
                e
            })
        else {
            return config_file_burn_fee_cap;
        };
        if active_miners_and_commits.is_empty() {
            warn!("No active miners detected; using config file burn_fee_cap");
            return config_file_burn_fee_cap;
        }

        let active_miners: Vec<_> = active_miners_and_commits
            .iter()
            .map(|(miner, _cmt)| miner.as_str())
            .collect();

        info!("Active miners: {active_miners:?}");

        let Ok(unconfirmed_block_commits) = miner_stats
            .get_unconfirmed_commits(tip.block_height + 1, &active_miners)
            .map_err(|e| {
                warn!("Failed to find unconfirmed block-commits: {e}");
                e
            })
        else {
            return config_file_burn_fee_cap;
        };

        let unconfirmed_miners_and_amounts: Vec<(String, u64)> = unconfirmed_block_commits
            .iter()
            .map(|cmt| (cmt.apparent_sender.to_string(), cmt.burn_fee))
            .collect();

        info!("Found unconfirmed block-commits: {unconfirmed_miners_and_amounts:?}");

        let (spend_dist, _total_spend) = MinerStats::get_spend_distribution(
            &active_miners_and_commits,
            &unconfirmed_block_commits,
            recipients,
        );
        let win_probs = if miner_config.fast_rampup {
            // look at spends 6+ blocks in the future
            MinerStats::get_future_win_distribution(
                &active_miners_and_commits,
                &unconfirmed_block_commits,
                recipients,
            )
        } else {
            // look at the current spends
            let Ok(unconfirmed_burn_dist) = miner_stats
                .get_unconfirmed_burn_distribution(
                    burnchain,
                    sortdb,
                    &active_miners_and_commits,
                    unconfirmed_block_commits,
                    recipients,
                    at_burn_block,
                )
                .map_err(|e| {
                    warn!("Failed to get unconfirmed burn distribution: {e:?}");
                    e
                })
            else {
                return config_file_burn_fee_cap;
            };

            MinerStats::burn_dist_to_prob_dist(&unconfirmed_burn_dist)
        };

        info!("Unconfirmed spend distribution: {spend_dist:?}");
        info!(
            "Unconfirmed win probabilities (fast_rampup={}): {win_probs:?}",
            miner_config.fast_rampup
        );

        let miner_addrs = Self::get_miner_addrs(config, keychain);
        let win_prob = miner_addrs
            .iter()
            .find_map(|x| win_probs.get(x))
            .copied()
            .unwrap_or(0.0);

        info!(
            "This miner's win probability at {} is {win_prob}",
            tip.block_height
        );
        set_prior_winning_prob(tip.block_height, win_prob);

        if win_prob < config.miner.target_win_probability {
            // no mining strategy is viable, so just quit.
            // Unless we're spinning up, that is.
            if start_mine_height + 6 < tip.block_height
                && config.miner.underperform_stop_threshold.is_some()
            {
                let underperform_stop_threshold =
                    config.miner.underperform_stop_threshold.unwrap_or(0);
                info!(
                    "Miner is spun up, but is not meeting target win probability as of {}",
                    tip.block_height
                );
                // we've spun up and we're underperforming. How long do we tolerate this?
                let mut underperformed_count = 0;
                for depth in 0..underperform_stop_threshold {
                    let prior_burn_height = tip.block_height.saturating_sub(depth);
                    let prior_win_prob = get_prior_winning_prob(prior_burn_height);
                    if prior_win_prob < config.miner.target_win_probability {
                        info!(
                            "Miner underperformed in block {prior_burn_height} ({underperformed_count}/{underperform_stop_threshold})"
                        );
                        underperformed_count += 1;
                    }
                }
                if underperformed_count == underperform_stop_threshold {
                    warn!(
                        "Miner underperformed since burn height {}; spinning down",
                        start_mine_height + 6 + underperform_stop_threshold
                    );
                    return 0;
                }
            }
        }

        config_file_burn_fee_cap
    }

    /// Produce the block-commit for this anchored block, if we can.
    /// Returns the op on success
    /// Returns None if we fail somehow.
    #[allow(clippy::too_many_arguments)]
    pub fn make_block_commit(
        &self,
        burn_db: &mut SortitionDB,
        chain_state: &mut StacksChainState,
        block_hash: BlockHeaderHash,
        parent_block_burn_height: u64,
        parent_winning_vtxindex: u16,
        vrf_proof: &VRFProof,
        target_epoch_id: StacksEpochId,
    ) -> Option<BlockstackOperationType> {
        // let's figure out the recipient set!
        let recipients = match get_next_recipients(
            &self.burn_block,
            chain_state,
            burn_db,
            &self.burnchain,
            &OnChainRewardSetProvider::new(),
            self.config.node.always_use_affirmation_maps,
        ) {
            Ok(x) => x,
            Err(e) => {
                error!("Relayer: Failure fetching recipient set: {e:?}");
                return None;
            }
        };

        let commit_outs = if !self
            .burnchain
            .pox_constants
            .is_after_pox_sunset_end(self.burn_block.block_height, target_epoch_id)
            && !self
                .burnchain
                .is_in_prepare_phase(self.burn_block.block_height + 1)
        {
            RewardSetInfo::into_commit_outs(recipients, self.config.is_mainnet())
        } else {
            vec![PoxAddress::standard_burn_address(self.config.is_mainnet())]
        };

        let burn_fee_cap = Self::get_mining_spend_amount(
            &self.config,
            &self.keychain,
            &self.burnchain,
            burn_db,
            &commit_outs,
            self.globals.get_start_mining_height(),
            None,
            |block_height| {
                self.globals
                    .get_estimated_win_prob(block_height)
                    .unwrap_or(0.0)
            },
            |block_height, win_prob| self.globals.add_estimated_win_prob(block_height, win_prob),
        );
        if burn_fee_cap == 0 {
            warn!("Calculated burn_fee_cap is 0; will not mine");
            return None;
        }
        let sunset_burn = self.burnchain.expected_sunset_burn(
            self.burn_block.block_height + 1,
            burn_fee_cap,
            target_epoch_id,
        );
        let rest_commit = burn_fee_cap - sunset_burn;

        // let's commit, but target the current burnchain tip with our modulus
        let op = self.inner_generate_block_commit_op(
            block_hash,
            rest_commit,
            &self.registered_key,
            parent_block_burn_height
                .try_into()
                .expect("Could not convert parent block height into u32"),
            parent_winning_vtxindex,
            VRFSeed::from_proof(vrf_proof),
            commit_outs,
            sunset_burn,
            self.burn_block.block_height,
        );
        Some(op)
    }

    /// Are there enough unprocessed blocks that we shouldn't mine?
    fn unprocessed_blocks_prevent_mining(
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        unprocessed_block_deadline: u64,
    ) -> bool {
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .expect("FATAL: could not query canonical sortition DB tip");

        if let Some(stacks_tip) =
            NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
                .expect("FATAL: could not query canonical Stacks chain tip")
        {
            // if a block hasn't been processed within some deadline seconds of receipt, don't block
            //  mining
            let process_deadline = get_epoch_time_secs() - unprocessed_block_deadline;
            let has_unprocessed = StacksChainState::has_higher_unprocessed_blocks(
                chainstate.db(),
                stacks_tip.anchored_header.height(),
                process_deadline,
            )
            .expect("FATAL: failed to query staging blocks");
            if has_unprocessed {
                let highest_unprocessed_opt = StacksChainState::get_highest_unprocessed_block(
                    chainstate.db(),
                    process_deadline,
                )
                .expect("FATAL: failed to query staging blocks");

                if let Some(highest_unprocessed) = highest_unprocessed_opt {
                    let highest_unprocessed_block_sn_opt =
                        SortitionDB::get_block_snapshot_consensus(
                            sortdb.conn(),
                            &highest_unprocessed.consensus_hash,
                        )
                        .expect("FATAL: could not query sortition DB");

                    // NOTE: this could be None if it's not part of the canonical PoX fork any
                    // longer
                    if let Some(highest_unprocessed_block_sn) = highest_unprocessed_block_sn_opt {
                        if stacks_tip.anchored_header.height()
                            + u64::from(burnchain.pox_constants.prepare_length)
                            > highest_unprocessed.height
                            && highest_unprocessed_block_sn.block_height
                                + u64::from(burnchain.pox_constants.prepare_length)
                                > sort_tip.block_height
                        {
                            // we're close enough to the chain tip that it's a bad idea for us to mine
                            // -- we'll likely create an orphan
                            return true;
                        }
                    }
                }
            }
        }
        // we can mine
        false
    }

    /// Only used in mock signing to generate a peer info view
    fn generate_peer_info(&self) -> PeerInfo {
        // Create a peer info view of the current state
        let server_version = version_string(
            "stacks-node",
            option_env!("STACKS_NODE_VERSION")
                .or(option_env!("CARGO_PKG_VERSION"))
                .unwrap_or("0.0.0.0"),
        );
        let stacks_tip_height = self.burn_block.canonical_stacks_tip_height;
        let stacks_tip = self.burn_block.canonical_stacks_tip_hash;
        let stacks_tip_consensus_hash = self.burn_block.canonical_stacks_tip_consensus_hash;
        let pox_consensus = self.burn_block.consensus_hash;
        let burn_block_height = self.burn_block.block_height;

        PeerInfo {
            burn_block_height,
            stacks_tip_consensus_hash,
            stacks_tip,
            stacks_tip_height,
            pox_consensus,
            server_version,
            network_id: self.config.get_burnchain_config().chain_id,
        }
    }

    /// Only used in mock signing to retrieve the mock signatures for the given mock proposal
    fn wait_for_mock_signatures(
        &self,
        mock_proposal: &MockProposal,
        stackerdbs: &StackerDBs,
        timeout: Duration,
    ) -> Result<Vec<MockSignature>, ChainstateError> {
        let reward_cycle = self
            .burnchain
            .block_height_to_reward_cycle(self.burn_block.block_height)
            .expect("BUG: block commit exists before first block height");
        let signers_contract_id = MessageSlotID::BlockResponse
            .stacker_db_contract(self.config.is_mainnet(), reward_cycle);
        let slot_ids: Vec<_> = stackerdbs
            .get_signers(&signers_contract_id)
            .expect("FATAL: could not get signers from stacker DB")
            .into_iter()
            .enumerate()
            .map(|(slot_id, _)| {
                u32::try_from(slot_id).expect("FATAL: too many signers to fit into u32 range")
            })
            .collect();
        let mock_poll_start = Instant::now();
        let mut mock_signatures = vec![];
        // Because we don't care really if all signers reach quorum and this is just for testing purposes,
        // we don't need to wait for ALL signers to sign the mock proposal and should not slow down mining too much
        // Just wait a min amount of time for the mock signatures to come in
        while mock_signatures.len() < slot_ids.len() && mock_poll_start.elapsed() < timeout {
            let chunks = stackerdbs.get_latest_chunks(&signers_contract_id, &slot_ids)?;
            for chunk in chunks.into_iter().flatten() {
                if let Ok(SignerMessage::MockSignature(mock_signature)) =
                    SignerMessage::consensus_deserialize(&mut chunk.as_slice())
                {
                    if mock_signature.mock_proposal == *mock_proposal
                        && !mock_signatures.contains(&mock_signature)
                    {
                        mock_signatures.push(mock_signature);
                    }
                }
            }
        }
        Ok(mock_signatures)
    }

    /// Only used in mock signing to determine if the peer info view was already signed across
    fn mock_block_exists(&self, peer_info: &PeerInfo) -> bool {
        let miner_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
        let mut miners_stackerdb =
            StackerDBSession::new(&self.config.node.rpc_bind, miner_contract_id);
        let miner_slot_ids: Vec<_> = (0..MINER_SLOT_COUNT * 2).collect();
        if let Ok(messages) = miners_stackerdb.get_latest_chunks(&miner_slot_ids) {
            for message in messages.into_iter().flatten() {
                if message.is_empty() {
                    continue;
                }
                let Ok(SignerMessage::MockBlock(mock_block)) =
                    SignerMessage::consensus_deserialize(&mut message.as_slice())
                else {
                    continue;
                };
                if mock_block.mock_proposal.peer_info == *peer_info {
                    return true;
                }
            }
        }
        false
    }

    /// Read any mock signatures from stackerdb and respond to them
    pub fn send_mock_miner_messages(&mut self) -> Result<(), String> {
        let burn_db_path = self.config.get_burn_db_file_path();
        let burn_db = SortitionDB::open(&burn_db_path, false, self.burnchain.pox_constants.clone())
            .expect("FATAL: could not open sortition DB");
        let epoch_id = SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height)
            .map_err(|e| e.to_string())?
            .expect("FATAL: no epoch defined")
            .epoch_id;
        if epoch_id != StacksEpochId::Epoch25 {
            debug!("Mock miner messaging is disabled for non-epoch 2.5 blocks.";
                "epoch_id" => epoch_id.to_string()
            );
            return Ok(());
        }

        let miner_config = self.config.get_miner_config();
        if !miner_config.pre_nakamoto_mock_signing {
            debug!("Pre-Nakamoto mock signing is disabled");
            return Ok(());
        }

        let mining_key = miner_config
            .mining_key
            .expect("Cannot mock sign without mining key");

        // Create a peer info view of the current state
        let peer_info = self.generate_peer_info();
        if self.mock_block_exists(&peer_info) {
            debug!(
                "Already sent mock miner block proposal for current peer info view. Not sending another mock proposal."
            );
            return Ok(());
        }

        // find out which slot we're in. If we are not the latest sortition winner, we should not be sending anymore messages anyway
        let ih = burn_db.index_handle(&self.burn_block.sortition_id);
        let last_winner_snapshot = ih
            .get_last_snapshot_with_sortition(self.burn_block.block_height)
            .map_err(|e| e.to_string())?;

        if last_winner_snapshot.miner_pk_hash
            != Some(Hash160::from_node_public_key(
                &StacksPublicKey::from_private(&mining_key),
            ))
        {
            return Ok(());
        }
        let election_sortition = last_winner_snapshot.consensus_hash;
        let mock_proposal = MockProposal::new(peer_info, &mining_key);

        info!("Sending mock proposal to stackerdb: {mock_proposal:?}");

        let stackerdbs = StackerDBs::connect(&self.config.get_stacker_db_file_path(), false)
            .map_err(|e| e.to_string())?;
        let miner_contract_id = boot_code_id(MINERS_NAME, self.config.is_mainnet());
        let mut miners_stackerdb =
            StackerDBSession::new(&self.config.node.rpc_bind, miner_contract_id);

        SignerCoordinator::send_miners_message(
            &mining_key,
            &burn_db,
            &self.burn_block,
            &stackerdbs,
            SignerMessage::MockProposal(mock_proposal.clone()),
            MinerSlotID::BlockProposal, // There is no specific slot for mock miner messages so we use BlockProposal for MockProposal as well.
            self.config.is_mainnet(),
            &mut miners_stackerdb,
            &election_sortition,
        )
        .map_err(|e| {
            warn!("Failed to write mock proposal to stackerdb.");
            e.to_string()
        })?;

        // Retrieve any MockSignatures from stackerdb
        info!("Waiting for mock signatures...");
        let mock_signatures = self
            .wait_for_mock_signatures(&mock_proposal, &stackerdbs, Duration::from_secs(10))
            .map_err(|e| e.to_string())?;

        let mock_block = MockBlock {
            mock_proposal,
            mock_signatures,
        };

        info!("Sending mock block to stackerdb: {mock_block:?}");
        SignerCoordinator::send_miners_message(
            &mining_key,
            &burn_db,
            &self.burn_block,
            &stackerdbs,
            SignerMessage::MockBlock(mock_block.clone()),
            MinerSlotID::BlockPushed, // There is no specific slot for mock miner messages. Let's use BlockPushed for MockBlock since MockProposal uses BlockProposal.
            self.config.is_mainnet(),
            &mut miners_stackerdb,
            &election_sortition,
        )
        .map_err(|e| {
            warn!("Failed to write mock block to stackerdb.");
            e.to_string()
        })?;
        Ok(())
    }

    // TODO: add tests from mutation testing results #4871
    #[cfg_attr(test, mutants::skip)]
    /// Try to mine a Stacks block by assembling one from mempool transactions and sending a
    /// burnchain block-commit transaction.  If we succeed, then return the assembled block data as
    /// well as the microblock private key to use to produce microblocks.
    /// Return None if we couldn't build a block for whatever reason.
    pub fn run_tenure(&mut self) -> Option<MinerThreadResult> {
        debug!("block miner thread ID is {:?}", thread::current().id());
        fault_injection_long_tenure();

        let burn_db_path = self.config.get_burn_db_file_path();
        let stacks_chainstate_path = self.config.get_chainstate_path_str();

        let cost_estimator = self
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = self
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mut bitcoin_controller = BitcoinRegtestController::new_ongoing_dummy(
            self.config.clone(),
            self.ongoing_commit.clone(),
        );

        let miner_config = self.config.get_miner_config();
        let last_miner_config_opt = self.globals.get_last_miner_config();
        let force_remine = if let Some(last_miner_config) = last_miner_config_opt {
            last_miner_config != miner_config
        } else {
            false
        };
        if force_remine {
            info!("Miner config changed; forcing a re-mine attempt");
        }

        self.globals.set_last_miner_config(miner_config);

        // NOTE: read-write access is needed in order to be able to query the recipient set.
        // This is an artifact of the way the MARF is built (see #1449)
        let mut burn_db =
            SortitionDB::open(&burn_db_path, true, self.burnchain.pox_constants.clone())
                .expect("FATAL: could not open sortition DB");

        let mut chain_state =
            open_chainstate_with_faults(&self.config).expect("FATAL: could not open chainstate DB");

        let mut mem_pool = MemPoolDB::open(
            self.config.is_mainnet(),
            self.config.burnchain.chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let tenure_begin = get_epoch_time_ms();

        let target_epoch_id =
            SortitionDB::get_stacks_epoch(burn_db.conn(), self.burn_block.block_height + 1)
                .ok()?
                .expect("FATAL: no epoch defined")
                .epoch_id;

        let (Some(mut parent_block_info), _) =
            self.load_block_parent_info(&mut burn_db, &mut chain_state)
        else {
            return None;
        };
        let (attempt, max_txs) =
            self.get_mine_attempt(&chain_state, &parent_block_info, force_remine)?;
        let vrf_proof = self.make_vrf_proof()?;

        // Generates a new secret key for signing the trail of microblocks
        // of the upcoming tenure.
        let microblock_private_key = self.make_microblock_private_key(
            &parent_block_info.stacks_parent_header.index_block_hash(),
        );
        let mblock_pubkey_hash = {
            let mut pubkh = Hash160::from_node_public_key(&StacksPublicKey::from_private(
                &microblock_private_key,
            ));
            if cfg!(test) {
                if let Ok(mblock_pubkey_hash_str) = std::env::var("STACKS_MICROBLOCK_PUBKEY_HASH") {
                    if let Ok(bad_pubkh) = Hash160::from_hex(&mblock_pubkey_hash_str) {
                        debug!("Fault injection: set microblock public key hash to {bad_pubkh}");
                        pubkh = bad_pubkh
                    }
                }
            }
            pubkh
        };

        // create our coinbase
        let coinbase_tx =
            self.inner_generate_coinbase_tx(parent_block_info.coinbase_nonce, target_epoch_id);

        // find the longest microblock tail we can build off of and vet microblocks for forks
        self.load_and_vet_parent_microblocks(
            &mut chain_state,
            &burn_db,
            &mut mem_pool,
            &mut parent_block_info,
        );

        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to read current burnchain tip");
        let microblocks_disabled =
            SortitionDB::are_microblocks_disabled(burn_db.conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        // build the block itself
        let mut builder_settings = self.config.make_block_builder_settings(
            attempt,
            false,
            self.globals.get_miner_status(),
        );
        if microblocks_disabled {
            builder_settings.confirm_microblocks = false;
            if cfg!(test)
                && std::env::var("STACKS_TEST_CONFIRM_MICROBLOCKS_POST_25").as_deref() == Ok("1")
            {
                builder_settings.confirm_microblocks = true;
            }
        }
        let (anchored_block, _, _) = match StacksBlockBuilder::build_anchored_block(
            &chain_state,
            &burn_db.index_handle(&burn_tip.sortition_id),
            &mut mem_pool,
            &parent_block_info.stacks_parent_header,
            parent_block_info.parent_block_total_burn,
            vrf_proof.clone(),
            mblock_pubkey_hash,
            &coinbase_tx,
            builder_settings,
            Some(&self.event_dispatcher),
            &self.burnchain,
        ) {
            Ok(block) => block,
            Err(ChainstateError::InvalidStacksMicroblock(msg, mblock_header_hash)) => {
                // part of the parent microblock stream is invalid, so try again
                info!(
                    "Parent microblock stream is invalid; trying again without microblocks";
                    "microblock_offender" => %mblock_header_hash,
                    "error" => &msg
                );

                let mut builder_settings = self.config.make_block_builder_settings(
                    attempt,
                    false,
                    self.globals.get_miner_status(),
                );
                builder_settings.confirm_microblocks = false;

                // try again
                match StacksBlockBuilder::build_anchored_block(
                    &chain_state,
                    &burn_db.index_handle(&burn_tip.sortition_id),
                    &mut mem_pool,
                    &parent_block_info.stacks_parent_header,
                    parent_block_info.parent_block_total_burn,
                    vrf_proof.clone(),
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    builder_settings,
                    Some(&self.event_dispatcher),
                    &self.burnchain,
                ) {
                    Ok(block) => block,
                    Err(e) => {
                        error!("Relayer: Failure mining anchor block even after removing offending microblock {mblock_header_hash}: {e}");
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("Relayer: Failure mining anchored block: {e}");
                return None;
            }
        };

        let miner_config = self.config.get_miner_config();

        if attempt > 1
            && miner_config.min_tx_count > 0
            && u64::try_from(anchored_block.txs.len()).expect("too many txs")
                < miner_config.min_tx_count
        {
            info!("Relayer: Succeeded assembling subsequent block with {} txs, but expected at least {}", anchored_block.txs.len(), miner_config.min_tx_count);
            return None;
        }

        if miner_config.only_increase_tx_count
            && max_txs > u64::try_from(anchored_block.txs.len()).expect("too many txs")
        {
            info!("Relayer: Succeeded assembling subsequent block with {} txs, but had previously produced a block with {max_txs} txs", anchored_block.txs.len());
            return None;
        }

        info!(
            "Relayer: Succeeded assembling {} block #{}: {}, with {} txs, attempt {attempt}",
            if parent_block_info.parent_block_total_burn == 0 {
                "Genesis"
            } else {
                "Stacks"
            },
            anchored_block.header.total_work.work,
            anchored_block.block_hash(),
            anchored_block.txs.len()
        );

        // let's commit
        let op = self.make_block_commit(
            &mut burn_db,
            &mut chain_state,
            anchored_block.block_hash(),
            parent_block_info.parent_block_burn_height,
            parent_block_info.parent_winning_vtxindex,
            &vrf_proof,
            target_epoch_id,
        )?;
        let burn_fee = if let BlockstackOperationType::LeaderBlockCommit(ref op) = &op {
            op.burn_fee
        } else {
            0
        };

        // last chance -- confirm that the stacks tip is unchanged (since it could have taken long
        // enough to build this block that another block could have arrived), and confirm that all
        // Stacks blocks with heights higher than the canoincal tip are processed.
        let cur_burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if let Some(stacks_tip) = Self::pick_best_tip(
            &self.globals,
            &self.config,
            &mut burn_db,
            &mut chain_state,
            None,
        ) {
            let is_miner_blocked = self
                .globals
                .get_miner_status()
                .lock()
                .expect("FATAL: mutex poisoned")
                .is_blocked();

            let has_unprocessed = Self::unprocessed_blocks_prevent_mining(
                &self.burnchain,
                &burn_db,
                &chain_state,
                miner_config.unprocessed_block_deadline_secs,
            );

            if stacks_tip.anchored_block_hash != anchored_block.header.parent_block
                || parent_block_info.parent_consensus_hash != stacks_tip.consensus_hash
                || cur_burn_chain_tip.burn_header_hash != self.burn_block.burn_header_hash
                || is_miner_blocked
                || has_unprocessed
            {
                info!(
                    "Relayer: Cancel block-commit; chain tip(s) have changed or cancelled";
                    "block_hash" => %anchored_block.block_hash(),
                    "tx_count" => anchored_block.txs.len(),
                    "target_height" => %anchored_block.header.total_work.work,
                    "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
                    "parent_block_hash" => %anchored_block.header.parent_block,
                    "parent_microblock_hash" => %anchored_block.header.parent_microblock,
                    "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
                    "old_tip_burn_block_hash" => %self.burn_block.burn_header_hash,
                    "old_tip_burn_block_height" => self.burn_block.block_height,
                    "old_tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
                    "attempt" => attempt,
                    "new_stacks_tip_block_hash" => %stacks_tip.anchored_block_hash,
                    "new_stacks_tip_consensus_hash" => %stacks_tip.consensus_hash,
                    "new_tip_burn_block_height" => cur_burn_chain_tip.block_height,
                    "new_tip_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "new_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
                    "miner_blocked" => %is_miner_blocked,
                    "has_unprocessed" => %has_unprocessed
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let mut op_signer = self.keychain.generate_op_signer();
        info!(
            "Relayer: Submit block-commit";
            "burn_fee" => burn_fee,
            "block_hash" => %anchored_block.block_hash(),
            "tx_count" => anchored_block.txs.len(),
            "target_height" => anchored_block.header.total_work.work,
            "parent_consensus_hash" => %parent_block_info.parent_consensus_hash,
            "parent_block_hash" => %anchored_block.header.parent_block,
            "parent_microblock_hash" => %anchored_block.header.parent_microblock,
            "parent_microblock_seq" => anchored_block.header.parent_microblock_sequence,
            "tip_burn_block_hash" => %self.burn_block.burn_header_hash,
            "tip_burn_block_height" => self.burn_block.block_height,
            "tip_burn_block_sortition_id" => %self.burn_block.sortition_id,
            "cur_burn_block_hash" => %cur_burn_chain_tip.burn_header_hash,
            "cur_burn_block_height" => %cur_burn_chain_tip.block_height,
            "cur_burn_block_sortition_id" => %cur_burn_chain_tip.sortition_id,
            "attempt" => attempt
        );

        let NodeConfig {
            mock_mining,
            mock_mining_output_dir,
            ..
        } = self.config.get_node_config(false);

        let res = bitcoin_controller.submit_operation(target_epoch_id, op, &mut op_signer, attempt);
        match res {
            Ok(_) => self.failed_to_submit_last_attempt = false,
            Err(_) if mock_mining => {
                debug!("Relayer: Mock-mining enabled; not sending Bitcoin transaction");
                self.failed_to_submit_last_attempt = true;
            }
            Err(BurnchainControllerError::IdenticalOperation) => {
                info!("Relayer: Block-commit already submitted");
                self.failed_to_submit_last_attempt = true;
                return None;
            }
            Err(e) => {
                warn!("Relayer: Failed to submit Bitcoin transaction: {e:?}");
                self.failed_to_submit_last_attempt = true;
                return None;
            }
        };

        let assembled_block = AssembledAnchorBlock {
            parent_consensus_hash: parent_block_info.parent_consensus_hash,
            consensus_hash: cur_burn_chain_tip.consensus_hash,
            burn_hash: cur_burn_chain_tip.burn_header_hash,
            burn_block_height: cur_burn_chain_tip.block_height,
            orig_burn_hash: self.burn_block.burn_header_hash,
            anchored_block,
            attempt,
            tenure_begin,
        };

        if mock_mining {
            let stacks_block_height = assembled_block.anchored_block.header.total_work.work;
            info!("Mock mined Stacks block {stacks_block_height}");
            if let Some(dir) = mock_mining_output_dir {
                info!("Writing mock mined Stacks block {stacks_block_height} to file");
                fs::create_dir_all(&dir).unwrap_or_else(|e| match e.kind() {
                    ErrorKind::AlreadyExists => { /* This is fine */ }
                    _ => error!("Failed to create directory '{dir:?}': {e}"),
                });
                let filename = format!("{stacks_block_height}.json");
                let filepath = dir.join(filename);
                assembled_block
                    .serialize_to_file(&filepath)
                    .unwrap_or_else(|e| match e.kind() {
                        ErrorKind::AlreadyExists => {
                            error!("Failed to overwrite file '{filepath:?}'")
                        }
                        _ => error!("Failed to write to file '{filepath:?}': {e}"),
                    });
            }
        }

        Some(MinerThreadResult::Block(
            assembled_block,
            microblock_private_key,
            bitcoin_controller.get_ongoing_commit(),
        ))
    }
}

impl RelayerThread {
    /// Instantiate off of a StacksNode, a runloop, and a relayer.
    pub fn new(runloop: &RunLoop, local_peer: LocalPeer, relayer: Relayer) -> RelayerThread {
        let config = runloop.config().clone();
        let globals = runloop.get_globals();
        let burn_db_path = config.get_burn_db_file_path();
        let stacks_chainstate_path = config.get_chainstate_path_str();
        let is_mainnet = config.is_mainnet();
        let chain_id = config.burnchain.chain_id;

        let sortdb = SortitionDB::open(&burn_db_path, true, runloop.get_burnchain().pox_constants)
            .expect("FATAL: failed to open burnchain DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: failed to open chainstate DB");

        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let mempool = MemPoolDB::open(
            is_mainnet,
            chain_id,
            &stacks_chainstate_path,
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool");

        let keychain = Keychain::default(config.node.seed.clone());
        let bitcoin_controller = BitcoinRegtestController::new_dummy(config.clone());

        RelayerThread {
            config: config.clone(),
            sortdb: Some(sortdb),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            globals,
            keychain,
            burnchain: runloop.get_burnchain(),
            last_vrf_key_burn_height: 0,
            last_mined_blocks: MinedBlocks::new(),
            bitcoin_controller,
            event_dispatcher: runloop.get_event_dispatcher(),
            local_peer,

            last_tenure_issue_time: 0,
            last_network_block_height: 0,
            last_network_block_height_ts: 0,
            last_network_download_passes: 0,
            min_network_download_passes: 0,
            last_network_inv_passes: 0,
            min_network_inv_passes: 0,

            last_tenure_consensus_hash: None,
            miner_tip: None,
            last_microblock_tenure_time: 0,
            microblock_deadline: 0,
            microblock_stream_cost: ExecutionCost::ZERO,

            relayer,

            miner_thread: None,
            mined_stacks_block: false,
        }
    }

    /// Get an immutible ref to the sortdb
    pub fn sortdb_ref(&self) -> &SortitionDB {
        self.sortdb
            .as_ref()
            .expect("FATAL: tried to access sortdb while taken")
    }

    /// Get an immutible ref to the chainstate
    pub fn chainstate_ref(&self) -> &StacksChainState {
        self.chainstate
            .as_ref()
            .expect("FATAL: tried to access chainstate while it was taken")
    }

    /// Fool the borrow checker into letting us do something with the chainstate databases.
    /// DOES NOT COMPOSE -- do NOT call this, or self.sortdb_ref(), or self.chainstate_ref(), within
    /// `func`.  You will get a runtime panic.
    pub fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut RelayerThread, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self
            .sortdb
            .take()
            .expect("FATAL: tried to take sortdb while taken");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("FATAL: tried to take chainstate while taken");
        let mut mempool = self
            .mempool
            .take()
            .expect("FATAL: tried to take mempool while taken");
        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);
        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);
        res
    }

    /// have we waited for the right conditions under which to start mining a block off of our
    /// chain tip?
    pub fn has_waited_for_latest_blocks(&self) -> bool {
        // a network download pass took place
        self.min_network_download_passes <= self.last_network_download_passes
        // we waited long enough for a download pass, but timed out waiting
        || self.last_network_block_height_ts + (self.config.node.wait_time_for_blocks as u128) < get_epoch_time_ms()
        // we're not supposed to wait at all
        || !self.config.miner.wait_for_block_download
    }

    /// Return debug string for waiting for latest blocks
    pub fn debug_waited_for_latest_blocks(&self) -> String {
        format!(
            "({} <= {} && {} <= {}) || {} + {} < {} || {}",
            self.min_network_download_passes,
            self.last_network_download_passes,
            self.min_network_inv_passes,
            self.last_network_inv_passes,
            self.last_network_block_height_ts,
            self.config.node.wait_time_for_blocks,
            get_epoch_time_ms(),
            self.config.miner.wait_for_block_download
        )
    }

    /// Handle a NetworkResult from the p2p/http state machine.  Usually this is the act of
    /// * preprocessing and storing new blocks and microblocks
    /// * relaying blocks, microblocks, and transacctions
    /// * updating unconfirmed state views
    pub fn process_network_result(&mut self, mut net_result: NetworkResult) {
        debug!(
            "Relayer: Handle network result (from {})",
            net_result.burn_height
        );

        if self.last_network_block_height != net_result.burn_height {
            // burnchain advanced; disable mining until we also do a download pass.
            self.last_network_block_height = net_result.burn_height;
            self.min_network_download_passes = net_result.num_download_passes + 1;
            self.min_network_inv_passes = net_result.num_inv_sync_passes + 1;
            self.last_network_block_height_ts = get_epoch_time_ms();
            debug!(
                "Relayer: block mining until the next download pass {}",
                self.min_network_download_passes
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let net_receipts = self.with_chainstate(|relayer_thread, sortdb, chainstate, mempool| {
            relayer_thread
                .relayer
                .process_network_result(
                    &relayer_thread.local_peer,
                    &mut net_result,
                    &relayer_thread.burnchain,
                    sortdb,
                    chainstate,
                    mempool,
                    relayer_thread.globals.sync_comms.get_ibd(),
                    Some(&relayer_thread.globals.coord_comms),
                    Some(&relayer_thread.event_dispatcher),
                )
                .expect("BUG: failure processing network results")
        });

        if net_receipts.num_new_blocks > 0 || net_receipts.num_new_confirmed_microblocks > 0 {
            // if we received any new block data that could invalidate our view of the chain tip,
            // then stop mining until we process it
            debug!("Relayer: block mining to process newly-arrived blocks or microblocks");
            signal_mining_blocked(self.globals.get_miner_status());
        }

        let mempool_txs_added = net_receipts.mempool_txs_added.len();
        if mempool_txs_added > 0 {
            self.event_dispatcher
                .process_new_mempool_txs(net_receipts.mempool_txs_added);
        }

        let num_unconfirmed_microblock_tx_receipts =
            net_receipts.processed_unconfirmed_state.receipts.len();
        if num_unconfirmed_microblock_tx_receipts > 0 {
            if let Some(unconfirmed_state) = self.chainstate_ref().unconfirmed_state.as_ref() {
                let canonical_tip = unconfirmed_state.confirmed_chain_tip;
                self.event_dispatcher.process_new_microblocks(
                    canonical_tip,
                    net_receipts.processed_unconfirmed_state,
                );
            } else {
                warn!("Relayer: oops, unconfirmed state is uninitialized but there are microblock events");
            }
        }

        // Dispatch retrieved attachments, if any.
        if net_result.has_attachments() {
            self.event_dispatcher
                .process_new_attachments(&net_result.attachments);
        }

        // synchronize unconfirmed tx index to p2p thread
        self.with_chainstate(|relayer_thread, _sortdb, chainstate, _mempool| {
            relayer_thread.globals.send_unconfirmed_txs(chainstate);
        });

        // resume mining if we blocked it, and if we've done the requisite download
        // passes
        self.last_network_download_passes = net_result.num_download_passes;
        self.last_network_inv_passes = net_result.num_inv_sync_passes;
        if self.has_waited_for_latest_blocks() {
            debug!("Relayer: did a download pass, so unblocking mining");
            signal_mining_ready(self.globals.get_miner_status());
        }
    }

    /// Process the block and microblocks from a sortition that we won.
    /// At this point, we're modifying the chainstate, and merging the artifacts from the previous tenure.
    /// Blocks until the given stacks block is processed.
    /// Returns true if we accepted this block as new.
    /// Returns false if we already processed this block.
    fn accept_winning_tenure(
        &mut self,
        anchored_block: &StacksBlock,
        consensus_hash: &ConsensusHash,
        parent_consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        if StacksChainState::has_stored_block(
            self.chainstate_ref().db(),
            &self.chainstate_ref().blocks_path,
            consensus_hash,
            &anchored_block.block_hash(),
        )? {
            // already processed my tenure
            return Ok(false);
        }
        let burn_height =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), consensus_hash)
                .map_err(|e| {
                    error!("Failed to find block snapshot for mined block: {e}");
                    e
                })?
                .ok_or_else(|| {
                    error!("Failed to find block snapshot for mined block");
                    ChainstateError::NoSuchBlockError
                })?
                .block_height;

        let ast_rules = SortitionDB::get_ast_rules(self.sortdb_ref().conn(), burn_height)?;
        let epoch_id = SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_height)?
            .expect("FATAL: no epoch defined")
            .epoch_id;

        // failsafe
        if !Relayer::static_check_problematic_relayed_block(
            self.chainstate_ref().mainnet,
            epoch_id,
            anchored_block,
            ASTRules::PrecheckSize,
        ) {
            // nope!
            warn!(
                "Our mined block {} was problematic",
                &anchored_block.block_hash()
            );
            #[cfg(any(test, feature = "testing"))]
            {
                use std::path::Path;
                if let Ok(path) = std::env::var("STACKS_BAD_BLOCKS_DIR") {
                    // record this block somewhere
                    if fs::metadata(&path).is_err() {
                        fs::create_dir_all(&path)
                            .unwrap_or_else(|_| panic!("FATAL: could not create '{path}'"));
                    }

                    let path = Path::new(&path);
                    let path = path.join(Path::new(&format!("{}", &anchored_block.block_hash())));
                    let mut file = fs::File::create(&path)
                        .unwrap_or_else(|_| panic!("FATAL: could not create '{path:?}'"));

                    let block_bits = anchored_block.serialize_to_vec();
                    let block_bits_hex = to_hex(&block_bits);
                    let block_json =
                        format!(r#"{{"block":"{block_bits_hex}","consensus":"{consensus_hash}"}}"#);
                    file.write_all(block_json.as_bytes()).unwrap_or_else(|_| {
                        panic!("FATAL: failed to write block bits to '{path:?}'")
                    });
                    info!(
                        "Fault injection: bad block {} saved to {}",
                        &anchored_block.block_hash(),
                        &path.to_str().unwrap()
                    );
                }
            }
            if !Relayer::process_mined_problematic_blocks(ast_rules, ASTRules::PrecheckSize) {
                // don't process it
                warn!(
                    "Will NOT process our problematic mined block {}",
                    &anchored_block.block_hash()
                );
                return Err(ChainstateError::NoTransactionsToMine);
            } else {
                warn!(
                    "Will process our problematic mined block {}",
                    &anchored_block.block_hash()
                )
            }
        }

        // Preprocess the anchored block
        self.with_chainstate(|_relayer_thread, sort_db, chainstate, _mempool| {
            let ic = sort_db.index_conn();
            chainstate.preprocess_anchored_block(
                &ic,
                consensus_hash,
                anchored_block,
                parent_consensus_hash,
                0,
            )
        })?;

        Ok(true)
    }

    /// Process a new block we mined
    /// Return true if we processed it
    /// Return false if we timed out waiting for it
    /// Return Err(..) if we couldn't reach the chains coordiantor thread
    fn process_new_block(&self) -> Result<bool, Error> {
        // process the block
        let stacks_blocks_processed = self.globals.coord_comms.get_stacks_blocks_processed();
        if !self.globals.coord_comms.announce_new_stacks_block() {
            return Err(Error::CoordinatorClosed);
        }
        if !self
            .globals
            .coord_comms
            .wait_for_stacks_blocks_processed(stacks_blocks_processed, u64::MAX)
        {
            // basically unreachable
            warn!("ChainsCoordinator timed out while waiting for new stacks block to be processed");
            return Ok(false);
        }
        debug!("Relayer: Stacks block has been processed");

        Ok(true)
    }

    /// Given the two miner tips, return the newer tip.
    fn pick_higher_tip(cur: Option<MinerTip>, new: Option<MinerTip>) -> Option<MinerTip> {
        match (cur, new) {
            (Some(cur), None) => Some(cur),
            (None, Some(new)) => Some(new),
            (None, None) => None,
            (Some(cur), Some(new)) => {
                if cur.stacks_height < new.stacks_height {
                    Some(new)
                } else if cur.stacks_height > new.stacks_height {
                    Some(cur)
                } else if cur.burn_height < new.burn_height {
                    Some(new)
                } else if cur.burn_height > new.burn_height {
                    Some(cur)
                } else {
                    assert_eq!(cur, new);
                    Some(cur)
                }
            }
        }
    }

    /// Given the pointer to a recently-discovered tenure, see if we won the sortition and if so,
    /// store it, preprocess it, and forward it to our neighbors.  All the while, keep track of the
    /// latest Stacks mining tip we have produced so far.
    ///
    /// Returns (true, Some(tip)) if the coordinator is still running and we have a miner tip to
    /// build on (i.e. we won this last sortition).
    ///
    /// Returns (true, None) if the coordinator is still running, and we do NOT have a miner tip to
    /// build on (i.e. we did not win this last sortition)
    ///
    /// Returns (false, _) if the coordinator could not be reached, meaning this thread should die.
    pub fn process_one_tenure(
        &mut self,
        consensus_hash: ConsensusHash,
        block_header_hash: BlockHeaderHash,
        burn_hash: BurnchainHeaderHash,
    ) -> (bool, Option<MinerTip>) {
        let mut miner_tip = None;
        let sn =
            SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), &consensus_hash)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: unknown consensus hash");

        debug!(
            "Relayer: Process tenure {consensus_hash}/{block_header_hash} in {burn_hash} burn height {}",
            sn.block_height
        );

        if let Some((last_mined_block_data, microblock_privkey)) =
            self.last_mined_blocks.remove(&block_header_hash)
        {
            // we won!
            let AssembledAnchorBlock {
                parent_consensus_hash,
                anchored_block: mined_block,
                burn_hash: mined_burn_hash,
                attempt: _,
                ..
            } = last_mined_block_data;

            let reward_block_height = mined_block.header.total_work.work + MINER_REWARD_MATURITY;
            info!(
                "Relayer: Won sortition! Mining reward will be received in {MINER_REWARD_MATURITY} blocks (block #{reward_block_height})"
            );
            debug!("Relayer: Won sortition!";
                  "stacks_header" => %block_header_hash,
                  "burn_hash" => %mined_burn_hash,
            );

            increment_stx_blocks_mined_counter();
            let has_new_data = match self.accept_winning_tenure(
                &mined_block,
                &consensus_hash,
                &parent_consensus_hash,
            ) {
                Ok(accepted) => accepted,
                Err(ChainstateError::ChannelClosed(_)) => {
                    warn!("Coordinator stopped, stopping relayer thread...");
                    return (false, None);
                }
                Err(e) => {
                    warn!("Error processing my tenure, bad block produced: {e}");
                    warn!(
                        "Bad block";
                        "stacks_header" => %block_header_hash,
                        "data" => %to_hex(&mined_block.serialize_to_vec()),
                    );
                    return (true, None);
                }
            };

            // advertize _and_ push blocks for now
            let blocks_available =
                Relayer::load_blocks_available_data(self.sortdb_ref(), vec![consensus_hash])
                    .expect("Failed to obtain block information for a block we mined.");

            let block_data = {
                let mut bd = HashMap::new();
                bd.insert(consensus_hash, mined_block.clone());
                bd
            };

            if let Err(e) = self.relayer.advertize_blocks(blocks_available, block_data) {
                warn!("Failed to advertise new block: {e}");
            }

            let snapshot = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("Failed to obtain snapshot for block")
            .expect("Failed to obtain snapshot for block");

            if !snapshot.pox_valid {
                warn!(
                    "Snapshot for {consensus_hash} is no longer valid; discarding {}...",
                    &mined_block.block_hash()
                );
                miner_tip = Self::pick_higher_tip(miner_tip, None);
            } else {
                let ch = snapshot.consensus_hash;
                let bh = mined_block.block_hash();
                let height = mined_block.header.total_work.work;

                let mut broadcast = true;
                if self.chainstate_ref().fault_injection.hide_blocks
                    && Relayer::fault_injection_is_block_hidden(
                        &mined_block.header,
                        snapshot.block_height,
                    )
                {
                    broadcast = false;
                }
                if broadcast {
                    if let Err(e) = self
                        .relayer
                        .broadcast_block(snapshot.consensus_hash, mined_block)
                    {
                        warn!("Failed to push new block: {e}");
                    }
                }

                // proceed to mine microblocks
                miner_tip = Some(MinerTip::new(
                    ch,
                    bh,
                    microblock_privkey,
                    height,
                    snapshot.block_height,
                ));
            }

            if has_new_data {
                // process the block, now that we've advertized it
                if let Err(Error::CoordinatorClosed) = self.process_new_block() {
                    // coordiantor stopped
                    return (false, None);
                }
            }
        } else {
            debug!(
                "Relayer: Did not win sortition in {burn_hash}, winning block was {consensus_hash}/{block_header_hash}"
            );
            miner_tip = None;
        }

        (true, miner_tip)
    }

    // TODO: add tests from mutation testing results #4872
    #[cfg_attr(test, mutants::skip)]
    /// Process all new tenures that we're aware of.
    /// Clear out stale tenure artifacts as well.
    /// Update the miner tip if we won the highest tenure (or clear it if we didn't).
    /// If we won any sortitions, send the block and microblock data to the p2p thread.
    /// Return true if we can still continue to run; false if not.
    pub fn process_new_tenures(
        &mut self,
        consensus_hash: ConsensusHash,
        burn_hash: BurnchainHeaderHash,
        block_header_hash: BlockHeaderHash,
    ) -> bool {
        let mut miner_tip = None;
        let mut num_sortitions = 0;

        // process all sortitions between the last-processed consensus hash and this
        // one.  ProcessTenure(..) messages can get lost.
        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to read current burnchain tip");
        let mut microblocks_disabled =
            SortitionDB::are_microblocks_disabled(self.sortdb_ref().conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        let tenures = if let Some(last_ch) = self.last_tenure_consensus_hash.as_ref() {
            let mut tenures = vec![];
            let last_sn =
                SortitionDB::get_block_snapshot_consensus(self.sortdb_ref().conn(), last_ch)
                    .expect("FATAL: failed to query sortition DB")
                    .expect("FATAL: unknown prior consensus hash");

            debug!(
                "Relayer: query tenures between burn block heights {} and {}",
                last_sn.block_height + 1,
                burn_tip.block_height + 1
            );
            for block_to_process in (last_sn.block_height + 1)..(burn_tip.block_height + 1) {
                num_sortitions += 1;
                let sn = {
                    let ic = self.sortdb_ref().index_conn();
                    SortitionDB::get_ancestor_snapshot(
                        &ic,
                        block_to_process,
                        &burn_tip.sortition_id,
                    )
                    .expect("FATAL: failed to read ancestor snapshot from sortition DB")
                    .expect("Failed to find block in fork processed by burnchain indexer")
                };
                if !sn.sortition {
                    debug!(
                        "Relayer: Skipping tenure {}/{} at burn hash/height {},{} -- no sortition",
                        &sn.consensus_hash,
                        &sn.winning_stacks_block_hash,
                        &sn.burn_header_hash,
                        sn.block_height
                    );
                    continue;
                }
                debug!(
                    "Relayer: Will process tenure {}/{} at burn hash/height {},{}",
                    &sn.consensus_hash,
                    &sn.winning_stacks_block_hash,
                    &sn.burn_header_hash,
                    sn.block_height
                );
                tenures.push((
                    sn.consensus_hash,
                    sn.burn_header_hash,
                    sn.winning_stacks_block_hash,
                ));
            }
            tenures
        } else {
            // first-ever tenure processed
            vec![(consensus_hash, burn_hash, block_header_hash)]
        };

        debug!("Relayer: will process {} tenures", &tenures.len());
        let num_tenures = tenures.len();
        if num_tenures > 0 {
            // temporarily halt mining
            debug!(
                "Relayer: block mining to process {} tenures",
                &tenures.len()
            );
            signal_mining_blocked(self.globals.get_miner_status());
        }

        for (consensus_hash, burn_hash, block_header_hash) in tenures.into_iter() {
            self.miner_thread_try_join();
            let (continue_thread, new_miner_tip) =
                self.process_one_tenure(consensus_hash, block_header_hash, burn_hash);
            if !continue_thread {
                // coordinator thread hang-up
                return false;
            }
            miner_tip = Self::pick_higher_tip(miner_tip, new_miner_tip);

            // clear all blocks up to this consensus hash
            let this_burn_tip = SortitionDB::get_block_snapshot_consensus(
                self.sortdb_ref().conn(),
                &consensus_hash,
            )
            .expect("FATAL: failed to query sortition DB")
            .expect("FATAL: no snapshot for consensus hash");

            let old_last_mined_blocks = mem::take(&mut self.last_mined_blocks);
            self.last_mined_blocks =
                Self::clear_stale_mined_blocks(this_burn_tip.block_height, old_last_mined_blocks);

            // update last-tenure pointer
            self.last_tenure_consensus_hash = Some(consensus_hash);
        }

        if let Some(mtip) = miner_tip.take() {
            // sanity check -- is this also the canonical tip?
            let (stacks_tip_consensus_hash, stacks_tip_block_hash) =
                self.with_chainstate(|_relayer_thread, sortdb, _chainstate, _| {
                    SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).expect(
                        "FATAL: failed to query sortition DB for canonical stacks chain tip hashes",
                    )
                });

            if mtip.consensus_hash != stacks_tip_consensus_hash
                || mtip.block_hash != stacks_tip_block_hash
            {
                debug!(
                    "Relayer: miner tip {}/{} is NOT canonical ({stacks_tip_consensus_hash}/{stacks_tip_block_hash})",
                    &mtip.consensus_hash,
                    &mtip.block_hash,
                );
                miner_tip = None;
            } else {
                debug!(
                    "Relayer: Microblock miner tip is now {}/{} ({})",
                    mtip.consensus_hash,
                    mtip.block_hash,
                    StacksBlockHeader::make_index_block_hash(
                        &mtip.consensus_hash,
                        &mtip.block_hash
                    )
                );

                self.with_chainstate(|relayer_thread, sortdb, chainstate, _mempool| {
                    Relayer::refresh_unconfirmed(chainstate, sortdb);
                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                });

                miner_tip = Some(mtip);
            }
        }

        // update state for microblock mining
        self.setup_microblock_mining_state(miner_tip);

        if cfg!(test)
            && std::env::var("STACKS_TEST_FORCE_MICROBLOCKS_POST_25").as_deref() == Ok("1")
        {
            debug!("Allowing miner to mine microblocks because STACKS_TEST_FORCE_MICROBLOCKS_POST_25 = 1");
            microblocks_disabled = false;
        }

        // resume mining if we blocked it
        if num_tenures > 0 || num_sortitions > 0 {
            if self.miner_tip.is_some() {
                // we won the highest tenure
                if self.config.node.mine_microblocks && !microblocks_disabled {
                    // mine a microblock first
                    self.mined_stacks_block = true;
                } else {
                    // mine a Stacks block first -- we won't build microblocks
                    self.mined_stacks_block = false;
                }
            } else {
                // mine a Stacks block first -- we didn't win
                self.mined_stacks_block = false;
            }
            signal_mining_ready(self.globals.get_miner_status());
        }
        true
    }

    /// Update the miner tip with a new tip.  If it's changed, then clear out the microblock stream
    /// cost since we won't be mining it anymore.
    fn setup_microblock_mining_state(&mut self, new_miner_tip: Option<MinerTip>) {
        // update state
        let my_miner_tip = std::mem::take(&mut self.miner_tip);
        let best_tip = Self::pick_higher_tip(my_miner_tip.clone(), new_miner_tip.clone());
        if best_tip == new_miner_tip && best_tip != my_miner_tip {
            // tip has changed
            debug!("Relayer: Best miner tip went from {my_miner_tip:?} to {new_miner_tip:?}");
            self.microblock_stream_cost = ExecutionCost::ZERO;
        }
        self.miner_tip = best_tip;
    }

    /// Try to resume microblock mining if we don't need to build an anchored block
    fn try_resume_microblock_mining(&mut self) {
        if self.miner_tip.is_some() {
            // we won the highest tenure
            if self.config.node.mine_microblocks {
                // mine a microblock first
                self.mined_stacks_block = true;
            } else {
                // mine a Stacks block first -- we won't build microblocks
                self.mined_stacks_block = false;
            }
        } else {
            // mine a Stacks block first -- we didn't win
            self.mined_stacks_block = false;
        }
    }

    /// Constructs and returns a LeaderKeyRegisterOp out of the provided params
    fn inner_generate_leader_key_register_op(
        vrf_public_key: VRFPublicKey,
        consensus_hash: &ConsensusHash,
        miner_pk: Option<&StacksPublicKey>,
    ) -> BlockstackOperationType {
        let memo = if let Some(pk) = miner_pk {
            Hash160::from_node_public_key(pk).as_bytes().to_vec()
        } else {
            vec![]
        };
        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo,
            consensus_hash: *consensus_hash,
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        })
    }

    /// Create and broadcast a VRF public key registration transaction.
    /// Returns true if we succeed in doing so; false if not.
    pub fn rotate_vrf_and_register(&mut self, burn_block: &BlockSnapshot) {
        if burn_block.block_height == self.last_vrf_key_burn_height {
            // already in-flight
            return;
        }
        let cur_epoch =
            SortitionDB::get_stacks_epoch(self.sortdb_ref().conn(), burn_block.block_height)
                .expect("FATAL: failed to query sortition DB")
                .expect("FATAL: no epoch defined")
                .epoch_id;
        let (vrf_pk, _) = self.keychain.make_vrf_keypair(burn_block.block_height);

        debug!(
            "Submit leader-key-register for {} {}",
            &vrf_pk.to_hex(),
            burn_block.block_height
        );

        let burnchain_tip_consensus_hash = &burn_block.consensus_hash;
        // if the miner has set a mining key in preparation for epoch-3.0, register it as part of their VRF key registration
        // once implemented in the nakamoto_node, this will allow miners to transition from 2.5 to 3.0 without submitting a new
        // VRF key registration.
        let miner_pk = self
            .config
            .miner
            .mining_key
            .as_ref()
            .map(StacksPublicKey::from_private);
        let op = Self::inner_generate_leader_key_register_op(
            vrf_pk,
            burnchain_tip_consensus_hash,
            miner_pk.as_ref(),
        );

        let mut one_off_signer = self.keychain.generate_op_signer();
        if let Ok(txid) =
            self.bitcoin_controller
                .submit_operation(cur_epoch, op, &mut one_off_signer, 1)
        {
            // advance key registration state
            self.last_vrf_key_burn_height = burn_block.block_height;
            self.globals
                .set_pending_leader_key_registration(burn_block.block_height, txid);
        }
    }

    /// Remove any block state we've mined for the given burnchain height.
    /// Return the filtered `last_mined_blocks`
    fn clear_stale_mined_blocks(burn_height: u64, last_mined_blocks: MinedBlocks) -> MinedBlocks {
        let mut ret = HashMap::new();
        for (stacks_bhh, (assembled_block, microblock_privkey)) in last_mined_blocks.into_iter() {
            if assembled_block.burn_block_height < burn_height {
                debug!(
                    "Stale mined block: {stacks_bhh} (as of {},{})",
                    &assembled_block.burn_hash, assembled_block.burn_block_height
                );
                continue;
            }
            debug!(
                "Mined block in-flight: {stacks_bhh} (as of {},{})",
                &assembled_block.burn_hash, assembled_block.burn_block_height
            );
            ret.insert(stacks_bhh, (assembled_block, microblock_privkey));
        }
        ret
    }

    /// Create the block miner thread state.
    /// Only proceeds if all of the following are true:
    ///   * The miner is not blocked
    ///   * `last_burn_block` corresponds to the canonical sortition DB's chain tip
    ///   * The time of issuance is sufficiently recent
    ///   * There are no unprocessed stacks blocks in the staging DB
    ///   * The relayer has already tried a download scan that included this sortition (which, if a
    ///     block was found, would have placed it into the staging DB and marked it as
    ///     unprocessed)
    ///   * A miner thread is not running already
    fn create_block_miner(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        issue_timestamp_ms: u128,
    ) -> Option<BlockMinerThread> {
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine Stacks block at this time",
                &last_burn_block.burn_header_hash
            );
            return None;
        }

        if fault_injection_skip_mining(&self.config.node.rpc_bind, last_burn_block.block_height) {
            debug!(
                "Relayer: fault injection skip mining at block height {}",
                last_burn_block.block_height
            );
            return None;
        }

        // start a new tenure
        if let Some(cur_sortition) = self.globals.get_last_sortition() {
            if last_burn_block.sortition_id != cur_sortition.sortition_id {
                debug!(
                    "Relayer: Drop stale RunTenure for {}: current sortition is for {}",
                    &last_burn_block.burn_header_hash, &cur_sortition.burn_header_hash
                );
                self.globals.counters.bump_missed_tenures();
                return None;
            }
        }

        let burn_header_hash = last_burn_block.burn_header_hash;
        let burn_chain_sn = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        let burn_chain_tip = burn_chain_sn.burn_header_hash;

        if burn_chain_tip != burn_header_hash {
            debug!(
                "Relayer: Drop stale RunTenure for {burn_header_hash}: current sortition is for {burn_chain_tip}"
            );
            self.globals.counters.bump_missed_tenures();
            return None;
        }

        let miner_config = self.config.get_miner_config();

        let has_unprocessed = BlockMinerThread::unprocessed_blocks_prevent_mining(
            &self.burnchain,
            self.sortdb_ref(),
            self.chainstate_ref(),
            miner_config.unprocessed_block_deadline_secs,
        );
        if has_unprocessed {
            debug!(
                "Relayer: Drop RunTenure for {burn_header_hash} because there are fewer than {} pending blocks",
                self.burnchain.pox_constants.prepare_length - 1
            );
            return None;
        }

        if burn_chain_sn.block_height != self.last_network_block_height
            || !self.has_waited_for_latest_blocks()
        {
            debug!("Relayer: network has not had a chance to process in-flight blocks ({} != {} || !({}))",
                    burn_chain_sn.block_height, self.last_network_block_height, self.debug_waited_for_latest_blocks());
            return None;
        }

        let tenure_cooldown = if self.config.node.mine_microblocks {
            self.config.node.wait_time_for_microblocks as u128
        } else {
            0
        };

        // no burnchain change, so only re-run block tenure every so often in order
        // to give microblocks a chance to collect
        if issue_timestamp_ms < self.last_tenure_issue_time + tenure_cooldown {
            debug!("Relayer: will NOT run tenure since issuance at {} is too fresh (wait until {} + {} = {})",
                    issue_timestamp_ms / 1000, self.last_tenure_issue_time / 1000, tenure_cooldown / 1000, (self.last_tenure_issue_time + tenure_cooldown) / 1000);
            return None;
        }

        // if we're still mining on this burn block, then do nothing
        if self.miner_thread.is_some() {
            debug!("Relayer: will NOT run tenure since miner thread is already running for burn tip {burn_chain_tip}");
            return None;
        }

        debug!(
            "Relayer: Spawn tenure thread";
            "height" => last_burn_block.block_height,
            "burn_header_hash" => %burn_header_hash,
        );

        let miner_thread_state =
            BlockMinerThread::from_relayer_thread(self, registered_key, last_burn_block);
        Some(miner_thread_state)
    }

    /// Try to start up a block miner thread with this given VRF key and current burnchain tip.
    /// Returns true if the thread was started; false if it was not (for any reason)
    #[allow(clippy::incompatible_msrv)]
    pub fn block_miner_thread_try_start(
        &mut self,
        registered_key: RegisteredKey,
        last_burn_block: BlockSnapshot,
        issue_timestamp_ms: u128,
    ) -> bool {
        if !self.miner_thread_try_join() {
            return false;
        }

        if !self.config.get_node_config(false).mock_mining {
            // mock miner can't mine microblocks yet, so don't stop it from trying multiple
            // anchored blocks
            if self.mined_stacks_block && self.config.node.mine_microblocks {
                debug!("Relayer: mined a Stacks block already; waiting for microblock miner");
                return false;
            }
        }

        let Some(mut miner_thread_state) =
            self.create_block_miner(registered_key, last_burn_block.clone(), issue_timestamp_ms)
        else {
            return false;
        };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-block-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                if let Err(e) = miner_thread_state.send_mock_miner_messages() {
                    warn!("Failed to send mock miner messages: {e}");
                }
                miner_thread_state.run_tenure()
            })
            .inspect_err(|e| error!("Relayer: Failed to start tenure thread: {e:?}"))
        {
            self.miner_thread = Some(miner_handle);
        }

        true
    }

    // TODO: add tests from mutation testing results #4872
    #[cfg_attr(test, mutants::skip)]
    /// See if we should run a microblock tenure now.
    /// Return true if so; false if not
    fn can_run_microblock_tenure(&mut self) -> bool {
        if !self.config.node.mine_microblocks {
            // not enabled
            test_debug!("Relayer: not configured to mine microblocks");
            return false;
        }

        let burn_tip = SortitionDB::get_canonical_burn_chain_tip(self.sortdb_ref().conn())
            .expect("FATAL: failed to read current burnchain tip");
        let microblocks_disabled =
            SortitionDB::are_microblocks_disabled(self.sortdb_ref().conn(), burn_tip.block_height)
                .expect("FATAL: failed to query epoch's microblock status");

        if microblocks_disabled {
            if cfg!(test)
                && std::env::var("STACKS_TEST_FORCE_MICROBLOCKS_POST_25").as_deref() == Ok("1")
            {
                debug!("Allowing miner to mine microblocks because STACKS_TEST_FORCE_MICROBLOCKS_POST_25 = 1");
            } else {
                return false;
            }
        }

        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            test_debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self.microblock_deadline > get_epoch_time_ms() {
            debug!(
                "Relayer: Too soon to start a microblock tenure ({} > {})",
                self.microblock_deadline,
                get_epoch_time_ms()
            );
            return false;
        }
        if self.miner_tip.is_none() {
            debug!("Relayer: did not win last block, so cannot mine microblocks");
            return false;
        }
        if !self.mined_stacks_block {
            // have not tried to mine a stacks block yet that confirms previously-mined unconfirmed
            // state (or have not tried to mine a new Stacks block yet for this active tenure);
            debug!("Relayer: Did not mine a block yet, so will not mine a microblock");
            return false;
        }
        if self.globals.get_last_sortition().is_none() {
            debug!("Relayer: no first sortition yet");
            return false;
        }

        // go ahead
        true
    }

    /// Start up a microblock miner thread if possible:
    ///   * No miner thread must be running already
    ///   * The miner must not be blocked
    ///   * We must have won the sortition on the Stacks chain tip
    ///
    /// Returns `true` if the thread was started; `false` if not.
    #[allow(clippy::incompatible_msrv)]
    pub fn microblock_miner_thread_try_start(&mut self) -> bool {
        let miner_tip = match self.miner_tip.as_ref() {
            Some(tip) => tip.clone(),
            None => {
                debug!("Relayer: did not win last block, so cannot mine microblocks");
                return false;
            }
        };

        let burnchain_tip = match self.globals.get_last_sortition() {
            Some(sn) => sn,
            None => {
                debug!("Relayer: no first sortition yet");
                return false;
            }
        };

        debug!(
            "Relayer: mined Stacks block {}/{} so can mine microblocks",
            &miner_tip.consensus_hash, &miner_tip.block_hash
        );

        if !self.miner_thread_try_join() {
            // already running (for an anchored block or microblock)
            debug!("Relayer: miner thread already running so cannot mine microblock");
            return false;
        }
        if self
            .globals
            .get_miner_status()
            .lock()
            .expect("FATAL: mutex poisoned")
            .is_blocked()
        {
            debug!(
                "Relayer: miner is blocked as of {}; cannot mine microblock at this time",
                &burnchain_tip.burn_header_hash
            );
            self.globals.counters.set_microblocks_processed(0);
            return false;
        }

        let parent_consensus_hash = &miner_tip.consensus_hash;
        let parent_block_hash = &miner_tip.block_hash;

        debug!("Relayer: Run microblock tenure for {parent_consensus_hash}/{parent_block_hash}");

        let Some(mut microblock_thread_state) = MicroblockMinerThread::from_relayer_thread(self)
        else {
            return false;
        };

        if let Ok(miner_handle) = thread::Builder::new()
            .name(format!("miner-microblock-{}", self.local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                Some(MinerThreadResult::Microblock(
                    microblock_thread_state.try_mine_microblock(miner_tip.clone()),
                    miner_tip,
                ))
            })
            .inspect_err(|e| error!("Relayer: Failed to start tenure thread: {e:?}"))
        {
            // thread started!
            self.miner_thread = Some(miner_handle);
            self.microblock_deadline =
                get_epoch_time_ms() + (self.config.node.microblock_frequency as u128);
        }

        true
    }

    /// Inner body of Self::miner_thread_try_join
    fn inner_miner_thread_try_join(
        &mut self,
        thread_handle: JoinHandle<Option<MinerThreadResult>>,
    ) -> Option<JoinHandle<Option<MinerThreadResult>>> {
        // tenure run already in progress; try and join
        if !thread_handle.is_finished() {
            debug!("Relayer: RunTenure thread not finished / is in-progress");
            return Some(thread_handle);
        }
        let last_mined_block_opt = thread_handle
            .join()
            .expect("FATAL: failed to join miner thread");
        if let Some(miner_result) = last_mined_block_opt {
            match miner_result {
                MinerThreadResult::Block(
                    last_mined_block,
                    microblock_privkey,
                    ongoing_commit_opt,
                ) => {
                    // finished mining a block
                    if BlockMinerThread::find_inflight_mined_blocks(
                        last_mined_block.burn_block_height,
                        &self.last_mined_blocks,
                    )
                    .is_empty()
                    {
                        // first time we've mined a block in this burnchain block
                        debug!(
                            "Bump block processed for burnchain block {}",
                            &last_mined_block.burn_block_height
                        );
                        self.globals.counters.bump_blocks_processed();
                    }

                    debug!(
                        "Relayer: RunTenure thread joined; got Stacks block {}",
                        &last_mined_block.anchored_block.block_hash()
                    );

                    let bhh = last_mined_block.burn_hash;
                    let orig_bhh = last_mined_block.orig_burn_hash;
                    let tenure_begin = last_mined_block.tenure_begin;

                    self.last_mined_blocks.insert(
                        last_mined_block.anchored_block.block_hash(),
                        (last_mined_block, microblock_privkey),
                    );

                    self.last_tenure_issue_time = get_epoch_time_ms();
                    self.bitcoin_controller
                        .set_ongoing_commit(ongoing_commit_opt);

                    debug!(
                        "Relayer: RunTenure finished at {} (in {}ms) targeting {bhh} (originally {orig_bhh})",
                        self.last_tenure_issue_time,
                        self.last_tenure_issue_time.saturating_sub(tenure_begin)
                    );

                    // this stacks block confirms all in-flight microblocks we know about,
                    // including the ones we produced.
                    self.mined_stacks_block = true;
                }
                MinerThreadResult::Microblock(microblock_result, miner_tip) => {
                    // finished mining a microblock
                    match microblock_result {
                        Ok(Some((next_microblock, new_cost))) => {
                            // apply it
                            let microblock_hash = next_microblock.block_hash();

                            let (processed_unconfirmed_state, num_mblocks) = self.with_chainstate(
                                |_relayer_thread, sortdb, chainstate, _mempool| {
                                    let processed_unconfirmed_state =
                                        Relayer::refresh_unconfirmed(chainstate, sortdb);
                                    let num_mblocks = chainstate
                                        .unconfirmed_state
                                        .as_ref()
                                        .map(|unconfirmed| unconfirmed.num_microblocks())
                                        .unwrap_or(0);

                                    (processed_unconfirmed_state, num_mblocks)
                                },
                            );

                            info!(
                                "Mined one microblock: {microblock_hash} seq {} txs {} (total processed: {num_mblocks})",
                                next_microblock.header.sequence,
                                next_microblock.txs.len()
                            );
                            self.globals.counters.set_microblocks_processed(num_mblocks);

                            let parent_index_block_hash = StacksBlockHeader::make_index_block_hash(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                            );
                            self.event_dispatcher.process_new_microblocks(
                                parent_index_block_hash,
                                processed_unconfirmed_state,
                            );

                            // send it off
                            if let Err(e) = self.relayer.broadcast_microblock(
                                &miner_tip.consensus_hash,
                                &miner_tip.block_hash,
                                next_microblock,
                            ) {
                                error!(
                                    "Failure trying to broadcast microblock {microblock_hash}: {e}"
                                );
                            }

                            self.last_microblock_tenure_time = get_epoch_time_ms();
                            self.microblock_stream_cost = new_cost;

                            // synchronise state
                            self.with_chainstate(
                                |relayer_thread, _sortdb, chainstate, _mempool| {
                                    relayer_thread.globals.send_unconfirmed_txs(chainstate);
                                },
                            );

                            // have not yet mined a stacks block that confirms this microblock, so
                            // do that on the next run
                            self.mined_stacks_block = false;
                        }
                        Ok(None) => {
                            debug!("Relayer: did not mine microblock in this tenure");

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                        Err(e) => {
                            warn!("Relayer: Failed to mine next microblock: {e:?}");

                            // switch back to block mining
                            self.mined_stacks_block = false;
                        }
                    }
                }
            }
        } else {
            // if we tried and failed to make an anchored block (e.g. because there's nothing to
            // do), then resume microblock mining
            if !self.mined_stacks_block {
                self.try_resume_microblock_mining();
            }
        }
        None
    }

    /// Try to join with the miner thread. If successful, join the thread and return `true`.
    /// Otherwise, if the thread is still running, return `false`.
    ///
    /// Updates internal state gleaned from the miner, such as:
    ///   * New Stacks block data
    ///   * New keychain state
    ///   * New metrics
    ///   * New unconfirmed state
    ///
    /// Returns `true` if joined; `false` if not.
    pub fn miner_thread_try_join(&mut self) -> bool {
        if let Some(thread_handle) = self.miner_thread.take() {
            let new_thread_handle = self.inner_miner_thread_try_join(thread_handle);
            self.miner_thread = new_thread_handle;
        }
        self.miner_thread.is_none()
    }

    /// Try loading up a saved VRF key
    pub(crate) fn load_saved_vrf_key(path: &str) -> Option<RegisteredKey> {
        let mut f = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Could not open {path}: {e:?}");
                return None;
            }
        };
        let mut registered_key_bytes = vec![];
        if let Err(e) = f.read_to_end(&mut registered_key_bytes) {
            warn!("Failed to read registered key bytes from {path}: {e:?}");
            return None;
        }

        let Ok(registered_key) = serde_json::from_slice(&registered_key_bytes) else {
            warn!("Did not load registered key from {path}: could not decode JSON");
            return None;
        };

        info!("Loaded registered key from {path}");
        Some(registered_key)
    }

    /// Top-level dispatcher
    pub fn handle_directive(&mut self, directive: RelayerDirective) -> bool {
        debug!("Relayer: received next directive");
        let continue_running = match directive {
            RelayerDirective::HandleNetResult(net_result) => {
                debug!("Relayer: directive Handle network result");
                self.process_network_result(net_result);
                debug!("Relayer: directive Handled network result");
                true
            }
            RelayerDirective::RegisterKey(last_burn_block) => {
                let mut saved_key_opt = None;
                if let Some(path) = self.config.miner.activated_vrf_key_path.as_ref() {
                    saved_key_opt = Self::load_saved_vrf_key(path);
                }
                if let Some(saved_key) = saved_key_opt {
                    self.globals.resume_leader_key(saved_key);
                } else {
                    self.rotate_vrf_and_register(&last_burn_block);
                    debug!("Relayer: directive Registered VRF key");
                }
                self.globals.counters.bump_blocks_processed();
                true
            }
            RelayerDirective::ProcessTenure(consensus_hash, burn_hash, block_header_hash) => {
                debug!("Relayer: directive Process tenures");
                let res = self.process_new_tenures(consensus_hash, burn_hash, block_header_hash);
                debug!("Relayer: directive Processed tenures");
                res
            }
            RelayerDirective::RunTenure(registered_key, last_burn_block, issue_timestamp_ms) => {
                debug!("Relayer: directive Run tenure");
                let Ok(Some(next_block_epoch)) = SortitionDB::get_stacks_epoch(
                    self.sortdb_ref().conn(),
                    last_burn_block.block_height.saturating_add(1),
                ) else {
                    warn!("Failed to load Stacks Epoch for next burn block, skipping RunTenure directive");
                    return true;
                };
                if next_block_epoch.epoch_id.uses_nakamoto_blocks() {
                    info!("Next burn block is in Nakamoto epoch, skipping RunTenure directive for 2.x node");
                    return true;
                }
                self.block_miner_thread_try_start(
                    registered_key,
                    last_burn_block,
                    issue_timestamp_ms,
                );
                debug!("Relayer: directive Ran tenure");
                true
            }
            RelayerDirective::NakamotoTenureStartProcessed(_, _) => {
                warn!("Relayer: Nakamoto tenure start notification received while still operating 2.x neon node");
                true
            }
            RelayerDirective::Exit => false,
        };
        if !continue_running {
            return false;
        }

        // see if we need to run a microblock tenure
        if self.can_run_microblock_tenure() {
            self.microblock_miner_thread_try_start();
        }
        continue_running
    }
}

impl ParentStacksBlockInfo {
    /// Determine where in the set of forks to attempt to mine the next anchored block.
    /// `mine_tip_ch` and `mine_tip_bhh` identify the parent block on top of which to mine.
    /// `check_burn_block` identifies what we believe to be the burn chain's sortition history tip.
    /// This is used to mitigate (but not eliminate) a TOCTTOU issue with mining: the caller's
    /// conception of the sortition history tip may have become stale by the time they call this
    /// method, in which case, mining should *not* happen (since the block will be invalid).
    pub fn lookup(
        chain_state: &mut StacksChainState,
        burn_db: &mut SortitionDB,
        check_burn_block: &BlockSnapshot,
        miner_address: StacksAddress,
        mine_tip_ch: &ConsensusHash,
        mine_tip_bh: &BlockHeaderHash,
    ) -> Result<ParentStacksBlockInfo, Error> {
        let stacks_tip_header = StacksChainState::get_anchored_block_header_info(
            chain_state.db(),
            mine_tip_ch,
            mine_tip_bh,
        )
        .unwrap()
        .ok_or_else(|| {
            error!(
                "Could not mine new tenure, since could not find header for known chain tip.";
                "tip_consensus_hash" => %mine_tip_ch,
                "tip_stacks_block_hash" => %mine_tip_bh
            );
            Error::HeaderNotFoundForChainTip
        })?;

        // the stacks block I'm mining off of's burn header hash and vtxindex:
        let parent_snapshot =
            SortitionDB::get_block_snapshot_consensus(burn_db.conn(), mine_tip_ch)
                .expect("Failed to look up block's parent snapshot")
                .expect("Failed to look up block's parent snapshot");

        let parent_sortition_id = &parent_snapshot.sortition_id;

        let (parent_block_height, parent_winning_vtxindex, parent_block_total_burn) = if mine_tip_ch
            == &FIRST_BURNCHAIN_CONSENSUS_HASH
        {
            (0, 0, 0)
        } else {
            let parent_winning_vtxindex =
                SortitionDB::get_block_winning_vtxindex(burn_db.conn(), parent_sortition_id)
                    .expect("SortitionDB failure.")
                    .ok_or_else(|| {
                        error!(
                            "Failed to find winning vtx index for the parent sortition";
                            "parent_sortition_id" => %parent_sortition_id
                        );
                        Error::WinningVtxNotFoundForChainTip
                    })?;

            let parent_block = SortitionDB::get_block_snapshot(burn_db.conn(), parent_sortition_id)
                .expect("SortitionDB failure.")
                .ok_or_else(|| {
                    error!(
                        "Failed to find block snapshot for the parent sortition";
                        "parent_sortition_id" => %parent_sortition_id
                    );
                    Error::SnapshotNotFoundForChainTip
                })?;

            (
                parent_block.block_height,
                parent_winning_vtxindex,
                parent_block.total_burn,
            )
        };

        // don't mine off of an old burnchain block
        let burn_chain_tip = SortitionDB::get_canonical_burn_chain_tip(burn_db.conn())
            .expect("FATAL: failed to query sortition DB for canonical burn chain tip");

        if burn_chain_tip.consensus_hash != check_burn_block.consensus_hash {
            info!(
                "New canonical burn chain tip detected. Will not try to mine.";
                "new_consensus_hash" => %burn_chain_tip.consensus_hash,
                "old_consensus_hash" => %check_burn_block.consensus_hash,
                "new_burn_height" => burn_chain_tip.block_height,
                "old_burn_height" => check_burn_block.block_height
            );
            return Err(Error::BurnchainTipChanged);
        }

        debug!("Mining tenure's last consensus hash: {} (height {} hash {}), stacks tip consensus hash: {mine_tip_ch} (height {} hash {})",
               &check_burn_block.consensus_hash, check_burn_block.block_height, &check_burn_block.burn_header_hash,
               parent_snapshot.block_height, &parent_snapshot.burn_header_hash);

        let coinbase_nonce = {
            let principal = miner_address.into();
            let account = chain_state
                .with_read_only_clarity_tx(
                    &burn_db.index_handle(&burn_chain_tip.sortition_id),
                    &StacksBlockHeader::make_index_block_hash(mine_tip_ch, mine_tip_bh),
                    |conn| StacksChainState::get_account(conn, &principal),
                )
                .unwrap_or_else(|| {
                    panic!(
                        "BUG: stacks tip block {mine_tip_ch}/{mine_tip_bh} no longer exists after we queried it"
                    )
                });
            account.nonce
        };

        Ok(ParentStacksBlockInfo {
            stacks_parent_header: stacks_tip_header,
            parent_consensus_hash: *mine_tip_ch,
            parent_block_burn_height: parent_block_height,
            parent_block_total_burn,
            parent_winning_vtxindex,
            coinbase_nonce,
        })
    }
}

/// Thread that runs the network state machine, handling both p2p and http requests.
pub struct PeerThread {
    /// Node config
    config: Config,
    /// instance of the peer network. Made optional in order to trick the borrow checker.
    net: Option<PeerNetwork>,
    /// handle to global inter-thread comms
    globals: Globals,
    /// how long to wait for network messages on each poll, in millis
    poll_timeout: u64,
    /// handle to the sortition DB (optional so we can take/replace it)
    sortdb: Option<SortitionDB>,
    /// handle to the chainstate DB (optional so we can take/replace it)
    chainstate: Option<StacksChainState>,
    /// handle to the mempool DB (optional so we can take/replace it)
    mempool: Option<MemPoolDB>,
    /// buffer of relayer commands with block data that couldn't be sent to the relayer just yet
    /// (i.e. due to backpressure).  We track this separately, instead of just using a bigger
    /// channel, because we need to know when backpressure occurs in order to throttle the p2p
    /// thread's downloader.
    results_with_data: VecDeque<RelayerDirective>,
    /// total number of p2p state-machine passes so far. Used to signal when to download the next
    /// reward cycle of blocks
    num_p2p_state_machine_passes: u64,
    /// total number of inventory state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_inv_sync_passes: u64,
    /// total number of download state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_download_passes: u64,
    /// last burnchain block seen in the PeerNetwork's chain view since the last run
    last_burn_block_height: u64,
}

impl PeerThread {
    /// set up the mempool DB connection
    pub fn connect_mempool_db(config: &Config) -> MemPoolDB {
        // create estimators, metric instances for RPC handler
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("Database failure opening mempool")
    }

    /// Instantiate the p2p thread.
    /// Binds the addresses in the config (which may panic if the port is blocked).
    /// This is so the node will crash "early" before any new threads start if there's going to be
    /// a bind error anyway.
    pub fn new(runloop: &RunLoop, net: PeerNetwork) -> PeerThread {
        Self::new_all(
            runloop.get_globals(),
            runloop.config(),
            runloop.get_burnchain().pox_constants,
            net,
        )
    }

    pub fn new_all(
        globals: Globals,
        config: &Config,
        pox_constants: PoxConstants,
        mut net: PeerNetwork,
    ) -> Self {
        let config = config.clone();
        let mempool = Self::connect_mempool_db(&config);
        let burn_db_path = config.get_burn_db_file_path();

        let sortdb = SortitionDB::open(&burn_db_path, false, pox_constants)
            .expect("FATAL: could not open sortition DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: could not open chainstate DB");

        let p2p_sock: SocketAddr = config
            .node
            .p2p_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_bind));
        let rpc_sock = config
            .node
            .rpc_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.rpc_bind));

        net.bind(&p2p_sock, &rpc_sock)
            .expect("BUG: PeerNetwork could not bind or is already bound");

        let poll_timeout = config.get_poll_time();

        PeerThread {
            config,
            net: Some(net),
            globals,
            poll_timeout,
            sortdb: Some(sortdb),
            chainstate: Some(chainstate),
            mempool: Some(mempool),
            results_with_data: VecDeque::new(),
            num_p2p_state_machine_passes: 0,
            num_inv_sync_passes: 0,
            num_download_passes: 0,
            last_burn_block_height: 0,
        }
    }

    /// Do something with mutable references to the mempool, sortdb, and chainstate
    /// Fools the borrow checker.
    /// NOT COMPOSIBLE
    fn with_chainstate<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut PeerThread, &mut SortitionDB, &mut StacksChainState, &mut MemPoolDB) -> R,
    {
        let mut sortdb = self.sortdb.take().expect("BUG: sortdb already taken");
        let mut chainstate = self
            .chainstate
            .take()
            .expect("BUG: chainstate already taken");
        let mut mempool = self.mempool.take().expect("BUG: mempool already taken");

        let res = func(self, &mut sortdb, &mut chainstate, &mut mempool);

        self.sortdb = Some(sortdb);
        self.chainstate = Some(chainstate);
        self.mempool = Some(mempool);

        res
    }

    /// Get an immutable ref to the inner network.
    /// DO NOT USE WITHIN with_network()
    fn get_network(&self) -> &PeerNetwork {
        self.net.as_ref().expect("BUG: did not replace net")
    }

    /// Do something with mutable references to the network.
    /// Fools the borrow checker.
    /// NOT COMPOSIBLE. DO NOT CALL THIS OR get_network() IN func
    fn with_network<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut PeerThread, &mut PeerNetwork) -> R,
    {
        let mut net = self.net.take().expect("BUG: net already taken");

        let res = func(self, &mut net);

        self.net = Some(net);
        res
    }

    /// Run one pass of the p2p/http state machine
    /// Return true if we should continue running passes; false if not
    #[allow(clippy::borrowed_box)]
    pub fn run_one_pass<B: BurnchainHeaderReader>(
        &mut self,
        indexer: &B,
        dns_client_opt: Option<&mut DNSClient>,
        event_dispatcher: &EventDispatcher,
        cost_estimator: &Box<dyn CostEstimator>,
        cost_metric: &Box<dyn CostMetric>,
        fee_estimator: Option<&Box<dyn FeeEstimator>>,
    ) -> bool {
        // initial block download?
        let ibd = self.globals.sync_comms.get_ibd();
        let download_backpressure = !self.results_with_data.is_empty();
        let poll_ms = if !download_backpressure && self.get_network().has_more_downloads() {
            // keep getting those blocks -- drive the downloader state-machine
            debug!(
                "P2P: backpressure: {download_backpressure}, more downloads: {}",
                self.get_network().has_more_downloads()
            );
            1
        } else {
            self.poll_timeout
        };

        // move over unconfirmed state obtained from the relayer
        self.with_chainstate(|p2p_thread, sortdb, chainstate, _mempool| {
            let _ = Relayer::setup_unconfirmed_state_readonly(chainstate, sortdb);
            p2p_thread.globals.recv_unconfirmed_txs(chainstate);
        });

        // do one pass
        let p2p_res = self.with_chainstate(|p2p_thread, sortdb, chainstate, mempool| {
            // NOTE: handler_args must be created such that it outlives the inner net.run() call and
            // doesn't ref anything within p2p_thread.
            let handler_args = RPCHandlerArgs {
                exit_at_block_height: p2p_thread.config.burnchain.process_exit_at_block_height,
                genesis_chainstate_hash: Sha256Sum::from_hex(stx_genesis::GENESIS_CHAINSTATE_HASH)
                    .unwrap(),
                event_observer: Some(event_dispatcher),
                cost_estimator: Some(cost_estimator.as_ref()),
                cost_metric: Some(cost_metric.as_ref()),
                fee_estimator: fee_estimator.map(|boxed_estimator| boxed_estimator.as_ref()),
                ..RPCHandlerArgs::default()
            };
            p2p_thread.with_network(|_, net| {
                net.run(
                    indexer,
                    sortdb,
                    chainstate,
                    mempool,
                    dns_client_opt,
                    download_backpressure,
                    ibd,
                    poll_ms,
                    &handler_args,
                )
            })
        });

        match p2p_res {
            Ok(network_result) => {
                let mut have_update = false;
                if self.num_p2p_state_machine_passes < network_result.num_state_machine_passes {
                    // p2p state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_p2p_state_pass();
                    self.num_p2p_state_machine_passes = network_result.num_state_machine_passes;
                }

                if self.num_inv_sync_passes < network_result.num_inv_sync_passes {
                    // inv-sync state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_inv_sync_pass();
                    self.num_inv_sync_passes = network_result.num_inv_sync_passes;

                    // the relayer cares about the number of inventory passes, so pass this along
                    have_update = true;
                }

                if self.num_download_passes < network_result.num_download_passes {
                    // download state-machine did a full pass.  Notify anyone listening.
                    self.globals.sync_comms.notify_download_pass();
                    self.num_download_passes = network_result.num_download_passes;

                    // the relayer cares about the number of download passes, so pass this along
                    have_update = true;
                }

                if network_result.has_data_to_store()
                    || self.last_burn_block_height != network_result.burn_height
                    || have_update
                {
                    // pass along if we have blocks, microblocks, or transactions, or a status
                    // update on the network's view of the burnchain
                    self.last_burn_block_height = network_result.burn_height;
                    self.results_with_data
                        .push_back(RelayerDirective::HandleNetResult(network_result));
                }
            }
            Err(e) => {
                // this is only reachable if the network is not instantiated correctly --
                // i.e. you didn't connect it
                panic!("P2P: Failed to process network dispatch: {e:?}");
            }
        };

        while let Some(next_result) = self.results_with_data.pop_front() {
            // have blocks, microblocks, and/or transactions (don't care about anything else),
            // or a directive to mine microblocks
            if let Err(e) = self.globals.relay_send.try_send(next_result) {
                debug!(
                    "P2P: {:?}: download backpressure detected (bufferred {})",
                    &self.get_network().local_peer,
                    self.results_with_data.len()
                );
                match e {
                    TrySendError::Full(directive) => {
                        if let RelayerDirective::RunTenure(..) = directive {
                            // can drop this
                        } else {
                            // don't lose this data -- just try it again
                            self.results_with_data.push_front(directive);
                        }
                        break;
                    }
                    TrySendError::Disconnected(_) => {
                        info!("P2P: Relayer hang up with p2p channel");
                        self.globals.signal_stop();
                        return false;
                    }
                }
            } else {
                debug!("P2P: Dispatched result to Relayer!");
            }
        }

        true
    }
}

impl StacksNode {
    /// Create a StacksPrivateKey from a given seed buffer
    pub fn make_node_private_key_from_seed(seed: &[u8]) -> StacksPrivateKey {
        let node_privkey = {
            let mut re_hashed_seed = seed.to_vec();
            let my_private_key = loop {
                match Secp256k1PrivateKey::from_slice(&re_hashed_seed[..]) {
                    Ok(sk) => break sk,
                    Err(_) => {
                        re_hashed_seed = Sha256Sum::from_data(&re_hashed_seed[..])
                            .as_bytes()
                            .to_vec()
                    }
                }
            };
            my_private_key
        };
        node_privkey
    }

    /// Set up the AST size-precheck height, if configured
    pub(crate) fn setup_ast_size_precheck(config: &Config, sortdb: &mut SortitionDB) {
        if let Some(ast_precheck_size_height) = config.burnchain.ast_precheck_size_height {
            info!(
                "Override burnchain height of {:?} to {ast_precheck_size_height}",
                ASTRules::PrecheckSize
            );
            let mut tx = sortdb
                .tx_begin()
                .expect("FATAL: failed to begin tx on sortition DB");
            SortitionDB::override_ast_rule_height(
                &mut tx,
                ASTRules::PrecheckSize,
                ast_precheck_size_height,
            )
            .expect("FATAL: failed to override AST PrecheckSize rule height");
            tx.commit()
                .expect("FATAL: failed to commit sortition DB transaction");
        }
    }

    /// Set up the mempool DB by making sure it exists.
    /// Panics on failure.
    fn setup_mempool_db(config: &Config) -> MemPoolDB {
        // force early mempool instantiation
        let cost_estimator = config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let metric = config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        MemPoolDB::open(
            config.is_mainnet(),
            config.burnchain.chain_id,
            &config.get_chainstate_path_str(),
            cost_estimator,
            metric,
        )
        .expect("BUG: failed to instantiate mempool")
    }

    /// Set up the Peer DB and update any soft state from the config file. This includes:
    ///   * Blacklisted/whitelisted nodes
    ///   * Node keys
    ///   * Bootstrap nodes
    ///
    /// Returns the instantiated `PeerDB`.
    ///
    /// Panics on failure.
    fn setup_peer_db(
        config: &Config,
        burnchain: &Burnchain,
        stackerdb_contract_ids: &[QualifiedContractIdentifier],
    ) -> PeerDB {
        let data_url = UrlString::try_from(config.node.data_url.to_string()).unwrap();
        let initial_neighbors = config.node.bootstrap_node.clone();
        if !initial_neighbors.is_empty() {
            info!(
                "Will bootstrap from peers {}",
                VecDisplay(&initial_neighbors)
            );
        } else {
            warn!("Without a peer to bootstrap from, the node will start mining a new chain");
        }

        let p2p_sock: SocketAddr = config
            .node
            .p2p_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_bind));
        let p2p_addr: SocketAddr = config
            .node
            .p2p_address
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_address));
        let node_privkey = Secp256k1PrivateKey::from_seed(&config.node.local_peer_seed);

        let mut peerdb = PeerDB::connect(
            &config.get_peer_db_file_path(),
            true,
            config.burnchain.chain_id,
            burnchain.network_id,
            Some(node_privkey),
            config.connection_options.private_key_lifetime,
            PeerAddress::from_socketaddr(&p2p_addr),
            p2p_sock.port(),
            data_url,
            &[],
            Some(&initial_neighbors),
            stackerdb_contract_ids,
        )
        .map_err(|e| {
            eprintln!("Failed to open {}: {e:?}", &config.get_peer_db_file_path());
            panic!();
        })
        .unwrap();

        // allow all bootstrap nodes
        {
            let tx = peerdb.tx_begin().unwrap();
            for initial_neighbor in initial_neighbors.iter() {
                // update peer in case public key changed
                PeerDB::update_peer(&tx, initial_neighbor).unwrap();
                PeerDB::set_allow_peer(
                    &tx,
                    initial_neighbor.addr.network_id,
                    &initial_neighbor.addr.addrbytes,
                    initial_neighbor.addr.port,
                    -1,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        if !config.node.deny_nodes.is_empty() {
            warn!("Will ignore nodes {:?}", &config.node.deny_nodes);
        }

        // deny all config-denied peers
        {
            let tx = peerdb.tx_begin().unwrap();
            for denied in config.node.deny_nodes.iter() {
                PeerDB::set_deny_peer(
                    &tx,
                    denied.addr.network_id,
                    &denied.addr.addrbytes,
                    denied.addr.port,
                    get_epoch_time_secs() + 24 * 365 * 3600,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        // update services to indicate we can support mempool sync and stackerdb
        {
            let tx = peerdb.tx_begin().unwrap();
            PeerDB::set_local_services(
                &tx,
                (ServiceFlags::RPC as u16)
                    | (ServiceFlags::RELAY as u16)
                    | (ServiceFlags::STACKERDB as u16),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        peerdb
    }

    /// Set up the PeerNetwork, but do not bind it.
    pub(crate) fn setup_peer_network(
        config: &Config,
        atlas_config: &AtlasConfig,
        burnchain: Burnchain,
    ) -> PeerNetwork {
        let sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sor/tition db");

        let epochs_vec = SortitionDB::get_stacks_epochs(sortdb.conn())
            .expect("Error while loading stacks epochs");
        let epochs = EpochList::new(&epochs_vec);

        let view = {
            let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .expect("Failed to get sortition tip");
            SortitionDB::get_burnchain_view(&sortdb.index_conn(), &burnchain, &sortition_tip)
                .unwrap()
        };

        let atlasdb =
            AtlasDB::connect(atlas_config.clone(), &config.get_atlas_db_file_path(), true).unwrap();

        let mut chainstate =
            open_chainstate_with_faults(config).expect("FATAL: could not open chainstate DB");

        let mut stackerdb_machines = HashMap::new();
        let mut stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true).unwrap();

        let mut stackerdb_configs = HashMap::new();
        for contract in config.node.stacker_dbs.iter() {
            stackerdb_configs.insert(contract.clone(), StackerDBConfig::noop());
        }
        let stackerdb_configs = stackerdbs
            .create_or_reconfigure_stackerdbs(
                &mut chainstate,
                &sortdb,
                stackerdb_configs,
                &config.connection_options,
            )
            .unwrap();

        let stackerdb_contract_ids: Vec<QualifiedContractIdentifier> =
            stackerdb_configs.keys().cloned().collect();
        for (contract_id, stackerdb_config) in stackerdb_configs {
            let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true).unwrap();
            let stacker_db_sync = StackerDBSync::new(
                contract_id.clone(),
                &stackerdb_config,
                PeerNetworkComms::new(),
                stackerdbs,
            );
            stackerdb_machines.insert(contract_id, (stackerdb_config, stacker_db_sync));
        }
        let peerdb = Self::setup_peer_db(config, &burnchain, &stackerdb_contract_ids);
        let burnchain_db = burnchain
            .open_burnchain_db(false)
            .expect("Failed to open burnchain DB");

        let local_peer = match PeerDB::get_local_peer(peerdb.conn()) {
            Ok(local_peer) => local_peer,
            _ => panic!("Unable to retrieve local peer"),
        };

        PeerNetwork::new(
            peerdb,
            atlasdb,
            stackerdbs,
            burnchain_db,
            local_peer,
            config.burnchain.peer_version,
            burnchain,
            view,
            config.connection_options.clone(),
            stackerdb_machines,
            epochs,
        )
    }

    /// Main loop of the relayer.
    /// Runs in a separate thread.
    /// Continuously receives
    pub fn relayer_main(mut relayer_thread: RelayerThread, relay_recv: Receiver<RelayerDirective>) {
        while let Ok(directive) = relay_recv.recv() {
            if !relayer_thread.globals.keep_running() {
                break;
            }

            if !relayer_thread.handle_directive(directive) {
                break;
            }
        }

        // kill miner if it's running
        signal_mining_blocked(relayer_thread.globals.get_miner_status());

        // set termination flag so other threads die
        relayer_thread.globals.signal_stop();

        debug!("Relayer exit!");
    }

    /// Main loop of the p2p thread.
    /// Runs in a separate thread.
    /// Continuously receives, until told otherwise.
    pub fn p2p_main(
        mut p2p_thread: PeerThread,
        event_dispatcher: EventDispatcher,
    ) -> Option<PeerNetwork> {
        let should_keep_running = p2p_thread.globals.should_keep_running.clone();
        let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);

        // spawn a daemon thread that runs the DNS resolver.
        // It will die when the rest of the system dies.
        {
            let _jh = thread::Builder::new()
                .name("dns-resolver".to_string())
                .spawn(move || {
                    debug!("DNS resolver thread ID is {:?}", thread::current().id());
                    dns_resolver.thread_main();
                })
                .unwrap();
        }

        // NOTE: these must be instantiated in the thread context, since it can't be safely sent
        // between threads
        let fee_estimator_opt = p2p_thread.config.make_fee_estimator();
        let cost_estimator = p2p_thread
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let cost_metric = p2p_thread
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let indexer = make_bitcoin_indexer(&p2p_thread.config, Some(should_keep_running));

        // receive until we can't reach the receiver thread
        loop {
            if !p2p_thread.globals.keep_running() {
                break;
            }
            if !p2p_thread.run_one_pass(
                &indexer,
                Some(&mut dns_client),
                &event_dispatcher,
                &cost_estimator,
                &cost_metric,
                fee_estimator_opt.as_ref(),
            ) {
                break;
            }
        }

        // kill miner
        signal_mining_blocked(p2p_thread.globals.get_miner_status());

        // set termination flag so other threads die
        p2p_thread.globals.signal_stop();

        // thread exited, so signal to the relayer thread to die.
        while let Err(TrySendError::Full(_)) = p2p_thread
            .globals
            .relay_send
            .try_send(RelayerDirective::Exit)
        {
            warn!("Failed to direct relayer thread to exit, sleeping and trying again");
            thread::sleep(Duration::from_secs(5));
        }
        info!("P2P thread exit!");
        p2p_thread.net
    }

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
    ) -> StacksNode {
        let config = runloop.config().clone();
        let is_miner = runloop.is_miner();
        let burnchain = runloop.get_burnchain();
        let atlas_config = config.atlas.clone();
        let keychain = Keychain::default(config.node.seed.clone());

        // we can call _open_ here rather than _connect_, since connect is first called in
        //   make_genesis_block
        let mut sortdb = SortitionDB::open(
            &config.get_burn_db_file_path(),
            true,
            burnchain.pox_constants.clone(),
        )
        .expect("Error while instantiating sortition db");

        Self::setup_ast_size_precheck(&config, &mut sortdb);

        let _ = Self::setup_mempool_db(&config);

        let mut p2p_net = Self::setup_peer_network(&config, &atlas_config, burnchain);

        let stackerdbs = StackerDBs::connect(&config.get_stacker_db_file_path(), true)
            .expect("FATAL: failed to connect to stacker DB");

        let relayer = Relayer::from_p2p(&mut p2p_net, stackerdbs);

        let local_peer = p2p_net.local_peer.clone();

        let NodeConfig {
            mock_mining, miner, ..
        } = config.get_node_config(false);

        // setup initial key registration
        let leader_key_registration_state = if mock_mining {
            // mock mining, pretend to have a registered key
            let (vrf_public_key, _) = keychain.make_vrf_keypair(VRF_MOCK_MINER_KEY);
            LeaderKeyRegistrationState::Active(RegisteredKey {
                target_block_height: VRF_MOCK_MINER_KEY,
                block_height: 1,
                op_vtxindex: 1,
                vrf_public_key,
                memo: vec![],
            })
        } else {
            // Warn the user that they need to set up a miner key
            if miner && config.miner.mining_key.is_none() {
                warn!("`[miner.mining_key]` not set in config file. This will be required to mine in Epoch 3.0!")
            }
            LeaderKeyRegistrationState::Inactive
        };
        globals.set_initial_leader_key_registration_state(leader_key_registration_state);

        let relayer_thread = RelayerThread::new(runloop, local_peer.clone(), relayer);

        StacksNode::set_monitoring_miner_address(&keychain, &relayer_thread);

        let relayer_thread_handle = thread::Builder::new()
            .name(format!("relayer-{}", &local_peer.data_url))
            .stack_size(BLOCK_PROCESSOR_STACK_SIZE)
            .spawn(move || {
                debug!("relayer thread ID is {:?}", thread::current().id());
                Self::relayer_main(relayer_thread, relay_recv);
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
                debug!("p2p thread ID is {:?}", thread::current().id());
                Self::p2p_main(p2p_thread, p2p_event_dispatcher)
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

    /// Manage the VRF public key registration state machine.
    /// Tell the relayer thread to fire off a tenure and a block commit op,
    /// if it is time to do so.
    /// `ibd` indicates whether or not we're in the initial block download.  Used to control when
    /// to try and register VRF keys.
    /// Called from the main thread.
    /// Return true if we succeeded in carrying out the next task of the operation.
    pub fn relayer_issue_tenure(&mut self, ibd: bool) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to issue a tenure
            return true;
        }

        if let Some(burnchain_tip) = self.globals.get_last_sortition() {
            if !ibd {
                // try and register a VRF key before issuing a tenure
                let leader_key_registration_state =
                    self.globals.get_leader_key_registration_state();
                match leader_key_registration_state {
                    LeaderKeyRegistrationState::Active(ref key) => {
                        debug!(
                            "Tenure: Using key {:?} off of {}",
                            &key.vrf_public_key, &burnchain_tip.burn_header_hash
                        );

                        self.globals
                            .relay_send
                            .send(RelayerDirective::RunTenure(
                                key.clone(),
                                burnchain_tip,
                                get_epoch_time_ms(),
                            ))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Inactive => {
                        warn!(
                            "Tenure: skipped tenure because no active VRF key. Trying to register one."
                        );
                        self.globals
                            .relay_send
                            .send(RelayerDirective::RegisterKey(burnchain_tip))
                            .is_ok()
                    }
                    LeaderKeyRegistrationState::Pending(..) => true,
                }
            } else {
                // still sync'ing so just try again later
                true
            }
        } else {
            warn!("Tenure: Do not know the last burn block. As a miner, this is bad.");
            true
        }
    }

    /// Notify the relayer of a sortition, telling it to process the block
    ///  and advertize it if it was mined by the node.
    /// returns _false_ if the relayer hung up the channel.
    /// Called from the main thread.
    pub fn relayer_sortition_notify(&self) -> bool {
        if !self.is_miner {
            // node is a follower, don't try to process my own tenure.
            return true;
        }

        if let Some(snapshot) = self.globals.get_last_sortition() {
            debug!(
                "Tenure: Notify sortition!";
                "consensus_hash" => %snapshot.consensus_hash,
                "burn_block_hash" => %snapshot.burn_header_hash,
                "winning_stacks_block_hash" => %snapshot.winning_stacks_block_hash,
                "burn_block_height" => &snapshot.block_height,
                "sortition_id" => %snapshot.sortition_id
            );
            if snapshot.sortition {
                return self
                    .globals
                    .relay_send
                    .send(RelayerDirective::ProcessTenure(
                        snapshot.consensus_hash,
                        snapshot.parent_burn_header_hash,
                        snapshot.winning_stacks_block_hash,
                    ))
                    .is_ok();
            }
        } else {
            debug!("Tenure: Notify sortition! No last burn block");
        }
        true
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
    ) -> Option<BlockSnapshot> {
        let mut last_sortitioned_block = None;

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
                last_sortitioned_block = Some((block_snapshot.clone(), op.vtxindex));
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

        self.globals.set_last_sortition(block_snapshot);
        let ret = last_sortitioned_block.map(|x| x.0);

        let num_key_registers = key_registers.len();
        debug!(
            "Processed burnchain state at height {block_height}: {num_key_registers} leader keys, {num_block_commits} block-commits (ibd = {ibd})"
        );

        // save the registered VRF key
        let activated_key_opt = self
            .globals
            .try_activate_leader_key_registration(block_height, key_registers);

        let Some(activated_key) = activated_key_opt else {
            return ret;
        };

        let Some(path) = config.miner.activated_vrf_key_path.as_ref() else {
            return ret;
        };

        info!("Activated VRF key; saving to {path}");

        let Ok(key_json) = serde_json::to_string(&activated_key) else {
            warn!("Failed to serialize VRF key");
            return ret;
        };

        let mut f = match fs::File::create(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to create {path}: {e:?}");
                return ret;
            }
        };

        if let Err(e) = f.write_all(key_json.as_bytes()) {
            warn!("Failed to write activated VRF key to {path}: {e:?}");
            return ret;
        }

        info!("Saved activated VRF key to {path}");
        ret
    }

    /// Join all inner threads
    pub fn join(self) -> Option<PeerNetwork> {
        self.relayer_thread_handle.join().unwrap();
        self.p2p_thread_handle.join().unwrap()
    }
}
