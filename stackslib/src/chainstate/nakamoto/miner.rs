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

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::{cmp, fs, mem};

use clarity::vm::analysis::{CheckError, CheckErrors};
use clarity::vm::ast::errors::ParseErrors;
use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::TransactionConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker, TrackerData};
use clarity::vm::database::BurnStateDB;
use clarity::vm::errors::Error as InterpreterError;
use clarity::vm::types::{
    QualifiedContractIdentifier, StacksAddressExtensions as ClarityStacksAddressExtensions,
    TypeSignature,
};
use libstackerdb::StackerDBChunkData;
use serde::Deserialize;
use stacks_common::codec::{read_next, write_next, Error as CodecError, StacksMessageCodec};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, TrieHash,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::get_epoch_time_ms;
use stacks_common::util::hash::{hex_bytes, Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PrivateKey};
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::{PrivateKey, PublicKey};
use crate::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionDBConn, SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::OnChainRewardSetProvider;
use crate::chainstate::nakamoto::{
    MaturedMinerRewards, NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, SetupBlockResult,
};
use crate::chainstate::stacks::address::StacksAddressExtensions;
use crate::chainstate::stacks::boot::MINERS_NAME;
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::blocks::{DummyEventDispatcher, MemPoolRejection};
use crate::chainstate::stacks::db::transactions::{
    handle_clarity_runtime_error, ClarityRuntimeTxError,
};
use crate::chainstate::stacks::db::{
    ChainstateTx, ClarityTx, MinerRewardInfo, StacksAccount, StacksBlockHeaderTypes,
    StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionEvent, StacksTransactionReceipt};
use crate::chainstate::stacks::miner::{
    BlockBuilder, BlockBuilderSettings, BlockLimitFunction, TransactionError, TransactionEvent,
    TransactionProblematic, TransactionResult, TransactionSkipped,
};
use crate::chainstate::stacks::{Error, StacksBlockHeader, *};
use crate::clarity_vm::clarity::{ClarityConnection, ClarityInstance};
use crate::core::mempool::*;
use crate::core::*;
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::CostEstimator;
use crate::monitoring::{
    set_last_mined_block_transaction_count, set_last_mined_execution_cost_observed,
};
use crate::net::relay::Relayer;
use crate::net::stackerdb::StackerDBs;
use crate::net::Error as net_error;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

/// Nakamaoto tenure information
#[derive(Debug, Default)]
pub struct NakamotoTenureInfo {
    /// Coinbase tx, if this is a new tenure
    pub coinbase_tx: Option<StacksTransaction>,
    /// Tenure change transaction from Stackers
    pub tenure_change_tx: Option<StacksTransaction>,
}

impl NakamotoTenureInfo {
    pub fn cause(&self) -> Option<TenureChangeCause> {
        self.tenure_change_tx
            .as_ref()
            .map(|tx| tx.try_as_tenure_change())?
            .map(|payload| payload.cause)
    }

    pub fn tenure_change_tx(&self) -> Option<&StacksTransaction> {
        self.tenure_change_tx.as_ref()
    }

    pub fn coinbase_tx(&self) -> Option<&StacksTransaction> {
        self.coinbase_tx.as_ref()
    }
}

pub struct NakamotoBlockBuilder {
    /// If there's a parent (i.e., not a genesis), this is Some(parent_header)
    parent_header: Option<StacksHeaderInfo>,
    /// Signed coinbase tx, if starting a new tenure
    coinbase_tx: Option<StacksTransaction>,
    /// Tenure change tx, if starting or extending a tenure
    tenure_tx: Option<StacksTransaction>,
    /// Total burn this block represents
    total_burn: u64,
    /// Matured miner rewards to process, if any.
    pub(crate) matured_miner_rewards_opt: Option<MaturedMinerRewards>,
    /// bytes of space consumed so far
    pub bytes_so_far: u64,
    /// transactions selected
    txs: Vec<StacksTransaction>,
    /// header we're filling in
    pub header: NakamotoBlockHeader,
    /// Optional soft limit for this block's budget usage
    soft_limit: Option<ExecutionCost>,
}

pub struct MinerTenureInfo<'a> {
    pub chainstate_tx: ChainstateTx<'a>,
    pub clarity_instance: &'a mut ClarityInstance,
    pub burn_tip: BurnchainHeaderHash,
    /// This is the expected burn tip height (i.e., the current burnchain tip + 1)
    ///  of the mined block
    pub burn_tip_height: u32,
    pub mainnet: bool,
    pub parent_consensus_hash: ConsensusHash,
    pub parent_header_hash: BlockHeaderHash,
    pub parent_stacks_block_height: u64,
    pub parent_burn_block_height: u32,
    pub coinbase_height: u64,
    pub cause: Option<TenureChangeCause>,
    pub active_reward_set: boot::RewardSet,
    pub tenure_block_commit_opt: Option<LeaderBlockCommitOp>,
}

impl NakamotoBlockBuilder {
    /// Make a block builder from genesis (testing only)
    pub fn new_first_block(
        tenure_change: &StacksTransaction,
        coinbase: &StacksTransaction,
    ) -> NakamotoBlockBuilder {
        NakamotoBlockBuilder {
            parent_header: None,
            total_burn: 0,
            coinbase_tx: Some(coinbase.clone()),
            tenure_tx: Some(tenure_change.clone()),
            matured_miner_rewards_opt: None,
            bytes_so_far: 0,
            txs: vec![],
            header: NakamotoBlockHeader::genesis(),
            soft_limit: None,
        }
    }

    /// Make a Nakamoto block builder appropriate for building atop the given block header
    ///
    /// * `parent_stacker_header` - the stacks header this builder's block will build off
    ///
    /// * `tenure_id_consensus_hash` - consensus hash of this tenure's burnchain block.
    ///    This is the consensus hash that goes into the block header.
    ///
    /// * `total_burn` - total BTC burnt so far in this fork.
    ///
    /// * `tenure_change` - the TenureChange tx if this is going to start or
    ///    extend a tenure
    ///
    /// * `coinbase` - the coinbase tx if this is going to start a new tenure
    ///
    /// * `bitvec_len` - the length of the bitvec of reward addresses that should be punished or not in this block.
    ///
    /// * `soft_limit` - an optional soft limit for the block's clarity cost for this block
    ///
    pub fn new(
        parent_stacks_header: &StacksHeaderInfo,
        tenure_id_consensus_hash: &ConsensusHash,
        total_burn: u64,
        tenure_change: Option<&StacksTransaction>,
        coinbase: Option<&StacksTransaction>,
        bitvec_len: u16,
        soft_limit: Option<ExecutionCost>,
    ) -> Result<NakamotoBlockBuilder, Error> {
        let next_height = parent_stacks_header
            .anchored_header
            .height()
            .checked_add(1)
            .ok_or_else(|| Error::InvalidStacksBlock("Block height exceeded u64".into()))?;
        if matches!(
            parent_stacks_header.anchored_header,
            StacksBlockHeaderTypes::Epoch2(_)
        ) {
            // building atop a stacks 2.x block.
            // we are necessarily starting a new tenure
            if tenure_change.is_none() || coinbase.is_none() {
                // not allowed
                warn!("Failed to start a Nakamoto tenure atop a Stacks 2.x block -- missing a coinbase and/or tenure");
                return Err(Error::ExpectedTenureChange);
            }
        }

        Ok(NakamotoBlockBuilder {
            parent_header: Some(parent_stacks_header.clone()),
            total_burn,
            coinbase_tx: coinbase.cloned(),
            tenure_tx: tenure_change.cloned(),
            matured_miner_rewards_opt: None,
            bytes_so_far: 0,
            txs: vec![],
            header: NakamotoBlockHeader::from_parent_empty(
                next_height,
                total_burn,
                tenure_id_consensus_hash.clone(),
                parent_stacks_header.index_block_hash(),
                bitvec_len,
                parent_stacks_header
                    .anchored_header
                    .as_stacks_nakamoto()
                    .map(|b| b.timestamp)
                    .unwrap_or(0),
            ),
            soft_limit,
        })
    }

    /// This function should be called before `tenure_begin`.
    /// It creates a MinerTenureInfo struct which owns connections to the chainstate and sortition
    /// DBs, so that block-processing is guaranteed to terminate before the lives of these handles
    /// expire.
    pub fn load_tenure_info<'a>(
        &self,
        chainstate: &'a mut StacksChainState,
        burn_dbconn: &'a SortitionHandleConn,
        cause: Option<TenureChangeCause>,
    ) -> Result<MinerTenureInfo<'a>, Error> {
        self.inner_load_tenure_info(chainstate, burn_dbconn, cause, false)
    }

    /// This function should be called before `tenure_begin`.
    /// It creates a MinerTenureInfo struct which owns connections to the chainstate and sortition
    /// DBs, so that block-processing is guaranteed to terminate before the lives of these handles
    /// expire.
    pub(crate) fn inner_load_tenure_info<'a>(
        &self,
        chainstate: &'a mut StacksChainState,
        burn_dbconn: &'a SortitionHandleConn,
        cause: Option<TenureChangeCause>,
        shadow_block: bool,
    ) -> Result<MinerTenureInfo<'a>, Error> {
        debug!("Nakamoto miner tenure begin"; "shadow" => shadow_block, "tenure_change" => ?cause);

        let Some(tenure_election_sn) =
            SortitionDB::get_block_snapshot_consensus(&burn_dbconn, &self.header.consensus_hash)?
        else {
            warn!("Could not find sortition snapshot for burn block that elected the miner";
                "consensus_hash" => %self.header.consensus_hash,
                "stacks_block_hash" => %self.header.block_hash(),
                "stacks_block_id" => %self.header.block_id()
            );
            return Err(Error::NoSuchBlockError);
        };

        let tenure_block_commit_opt = if shadow_block {
            None
        } else {
            let Some(tenure_block_commit) = SortitionDB::get_block_commit(
                &burn_dbconn,
                &tenure_election_sn.winning_block_txid,
                &tenure_election_sn.sortition_id,
            )?
            else {
                warn!("Could not find winning block commit for burn block that elected the miner";
                    "consensus_hash" => %self.header.consensus_hash,
                    "stacks_block_hash" => %self.header.block_hash(),
                    "stacks_block_id" => %self.header.block_id(),
                    "winning_txid" => %tenure_election_sn.winning_block_txid
                );
                return Err(Error::NoSuchBlockError);
            };
            Some(tenure_block_commit)
        };

        let elected_height = tenure_election_sn.block_height;
        let elected_in_cycle = burn_dbconn
            .context
            .pox_constants
            .block_height_to_reward_cycle(burn_dbconn.context.first_block_height, elected_height)
            .ok_or_else(|| {
                Error::InvalidStacksBlock(
                    "Elected in block height before first_block_height".into(),
                )
            })?;
        let rs_provider = OnChainRewardSetProvider::<DummyEventDispatcher>(None);
        let coinbase_height_of_calc = rs_provider.get_height_of_pox_calculation(
            elected_in_cycle,
            chainstate,
            burn_dbconn,
            &self.header.parent_block_id,
        ).map_err(|e| {
            warn!(
                "Cannot process Nakamoto block: could not find height at which the PoX reward set was calculated";
                "err" => ?e,
                "stacks_tip" => %self.header.parent_block_id,
                "elected_height" => elected_height,
                "elected_cycle" => elected_in_cycle
            );
            Error::NoSuchBlockError
        })?;
        let active_reward_set = rs_provider.read_reward_set_at_calculated_block(
            coinbase_height_of_calc,
            chainstate,
            &self.header.parent_block_id,
            true,
        ).map_err(|e| {
            warn!(
                "Cannot process Nakamoto block: could not load reward set that elected the block";
                "err" => ?e,
            );
            Error::NoSuchBlockError
        })?;

        // must build off of the header's consensus hash as the burnchain view, not the canonical_tip_bhh:
        let burn_sn = SortitionDB::get_block_snapshot_consensus(burn_dbconn.conn(), &self.header.consensus_hash)?
            .ok_or_else(|| {
                warn!(
                    "Could not mine. The expected burnchain consensus hash has not been processed by our SortitionDB";
                    "consensus_hash" => %self.header.consensus_hash
                );
                Error::NoSuchBlockError
            })?;
        let burn_tip = burn_sn.burn_header_hash;
        let burn_tip_height = u32::try_from(burn_sn.block_height).expect("block height overflow");

        let mainnet = chainstate.config().mainnet;

        let (chain_tip, parent_consensus_hash, parent_header_hash) = match self.parent_header {
            Some(ref header_info) => (
                header_info.clone(),
                header_info.consensus_hash.clone(),
                header_info.anchored_header.block_hash(),
            ),
            None => {
                // parent is genesis (testing only)
                (
                    StacksHeaderInfo::regtest_genesis(),
                    FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
                    FIRST_STACKS_BLOCK_HASH.clone(),
                )
            }
        };

        let parent_block_id = StacksBlockId::new(&parent_consensus_hash, &parent_header_hash);
        let parent_coinbase_height =
            NakamotoChainState::get_coinbase_height(&mut chainstate.index_conn(), &parent_block_id)
                .ok()
                .flatten()
                .unwrap_or(0);

        let new_tenure = cause == Some(TenureChangeCause::BlockFound);
        let coinbase_height = if new_tenure {
            parent_coinbase_height
                .checked_add(1)
                .expect("Blockchain overflow")
        } else {
            parent_coinbase_height
        };

        // data won't be committed, so do a concurrent transaction
        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin()?;

        Ok(MinerTenureInfo {
            chainstate_tx,
            clarity_instance,
            burn_tip,
            burn_tip_height,
            mainnet,
            parent_consensus_hash,
            parent_header_hash,
            parent_stacks_block_height: chain_tip.stacks_block_height,
            parent_burn_block_height: chain_tip.burn_header_height,
            cause,
            coinbase_height,
            active_reward_set,
            tenure_block_commit_opt,
        })
    }

    /// Begin/resume mining a (normal) tenure's transactions.
    /// Returns an open ClarityTx for mining the block.
    /// NOTE: even though we don't yet know the block hash, the Clarity VM ensures that a
    /// transaction can't query information about the _current_ block (i.e. information that is not
    /// yet known).
    pub fn tenure_begin<'a, 'b>(
        &mut self,
        burn_dbconn: &'a SortitionHandleConn,
        info: &'b mut MinerTenureInfo<'a>,
    ) -> Result<ClarityTx<'b, 'b>, Error> {
        let Some(block_commit) = info.tenure_block_commit_opt.as_ref() else {
            return Err(Error::InvalidStacksBlock(
                "Block-commit is required; cannot mine a shadow block".into(),
            ));
        };

        let SetupBlockResult {
            clarity_tx,
            matured_miner_rewards_opt,
            ..
        } = NakamotoChainState::setup_block(
            &mut info.chainstate_tx,
            info.clarity_instance,
            burn_dbconn,
            burn_dbconn.context.first_block_height,
            &burn_dbconn.context.pox_constants,
            info.parent_consensus_hash,
            info.parent_header_hash,
            info.parent_burn_block_height,
            info.burn_tip,
            info.burn_tip_height,
            info.cause == Some(TenureChangeCause::BlockFound),
            info.coinbase_height,
            info.cause == Some(TenureChangeCause::Extended),
            &self.header.pox_treatment,
            block_commit,
            &info.active_reward_set,
        )?;
        self.matured_miner_rewards_opt = matured_miner_rewards_opt;
        Ok(clarity_tx)
    }

    /// Finish up mining an epoch's transactions.
    /// Return the ExecutionCost consumed so far.
    pub fn tenure_finish(self, tx: ClarityTx) -> Result<ExecutionCost, Error> {
        let new_consensus_hash = MINER_BLOCK_CONSENSUS_HASH.clone();
        let new_block_hash = MINER_BLOCK_HEADER_HASH.clone();

        let index_block_hash =
            StacksBlockHeader::make_index_block_hash(&new_consensus_hash, &new_block_hash);

        // write out the trie...
        let consumed = tx.commit_mined_block(&index_block_hash)?;

        test_debug!("\n\nFinished mining. Trie is in mined_blocks table.\n",);

        Ok(consumed)
    }

    /// Finish constructing a Nakamoto block.
    /// The block will not be signed yet.
    /// Returns the unsigned Nakamoto block
    fn finalize_block(&mut self, clarity_tx: &mut ClarityTx) -> NakamotoBlock {
        // done!  Calculate state root and tx merkle root
        let txid_vecs: Vec<_> = self
            .txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
        let tx_merkle_root = merkle_tree.root();
        let state_root_hash = clarity_tx.seal();

        self.header.tx_merkle_root = tx_merkle_root;
        self.header.state_index_root = state_root_hash;

        let block = NakamotoBlock {
            header: self.header.clone(),
            txs: self.txs.clone(),
        };

        test_debug!(
            "\n\nMined Nakamoto block {}, {} transactions, state root is {}\n",
            block.header.block_hash(),
            block.txs.len(),
            state_root_hash
        );

        debug!(
            "Miner: mined Nakamoto block (miner hashes include zeroed signatures)";
            "consensus_hash" => %block.header.consensus_hash,
            "block_hash" => %block.header.block_hash(),
            "block_height" => block.header.chain_length,
            "num_txs" => block.txs.len(),
            "parent_block" => %block.header.parent_block_id,
            "state_root" => %state_root_hash
        );

        block
    }

    /// Finish building the Nakamoto block
    pub fn mine_nakamoto_block(&mut self, clarity_tx: &mut ClarityTx) -> NakamotoBlock {
        NakamotoChainState::finish_block(clarity_tx, self.matured_miner_rewards_opt.as_ref())
            .expect("FATAL: call to `finish_block` failed");
        self.finalize_block(clarity_tx)
    }

    /// Given access to the mempool, mine a nakamoto block.
    /// It will not be signed.
    pub fn build_nakamoto_block(
        // not directly used; used as a handle to open other chainstates
        chainstate_handle: &StacksChainState,
        burn_dbconn: &SortitionHandleConn,
        mempool: &mut MemPoolDB,
        // Stacks header we're building off of.
        parent_stacks_header: &StacksHeaderInfo,
        // tenure ID consensus hash of this block
        tenure_id_consensus_hash: &ConsensusHash,
        // the burn so far on the burnchain (i.e. from the last burnchain block)
        total_burn: u64,
        tenure_info: NakamotoTenureInfo,
        settings: BlockBuilderSettings,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
        signer_bitvec_len: u16,
    ) -> Result<(NakamotoBlock, ExecutionCost, u64, Vec<TransactionEvent>), Error> {
        let (tip_consensus_hash, tip_block_hash, tip_height) = (
            parent_stacks_header.consensus_hash.clone(),
            parent_stacks_header.anchored_header.block_hash(),
            parent_stacks_header.stacks_block_height,
        );

        debug!(
            "Build Nakamoto block off of {}/{} height {}",
            &tip_consensus_hash, &tip_block_hash, tip_height
        );

        let (mut chainstate, _) = chainstate_handle.reopen()?;

        let mut builder = NakamotoBlockBuilder::new(
            parent_stacks_header,
            tenure_id_consensus_hash,
            total_burn,
            tenure_info.tenure_change_tx(),
            tenure_info.coinbase_tx(),
            signer_bitvec_len,
            None,
        )?;

        let ts_start = get_epoch_time_ms();

        let mut miner_tenure_info =
            builder.load_tenure_info(&mut chainstate, burn_dbconn, tenure_info.cause())?;
        let mut tenure_tx = builder.tenure_begin(burn_dbconn, &mut miner_tenure_info)?;

        let block_limit = tenure_tx
            .block_limit()
            .expect("Failed to obtain block limit from miner's block connection");

        let mut soft_limit = None;
        if let Some(percentage) = settings
            .mempool_settings
            .tenure_cost_limit_per_block_percentage
        {
            // Make sure we aren't actually going to multiply by 0 or attempt to increase the block limit.
            assert!(
                (1..=100).contains(&percentage),
                "BUG: tenure_cost_limit_per_block_percentage: {percentage}%. Must be between between 1 and 100"
            );
            let mut remaining_limit = block_limit.clone();
            let cost_so_far = tenure_tx.cost_so_far();
            if remaining_limit.sub(&cost_so_far).is_ok() && remaining_limit.divide(100).is_ok() {
                remaining_limit.multiply(percentage.into()).expect(
                    "BUG: failed to multiply by {percentage} when previously divided by 100",
                );
                remaining_limit.add(&cost_so_far).expect("BUG: unexpected overflow when adding cost_so_far, which was previously checked");
                debug!(
                    "Setting soft limit for clarity cost to {percentage}% of remaining block limit";
                    "remaining_limit" => %remaining_limit,
                    "cost_so_far" => %cost_so_far,
                    "block_limit" => %block_limit,
                );
                soft_limit = Some(remaining_limit);
            };
        }

        builder.soft_limit = soft_limit;

        let initial_txs: Vec<_> = [
            tenure_info.tenure_change_tx.clone(),
            tenure_info.coinbase_tx.clone(),
        ]
        .into_iter()
        .flatten()
        .collect();

        // TODO: update this mempool check to prioritize signer vote transactions over other transactions
        let (blocked, tx_events) = match StacksBlockBuilder::select_and_apply_transactions(
            &mut tenure_tx,
            &mut builder,
            mempool,
            parent_stacks_header.stacks_block_height,
            &initial_txs,
            settings,
            event_observer,
            ASTRules::PrecheckSize,
        ) {
            Ok(x) => x,
            Err(e) => {
                warn!("Failure building block: {}", e);
                tenure_tx.rollback_block();
                return Err(e);
            }
        };

        if blocked {
            debug!(
                "Miner: block transaction selection aborted (child of {})",
                &parent_stacks_header.anchored_header.block_hash()
            );
            return Err(Error::MinerAborted);
        }

        if builder.txs.is_empty() {
            return Err(Error::NoTransactionsToMine);
        }

        // save the block so we can build microblocks off of it
        let block = builder.mine_nakamoto_block(&mut tenure_tx);
        let size = builder.bytes_so_far;
        let consumed = builder.tenure_finish(tenure_tx)?;

        let ts_end = get_epoch_time_ms();

        set_last_mined_block_transaction_count(block.txs.len() as u64);
        set_last_mined_execution_cost_observed(&consumed, &block_limit);

        info!(
            "Miner: mined Nakamoto block";
            "stacks_block_hash" => %block.header.block_hash(),
            "stacks_block_id" => %block.header.block_id(),
            "height" => block.header.chain_length,
            "tx_count" => block.txs.len(),
            "parent_block_id" => %block.header.parent_block_id,
            "block_size" => size,
            "execution_consumed" => %consumed,
            "percent_full" => block_limit.proportion_largest_dimension(&consumed),
            "assembly_time_ms" => ts_end.saturating_sub(ts_start),
            "consensus_hash" => %block.header.consensus_hash
        );

        Ok((block, consumed, size, tx_events))
    }

    pub fn get_bytes_so_far(&self) -> u64 {
        self.bytes_so_far
    }
}

impl BlockBuilder for NakamotoBlockBuilder {
    /// Append a transaction if doing so won't exceed the epoch data size.
    /// Errors out if we exceed budget, or the transaction is invalid.
    fn try_mine_tx_with_len(
        &mut self,
        clarity_tx: &mut ClarityTx,
        tx: &StacksTransaction,
        tx_len: u64,
        limit_behavior: &BlockLimitFunction,
        ast_rules: ASTRules,
    ) -> TransactionResult {
        if self.bytes_so_far + tx_len >= MAX_EPOCH_SIZE.into() {
            return TransactionResult::skipped_due_to_error(&tx, Error::BlockTooBigError);
        }

        let non_boot_code_contract_call = match &tx.payload {
            TransactionPayload::ContractCall(cc) => !cc.address.is_boot_code_addr(),
            TransactionPayload::SmartContract(..) => true,
            _ => false,
        };

        match limit_behavior {
            BlockLimitFunction::CONTRACT_LIMIT_HIT => {
                if non_boot_code_contract_call {
                    return TransactionResult::skipped(
                        &tx,
                        "BlockLimitFunction::CONTRACT_LIMIT_HIT".to_string(),
                    );
                }
            }
            BlockLimitFunction::LIMIT_REACHED => {
                return TransactionResult::skipped(
                    &tx,
                    "BlockLimitFunction::LIMIT_REACHED".to_string(),
                )
            }
            BlockLimitFunction::NO_LIMIT_HIT => {}
        };

        let quiet = !cfg!(test);
        let result = {
            // preemptively skip problematic transactions
            if let Err(e) = Relayer::static_check_problematic_relayed_tx(
                clarity_tx.config.mainnet,
                clarity_tx.get_epoch(),
                &tx,
                ast_rules,
            ) {
                info!(
                    "Detected problematic tx {} while mining; dropping from mempool",
                    tx.txid()
                );
                return TransactionResult::problematic(&tx, Error::NetError(e));
            }

            let cost_before = clarity_tx.cost_so_far();
            let (fee, receipt) =
                match StacksChainState::process_transaction(clarity_tx, tx, quiet, ast_rules) {
                    Ok(x) => x,
                    Err(e) => {
                        return parse_process_transaction_error(clarity_tx, tx, e);
                    }
                };
            let cost_after = clarity_tx.cost_so_far();
            let mut soft_limit_reached = false;
            // We only attempt to apply the soft limit to non-boot code contract calls.
            if non_boot_code_contract_call {
                if let Some(soft_limit) = self.soft_limit.as_ref() {
                    soft_limit_reached = cost_after.exceeds(soft_limit);
                }
            }

            info!("Include tx";
                  "tx" => %tx.txid(),
                  "payload" => tx.payload.name(),
                  "origin" => %tx.origin_address(),
                  "soft_limit_reached" => soft_limit_reached,
                  "cost_after" => %cost_after,
                  "cost_before" => %cost_before,
            );

            // save
            self.txs.push(tx.clone());
            TransactionResult::success_with_soft_limit(&tx, fee, receipt, soft_limit_reached)
        };

        self.bytes_so_far += tx_len;
        result
    }
}

fn parse_process_transaction_error(
    clarity_tx: &mut ClarityTx,
    tx: &StacksTransaction,
    e: Error,
) -> TransactionResult {
    let (is_problematic, e) = TransactionResult::is_problematic(&tx, e, clarity_tx.get_epoch());
    if is_problematic {
        TransactionResult::problematic(&tx, e)
    } else {
        match e {
            Error::CostOverflowError(cost_before, cost_after, total_budget) => {
                clarity_tx.reset_cost(cost_before.clone());
                if total_budget.proportion_largest_dimension(&cost_before)
                    < TX_BLOCK_LIMIT_PROPORTION_HEURISTIC
                {
                    warn!(
                            "Transaction {} consumed over {}% of block budget, marking as invalid; budget was {}",
                            tx.txid(),
                            100 - TX_BLOCK_LIMIT_PROPORTION_HEURISTIC,
                            &total_budget
                    );
                    let mut measured_cost = cost_after;
                    let measured_cost = if measured_cost.sub(&cost_before).is_ok() {
                        Some(measured_cost)
                    } else {
                        warn!("Failed to compute measured cost of a too big transaction");
                        None
                    };
                    TransactionResult::error(&tx, Error::TransactionTooBigError(measured_cost))
                } else {
                    warn!(
                        "Transaction {} reached block cost {}; budget was {}",
                        tx.txid(),
                        &cost_after,
                        &total_budget
                    );
                    TransactionResult::skipped_due_to_error(&tx, Error::BlockTooBigError)
                }
            }
            _ => TransactionResult::error(&tx, e),
        }
    }
}
