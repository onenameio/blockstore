// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::types::*;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use stacks_common::address::*;
use stacks_common::consts::FIRST_BURNCHAIN_CONSENSUS_HASH;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey};

use crate::burnchains::tests::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::Error as CoordinatorError;
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::db::blocks::test::store_staging_block;
use crate::chainstate::stacks::db::test::*;
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::{
    Error as ChainstateError, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::test::*;
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

pub mod accounting;
pub mod block_construction;
pub mod chain_histories;

pub const COINBASE: u128 = 500 * 1_000_000;

pub fn coinbase_total_at(stacks_height: u64) -> u128 {
    if stacks_height > MINER_REWARD_MATURITY {
        COINBASE * ((stacks_height - MINER_REWARD_MATURITY) as u128)
    } else {
        0
    }
}

pub fn path_join(dir: &str, path: &str) -> String {
    // force path to be relative
    let tail = if !path.starts_with("/") {
        path.to_string()
    } else {
        String::from_utf8(path.as_bytes()[1..].to_vec()).unwrap()
    };

    let p = PathBuf::from(dir);
    let res = p.join(PathBuf::from(tail));
    res.to_str().unwrap().to_string()
}

// copy src to dest
pub fn copy_dir(src_dir: &str, dest_dir: &str) -> Result<(), io::Error> {
    eprintln!("Copy directory {src_dir} to {dest_dir}");

    let mut dir_queue = VecDeque::new();
    dir_queue.push_back("/".to_string());

    while !dir_queue.is_empty() {
        let next_dir = dir_queue.pop_front().unwrap();
        let next_src_dir = path_join(&src_dir, &next_dir);
        let next_dest_dir = path_join(&dest_dir, &next_dir);

        eprintln!("mkdir {next_dest_dir}");
        fs::create_dir_all(&next_dest_dir)?;

        for dirent_res in fs::read_dir(&next_src_dir)? {
            let dirent = dirent_res?;
            let path = dirent.path();
            let md = fs::metadata(&path)?;
            if md.is_dir() {
                let frontier = path_join(&next_dir, &dirent.file_name().to_str().unwrap());
                eprintln!("push {frontier}");
                dir_queue.push_back(frontier);
            } else {
                let dest_path = path_join(&next_dest_dir, &dirent.file_name().to_str().unwrap());
                eprintln!("copy {} to {dest_path}", &path.to_str().unwrap());
                fs::copy(path, dest_path)?;
            }
        }
    }
    Ok(())
}

// one point per round
pub struct TestMinerTracePoint {
    pub fork_snapshots: HashMap<usize, BlockSnapshot>, // map miner ID to snapshot
    pub stacks_blocks: HashMap<usize, StacksBlock>,    // map miner ID to stacks block
    pub microblocks: HashMap<usize, Vec<StacksMicroblock>>, // map miner ID to microblocks
    pub block_commits: HashMap<usize, LeaderBlockCommitOp>, // map miner ID to block commit
    pub miner_node_map: HashMap<usize, String>,        // map miner ID to the node it worked on
}

impl TestMinerTracePoint {
    pub fn new() -> TestMinerTracePoint {
        TestMinerTracePoint {
            fork_snapshots: HashMap::new(),
            stacks_blocks: HashMap::new(),
            microblocks: HashMap::new(),
            block_commits: HashMap::new(),
            miner_node_map: HashMap::new(),
        }
    }

    pub fn add(
        &mut self,
        miner_id: usize,
        node_name: String,
        fork_snapshot: BlockSnapshot,
        stacks_block: StacksBlock,
        microblocks: Vec<StacksMicroblock>,
        block_commit: LeaderBlockCommitOp,
    ) {
        self.fork_snapshots.insert(miner_id, fork_snapshot);
        self.stacks_blocks.insert(miner_id, stacks_block);
        self.microblocks.insert(miner_id, microblocks);
        self.block_commits.insert(miner_id, block_commit);
        self.miner_node_map.insert(miner_id, node_name);
    }

    pub fn get_block_snapshot(&self, miner_id: usize) -> Option<BlockSnapshot> {
        self.fork_snapshots.get(&miner_id).cloned()
    }

    pub fn get_stacks_block(&self, miner_id: usize) -> Option<StacksBlock> {
        self.stacks_blocks.get(&miner_id).cloned()
    }

    pub fn get_microblocks(&self, miner_id: usize) -> Option<Vec<StacksMicroblock>> {
        self.microblocks.get(&miner_id).cloned()
    }

    pub fn get_block_commit(&self, miner_id: usize) -> Option<LeaderBlockCommitOp> {
        self.block_commits.get(&miner_id).cloned()
    }

    pub fn get_node_name(&self, miner_id: usize) -> Option<String> {
        self.miner_node_map.get(&miner_id).cloned()
    }

    pub fn get_miner_ids(&self) -> Vec<usize> {
        let mut miner_ids = HashSet::new();
        for miner_id in self.fork_snapshots.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.stacks_blocks.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.microblocks.keys() {
            miner_ids.insert(*miner_id);
        }
        for miner_id in self.block_commits.keys() {
            miner_ids.insert(*miner_id);
        }
        let mut ret = vec![];
        for miner_id in miner_ids.iter() {
            ret.push(*miner_id);
        }
        ret
    }
}

pub struct TestMinerTrace {
    pub points: Vec<TestMinerTracePoint>,
    pub burn_node: TestBurnchainNode,
    pub miners: Vec<TestMiner>,
}

impl TestMinerTrace {
    pub fn new(
        burn_node: TestBurnchainNode,
        miners: Vec<TestMiner>,
        points: Vec<TestMinerTracePoint>,
    ) -> TestMinerTrace {
        TestMinerTrace {
            points,
            burn_node,
            miners,
        }
    }

    /// how many blocks represented here?
    pub fn get_num_blocks(&self) -> usize {
        let mut num_blocks = 0;
        for p in self.points.iter() {
            for miner_id in p.stacks_blocks.keys() {
                if p.stacks_blocks.contains_key(miner_id) {
                    num_blocks += 1;
                }
            }
        }
        num_blocks
    }

    /// how many sortitions represented here?
    pub fn get_num_sortitions(&self) -> usize {
        let mut num_sortitions = 0;
        for p in self.points.iter() {
            for miner_id in p.fork_snapshots.keys() {
                if p.fork_snapshots.contains_key(miner_id) {
                    num_sortitions += 1;
                }
            }
        }
        num_sortitions
    }

    /// how many rounds did this trace go for?
    pub fn rounds(&self) -> usize {
        self.points.len()
    }

    /// what are the chainstate directories?
    pub fn get_test_names(&self) -> Vec<String> {
        let mut all_test_names = HashSet::new();
        for p in self.points.iter() {
            for miner_id in p.miner_node_map.keys() {
                if let Some(test_name) = p.miner_node_map.get(miner_id) {
                    if !all_test_names.contains(test_name) {
                        all_test_names.insert(test_name.to_owned());
                    }
                }
            }
        }
        let mut ret = vec![];
        for name in all_test_names.drain() {
            ret.push(name.to_owned());
        }
        ret
    }
}

pub struct TestStacksNode {
    pub chainstate: StacksChainState,
    pub prev_keys: Vec<LeaderKeyRegisterOp>, // _all_ keys generated
    pub key_ops: HashMap<VRFPublicKey, usize>, // map VRF public keys to their locations in the prev_keys array
    pub anchored_blocks: Vec<StacksBlock>,
    pub microblocks: Vec<Vec<StacksMicroblock>>,
    pub nakamoto_blocks: Vec<Vec<NakamotoBlock>>,
    pub commit_ops: HashMap<BlockHeaderHash, usize>,
    pub nakamoto_commit_ops: HashMap<StacksBlockId, usize>,
    pub test_name: String,
    forkable: bool,
}

impl TestStacksNode {
    pub fn new(
        mainnet: bool,
        chain_id: u32,
        test_name: &str,
        mut initial_balance_recipients: Vec<StacksAddress>,
    ) -> TestStacksNode {
        initial_balance_recipients.sort();
        let initial_balances = initial_balance_recipients
            .into_iter()
            .map(|addr| (addr, 10_000_000_000))
            .collect();
        let chainstate =
            instantiate_chainstate_with_balances(mainnet, chain_id, test_name, initial_balances);
        TestStacksNode {
            chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: test_name.to_string(),
            forkable: true,
        }
    }

    pub fn open(mainnet: bool, chain_id: u32, test_name: &str) -> TestStacksNode {
        let chainstate = open_chainstate(mainnet, chain_id, test_name);
        TestStacksNode {
            chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: test_name.to_string(),
            forkable: true,
        }
    }

    pub fn from_chainstate(chainstate: StacksChainState) -> TestStacksNode {
        TestStacksNode {
            chainstate,
            prev_keys: vec![],
            key_ops: HashMap::new(),
            anchored_blocks: vec![],
            microblocks: vec![],
            nakamoto_blocks: vec![],
            commit_ops: HashMap::new(),
            nakamoto_commit_ops: HashMap::new(),
            test_name: "".to_string(),
            forkable: false,
        }
    }

    // NOTE: can't do this if instantiated via from_chainstate()
    pub fn fork(&self, new_test_name: &str) -> TestStacksNode {
        if !self.forkable {
            panic!("Tried to fork an unforkable chainstate instance");
        }

        match fs::metadata(&chainstate_path(new_test_name)) {
            Ok(_) => {
                fs::remove_dir_all(&chainstate_path(new_test_name)).unwrap();
            }
            Err(_) => {}
        }

        copy_dir(
            &chainstate_path(&self.test_name),
            &chainstate_path(new_test_name),
        )
        .unwrap();
        let chainstate = open_chainstate(
            self.chainstate.mainnet,
            self.chainstate.chain_id,
            new_test_name,
        );
        TestStacksNode {
            chainstate,
            prev_keys: self.prev_keys.clone(),
            key_ops: self.key_ops.clone(),
            anchored_blocks: self.anchored_blocks.clone(),
            microblocks: self.microblocks.clone(),
            nakamoto_blocks: self.nakamoto_blocks.clone(),
            commit_ops: self.commit_ops.clone(),
            nakamoto_commit_ops: self.nakamoto_commit_ops.clone(),
            test_name: new_test_name.to_string(),
            forkable: true,
        }
    }

    pub fn next_burn_block(
        sortdb: &mut SortitionDB,
        fork: &mut TestBurnchainFork,
    ) -> TestBurnchainBlock {
        let burn_block = {
            let ic = sortdb.index_conn();
            fork.next_block(&ic)
        };
        burn_block
    }

    pub fn add_key_register(
        &mut self,
        block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
    ) -> LeaderKeyRegisterOp {
        let key_register_op = block.add_leader_key_register(miner);
        self.prev_keys.push(key_register_op.clone());
        self.key_ops
            .insert(key_register_op.public_key.clone(), self.prev_keys.len() - 1);
        key_register_op
    }

    pub fn add_key_register_op(&mut self, op: &LeaderKeyRegisterOp) {
        self.prev_keys.push(op.clone());
        self.key_ops
            .insert(op.public_key.clone(), self.prev_keys.len() - 1);
    }

    pub fn add_block_commit(
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        block_hash: &BlockHeaderHash,
        burn_amount: u64,
        key_op: &LeaderKeyRegisterOp,
        parent_block_snapshot: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        let block_commit_op = {
            let ic = sortdb.index_conn();
            let parent_snapshot = burn_block.parent_snapshot.clone();
            burn_block.add_leader_block_commit(
                &ic,
                miner,
                block_hash,
                burn_amount,
                key_op,
                Some(&parent_snapshot),
                parent_block_snapshot,
            )
        };
        block_commit_op
    }

    pub fn get_last_key(&self, miner: &TestMiner) -> LeaderKeyRegisterOp {
        let last_vrf_pubkey = miner.last_VRF_public_key().unwrap();
        let idx = *self.key_ops.get(&last_vrf_pubkey).unwrap();
        self.prev_keys[idx].clone()
    }

    pub fn get_last_anchored_block(&self, miner: &TestMiner) -> Option<StacksBlock> {
        let mut num_commits = miner.num_block_commits();
        if num_commits == 0 {
            return None;
        }

        while num_commits > 0 {
            num_commits -= 1;
            match miner.block_commit_at(num_commits) {
                None => {
                    continue;
                }
                Some(block_commit_op) => {
                    match self.commit_ops.get(&block_commit_op.block_header_hash) {
                        None => {
                            continue;
                        }
                        Some(idx) => {
                            return Some(self.anchored_blocks[*idx].clone());
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_last_accepted_anchored_block(
        &self,
        sortdb: &SortitionDB,
        miner: &TestMiner,
    ) -> Option<StacksBlock> {
        for bc in miner.block_commits.iter().rev() {
            let consensus_hash = match SortitionDB::get_block_snapshot(
                sortdb.conn(),
                &SortitionId::stubbed(&bc.burn_header_hash),
            )
            .unwrap()
            {
                Some(sn) => sn.consensus_hash,
                None => {
                    continue;
                }
            };

            if StacksChainState::has_stored_block(
                self.chainstate.db(),
                &self.chainstate.blocks_path,
                &consensus_hash,
                &bc.block_header_hash,
            )
            .unwrap()
                && !StacksChainState::is_block_orphaned(
                    self.chainstate.db(),
                    &consensus_hash,
                    &bc.block_header_hash,
                )
                .unwrap()
            {
                match self.commit_ops.get(&bc.block_header_hash) {
                    None => {
                        continue;
                    }
                    Some(idx) => {
                        return Some(self.anchored_blocks[*idx].clone());
                    }
                }
            }
        }
        return None;
    }

    pub fn get_microblock_stream(
        &self,
        miner: &TestMiner,
        block_hash: &BlockHeaderHash,
    ) -> Option<Vec<StacksMicroblock>> {
        match self.commit_ops.get(block_hash) {
            None => None,
            Some(idx) => Some(self.microblocks[*idx].clone()),
        }
    }

    pub fn get_anchored_block(&self, block_hash: &BlockHeaderHash) -> Option<StacksBlock> {
        match self.commit_ops.get(block_hash) {
            None => None,
            Some(idx) => Some(self.anchored_blocks[*idx].clone()),
        }
    }

    pub fn get_last_winning_snapshot(
        ic: &SortitionDBConn,
        fork_tip: &BlockSnapshot,
        miner: &TestMiner,
    ) -> Option<BlockSnapshot> {
        for commit_op in miner.block_commits.iter().rev() {
            match SortitionDB::get_block_snapshot_for_winning_stacks_block(
                ic,
                &fork_tip.sortition_id,
                &commit_op.block_header_hash,
            )
            .unwrap()
            {
                Some(sn) => {
                    return Some(sn);
                }
                None => {}
            }
        }
        return None;
    }

    pub fn get_miner_balance(clarity_tx: &mut ClarityTx, addr: &StacksAddress) -> u128 {
        clarity_tx.with_clarity_db_readonly(|db| {
            db.get_account_stx_balance(&StandardPrincipalData::from(addr.clone()).into())
                .unwrap()
                .amount_unlocked()
        })
    }

    pub fn make_tenure_commitment(
        &mut self,
        sortdb: &SortitionDB,
        burn_block: &mut TestBurnchainBlock,
        miner: &mut TestMiner,
        stacks_block: &StacksBlock,
        microblocks: Vec<StacksMicroblock>,
        burn_amount: u64,
        miner_key: &LeaderKeyRegisterOp,
        parent_block_snapshot_opt: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        self.anchored_blocks.push(stacks_block.clone());
        self.microblocks.push(microblocks);

        test_debug!(
            "Miner {}: Commit to stacks block {} (work {},{})",
            miner.id,
            stacks_block.block_hash(),
            stacks_block.header.total_work.burn,
            stacks_block.header.total_work.work
        );

        // send block commit for this block
        let block_commit_op = TestStacksNode::add_block_commit(
            sortdb,
            burn_block,
            miner,
            &stacks_block.block_hash(),
            burn_amount,
            miner_key,
            parent_block_snapshot_opt,
        );

        test_debug!(
            "Miner {}: Block commit transaction builds on {},{} (parent snapshot is {parent_block_snapshot_opt:?})",
            miner.id,
            block_commit_op.parent_block_ptr,
            block_commit_op.parent_vtxindex
        );
        self.commit_ops.insert(
            block_commit_op.block_header_hash.clone(),
            self.anchored_blocks.len() - 1,
        );
        block_commit_op
    }

    /// Mine a single Stacks block and a microblock stream.
    /// Produce its block-commit.
    pub fn mine_stacks_block<F>(
        &mut self,
        sortdb: &SortitionDB,
        miner: &mut TestMiner,
        burn_block: &mut TestBurnchainBlock,
        miner_key: &LeaderKeyRegisterOp,
        parent_stacks_block: Option<&StacksBlock>,
        burn_amount: u64,
        block_assembler: F,
    ) -> (StacksBlock, Vec<StacksMicroblock>, LeaderBlockCommitOp)
    where
        F: FnOnce(
            StacksBlockBuilder,
            &mut TestMiner,
            &SortitionDB,
        ) -> (StacksBlock, Vec<StacksMicroblock>),
    {
        let proof = miner
            .make_proof(
                &miner_key.public_key,
                &burn_block.parent_snapshot.sortition_hash,
            )
            .expect(&format!(
                "FATAL: no private key for {}",
                miner_key.public_key.to_hex()
            ));

        let (builder, parent_block_snapshot_opt) = match parent_stacks_block {
            None => {
                // first stacks block
                let builder = StacksBlockBuilder::first(
                    miner.id,
                    &burn_block.parent_snapshot.consensus_hash,
                    &burn_block.parent_snapshot.burn_header_hash,
                    burn_block.parent_snapshot.block_height as u32,
                    burn_block.parent_snapshot.burn_header_timestamp,
                    &proof,
                    &miner.next_microblock_privkey(),
                );
                (builder, None)
            }
            Some(parent_stacks_block) => {
                // building off an existing stacks block
                let parent_stacks_block_snapshot = {
                    let ic = sortdb.index_conn();
                    let parent_stacks_block_snapshot =
                        SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &burn_block.parent_snapshot.sortition_id,
                            &parent_stacks_block.block_hash(),
                        )
                        .unwrap()
                        .unwrap();
                    let burned_last =
                        SortitionDB::get_block_burn_amount(&ic, &burn_block.parent_snapshot)
                            .unwrap();
                    parent_stacks_block_snapshot
                };

                let parent_chain_tip = StacksChainState::get_anchored_block_header_info(
                    self.chainstate.db(),
                    &parent_stacks_block_snapshot.consensus_hash,
                    &parent_stacks_block.header.block_hash(),
                )
                .unwrap()
                .unwrap();

                let new_work = StacksWorkScore {
                    burn: parent_stacks_block_snapshot.total_burn,
                    work: parent_stacks_block
                        .header
                        .total_work
                        .work
                        .checked_add(1)
                        .expect("FATAL: stacks block height overflow"),
                };

                test_debug!(
                    "Work in {} {}: {},{}",
                    burn_block.block_height,
                    burn_block.parent_snapshot.burn_header_hash,
                    new_work.burn,
                    new_work.work
                );
                let builder = StacksBlockBuilder::from_parent(
                    miner.id,
                    &parent_chain_tip,
                    &new_work,
                    &proof,
                    &miner.next_microblock_privkey(),
                );
                (builder, Some(parent_stacks_block_snapshot))
            }
        };

        test_debug!(
            "Miner {}: Assemble stacks block from {}",
            miner.id,
            miner.origin_address().unwrap().to_string()
        );

        let (stacks_block, microblocks) = block_assembler(builder, miner, sortdb);
        let block_commit_op = self.make_tenure_commitment(
            sortdb,
            burn_block,
            miner,
            &stacks_block,
            microblocks.clone(),
            burn_amount,
            miner_key,
            parent_block_snapshot_opt.as_ref(),
        );

        (stacks_block, microblocks, block_commit_op)
    }
}

/// Return Some(bool) to indicate whether or not the anchored block was accepted into the queue.
/// Return None if the block was not submitted at all.
pub fn preprocess_stacks_block_data(
    node: &mut TestStacksNode,
    burn_node: &mut TestBurnchainNode,
    fork_snapshot: &BlockSnapshot,
    stacks_block: &StacksBlock,
    stacks_microblocks: &[StacksMicroblock],
    block_commit_op: &LeaderBlockCommitOp,
) -> Option<bool> {
    let block_hash = stacks_block.block_hash();

    let ic = burn_node.sortdb.index_conn();
    let ch_opt = SortitionDB::get_block_commit_parent(
        &ic,
        block_commit_op.parent_block_ptr.into(),
        block_commit_op.parent_vtxindex.into(),
        &fork_snapshot.sortition_id,
    )
    .unwrap();
    let parent_block_consensus_hash = match ch_opt {
        Some(parent_commit) => {
            let db_handle = SortitionHandleConn::open_reader(
                &ic,
                &SortitionId::stubbed(&block_commit_op.burn_header_hash),
            )
            .unwrap();
            let sn = db_handle
                .get_block_snapshot(&parent_commit.burn_header_hash)
                .unwrap()
                .unwrap();
            sn.consensus_hash
        }
        None => {
            // only allowed if this is the first-ever block in the stacks fork
            assert_eq!(block_commit_op.parent_block_ptr, 0);
            assert_eq!(block_commit_op.parent_vtxindex, 0);
            assert!(stacks_block.header.is_first_mined());

            FIRST_BURNCHAIN_CONSENSUS_HASH.clone()
        }
    };

    let commit_snapshot = match SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &ic,
        &fork_snapshot.sortition_id,
        &block_hash,
    )
    .unwrap()
    {
        Some(sn) => sn,
        None => {
            test_debug!("Block commit did not win sorition: {block_commit_op:?}");
            return None;
        }
    };

    // "discover" this stacks block
    test_debug!(
        "\n\nPreprocess Stacks block {}/{block_hash} ({})",
        &commit_snapshot.consensus_hash,
        StacksBlockHeader::make_index_block_hash(&commit_snapshot.consensus_hash, &block_hash)
    );
    let block_res = node
        .chainstate
        .preprocess_anchored_block(
            &ic,
            &commit_snapshot.consensus_hash,
            &stacks_block,
            &parent_block_consensus_hash,
            5,
        )
        .unwrap();

    // "discover" this stacks microblock stream
    for mblock in stacks_microblocks.iter() {
        test_debug!(
            "Preprocess Stacks microblock {block_hash}-{} (seq {})",
            mblock.block_hash(),
            mblock.header.sequence
        );
        match node.chainstate.preprocess_streamed_microblock(
            &commit_snapshot.consensus_hash,
            &stacks_block.block_hash(),
            mblock,
        ) {
            Ok(_) => {}
            Err(_) => {
                return Some(false);
            }
        }
    }

    Some(block_res)
}

/// Verify that the stacks block's state root matches the state root in the chain state
pub fn check_block_state_index_root(
    chainstate: &mut StacksChainState,
    consensus_hash: &ConsensusHash,
    stacks_header: &StacksBlockHeader,
) -> bool {
    let index_block_hash =
        StacksBlockHeader::make_index_block_hash(consensus_hash, &stacks_header.block_hash());
    let mut state_root_index =
        StacksChainState::open_index(&chainstate.clarity_state_index_path).unwrap();
    let state_root = state_root_index
        .borrow_storage_backend()
        .read_block_root_hash(&index_block_hash)
        .unwrap();
    test_debug!(
        "checking {consensus_hash}/{} state root: expecting {}, got {state_root}",
        &stacks_header.block_hash(),
        &stacks_header.state_index_root
    );
    state_root == stacks_header.state_index_root
}

/// Verify that the miner got the expected block reward
pub fn check_mining_reward(
    clarity_tx: &mut ClarityTx,
    miner: &mut TestMiner,
    block_height: u64,
    prev_block_rewards: &[Vec<MinerPaymentSchedule>],
) -> bool {
    let mut block_rewards = HashMap::new();
    let mut stream_rewards = HashMap::new();
    let mut heights = HashMap::new();
    let mut confirmed = HashSet::new();
    for (i, reward_list) in prev_block_rewards.iter().enumerate() {
        for reward in reward_list.iter() {
            let ibh = StacksBlockHeader::make_index_block_hash(
                &reward.consensus_hash,
                &reward.block_hash,
            );
            if reward.coinbase > 0 {
                block_rewards.insert(ibh.clone(), reward.clone());
            }
            if let MinerPaymentTxFees::Epoch2 { streamed, .. } = &reward.tx_fees {
                if *streamed > 0 {
                    stream_rewards.insert(ibh.clone(), reward.clone());
                }
            }
            heights.insert(ibh.clone(), i);
            confirmed.insert((
                StacksBlockHeader::make_index_block_hash(
                    &reward.parent_consensus_hash,
                    &reward.parent_block_hash,
                ),
                i,
            ));
        }
    }

    // what was the miner's total spend?
    let miner_nonce = clarity_tx.with_clarity_db_readonly(|db| {
        db.get_account_nonce(&StandardPrincipalData::from(miner.origin_address().unwrap()).into())
            .unwrap()
    });

    let mut spent_total = 0;
    for (nonce, spent) in miner.spent_at_nonce.iter() {
        if *nonce < miner_nonce {
            spent_total += *spent;
        }
    }

    let mut total: u128 = 10_000_000_000 - spent_total;
    test_debug!(
        "Miner {} has spent {spent_total} in total so far",
        &miner.origin_address().unwrap()
    );

    if block_height >= MINER_REWARD_MATURITY {
        for (i, prev_block_reward) in prev_block_rewards.iter().enumerate() {
            if i as u64 > block_height - MINER_REWARD_MATURITY {
                break;
            }
            let mut found = false;
            for recipient in prev_block_reward {
                if recipient.address == miner.origin_address().unwrap() {
                    let (anchored, streamed) = match &recipient.tx_fees {
                        MinerPaymentTxFees::Epoch2 { anchored, streamed } => (anchored, streamed),
                        _ => panic!("Expected Epoch2 style miner rewards"),
                    };
                    let reward = recipient.coinbase + anchored + (3 * streamed / 5);

                    test_debug!(
                        "Miner {} received a reward {reward} = {} + {anchored} + {} at block {i}",
                        &recipient.address.to_string(),
                        recipient.coinbase,
                        (3 * streamed / 5),
                    );
                    total += reward;
                    found = true;
                }
            }
            if !found {
                test_debug!(
                    "Miner {} received no reward at block {i}",
                    miner.origin_address().unwrap()
                );
            }
        }

        for (parent_block, confirmed_block_height) in confirmed.into_iter() {
            if confirmed_block_height as u64 > block_height - MINER_REWARD_MATURITY {
                continue;
            }
            if let Some(ref parent_reward) = stream_rewards.get(&parent_block) {
                if parent_reward.address == miner.origin_address().unwrap() {
                    let streamed = match &parent_reward.tx_fees {
                        MinerPaymentTxFees::Epoch2 { streamed, .. } => streamed,
                        _ => panic!("Expected Epoch2 style miner reward"),
                    };
                    let parent_streamed = (2 * streamed) / 5;
                    let parent_ibh = StacksBlockHeader::make_index_block_hash(
                        &parent_reward.consensus_hash,
                        &parent_reward.block_hash,
                    );
                    test_debug!(
                        "Miner {} received a produced-stream reward {parent_streamed} from {} confirmed at {confirmed_block_height}",
                        miner.origin_address().unwrap().to_string(),
                        heights.get(&parent_ibh).unwrap()
                    );
                    total += parent_streamed;
                }
            }
        }
    }

    let amount = TestStacksNode::get_miner_balance(clarity_tx, &miner.origin_address().unwrap());
    if amount == 0 {
        test_debug!(
            "Miner {} '{}' has no mature funds in this fork",
            miner.id,
            miner.origin_address().unwrap().to_string()
        );
        return total == 0;
    } else {
        if amount != total {
            test_debug!("Amount {amount} != {total}");
            return false;
        }
        return true;
    }
}

pub fn get_last_microblock_header(
    node: &TestStacksNode,
    miner: &TestMiner,
    parent_block_opt: Option<&StacksBlock>,
) -> Option<StacksMicroblockHeader> {
    let last_microblocks_opt = match parent_block_opt {
        Some(ref block) => node.get_microblock_stream(&miner, &block.block_hash()),
        None => None,
    };

    let last_microblock_header_opt = match last_microblocks_opt {
        Some(last_microblocks) => {
            if last_microblocks.is_empty() {
                None
            } else {
                let l = last_microblocks.len() - 1;
                Some(last_microblocks[l].header.clone())
            }
        }
        None => None,
    };

    last_microblock_header_opt
}

pub fn get_all_mining_rewards(
    chainstate: &mut StacksChainState,
    tip: &StacksHeaderInfo,
    block_height: u64,
) -> Vec<Vec<MinerPaymentSchedule>> {
    let mut ret = vec![];
    let mut tx = chainstate.index_tx_begin();

    for i in 0..block_height {
        let block_rewards =
            StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, tip, i)
                .unwrap();
        ret.push(block_rewards);
    }

    ret
}

pub fn make_coinbase(miner: &mut TestMiner, burnchain_height: usize) -> StacksTransaction {
    make_coinbase_with_nonce(miner, burnchain_height, miner.get_nonce(), None)
}

pub fn make_coinbase_to_contract(
    miner: &mut TestMiner,
    burnchain_height: usize,
    contract: QualifiedContractIdentifier,
) -> StacksTransaction {
    make_coinbase_with_nonce(
        miner,
        burnchain_height,
        miner.get_nonce(),
        Some(PrincipalData::Contract(contract)),
    )
}

pub fn make_coinbase_with_nonce(
    miner: &mut TestMiner,
    burnchain_height: usize,
    nonce: u64,
    recipient: Option<PrincipalData>,
) -> StacksTransaction {
    // make a coinbase for this miner
    let mut tx_coinbase = StacksTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::Coinbase(
            CoinbasePayload([(burnchain_height % 256) as u8; 32]),
            recipient,
            None,
        ),
    );
    tx_coinbase.chain_id = miner.chain_id;
    tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
    tx_coinbase.auth.set_origin_nonce(nonce);

    let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
    miner.sign_as_origin(&mut tx_signer);
    let tx_coinbase_signed = tx_signer.get_tx().unwrap();
    tx_coinbase_signed
}

pub fn make_smart_contract(
    miner: &mut TestMiner,
    burnchain_height: usize,
    stacks_block_height: usize,
) -> StacksTransaction {
    make_smart_contract_with_version(
        miner,
        miner.get_nonce(),
        burnchain_height,
        stacks_block_height,
        None,
        None,
    )
}

pub fn make_smart_contract_with_version(
    miner: &mut TestMiner,
    nonce: u64,
    burnchain_height: usize,
    stacks_block_height: usize,
    version: Option<ClarityVersion>,
    fee: Option<u64>,
) -> StacksTransaction {
    // make a smart contract
    let contract = "
    (define-data-var bar int 0)
    (define-public (get-bar) (ok (var-get bar)))
    (define-public (set-bar (x int) (y int))
      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

    test_debug!(
        "Make smart contract block at hello-world-{burnchain_height}-{stacks_block_height}"
    );

    let mut tx_contract = StacksTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::new_smart_contract(
            &format!("hello-world-{burnchain_height}-{stacks_block_height}"),
            &contract.to_string(),
            version,
        )
        .unwrap(),
    );

    tx_contract.chain_id = 0x80000000;
    tx_contract.auth.set_origin_nonce(nonce);

    if miner.test_with_tx_fees {
        tx_contract.set_tx_fee(fee.unwrap_or(123));
        miner
            .spent_at_nonce
            .insert(nonce, fee.unwrap_or(123).into());
    } else {
        tx_contract.set_tx_fee(fee.unwrap_or(0));
    }

    let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
    miner.sign_as_origin(&mut tx_signer);
    let tx_contract_signed = tx_signer.get_tx().unwrap();

    tx_contract_signed
}

/// paired with make_smart_contract
pub fn make_contract_call(
    miner: &mut TestMiner,
    burnchain_height: usize,
    stacks_block_height: usize,
    arg1: i128,
    arg2: i128,
) -> StacksTransaction {
    let addr = miner.origin_address().unwrap();
    let mut tx_contract_call = StacksTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::new_contract_call(
            addr.clone(),
            &format!("hello-world-{burnchain_height}-{stacks_block_height}"),
            "set-bar",
            vec![Value::Int(arg1), Value::Int(arg2)],
        )
        .unwrap(),
    );

    tx_contract_call.chain_id = miner.chain_id;
    tx_contract_call.auth.set_origin_nonce(miner.get_nonce());

    if miner.test_with_tx_fees {
        tx_contract_call.set_tx_fee(456);
        miner.spent_at_nonce.insert(miner.get_nonce(), 456);
    } else {
        tx_contract_call.set_tx_fee(0);
    }

    let mut tx_signer = StacksTransactionSigner::new(&tx_contract_call);
    miner.sign_as_origin(&mut tx_signer);
    let tx_contract_call_signed = tx_signer.get_tx().unwrap();
    tx_contract_call_signed
}

/// make a token transfer
pub fn make_token_transfer(
    miner: &mut TestMiner,
    burnchain_height: usize,
    nonce: Option<u64>,
    recipient: &StacksAddress,
    amount: u64,
    memo: &TokenTransferMemo,
) -> StacksTransaction {
    let addr = miner.origin_address().unwrap();
    let mut tx_stx_transfer = StacksTransaction::new(
        TransactionVersion::Testnet,
        miner.as_transaction_auth().unwrap(),
        TransactionPayload::TokenTransfer((*recipient).clone().into(), amount, (*memo).clone()),
    );

    tx_stx_transfer.chain_id = miner.chain_id;
    tx_stx_transfer
        .auth
        .set_origin_nonce(nonce.unwrap_or(miner.get_nonce()));
    tx_stx_transfer.set_tx_fee(0);

    let mut tx_signer = StacksTransactionSigner::new(&tx_stx_transfer);
    miner.sign_as_origin(&mut tx_signer);
    let tx_stx_transfer_signed = tx_signer.get_tx().unwrap();
    tx_stx_transfer_signed
}

// TODO: merge with vm/tests/integrations.rs.
// Distinct here because we use a different testnet ID
pub fn make_user_contract_publish(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
) -> StacksTransaction {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionSmartContract { name, code_body };

    sign_standard_singlesig_tx(payload.into(), sender, nonce, tx_fee)
}

pub fn make_versioned_user_contract_publish(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_name: &str,
    contract_content: &str,
    version: ClarityVersion,
) -> StacksTransaction {
    let name = ContractName::from(contract_name);
    let code_body = StacksString::from_string(&contract_content.to_string()).unwrap();

    let payload = TransactionPayload::SmartContract(
        TransactionSmartContract { name, code_body },
        Some(version),
    );

    sign_standard_singlesig_tx(payload, sender, nonce, tx_fee)
}

pub fn sign_tx_order_independent_p2sh(
    payload: TransactionPayload,
    privks: &[StacksPrivateKey],
    num_sigs: usize,
    sender_nonce: u64,
    tx_fee: u64,
) -> StacksTransaction {
    let mut pubks = vec![];
    for privk in privks.iter() {
        pubks.push(StacksPublicKey::from_private(privk));
    }
    let mut sender_spending_condition =
        TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            num_sigs as u16,
            pubks.clone(),
        )
        .expect("Failed to create p2sh spending condition.");
    sender_spending_condition.set_nonce(sender_nonce);
    sender_spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(sender_spending_condition);
    let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
    unsigned_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
    unsigned_tx.chain_id = 0x80000000;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);

    for signer in 0..num_sigs {
        tx_signer.sign_origin(&privks[signer]).unwrap();
    }

    for signer in num_sigs..pubks.len() {
        tx_signer.append_origin(&pubks[signer]).unwrap();
    }

    tx_signer.get_tx().unwrap()
}

pub fn sign_tx_order_independent_p2wsh(
    payload: TransactionPayload,
    privks: &[StacksPrivateKey],
    num_sigs: usize,
    sender_nonce: u64,
    tx_fee: u64,
) -> StacksTransaction {
    let mut pubks = vec![];
    for privk in privks.iter() {
        pubks.push(StacksPublicKey::from_private(privk));
    }
    let mut sender_spending_condition =
        TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            num_sigs as u16,
            pubks.clone(),
        )
        .expect("Failed to create p2wsh spending condition.");
    sender_spending_condition.set_nonce(sender_nonce);
    sender_spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(sender_spending_condition);
    let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
    unsigned_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
    unsigned_tx.chain_id = 0x80000000;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);

    for signer in 0..num_sigs {
        tx_signer.sign_origin(&privks[signer]).unwrap();
    }

    for signer in num_sigs..pubks.len() {
        tx_signer.append_origin(&pubks[signer]).unwrap();
    }

    tx_signer.get_tx().unwrap()
}

pub fn make_stacks_transfer_order_independent_p2sh(
    privks: &[StacksPrivateKey],
    num_sigs: usize,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_tx_order_independent_p2sh(payload, privks, num_sigs, nonce, tx_fee)
}

pub fn make_stacks_transfer_order_independent_p2wsh(
    privks: &[StacksPrivateKey],
    num_sigs: usize,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_tx_order_independent_p2wsh(payload, privks, num_sigs, nonce, tx_fee)
}

pub fn make_user_contract_call(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    contract_addr: &StacksAddress,
    contract_name: &str,
    contract_function: &str,
    args: Vec<Value>,
) -> StacksTransaction {
    let mut tx_contract_call = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(sender).unwrap(),
        TransactionPayload::new_contract_call(
            contract_addr.clone(),
            contract_name,
            contract_function,
            args,
        )
        .unwrap(),
    );

    tx_contract_call.chain_id = 0x80000000;
    tx_contract_call.auth.set_origin_nonce(nonce);
    tx_contract_call.auth.set_tx_fee(tx_fee);
    tx_contract_call.post_condition_mode = TransactionPostConditionMode::Allow;

    let mut tx_signer = StacksTransactionSigner::new(&tx_contract_call);
    tx_signer.sign_origin(sender).unwrap();
    let tx_contract_call_signed = tx_signer.get_tx().unwrap();
    tx_contract_call_signed
}

pub fn make_user_stacks_transfer(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    recipient: &PrincipalData,
    amount: u64,
) -> StacksTransaction {
    let payload =
        TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));
    sign_standard_singlesig_tx(payload, sender, nonce, tx_fee)
}

pub fn make_user_coinbase(sender: &StacksPrivateKey, nonce: u64, tx_fee: u64) -> StacksTransaction {
    let payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None, None);
    sign_standard_singlesig_tx(payload, sender, nonce, tx_fee)
}

pub fn make_user_poison_microblock(
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
    payload: TransactionPayload,
) -> StacksTransaction {
    sign_standard_singlesig_tx(payload, sender, nonce, tx_fee)
}

pub fn sign_standard_singlesig_tx(
    payload: TransactionPayload,
    sender: &StacksPrivateKey,
    nonce: u64,
    tx_fee: u64,
) -> StacksTransaction {
    let mut spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
    spending_condition.set_nonce(nonce);
    spending_condition.set_tx_fee(tx_fee);
    let auth = TransactionAuth::Standard(spending_condition);
    let mut unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);

    unsigned_tx.chain_id = 0x80000000;
    unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;

    let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
    tx_signer.sign_origin(sender).unwrap();

    tx_signer.get_tx().unwrap()
}

pub fn get_stacks_account(peer: &mut TestPeer, addr: &PrincipalData) -> StacksAccount {
    let account = peer
        .with_db_state(|ref mut sortdb, ref mut chainstate, _, _| {
            let (consensus_hash, block_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
            let stacks_block_id =
                StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
            let acct = chainstate
                .with_read_only_clarity_tx(
                    &sortdb.index_handle_at_tip(),
                    &stacks_block_id,
                    |clarity_tx| StacksChainState::get_account(clarity_tx, addr),
                )
                .unwrap();
            Ok(acct)
        })
        .unwrap();
    account
}

pub fn instantiate_and_exec(
    mainnet: bool,
    chain_id: u32,
    test_name: &str,
    balances: Vec<(StacksAddress, u64)>,
    post_flight_callback: Option<Box<dyn FnOnce(&mut ClarityTx)>>,
) -> StacksChainState {
    let path = chainstate_path(test_name);
    match fs::metadata(&path) {
        Ok(_) => {
            fs::remove_dir_all(&path).unwrap();
        }
        Err(_) => {}
    };

    let initial_balances = balances
        .into_iter()
        .map(|(addr, balance)| (PrincipalData::from(addr), balance))
        .collect();

    let mut boot_data = ChainStateBootData {
        initial_balances,
        post_flight_callback,
        first_burnchain_block_hash: BurnchainHeaderHash::zero(),
        first_burnchain_block_height: 0,
        first_burnchain_block_timestamp: 0,
        pox_constants: PoxConstants::testnet_default(),
        get_bulk_initial_lockups: None,
        get_bulk_initial_balances: None,
        get_bulk_initial_names: None,
        get_bulk_initial_namespaces: None,
    };

    StacksChainState::open_and_exec(mainnet, chain_id, &path, Some(&mut boot_data), None)
        .unwrap()
        .0
}
