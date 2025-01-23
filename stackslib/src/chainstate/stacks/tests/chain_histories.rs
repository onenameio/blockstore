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

/// This test module is concerned with verifying that the miner can build block histories out of
/// blocks and microblocks in which either the Stacks or burnchain histories fork (or both), and
/// that the Stacks chain state can still process all blocks and microblocks on each fork correctly
/// (even if they arrive out-of-order).  This module differs from the `block_construction` module in that this
/// module focuses on building and testing chain histories; unlike `block_construction`, this module does not
/// test anything about block construction from mempool state.
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::ast::ASTRules;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::types::*;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use stacks_common::address::*;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::util::hash::MerkleTree;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::db::BurnchainDB;
use crate::burnchains::tests::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::Error as CoordinatorError;
use crate::chainstate::stacks::db::blocks::test::store_staging_block;
use crate::chainstate::stacks::db::test::*;
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::tests::*;
use crate::chainstate::stacks::{
    Error as ChainstateError, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::core::*;
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::test::*;
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

fn connect_burnchain_db(burnchain: &Burnchain) -> BurnchainDB {
    let burnchain_db =
        BurnchainDB::connect(&burnchain.get_burnchaindb_path(), &burnchain, true).unwrap();
    burnchain_db
}

/// Simplest end-to-end test: create 1 fork of N Stacks epochs, mined on 1 burn chain fork,
/// all from the same miner.
fn mine_stacks_blocks_1_fork_1_miner_1_burnchain<F, G>(
    test_name: &String,
    rounds: usize,
    mut block_builder: F,
    mut check_oracle: G,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
    G: FnMut(&StacksBlock, &[StacksMicroblock]) -> bool,
{
    let full_test_name = format!("{}-1_fork_1_miner_1_burnchain", test_name);
    let mut burn_node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();
    let mut miner =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

    let mut node = TestStacksNode::new(
        false,
        0x80000000,
        &full_test_name,
        vec![miner.origin_address().unwrap()],
    );

    let first_snapshot = SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
    let mut fork = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    let mut first_burn_block = TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

    // first, register a VRF key
    node.add_key_register(&mut first_burn_block, &mut miner);

    test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

    fork.append_block(first_burn_block);
    burn_node.mine_fork(&mut fork);

    let mut miner_trace = vec![];

    // next, build up some stacks blocks
    for i in 0..rounds {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork.next_block(&ic)
        };

        let last_key = node.get_last_key(&miner);
        let parent_block_opt = node.get_last_accepted_anchored_block(&burn_node.sortdb, &miner);
        let last_microblock_header =
            get_last_microblock_header(&node, &miner, parent_block_opt.as_ref());

        // next key
        node.add_key_register(&mut burn_block, &mut miner);

        let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner,
            &mut burn_block,
            &last_key,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork);

        // "discover" the stacks block and its microblocks
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block,
            &microblocks,
            &block_commit_op,
        );

        // process all blocks
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block.block_hash(),
            microblocks.len()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                1,
            )
            .unwrap();

        let expect_success = check_oracle(&stacks_block, &microblocks);
        if expect_success {
            // processed _this_ block
            assert_eq!(tip_info_list.len(), 1);
            let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());

            let chain_tip = chain_tip_opt.unwrap().header;

            assert_eq!(
                chain_tip.anchored_header.block_hash(),
                stacks_block.block_hash()
            );
            assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
            ));
        }

        let mut next_miner_trace = TestMinerTracePoint::new();
        next_miner_trace.add(
            miner.id,
            full_test_name.clone(),
            fork_snapshot,
            stacks_block,
            microblocks,
            block_commit_op,
        );
        miner_trace.push(next_miner_trace);
    }

    TestMinerTrace::new(burn_node, vec![miner], miner_trace)
}

/// one miner begins a chain, and another miner joins it in the same fork at rounds/2.
fn mine_stacks_blocks_1_fork_2_miners_1_burnchain<F>(
    test_name: &String,
    rounds: usize,
    mut miner_1_block_builder: F,
    mut miner_2_block_builder: F,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
{
    let full_test_name = format!("{}-1_fork_2_miners_1_burnchain", test_name);
    let mut burn_node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();
    let mut miner_1 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
    let mut miner_2 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

    let mut node = TestStacksNode::new(
        false,
        0x80000000,
        &full_test_name,
        vec![
            miner_1.origin_address().unwrap(),
            miner_2.origin_address().unwrap(),
        ],
    );

    let mut sortition_winners = vec![];

    let first_snapshot = SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
    let mut fork = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    let mut first_burn_block = TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

    // first, register a VRF key
    node.add_key_register(&mut first_burn_block, &mut miner_1);

    test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

    fork.append_block(first_burn_block);
    burn_node.mine_fork(&mut fork);

    let mut miner_trace = vec![];

    // next, build up some stacks blocks
    for i in 0..rounds / 2 {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork.next_block(&ic)
        };

        let last_key = node.get_last_key(&miner_1);
        let parent_block_opt = node.get_last_anchored_block(&miner_1);
        let last_microblock_header_opt =
            get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref());

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block, microblocks, block_commit_op) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork);

        // "discover" the stacks block and its microblocks
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block,
            &microblocks,
            &block_commit_op,
        );

        // process all blocks
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block.block_hash(),
            microblocks.len()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                1,
            )
            .unwrap();

        // processed _this_ block
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        assert_eq!(
            chain_tip.anchored_header.block_hash(),
            stacks_block.block_hash()
        );
        assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

        // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
        assert!(check_block_state_index_root(
            &mut node.chainstate,
            &fork_snapshot.consensus_hash,
            chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
        ));

        sortition_winners.push(miner_1.origin_address().unwrap());

        let mut next_miner_trace = TestMinerTracePoint::new();
        next_miner_trace.add(
            miner_1.id,
            full_test_name.clone(),
            fork_snapshot,
            stacks_block,
            microblocks,
            block_commit_op,
        );
        miner_trace.push(next_miner_trace);
    }

    // miner 2 begins mining
    for i in rounds / 2..rounds {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);

        let last_winning_snapshot = {
            let first_block_height = burn_node.sortdb.first_block_height;
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork.get_tip(&ic);
            ic.as_handle(&chain_tip.sortition_id)
                .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                .expect("FATAL: no prior snapshot with sortition")
        };

        let parent_block_opt = Some(
            node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                .expect("FATAL: no prior block from last winning snapshot"),
        );

        let last_microblock_header_opt =
            match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                Some(stream) => Some(stream),
                None => get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref()),
            };

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key_1,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 1 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block,
            &last_key_2,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 2 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork);

        // "discover" the stacks blocks
        let res_1 = preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        let res_2 = preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // exactly one stacks block will have been queued up, since sortition picks only one.
        match (res_1, res_2) {
            (Some(res), None) => {}
            (None, Some(res)) => {}
            (_, _) => assert!(false),
        }

        // process all blocks
        test_debug!(
            "Process Stacks block {}",
            &fork_snapshot.winning_stacks_block_hash
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed exactly one block, but got back two tip-infos
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        // selected block is the sortition-winning block
        assert_eq!(
            chain_tip.anchored_header.block_hash(),
            fork_snapshot.winning_stacks_block_hash
        );
        assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

        let mut next_miner_trace = TestMinerTracePoint::new();
        if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
            test_debug!(
                "\n\nMiner 1 ({}) won sortition\n",
                miner_1.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_1.header
            ));
            sortition_winners.push(miner_1.origin_address().unwrap());

            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block_1,
                microblocks_1,
                block_commit_op_1,
            );
        } else {
            test_debug!(
                "\n\nMiner 2 ({}) won sortition\n",
                miner_2.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_2.header
            ));
            sortition_winners.push(miner_2.origin_address().unwrap());

            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block_2,
                microblocks_2,
                block_commit_op_2,
            );
        }

        miner_trace.push(next_miner_trace);
    }

    TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
}

/// two miners begin working on the same stacks chain, and then the stacks chain forks
/// (resulting in two chainstates).  The burnchain is unaffected.  One miner continues on one
/// chainstate, and the other continues on the other chainstate.  Fork happens on rounds/2
fn mine_stacks_blocks_2_forks_2_miners_1_burnchain<F>(
    test_name: &String,
    rounds: usize,
    miner_1_block_builder: F,
    miner_2_block_builder: F,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
{
    mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain(
        test_name,
        rounds,
        rounds / 2,
        miner_1_block_builder,
        miner_2_block_builder,
    )
}

/// two miners begin working on the same stacks chain, and then the stacks chain forks
/// (resulting in two chainstates).  The burnchain is unaffected.  One miner continues on one
/// chainstate, and the other continues on the other chainstate.  Fork happens on fork_height
fn mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain<F>(
    test_name: &String,
    rounds: usize,
    fork_height: usize,
    mut miner_1_block_builder: F,
    mut miner_2_block_builder: F,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
{
    let full_test_name = format!("{}-2_forks_2_miners_1_burnchain", test_name);
    let mut burn_node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();
    let mut miner_1 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
    let mut miner_2 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

    let mut node = TestStacksNode::new(
        false,
        0x80000000,
        &full_test_name,
        vec![
            miner_1.origin_address().unwrap(),
            miner_2.origin_address().unwrap(),
        ],
    );

    let mut sortition_winners = vec![];

    let first_snapshot = SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
    let mut fork = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    let mut first_burn_block = TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork);

    // first, register a VRF key
    node.add_key_register(&mut first_burn_block, &mut miner_1);
    node.add_key_register(&mut first_burn_block, &mut miner_2);

    test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

    fork.append_block(first_burn_block);
    burn_node.mine_fork(&mut fork);

    let mut miner_trace = vec![];

    // miner 1 and 2 cooperate to build a shared fork
    for i in 0..fork_height {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);

        let last_winning_snapshot = {
            let first_block_height = burn_node.sortdb.first_block_height;
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork.get_tip(&ic);
            ic.as_handle(&chain_tip.sortition_id)
                .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                .expect("FATAL: no prior snapshot with sortition")
        };

        let (parent_block_opt, last_microblock_header_opt) = if last_winning_snapshot.num_sortitions
            == 0
        {
            // this is the first block
            (None, None)
        } else {
            // this is a subsequent block
            let parent_block_opt = Some(
                node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                    .expect("FATAL: no prior block from last winning snapshot"),
            );
            let last_microblock_header_opt =
                match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                    Some(stream) => Some(stream),
                    None => get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref()),
                };
            (parent_block_opt, last_microblock_header_opt)
        };

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key_1,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 1 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block,
            &last_key_2,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 2 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork);

        // "discover" the stacks block and its microblocks
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // process all blocks
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_1.block_hash(),
            microblocks_1.len()
        );
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_2.block_hash(),
            microblocks_2.len()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed _one_ block
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        let mut next_miner_trace = TestMinerTracePoint::new();
        if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
            test_debug!(
                "\n\nMiner 1 ({}) won sortition\n",
                miner_1.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_1.header
            ));
            sortition_winners.push(miner_1.origin_address().unwrap());
        } else {
            test_debug!(
                "\n\nMiner 2 ({}) won sortition\n",
                miner_2.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_2.header
            ));
            sortition_winners.push(miner_2.origin_address().unwrap());
        }

        // add both blocks to the miner trace, because in this test runner, there will be _two_
        // nodes that process _all_ blocks
        next_miner_trace.add(
            miner_1.id,
            full_test_name.clone(),
            fork_snapshot.clone(),
            stacks_block_1.clone(),
            microblocks_1.clone(),
            block_commit_op_1.clone(),
        );
        next_miner_trace.add(
            miner_2.id,
            full_test_name.clone(),
            fork_snapshot.clone(),
            stacks_block_2.clone(),
            microblocks_2.clone(),
            block_commit_op_2.clone(),
        );
        miner_trace.push(next_miner_trace);
    }

    test_debug!("\n\nMiner 1 and Miner 2 now separate\n\n");

    let mut sortition_winners_1 = sortition_winners.clone();
    let mut sortition_winners_2 = sortition_winners.clone();
    let snapshot_at_fork = {
        let ic = burn_node.sortdb.index_conn();
        let tip = fork.get_tip(&ic);
        tip
    };

    assert_eq!(snapshot_at_fork.num_sortitions, fork_height as u64);

    // give miner 2 its own chain state directory
    let full_test_name_2 = format!("{}.2", &full_test_name);
    let mut node_2 = node.fork(&full_test_name_2);

    // miner 1 begins working on its own fork.
    // miner 2 begins working on its own fork.
    for i in fork_height..rounds {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node_2.get_last_key(&miner_2);

        let mut last_winning_snapshot_1 = {
            let ic = burn_node.sortdb.index_conn();
            let tip = fork.get_tip(&ic);
            match TestStacksNode::get_last_winning_snapshot(&ic, &tip, &miner_1) {
                Some(sn) => sn,
                None => SortitionDB::get_first_block_snapshot(&ic).unwrap(),
            }
        };

        let mut last_winning_snapshot_2 = {
            let ic = burn_node.sortdb.index_conn();
            let tip = fork.get_tip(&ic);
            match TestStacksNode::get_last_winning_snapshot(&ic, &tip, &miner_2) {
                Some(sn) => sn,
                None => SortitionDB::get_first_block_snapshot(&ic).unwrap(),
            }
        };

        // build off of the point where the fork occurred, regardless of who won that sortition
        if last_winning_snapshot_1.num_sortitions < snapshot_at_fork.num_sortitions {
            last_winning_snapshot_1 = snapshot_at_fork.clone();
        }
        if last_winning_snapshot_2.num_sortitions < snapshot_at_fork.num_sortitions {
            last_winning_snapshot_2 = snapshot_at_fork.clone();
        }

        let parent_block_opt_1 =
            node.get_anchored_block(&last_winning_snapshot_1.winning_stacks_block_hash);
        let parent_block_opt_2 =
            node_2.get_anchored_block(&last_winning_snapshot_2.winning_stacks_block_hash);

        let last_microblock_header_opt_1 =
            get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
        let last_microblock_header_opt_2 =
            get_last_microblock_header(&node_2, &miner_2, parent_block_opt_2.as_ref());

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node_2.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key_1,
            parent_block_opt_1.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Miner {}: Produce anchored stacks block in stacks fork 1 via {}",
                    miner.id,
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_1.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node_2.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block,
            &last_key_2,
            parent_block_opt_2.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Miner {}: Produce anchored stacks block in stacks fork 2 via {}",
                    miner.id,
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name_2);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_2.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork);

        // "discover" the stacks blocks
        let res_1 = preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        let res_2 = preprocess_stacks_block_data(
            &mut node_2,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // exactly one stacks block will have been queued up, since sortition picks only one.
        match (res_1, res_2) {
            (Some(res), None) => assert!(res),
            (None, Some(res)) => assert!(res),
            (_, _) => assert!(false),
        }

        // process all blocks
        test_debug!(
            "Process Stacks block {}",
            &fork_snapshot.winning_stacks_block_hash
        );
        let mut tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();
        let mut tip_info_list_2 = node_2
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        tip_info_list.append(&mut tip_info_list_2);

        // processed exactly one block, but got back two tip-infos
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        // selected block is the sortition-winning block
        assert_eq!(
            chain_tip.anchored_header.block_hash(),
            fork_snapshot.winning_stacks_block_hash
        );
        assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

        let mut next_miner_trace = TestMinerTracePoint::new();
        if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
            test_debug!(
                "\n\nMiner 1 ({}) won sortition\n",
                miner_1.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_1.header
            ));
            sortition_winners_1.push(miner_1.origin_address().unwrap());
        } else {
            test_debug!(
                "\n\nMiner 2 ({}) won sortition\n",
                miner_2.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node_2.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_2.header
            ));
            sortition_winners_2.push(miner_2.origin_address().unwrap());
        }

        // each miner produced a block; just one of them got accepted
        next_miner_trace.add(
            miner_1.id,
            full_test_name.clone(),
            fork_snapshot.clone(),
            stacks_block_1.clone(),
            microblocks_1.clone(),
            block_commit_op_1.clone(),
        );
        next_miner_trace.add(
            miner_2.id,
            full_test_name_2.clone(),
            fork_snapshot.clone(),
            stacks_block_2.clone(),
            microblocks_2.clone(),
            block_commit_op_2.clone(),
        );
        miner_trace.push(next_miner_trace);

        // keep chainstates in sync with one another -- each node discovers each other nodes'
        // block data.
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );
        preprocess_stacks_block_data(
            &mut node_2,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        let _ = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();
        let _ = node_2
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();
    }

    TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
}

/// two miners work on the same fork, and the burnchain splits them.
/// the split happens at rounds/2
fn mine_stacks_blocks_1_fork_2_miners_2_burnchains<F>(
    test_name: &String,
    rounds: usize,
    mut miner_1_block_builder: F,
    mut miner_2_block_builder: F,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
{
    let full_test_name = format!("{}-1_fork_2_miners_2_burnchain", test_name);
    let mut burn_node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();
    let mut miner_1 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
    let mut miner_2 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

    let mut node = TestStacksNode::new(
        false,
        0x80000000,
        &full_test_name,
        vec![
            miner_1.origin_address().unwrap(),
            miner_2.origin_address().unwrap(),
        ],
    );

    let first_snapshot = SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    let mut first_burn_block = TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork_1);

    // first, register a VRF key
    node.add_key_register(&mut first_burn_block, &mut miner_1);
    node.add_key_register(&mut first_burn_block, &mut miner_2);

    test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

    fork_1.append_block(first_burn_block);
    burn_node.mine_fork(&mut fork_1);

    let mut miner_trace = vec![];

    // next, build up some stacks blocks, cooperatively
    for i in 0..rounds / 2 {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork_1.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);

        let last_winning_snapshot = {
            let first_block_height = burn_node.sortdb.first_block_height;
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_1.get_tip(&ic);
            ic.as_handle(&chain_tip.sortition_id)
                .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                .expect("FATAL: no prior snapshot with sortition")
        };

        let (parent_block_opt, last_microblock_header_opt) = if last_winning_snapshot.num_sortitions
            == 0
        {
            // this is the first block
            (None, None)
        } else {
            // this is a subsequent block
            let parent_block_opt = Some(
                node.get_anchored_block(&last_winning_snapshot.winning_stacks_block_hash)
                    .expect("FATAL: no prior block from last winning snapshot"),
            );
            let last_microblock_header_opt =
                match get_last_microblock_header(&node, &miner_1, parent_block_opt.as_ref()) {
                    Some(stream) => Some(stream),
                    None => get_last_microblock_header(&node, &miner_2, parent_block_opt.as_ref()),
                };
            (parent_block_opt, last_microblock_header_opt)
        };

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key_1,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block from miner 1");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block,
            &last_key_2,
            parent_block_opt.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block from miner 2");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork_1.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork_1);

        // "discover" the stacks block
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // process all blocks
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_1.block_hash(),
            microblocks_1.len()
        );
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_2.block_hash(),
            microblocks_2.len()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed _one_ block
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        // selected block is the sortition-winning block
        assert_eq!(
            chain_tip.anchored_header.block_hash(),
            fork_snapshot.winning_stacks_block_hash
        );
        assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

        let mut next_miner_trace = TestMinerTracePoint::new();
        if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
            test_debug!(
                "\n\nMiner 1 ({}) won sortition\n",
                miner_1.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_1.header
            ));
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block_1,
                microblocks_1,
                block_commit_op_1,
            );
        } else {
            test_debug!(
                "\n\nMiner 2 ({}) won sortition\n",
                miner_2.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_2.header
            ));
            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block_2,
                microblocks_2,
                block_commit_op_2,
            );
        }
        miner_trace.push(next_miner_trace);
    }

    let mut fork_2 = fork_1.fork();

    test_debug!("\n\n\nbegin burnchain fork\n\n");

    // next, build up some stacks blocks on two separate burnchain forks.
    // send the same leader key register transactions to both forks.
    for i in rounds / 2..rounds {
        let mut burn_block_1 = {
            let ic = burn_node.sortdb.index_conn();
            fork_1.next_block(&ic)
        };
        let mut burn_block_2 = {
            let ic = burn_node.sortdb.index_conn();
            fork_2.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);

        let block_1_snapshot = {
            let first_block_height = burn_node.sortdb.first_block_height;
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_1.get_tip(&ic);
            ic.as_handle(&chain_tip.sortition_id)
                .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                .expect("FATAL: no prior snapshot with sortition")
        };

        let block_2_snapshot = {
            let first_block_height = burn_node.sortdb.first_block_height;
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_2.get_tip(&ic);
            ic.as_handle(&chain_tip.sortition_id)
                .get_last_snapshot_with_sortition(first_block_height + (i as u64) + 1)
                .expect("FATAL: no prior snapshot with sortition")
        };

        let parent_block_opt_1 =
            node.get_anchored_block(&block_1_snapshot.winning_stacks_block_hash);
        let parent_block_opt_2 =
            node.get_anchored_block(&block_2_snapshot.winning_stacks_block_hash);

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block_1, &mut miner_1);
        node.add_key_register(&mut burn_block_2, &mut miner_2);

        let last_microblock_header_opt_1 =
            get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
        let last_microblock_header_opt_2 =
            get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block_1,
            &last_key_1,
            parent_block_opt_1.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 1 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_1.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block_2,
            &last_key_2,
            parent_block_opt_2.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 2 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_2.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork_1.append_block(burn_block_1);
        fork_2.append_block(burn_block_2);
        let fork_snapshot_1 = burn_node.mine_fork(&mut fork_1);
        let fork_snapshot_2 = burn_node.mine_fork(&mut fork_2);

        assert!(fork_snapshot_1.burn_header_hash != fork_snapshot_2.burn_header_hash);
        assert!(fork_snapshot_1.consensus_hash != fork_snapshot_2.consensus_hash);

        // "discover" the stacks block
        test_debug!("preprocess fork 1 {}", stacks_block_1.block_hash());
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot_1,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );

        test_debug!("preprocess fork 2 {}", stacks_block_1.block_hash());
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot_2,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // process all blocks
        test_debug!(
            "Process all Stacks blocks: {}, {}",
            &stacks_block_1.block_hash(),
            &stacks_block_2.block_hash()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed all stacks blocks -- one on each burn chain fork
        assert_eq!(tip_info_list.len(), 2);

        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());
        }

        // fork 1?
        let mut found_fork_1 = false;
        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            let chain_tip = chain_tip_opt.clone().unwrap().header;
            if chain_tip.consensus_hash == fork_snapshot_1.consensus_hash {
                found_fork_1 = true;
                assert_eq!(
                    chain_tip.anchored_header.block_hash(),
                    stacks_block_1.block_hash()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot_1.consensus_hash,
                    chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
                ));
            }
        }

        assert!(found_fork_1);

        let mut found_fork_2 = false;
        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            let chain_tip = chain_tip_opt.clone().unwrap().header;
            if chain_tip.consensus_hash == fork_snapshot_2.consensus_hash {
                found_fork_2 = true;
                assert_eq!(
                    chain_tip.anchored_header.block_hash(),
                    stacks_block_2.block_hash()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot_2.consensus_hash,
                    chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
                ));
            }
        }

        assert!(found_fork_2);

        let mut next_miner_trace = TestMinerTracePoint::new();
        next_miner_trace.add(
            miner_1.id,
            full_test_name.clone(),
            fork_snapshot_1,
            stacks_block_1,
            microblocks_1,
            block_commit_op_1,
        );
        next_miner_trace.add(
            miner_2.id,
            full_test_name.clone(),
            fork_snapshot_2,
            stacks_block_2,
            microblocks_2,
            block_commit_op_2,
        );
        miner_trace.push(next_miner_trace);
    }

    TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
}

/// two miners begin working on separate forks, and the burnchain splits out under them,
/// putting each one on a different fork.
/// split happens at rounds/2
fn mine_stacks_blocks_2_forks_2_miners_2_burnchains<F>(
    test_name: &String,
    rounds: usize,
    mut miner_1_block_builder: F,
    mut miner_2_block_builder: F,
) -> TestMinerTrace
where
    F: FnMut(
        &mut ClarityTx,
        &mut StacksBlockBuilder,
        &mut TestMiner,
        usize,
        Option<&StacksMicroblockHeader>,
    ) -> (StacksBlock, Vec<StacksMicroblock>),
{
    let full_test_name = format!("{}-2_forks_2_miner_2_burnchains", test_name);
    let mut burn_node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();
    let mut miner_1 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
    let mut miner_2 =
        miner_factory.next_miner(&burn_node.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);

    let mut node = TestStacksNode::new(
        false,
        0x80000000,
        &full_test_name,
        vec![
            miner_1.origin_address().unwrap(),
            miner_2.origin_address().unwrap(),
        ],
    );

    let first_snapshot = SortitionDB::get_first_block_snapshot(burn_node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );

    let mut first_burn_block = TestStacksNode::next_burn_block(&mut burn_node.sortdb, &mut fork_1);

    // first, register a VRF key
    node.add_key_register(&mut first_burn_block, &mut miner_1);
    node.add_key_register(&mut first_burn_block, &mut miner_2);

    test_debug!("Mine {} initial transactions", first_burn_block.txs.len());

    fork_1.append_block(first_burn_block);
    burn_node.mine_fork(&mut fork_1);

    let mut miner_trace = vec![];

    // next, build up some stacks blocks. miners cooperate
    for i in 0..rounds / 2 {
        let mut burn_block = {
            let ic = burn_node.sortdb.index_conn();
            fork_1.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);

        let (block_1_snapshot_opt, block_2_snapshot_opt) = {
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_1.get_tip(&ic);
            let block_1_snapshot_opt =
                TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_1);
            let block_2_snapshot_opt =
                TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_2);
            (block_1_snapshot_opt, block_2_snapshot_opt)
        };

        let parent_block_opt_1 = match block_1_snapshot_opt {
            Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
            None => None,
        };

        let parent_block_opt_2 = match block_2_snapshot_opt {
            Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
            None => parent_block_opt_1.clone(),
        };

        let last_microblock_header_opt_1 =
            get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
        let last_microblock_header_opt_2 =
            get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block, &mut miner_1);
        node.add_key_register(&mut burn_block, &mut miner_2);

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block,
            &last_key_1,
            parent_block_opt_1.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_1.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block,
            &last_key_2,
            parent_block_opt_2.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!("Produce anchored stacks block");

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_2.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork_1.append_block(burn_block);
        let fork_snapshot = burn_node.mine_fork(&mut fork_1);

        // "discover" the stacks block
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // process all blocks
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_1.block_hash(),
            microblocks_1.len()
        );
        test_debug!(
            "Process Stacks block {} and {} microblocks",
            &stacks_block_2.block_hash(),
            microblocks_2.len()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed _one_ block
        assert_eq!(tip_info_list.len(), 1);
        let (chain_tip_opt, poison_opt) = tip_info_list[0].clone();

        assert!(chain_tip_opt.is_some());
        assert!(poison_opt.is_none());

        let chain_tip = chain_tip_opt.unwrap().header;

        // selected block is the sortition-winning block
        assert_eq!(
            chain_tip.anchored_header.block_hash(),
            fork_snapshot.winning_stacks_block_hash
        );
        assert_eq!(chain_tip.consensus_hash, fork_snapshot.consensus_hash);

        let mut next_miner_trace = TestMinerTracePoint::new();
        if fork_snapshot.winning_stacks_block_hash == stacks_block_1.block_hash() {
            test_debug!(
                "\n\nMiner 1 ({}) won sortition\n",
                miner_1.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_1.header
            ));
            next_miner_trace.add(
                miner_1.id,
                full_test_name.clone(),
                fork_snapshot.clone(),
                stacks_block_1,
                microblocks_1,
                block_commit_op_1,
            );
        } else {
            test_debug!(
                "\n\nMiner 2 ({}) won sortition\n",
                miner_2.origin_address().unwrap().to_string()
            );

            // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
            assert!(check_block_state_index_root(
                &mut node.chainstate,
                &fork_snapshot.consensus_hash,
                &stacks_block_2.header
            ));
            next_miner_trace.add(
                miner_2.id,
                full_test_name.clone(),
                fork_snapshot,
                stacks_block_2,
                microblocks_2,
                block_commit_op_2,
            );
        }

        miner_trace.push(next_miner_trace);
    }

    let mut fork_2 = fork_1.fork();

    test_debug!("\n\n\nbegin burnchain fork\n\n");

    // next, build up some stacks blocks on two separate burnchain forks.
    // send the same leader key register transactions to both forks.
    // miner 1 works on fork 1
    // miner 2 works on fork 2
    for i in rounds / 2..rounds {
        let mut burn_block_1 = {
            let ic = burn_node.sortdb.index_conn();
            fork_1.next_block(&ic)
        };
        let mut burn_block_2 = {
            let ic = burn_node.sortdb.index_conn();
            fork_2.next_block(&ic)
        };

        let last_key_1 = node.get_last_key(&miner_1);
        let last_key_2 = node.get_last_key(&miner_2);
        let block_1_snapshot_opt = {
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_1.get_tip(&ic);
            TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_1)
        };
        let block_2_snapshot_opt = {
            let ic = burn_node.sortdb.index_conn();
            let chain_tip = fork_2.get_tip(&ic);
            TestStacksNode::get_last_winning_snapshot(&ic, &chain_tip, &miner_2)
        };

        let parent_block_opt_1 = match block_1_snapshot_opt {
            Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
            None => None,
        };

        let parent_block_opt_2 = match block_2_snapshot_opt {
            Some(sn) => node.get_anchored_block(&sn.winning_stacks_block_hash),
            None => parent_block_opt_1.clone(),
        };

        // send next key (key for block i+1)
        node.add_key_register(&mut burn_block_1, &mut miner_1);
        node.add_key_register(&mut burn_block_2, &mut miner_2);

        let last_microblock_header_opt_1 =
            get_last_microblock_header(&node, &miner_1, parent_block_opt_1.as_ref());
        let last_microblock_header_opt_2 =
            get_last_microblock_header(&node, &miner_2, parent_block_opt_2.as_ref());

        let (stacks_block_1, microblocks_1, block_commit_op_1) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_1,
            &mut burn_block_1,
            &last_key_1,
            parent_block_opt_1.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 1 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_1_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_1.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        let (stacks_block_2, microblocks_2, block_commit_op_2) = node.mine_stacks_block(
            &burn_node.sortdb,
            &mut miner_2,
            &mut burn_block_2,
            &last_key_2,
            parent_block_opt_2.as_ref(),
            1000,
            |mut builder, ref mut miner, ref sortdb| {
                test_debug!(
                    "Produce anchored stacks block in stacks fork 2 via {}",
                    miner.origin_address().unwrap().to_string()
                );

                let mut miner_chainstate = open_chainstate(false, 0x80000000, &full_test_name);
                let all_prev_mining_rewards = get_all_mining_rewards(
                    &mut miner_chainstate,
                    &builder.chain_tip,
                    builder.chain_tip.stacks_block_height,
                );

                let sort_iconn = sortdb.index_handle_at_tip();
                let mut miner_epoch_info = builder
                    .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                    .unwrap();
                let mut epoch = builder
                    .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                    .unwrap()
                    .0;
                let (stacks_block, microblocks) = miner_2_block_builder(
                    &mut epoch,
                    &mut builder,
                    miner,
                    i,
                    last_microblock_header_opt_2.as_ref(),
                );

                assert!(check_mining_reward(
                    &mut epoch,
                    miner,
                    builder.chain_tip.stacks_block_height,
                    &all_prev_mining_rewards
                ));

                builder.epoch_finish(epoch).unwrap();
                (stacks_block, microblocks)
            },
        );

        // process burn chain
        fork_1.append_block(burn_block_1);
        fork_2.append_block(burn_block_2);
        let fork_snapshot_1 = burn_node.mine_fork(&mut fork_1);
        let fork_snapshot_2 = burn_node.mine_fork(&mut fork_2);

        assert!(fork_snapshot_1.burn_header_hash != fork_snapshot_2.burn_header_hash);
        assert!(fork_snapshot_1.consensus_hash != fork_snapshot_2.consensus_hash);

        // "discover" the stacks block
        test_debug!("preprocess fork 1 {}", stacks_block_1.block_hash());
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot_1,
            &stacks_block_1,
            &microblocks_1,
            &block_commit_op_1,
        );

        test_debug!("preprocess fork 2 {}", stacks_block_1.block_hash());
        preprocess_stacks_block_data(
            &mut node,
            &mut burn_node,
            &fork_snapshot_2,
            &stacks_block_2,
            &microblocks_2,
            &block_commit_op_2,
        );

        // process all blocks
        test_debug!(
            "Process all Stacks blocks: {}, {}",
            &stacks_block_1.block_hash(),
            &stacks_block_2.block_hash()
        );
        let tip_info_list = node
            .chainstate
            .process_blocks_at_tip(
                connect_burnchain_db(&burn_node.burnchain).conn(),
                &mut burn_node.sortdb,
                2,
            )
            .unwrap();

        // processed all stacks blocks -- one on each burn chain fork
        assert_eq!(tip_info_list.len(), 2);

        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            assert!(chain_tip_opt.is_some());
            assert!(poison_opt.is_none());
        }

        // fork 1?
        let mut found_fork_1 = false;
        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            let chain_tip = chain_tip_opt.clone().unwrap().header;
            if chain_tip.consensus_hash == fork_snapshot_1.consensus_hash {
                found_fork_1 = true;
                assert_eq!(
                    chain_tip.anchored_header.block_hash(),
                    stacks_block_1.block_hash()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot_1.consensus_hash,
                    chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
                ));
            }
        }

        assert!(found_fork_1);

        let mut found_fork_2 = false;
        for (ref chain_tip_opt, ref poison_opt) in tip_info_list.iter() {
            let chain_tip = chain_tip_opt.clone().unwrap().header;
            if chain_tip.consensus_hash == fork_snapshot_2.consensus_hash {
                found_fork_2 = true;
                assert_eq!(
                    chain_tip.anchored_header.block_hash(),
                    stacks_block_2.block_hash()
                );

                // MARF trie exists for the block header's chain state, so we can make merkle proofs on it
                assert!(check_block_state_index_root(
                    &mut node.chainstate,
                    &fork_snapshot_2.consensus_hash,
                    chain_tip.anchored_header.as_stacks_epoch2().unwrap(),
                ));
            }
        }

        assert!(found_fork_2);

        let mut next_miner_trace = TestMinerTracePoint::new();
        next_miner_trace.add(
            miner_1.id,
            full_test_name.clone(),
            fork_snapshot_1,
            stacks_block_1,
            microblocks_1,
            block_commit_op_1,
        );
        next_miner_trace.add(
            miner_2.id,
            full_test_name.clone(),
            fork_snapshot_2,
            stacks_block_2,
            microblocks_2,
            block_commit_op_2,
        );
        miner_trace.push(next_miner_trace);
    }

    TestMinerTrace::new(burn_node, vec![miner_1, miner_2], miner_trace)
}

/// compare two chainstates to see if they have exactly the same blocks and microblocks.
fn assert_chainstate_blocks_eq(test_name_1: &str, test_name_2: &str) {
    let ch1 = open_chainstate(false, 0x80000000, test_name_1);
    let ch2 = open_chainstate(false, 0x80000000, test_name_2);

    // check presence of anchored blocks
    let mut all_blocks_1 = StacksChainState::list_blocks(&ch1.db()).unwrap();
    let mut all_blocks_2 = StacksChainState::list_blocks(&ch2.db()).unwrap();

    all_blocks_1.sort();
    all_blocks_2.sort();

    assert_eq!(all_blocks_1.len(), all_blocks_2.len());
    for i in 0..all_blocks_1.len() {
        assert_eq!(all_blocks_1[i], all_blocks_2[i]);
    }

    // check presence and ordering of microblocks
    let mut all_microblocks_1 =
        StacksChainState::list_microblocks(&ch1.db(), &ch1.blocks_path).unwrap();
    let mut all_microblocks_2 =
        StacksChainState::list_microblocks(&ch2.db(), &ch2.blocks_path).unwrap();

    all_microblocks_1.sort();
    all_microblocks_2.sort();

    assert_eq!(all_microblocks_1.len(), all_microblocks_2.len());
    for i in 0..all_microblocks_1.len() {
        assert_eq!(all_microblocks_1[i].0, all_microblocks_2[i].0);
        assert_eq!(all_microblocks_1[i].1, all_microblocks_2[i].1);

        assert_eq!(all_microblocks_1[i].2.len(), all_microblocks_2[i].2.len());
        for j in 0..all_microblocks_1[i].2.len() {
            assert_eq!(all_microblocks_1[i].2[j], all_microblocks_2[i].2[j]);
        }
    }

    // compare block status (staging vs confirmed) and contents
    for i in 0..all_blocks_1.len() {
        let staging_1_opt = StacksChainState::load_staging_block(
            &ch1.db(),
            &ch2.blocks_path,
            &all_blocks_1[i].0,
            &all_blocks_1[i].1,
        )
        .unwrap();
        let staging_2_opt = StacksChainState::load_staging_block(
            &ch2.db(),
            &ch2.blocks_path,
            &all_blocks_2[i].0,
            &all_blocks_2[i].1,
        )
        .unwrap();

        let chunk_1_opt =
            StacksChainState::load_block(&ch1.blocks_path, &all_blocks_1[i].0, &all_blocks_1[i].1)
                .unwrap();
        let chunk_2_opt =
            StacksChainState::load_block(&ch2.blocks_path, &all_blocks_2[i].0, &all_blocks_2[i].1)
                .unwrap();

        match (staging_1_opt, staging_2_opt) {
            (Some(staging_1), Some(staging_2)) => {
                assert_eq!(staging_1.block_data, staging_2.block_data);
            }
            (None, None) => {}
            (_, _) => {
                assert!(false);
            }
        }

        match (chunk_1_opt, chunk_2_opt) {
            (Some(block_1), Some(block_2)) => {
                assert_eq!(block_1, block_2);
            }
            (None, None) => {}
            (_, _) => {
                assert!(false);
            }
        }
    }

    for i in 0..all_microblocks_1.len() {
        if all_microblocks_1[i].2.is_empty() {
            continue;
        }

        let chunk_1_opt = StacksChainState::load_descendant_staging_microblock_stream(
            &ch1.db(),
            &StacksBlockHeader::make_index_block_hash(
                &all_microblocks_1[i].0,
                &all_microblocks_1[i].1,
            ),
            0,
            u16::MAX,
        )
        .unwrap();
        let chunk_2_opt = StacksChainState::load_descendant_staging_microblock_stream(
            &ch1.db(),
            &StacksBlockHeader::make_index_block_hash(
                &all_microblocks_2[i].0,
                &all_microblocks_2[i].1,
            ),
            0,
            u16::MAX,
        )
        .unwrap();

        match (chunk_1_opt, chunk_2_opt) {
            (Some(chunk_1), Some(chunk_2)) => {
                assert_eq!(chunk_1, chunk_2);
            }
            (None, None) => {}
            (_, _) => {
                assert!(false);
            }
        }
        for j in 0..all_microblocks_1[i].2.len() {
            // staging status is the same
            let staging_1_opt = StacksChainState::load_staging_microblock(
                &ch1.db(),
                &all_microblocks_1[i].0,
                &all_microblocks_1[i].1,
                &all_microblocks_1[i].2[j],
            )
            .unwrap();
            let staging_2_opt = StacksChainState::load_staging_microblock(
                &ch2.db(),
                &all_microblocks_2[i].0,
                &all_microblocks_2[i].1,
                &all_microblocks_2[i].2[j],
            )
            .unwrap();

            match (staging_1_opt, staging_2_opt) {
                (Some(staging_1), Some(staging_2)) => {
                    assert_eq!(staging_1.block_data, staging_2.block_data);
                }
                (None, None) => {}
                (_, _) => {
                    assert!(false);
                }
            }
        }
    }
}

/// produce all stacks blocks, but don't process them in order.  Instead, queue them all up and
/// process them in randomized order.
/// This works by running mine_stacks_blocks_1_fork_1_miner_1_burnchain, extracting the blocks,
/// and then re-processing them in a different chainstate directory.
fn miner_trace_replay_randomized(miner_trace: &mut TestMinerTrace) {
    test_debug!("\n\n");
    test_debug!("------------------------------------------------------------------------");
    test_debug!("                   Randomize and re-apply blocks");
    test_debug!("------------------------------------------------------------------------");
    test_debug!("\n\n");

    let rounds = miner_trace.rounds();
    let test_names = miner_trace.get_test_names();
    let mut nodes = HashMap::new();
    for (i, test_name) in test_names.iter().enumerate() {
        let rnd_test_name = format!("{}-replay_randomized", test_name);
        let next_node = TestStacksNode::new(
            false,
            0x80000000,
            &rnd_test_name,
            miner_trace
                .miners
                .iter()
                .map(|ref miner| miner.origin_address().unwrap())
                .collect(),
        );
        nodes.insert(test_name, next_node);
    }

    let expected_num_sortitions = miner_trace.get_num_sortitions();
    let expected_num_blocks = miner_trace.get_num_blocks();
    let mut num_processed = 0;

    let mut rng = thread_rng();
    miner_trace.points.as_mut_slice().shuffle(&mut rng);

    // "discover" blocks in random order
    for point in miner_trace.points.drain(..) {
        let mut miner_ids = point.get_miner_ids();
        miner_ids.as_mut_slice().shuffle(&mut rng);

        for miner_id in miner_ids {
            let fork_snapshot_opt = point.get_block_snapshot(miner_id);
            let stacks_block_opt = point.get_stacks_block(miner_id);
            let microblocks_opt = point.get_microblocks(miner_id);
            let block_commit_op_opt = point.get_block_commit(miner_id);

            if fork_snapshot_opt.is_none() || block_commit_op_opt.is_none() {
                // no sortition by this miner at this point in time
                continue;
            }

            let fork_snapshot = fork_snapshot_opt.unwrap();
            let block_commit_op = block_commit_op_opt.unwrap();

            match stacks_block_opt {
                Some(stacks_block) => {
                    let mut microblocks = microblocks_opt.unwrap_or(vec![]);

                    // "discover" the stacks block and its microblocks in all nodes
                    // TODO: randomize microblock discovery order too
                    for (node_name, mut node) in nodes.iter_mut() {
                        microblocks.as_mut_slice().shuffle(&mut rng);

                        preprocess_stacks_block_data(
                            &mut node,
                            &mut miner_trace.burn_node,
                            &fork_snapshot,
                            &stacks_block,
                            &[],
                            &block_commit_op,
                        );

                        if microblocks.is_empty() {
                            // process all the blocks we can
                            test_debug!(
                                "Process Stacks block {} and {} microblocks in {}",
                                &stacks_block.block_hash(),
                                microblocks.len(),
                                &node_name
                            );
                            let tip_info_list = node
                                .chainstate
                                .process_blocks_at_tip(
                                    connect_burnchain_db(&miner_trace.burn_node.burnchain).conn(),
                                    &mut miner_trace.burn_node.sortdb,
                                    expected_num_blocks,
                                )
                                .unwrap();

                            num_processed += tip_info_list.len();
                        } else {
                            for mblock in microblocks.iter() {
                                preprocess_stacks_block_data(
                                    &mut node,
                                    &mut miner_trace.burn_node,
                                    &fork_snapshot,
                                    &stacks_block,
                                    &[mblock.clone()],
                                    &block_commit_op,
                                );

                                // process all the blocks we can
                                test_debug!(
                                    "Process Stacks block {} and microblock {} {}",
                                    &stacks_block.block_hash(),
                                    mblock.block_hash(),
                                    mblock.header.sequence
                                );
                                let tip_info_list = node
                                    .chainstate
                                    .process_blocks_at_tip(
                                        connect_burnchain_db(&miner_trace.burn_node.burnchain)
                                            .conn(),
                                        &mut miner_trace.burn_node.sortdb,
                                        expected_num_blocks,
                                    )
                                    .unwrap();

                                num_processed += tip_info_list.len();
                            }
                        }
                    }
                }
                None => {
                    // no block announced at this point in time
                    test_debug!(
                        "Miner {} did not produce a Stacks block for {:?} (commit {:?})",
                        miner_id,
                        &fork_snapshot,
                        &block_commit_op
                    );
                    continue;
                }
            }
        }
    }

    // must have processed the same number of blocks in all nodes
    assert_eq!(num_processed, expected_num_blocks);

    // must have processed all blocks the same way
    for test_name in test_names.iter() {
        let rnd_test_name = format!("{}-replay_randomized", test_name);
        assert_chainstate_blocks_eq(test_name, &rnd_test_name);
    }
}

pub fn mine_empty_anchored_block(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    test_debug!(
        "Produce anchored stacks block at burnchain height {} stacks height {}",
        burnchain_height,
        stacks_block.header.total_work.work
    );
    (stacks_block, vec![])
}

pub fn mine_empty_anchored_block_with_burn_height_pubkh(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    let mut pubkh_bytes = [0u8; 20];
    pubkh_bytes[0..8].copy_from_slice(&burnchain_height.to_be_bytes());
    assert!(builder.set_microblock_pubkey_hash(Hash160(pubkh_bytes)));

    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );

    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    test_debug!(
        "Produce anchored stacks block at burnchain height {} stacks height {} pubkeyhash {}",
        burnchain_height,
        stacks_block.header.total_work.work,
        &stacks_block.header.microblock_pubkey_hash
    );
    (stacks_block, vec![])
}

pub fn mine_empty_anchored_block_with_stacks_height_pubkh(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    let mut pubkh_bytes = [0u8; 20];
    pubkh_bytes[0..8].copy_from_slice(&burnchain_height.to_be_bytes());
    assert!(builder.set_microblock_pubkey_hash(Hash160(pubkh_bytes)));

    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);

    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    test_debug!(
        "Produce anchored stacks block at burnchain height {} stacks height {} pubkeyhash {}",
        burnchain_height,
        stacks_block.header.total_work.work,
        &stacks_block.header.microblock_pubkey_hash
    );
    (stacks_block, vec![])
}

/// Mine invalid token transfers
pub fn mine_invalid_token_transfers_block(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    let recipient = StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, Hash160([0xff; 20]));
    let tx1 = make_token_transfer(
        miner,
        burnchain_height,
        Some(1),
        &recipient,
        11111,
        &TokenTransferMemo([1u8; 34]),
    );
    builder.force_mine_tx(clarity_tx, &tx1).unwrap();

    if !miner.spent_at_nonce.contains_key(&1) {
        miner.spent_at_nonce.insert(1, 11111);
    }

    let tx2 = make_token_transfer(
        miner,
        burnchain_height,
        Some(2),
        &recipient,
        22222,
        &TokenTransferMemo([2u8; 34]),
    );
    builder.force_mine_tx(clarity_tx, &tx2).unwrap();

    if !miner.spent_at_nonce.contains_key(&2) {
        miner.spent_at_nonce.insert(2, 22222);
    }

    let tx3 = make_token_transfer(
        miner,
        burnchain_height,
        Some(1),
        &recipient,
        33333,
        &TokenTransferMemo([3u8; 34]),
    );
    builder.force_mine_tx(clarity_tx, &tx3).unwrap();

    let tx4 = make_token_transfer(
        miner,
        burnchain_height,
        Some(2),
        &recipient,
        44444,
        &TokenTransferMemo([4u8; 34]),
    );
    builder.force_mine_tx(clarity_tx, &tx4).unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    test_debug!("Produce anchored stacks block {} with invalid token transfers at burnchain height {} stacks height {}", stacks_block.block_hash(), burnchain_height, stacks_block.header.total_work.work);

    (stacks_block, vec![])
}

/// mine a smart contract in an anchored block, and mine a contract-call in the same anchored
/// block
pub fn mine_smart_contract_contract_call_block(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    // make a smart contract
    let tx_contract_signed = make_smart_contract(
        miner,
        burnchain_height,
        builder.header.total_work.work as usize,
    );
    builder
        .try_mine_tx(clarity_tx, &tx_contract_signed, ASTRules::PrecheckSize)
        .unwrap();

    // make a contract call
    let tx_contract_call_signed = make_contract_call(
        miner,
        burnchain_height,
        builder.header.total_work.work as usize,
        6,
        2,
    );
    builder
        .try_mine_tx(clarity_tx, &tx_contract_call_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    // TODO: test value of 'bar' in last contract(s)

    test_debug!("Produce anchored stacks block {} with smart contract and contract call at burnchain height {} stacks height {}", stacks_block.block_hash(), burnchain_height, stacks_block.header.total_work.work);
    (stacks_block, vec![])
}

/// mine a smart contract in an anchored block, and mine some contract-calls to it in a microblock tail
pub fn mine_smart_contract_block_contract_call_microblock(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    if burnchain_height > 0 && builder.chain_tip.anchored_header.height() > 0 {
        // find previous contract in this fork
        for i in (0..burnchain_height).rev() {
            let prev_contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(miner.origin_address().unwrap()),
                ContractName::try_from(
                    format!(
                        "hello-world-{}-{}",
                        i,
                        builder.chain_tip.anchored_header.height()
                    )
                    .as_str(),
                )
                .unwrap(),
            );
            let contract = StacksChainState::get_contract(clarity_tx, &prev_contract_id).unwrap();
            if contract.is_none() {
                continue;
            }

            let prev_bar_value =
                StacksChainState::get_data_var(clarity_tx, &prev_contract_id, "bar").unwrap();
            assert_eq!(prev_bar_value, Some(Value::Int(3)));
            break;
        }
    }

    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    // make a smart contract
    let tx_contract_signed = make_smart_contract(
        miner,
        burnchain_height,
        builder.header.total_work.work as usize,
    );
    builder
        .try_mine_tx(clarity_tx, &tx_contract_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);
    let mut microblocks = vec![];

    for i in 0..3 {
        // make a contract call
        let tx_contract_call_signed = make_contract_call(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
            6,
            2,
        );

        builder.micro_txs.clear();
        builder.micro_txs.push(tx_contract_call_signed);

        // put the contract-call into a microblock
        let microblock = builder.mine_next_microblock().unwrap();
        microblocks.push(microblock);
    }

    test_debug!("Produce anchored stacks block {} with smart contract and {} microblocks with contract call at burnchain height {} stacks height {}",
                stacks_block.block_hash(), microblocks.len(), burnchain_height, stacks_block.header.total_work.work);

    (stacks_block, microblocks)
}

/// mine a smart contract in an anchored block, and mine a contract-call to it in a microblock.
/// Make it so all microblocks throw a runtime exception, but confirm that they are still mined
/// anyway.
pub fn mine_smart_contract_block_contract_call_microblock_exception(
    clarity_tx: &mut ClarityTx,
    builder: &mut StacksBlockBuilder,
    miner: &mut TestMiner,
    burnchain_height: usize,
    parent_microblock_header: Option<&StacksMicroblockHeader>,
) -> (StacksBlock, Vec<StacksMicroblock>) {
    if burnchain_height > 0 && builder.chain_tip.anchored_header.height() > 0 {
        // find previous contract in this fork
        for i in (0..burnchain_height).rev() {
            let prev_contract_id = QualifiedContractIdentifier::new(
                StandardPrincipalData::from(miner.origin_address().unwrap()),
                ContractName::try_from(
                    format!(
                        "hello-world-{}-{}",
                        i,
                        builder.chain_tip.anchored_header.height(),
                    )
                    .as_str(),
                )
                .unwrap(),
            );
            let contract = StacksChainState::get_contract(clarity_tx, &prev_contract_id).unwrap();
            if contract.is_none() {
                continue;
            }

            test_debug!("Found contract {:?}", &prev_contract_id);
            let prev_bar_value =
                StacksChainState::get_data_var(clarity_tx, &prev_contract_id, "bar").unwrap();
            assert_eq!(prev_bar_value, Some(Value::Int(0)));
            break;
        }
    }

    let miner_account = StacksChainState::get_account(
        clarity_tx,
        &miner.origin_address().unwrap().to_account_principal(),
    );
    miner.set_nonce(miner_account.nonce);

    // make a coinbase for this miner
    let tx_coinbase_signed = make_coinbase(miner, burnchain_height);
    builder
        .try_mine_tx(clarity_tx, &tx_coinbase_signed, ASTRules::PrecheckSize)
        .unwrap();

    // make a smart contract
    let tx_contract_signed = make_smart_contract(
        miner,
        burnchain_height,
        builder.header.total_work.work as usize,
    );
    builder
        .try_mine_tx(clarity_tx, &tx_contract_signed, ASTRules::PrecheckSize)
        .unwrap();

    let stacks_block = builder.mine_anchored_block(clarity_tx);

    let mut microblocks = vec![];
    for i in 0..3 {
        // make a contract call (note: triggers a divide-by-zero runtime error)
        let tx_contract_call_signed = make_contract_call(
            miner,
            burnchain_height,
            builder.header.total_work.work as usize,
            6,
            0,
        );
        builder.micro_txs.clear();
        builder.micro_txs.push(tx_contract_call_signed);

        // put the contract-call into a microblock
        let microblock = builder.mine_next_microblock().unwrap();
        microblocks.push(microblock);
    }

    test_debug!("Produce anchored stacks block {} with smart contract and {} microblocks with contract call at burnchain height {} stacks height {}",
                stacks_block.block_hash(), microblocks.len(), burnchain_height, stacks_block.header.total_work.work);

    (stacks_block, microblocks)
}

#[test]
fn mine_anchored_empty_blocks_single() {
    mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"empty-anchored-blocks".to_string(),
        10,
        mine_empty_anchored_block,
        |_, _| true,
    );
}

#[test]
fn mine_anchored_empty_blocks_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"empty-anchored-blocks-random".to_string(),
        10,
        mine_empty_anchored_block,
        |_, _| true,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_empty_blocks_multiple_miners() {
    mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"empty-anchored-blocks-multiple-miners".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
}

#[test]
fn mine_anchored_empty_blocks_multiple_miners_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"empty-anchored-blocks-multiple-miners-random".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_empty_blocks_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"empty-anchored-blocks-stacks-fork".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
}

#[test]
fn mine_anchored_empty_blocks_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"empty-anchored-blocks-stacks-fork-random".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_empty_blocks_burnchain_fork() {
    mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"empty-anchored-blocks-burnchain-fork".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
}

#[test]
fn mine_anchored_empty_blocks_burnchain_fork_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"empty-anchored-blocks-burnchain-fork-random".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_empty_blocks_burnchain_fork_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"empty-anchored-blocks-burnchain-stacks-fork".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
}

#[test]
fn mine_anchored_empty_blocks_burnchain_fork_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"empty-anchored-blocks-burnchain-stacks-fork-random".to_string(),
        10,
        mine_empty_anchored_block,
        mine_empty_anchored_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_single() {
    mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        |_, _| true,
    );
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_single_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks-random".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        |_, _| true,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_multiple_miners() {
    mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks-multiple-miners".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_multiple_miners_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks-multiple-miners-random".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks-stacks-fork".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-contract-call-anchored-blocks-stacks-fork-random".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork() {
    mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-contract-call-anchored-blocks-burnchain-fork".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-contract-call-anchored-blocks-burnchain-fork-random".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-contract-call-anchored-blocks-burnchain-stacks-fork".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
}

#[test]
fn mine_anchored_smart_contract_contract_call_blocks_burnchain_fork_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-contract-call-anchored-blocks-burnchain-stacks-fork-random".to_string(),
        10,
        mine_smart_contract_contract_call_block,
        mine_smart_contract_contract_call_block,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_single() {
    mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-block-contract-call-microblock".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        |_, _| true,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_single_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-block-contract-call-microblock-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        |_, _| true,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_multiple_miners() {
    mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-multiple-miners".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_multiple_miners_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-multiple-miners-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-stacks-fork".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
}

#[test]
#[ignore]
fn mine_anchored_smart_contract_block_contract_call_microblock_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-stacks-fork-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork() {
    mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-burnchain-fork".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-burnchain-fork-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-burnchain-stacks-fork".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_burnchain_fork_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-burnchain-stacks-fork-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock,
        mine_smart_contract_block_contract_call_microblock,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_single() {
    mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        |_, _| true,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_single_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        |_, _| true,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_multiple_miners() {
    mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception-multiple-miners".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_multiple_miners_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception-multiple-miners-random"
            .to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception-stacks-fork".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
}

#[test]
#[ignore]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_stacks_fork_random() {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"smart-contract-block-contract-call-microblock-exception-stacks-fork-random".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork() {
    mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-exception-burnchain-fork".to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_random() {
    let mut miner_trace = mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-exception-burnchain-fork-random"
            .to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_stacks_fork(
) {
    mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-exception-burnchain-stacks-fork"
            .to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
}

#[test]
fn mine_anchored_smart_contract_block_contract_call_microblock_exception_burnchain_fork_stacks_fork_random(
) {
    let mut miner_trace = mine_stacks_blocks_2_forks_2_miners_2_burnchains(
        &"smart-contract-block-contract-call-microblock-exception-burnchain-stacks-fork-random"
            .to_string(),
        10,
        mine_smart_contract_block_contract_call_microblock_exception,
        mine_smart_contract_block_contract_call_microblock_exception,
    );
    miner_trace_replay_randomized(&mut miner_trace);
}

#[test]
fn mine_empty_anchored_block_deterministic_pubkeyhash_burnchain_fork() {
    mine_stacks_blocks_1_fork_2_miners_2_burnchains(
        &"mine_empty_anchored_block_deterministic_pubkeyhash_burnchain_fork".to_string(),
        10,
        mine_empty_anchored_block_with_burn_height_pubkh,
        mine_empty_anchored_block_with_burn_height_pubkh,
    );
}

#[test]
fn mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork() {
    mine_stacks_blocks_2_forks_2_miners_1_burnchain(
        &"mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork".to_string(),
        10,
        mine_empty_anchored_block_with_stacks_height_pubkh,
        mine_empty_anchored_block_with_stacks_height_pubkh,
    );
}

#[test]
fn mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork_at_genesis() {
    mine_stacks_blocks_2_forks_at_height_2_miners_1_burnchain(
        &"mine_empty_anchored_block_deterministic_pubkeyhash_stacks_fork_at_genesis".to_string(),
        10,
        0,
        mine_empty_anchored_block_with_stacks_height_pubkh,
        mine_empty_anchored_block_with_stacks_height_pubkh,
    );
}

#[test]
fn mine_anchored_invalid_token_transfer_blocks_single() {
    let miner_trace = mine_stacks_blocks_1_fork_1_miner_1_burnchain(
        &"invalid-token-transfers".to_string(),
        10,
        mine_invalid_token_transfers_block,
        |_, _| false,
    );

    let full_test_name = "invalid-token-transfers-1_fork_1_miner_1_burnchain";
    let chainstate = open_chainstate(false, 0x80000000, full_test_name);

    // each block must be orphaned
    for point in miner_trace.points.iter() {
        for (height, bc) in point.block_commits.iter() {
            // NOTE: this only works because there are no PoX forks in this test
            let sn = SortitionDB::get_block_snapshot(
                miner_trace.burn_node.sortdb.conn(),
                &SortitionId::stubbed(&bc.burn_header_hash),
            )
            .unwrap()
            .unwrap();
            assert!(StacksChainState::is_block_orphaned(
                &chainstate.db(),
                &sn.consensus_hash,
                &bc.block_header_hash
            )
            .unwrap());
        }
    }
}

// TODO: invalid block with duplicate microblock public key hash (okay between forks, but not
// within the same fork)
// TODO; skipped blocks
// TODO: missing blocks
// TODO: no-sortition
// TODO: burnchain forks, and we mine the same anchored stacks block in the beginnings of the two descendent
// forks.  Verify all descendents are unique -- if A --> B and A --> C, and B --> D and C -->
// E, and B == C, verify that it is never the case that D == E (but it is allowed that B == C
// if the burnchain forks).
// TODO: confirm that if A is accepted but B is rejected, then C must also be rejected even if
// it's on a different burnchain fork.
// TODO: confirm that we can process B and C separately, even though they're the same block
