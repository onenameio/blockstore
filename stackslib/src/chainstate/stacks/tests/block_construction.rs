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

/// This test module is concerned with verifying that the system can build blocks out of
/// transactions from the mempool under various circumstances.  The tests here focus on testing
/// block construction from various types of transactions and block availabilities, based on data
/// available in the mempool.  This differs from the `chain_histories` module in that the `chain_histories` module is
/// concerned with building out and testing block histories from manually-constructed blocks,
/// ignoring mempool-level concerns entirely.
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::{fs, io};

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::test_util::TEST_BURN_STATE_DB;
use clarity::vm::types::*;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use rusqlite::params;
use stacks_common::address::*;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::util::hash::MerkleTree;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::{get_epoch_time_ms, sleep_ms};

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
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::test::codec_all_transactions;
use crate::chainstate::stacks::tests::*;
use crate::chainstate::stacks::{
    Error as ChainstateError, C32_ADDRESS_VERSION_TESTNET_SINGLESIG, *,
};
use crate::core::mempool::MemPoolWalkSettings;
use crate::core::tests::make_block;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, *};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::net::test::*;
use crate::util_lib::boot::boot_code_addr;
use crate::util_lib::db::Error as db_error;

#[test]
fn test_build_anchored_blocks_empty() {
    let peer_config = TestPeerConfig::new(function_name!(), 2000, 2001);
    let burnchain = peer_config.burnchain.clone();
    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let mut last_block: Option<StacksBlock> = None;
    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        assert_eq!(
            tip.block_height,
            first_stacks_block_height + (tenure_id as u64)
        );
        if let Some(block) = last_block {
            assert_eq!(tip.winning_stacks_block_hash, block.block_hash());
        }

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        last_block = Some(stacks_block.clone());

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }
}

#[test]
fn test_build_anchored_blocks_stx_transfers_single() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2002, 2003);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
    let mut sender_nonce = 0;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);

                if tenure_id > 0 {
                    let stx_transfer = make_user_stacks_transfer(
                        &privk,
                        sender_nonce,
                        200,
                        &recipient.to_account_principal(),
                        1,
                    );
                    sender_nonce += 1;

                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &stx_transfer,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if tenure_id > 0 {
            // transaction was mined
            assert_eq!(stacks_block.txs.len(), 2);
            if let TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) =
                stacks_block.txs[1].payload
            {
                assert_eq!(*addr, recipient.to_account_principal());
                assert_eq!(*amount, 1);
            } else {
                assert!(false);
            }
        }
    }
}

#[test]
fn test_build_anchored_blocks_empty_with_builder_timeout() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2022, 2023);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
    let mut sender_nonce = 0;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);

                if tenure_id > 0 {
                    let stx_transfer = make_user_stacks_transfer(
                        &privk,
                        sender_nonce,
                        200,
                        &recipient.to_account_principal(),
                        1,
                    );
                    sender_nonce += 1;

                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &stx_transfer,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    // no time to mine anything, so all blocks should be empty
                    BlockBuilderSettings {
                        max_miner_time_ms: 0,
                        ..BlockBuilderSettings::max_value()
                    },
                    None,
                    &burnchain,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if tenure_id > 0 {
            // transaction was NOT mined due to timeout
            assert_eq!(stacks_block.txs.len(), 1);
        }
    }
}

#[test]
fn test_build_anchored_blocks_stx_transfers_multi() {
    let mut privks = vec![];
    let mut balances = vec![];
    let num_blocks = 10;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        privks.push(privk);
        balances.push((addr.to_account_principal(), 100000000));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2004, 2005);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
    let mut sender_nonce = 0;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);

                if tenure_id > 0 {
                    for i in 0..5 {
                        let stx_transfer = make_user_stacks_transfer(
                            &privks[i],
                            sender_nonce,
                            200,
                            &recipient.to_account_principal(),
                            1,
                        );
                        mempool
                            .submit(
                                chainstate,
                                sortdb,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    // test pagination by timestamp
                    test_debug!("Delay for 1.5s");
                    sleep_ms(1500);

                    for i in 5..10 {
                        let stx_transfer = make_user_stacks_transfer(
                            &privks[i],
                            sender_nonce,
                            200,
                            &recipient.to_account_principal(),
                            1,
                        );
                        mempool
                            .submit(
                                chainstate,
                                sortdb,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                &stx_transfer,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch20,
                            )
                            .unwrap();
                    }

                    sender_nonce += 1;
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if tenure_id > 0 {
            // transaction was mined, even though they were staggerred by time
            assert_eq!(stacks_block.txs.len(), 11);
            for i in 1..11 {
                if let TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) =
                    stacks_block.txs[i].payload
                {
                    assert_eq!(*addr, recipient.to_account_principal());
                    assert_eq!(*amount, 1);
                } else {
                    assert!(false);
                }
            }
        }
    }
}

#[test]
fn test_build_anchored_blocks_connected_by_microblocks_across_epoch() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2016, 2017);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let epochs = EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 30, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 30,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost {
                write_length: 205205,
                write_count: 205205,
                read_length: 205205,
                read_count: 205205,
                runtime: 205205,
            },
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
    ]);
    peer_config.epochs = Some(epochs);

    let num_blocks = 10;

    let mut mblock_privks = vec![];
    for _ in 0..num_blocks {
        let mblock_privk = StacksPrivateKey::random();
        mblock_privks.push(mblock_privk);
    }

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let mut last_block = None;
    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let acct = get_stacks_account(&mut peer, &addr.to_account_principal());

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &parent_header_hash,
                );

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);
                let sort_ic = sortdb.index_handle_at_tip();
                let (parent_mblock_stream, mblock_pubkey_hash) = {
                    if tenure_id > 0 {
                        chainstate
                            .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                            .unwrap();

                        let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();
                        // produce the microblock stream for the parent, which this tenure's anchor
                        // block will confirm.
                        let mut microblock_builder = StacksMicroblockBuilder::new(
                            parent_header_hash.clone(),
                            parent_consensus_hash.clone(),
                            chainstate,
                            &sort_ic,
                            BlockBuilderSettings::max_value(),
                        )
                        .unwrap();

                        let mut microblocks = vec![];

                        let mblock_tx = make_user_stacks_transfer(
                            &privk,
                            acct.nonce,
                            200,
                            &recipient.to_account_principal(),
                            1,
                        );

                        let mblock_tx_len = {
                            let mut bytes = vec![];
                            mblock_tx.consensus_serialize(&mut bytes).unwrap();
                            bytes.len() as u64
                        };

                        test_debug!(
                            "Make microblock parent stream for block in tenure {}",
                            tenure_id
                        );
                        let mblock = microblock_builder
                            .mine_next_microblock_from_txs(
                                vec![(mblock_tx, mblock_tx_len)],
                                &parent_microblock_privkey,
                            )
                            .unwrap();
                        microblocks.push(mblock);

                        let microblock_privkey = mblock_privks[tenure_id].clone();
                        let mblock_pubkey_hash = Hash160::from_node_public_key(
                            &StacksPublicKey::from_private(&microblock_privkey),
                        );
                        (microblocks, mblock_pubkey_hash)
                    } else {
                        let parent_microblock_privkey = mblock_privks[tenure_id].clone();
                        let mblock_pubkey_hash = Hash160::from_node_public_key(
                            &StacksPublicKey::from_private(&parent_microblock_privkey),
                        );
                        (vec![], mblock_pubkey_hash)
                    }
                };

                test_debug!("Store parent microblocks for tenure {}", tenure_id);
                for mblock in parent_mblock_stream.iter() {
                    let stored = chainstate
                        .preprocess_streamed_microblock(
                            &parent_consensus_hash,
                            &parent_header_hash,
                            mblock,
                        )
                        .unwrap();
                    assert!(stored);
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sort_ic,
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                if !parent_mblock_stream.is_empty() {
                    if tenure_id != 5 {
                        assert_eq!(
                            anchored_block.0.header.parent_microblock,
                            parent_mblock_stream.last().unwrap().block_hash()
                        );
                    } else {
                        // epoch change happened, so miner didn't confirm any microblocks
                        assert!(!anchored_block.0.has_microblock_parent());
                    }
                }

                (anchored_block.0, parent_mblock_stream)
            },
        );

        last_block = Some(stacks_block.clone());

        test_debug!("Process tenure {}", tenure_id);

        // should always succeed
        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip_checked(&stacks_block, &[])
            .unwrap();
    }

    let last_block = last_block.unwrap();
    assert_eq!(last_block.header.total_work.work, 10); // mined a chain successfully across the epoch boundary
}

#[test]
#[should_panic(expected = "success")]
fn test_build_anchored_blocks_connected_by_microblocks_across_epoch_invalid() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2018, 2019);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let epochs = EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 30, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 30,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost {
                write_length: 205205,
                write_count: 205205,
                read_length: 205205,
                read_count: 205205,
                runtime: 205205,
            },
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
    ]);
    peer_config.epochs = Some(epochs);

    let num_blocks = 10;

    let mut mblock_privks = vec![];
    for _ in 0..num_blocks {
        let mblock_privk = StacksPrivateKey::random();
        mblock_privks.push(mblock_privk);
    }

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let mut last_block: Option<StacksBlock> = None;
    let mut last_block_ch: Option<ConsensusHash> = None;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let acct = get_stacks_account(&mut peer, &addr.to_account_principal());

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();

                        if tenure_id < 6 {
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &block.block_hash(),
                                )
                                .unwrap()
                                .unwrap();

                            StacksChainState::get_anchored_block_header_info(
                                chainstate.db(),
                                &snapshot.consensus_hash,
                                &snapshot.winning_stacks_block_hash,
                            )
                            .unwrap()
                            .unwrap()
                        } else {
                            // first block after the invalid block that had a microblock parent
                            // while straddling the epoch boundary.
                            // Verify that the last block was indeed marked as invalid, and abort.
                            let bhh = last_block.as_ref().unwrap().block_hash();
                            let ch = last_block_ch.as_ref().unwrap().clone();
                            assert!(StacksChainState::is_block_orphaned(
                                chainstate.db(),
                                &ch,
                                &bhh
                            )
                            .unwrap());
                            panic!("success");
                        }
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &parent_header_hash,
                );

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let coinbase_tx = make_coinbase(miner, tenure_id);
                let sort_ic = sortdb.index_handle_at_tip();
                let (parent_mblock_stream, mblock_pubkey_hash) = {
                    if tenure_id > 0 {
                        chainstate
                            .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                            .unwrap();

                        let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                        // produce the microblock stream for the parent, which this tenure's anchor
                        // block will confirm.
                        let mut microblock_builder = StacksMicroblockBuilder::new(
                            parent_header_hash.clone(),
                            parent_consensus_hash.clone(),
                            chainstate,
                            &sort_ic,
                            BlockBuilderSettings::max_value(),
                        )
                        .unwrap();

                        let mut microblocks = vec![];

                        let mblock_tx = make_user_stacks_transfer(
                            &privk,
                            acct.nonce,
                            (200 + tenure_id) as u64,
                            &recipient.to_account_principal(),
                            1,
                        );

                        let mblock_tx_len = {
                            let mut bytes = vec![];
                            mblock_tx.consensus_serialize(&mut bytes).unwrap();
                            bytes.len() as u64
                        };

                        test_debug!(
                            "Make microblock parent stream for block in tenure {}",
                            tenure_id
                        );
                        let mblock = microblock_builder
                            .mine_next_microblock_from_txs(
                                vec![(mblock_tx, mblock_tx_len)],
                                &parent_microblock_privkey,
                            )
                            .unwrap();
                        microblocks.push(mblock);

                        let microblock_privkey = mblock_privks[tenure_id].clone();
                        let mblock_pubkey_hash = Hash160::from_node_public_key(
                            &StacksPublicKey::from_private(&microblock_privkey),
                        );
                        (microblocks, mblock_pubkey_hash)
                    } else {
                        let parent_microblock_privkey = mblock_privks[tenure_id].clone();
                        let mblock_pubkey_hash = Hash160::from_node_public_key(
                            &StacksPublicKey::from_private(&parent_microblock_privkey),
                        );
                        (vec![], mblock_pubkey_hash)
                    }
                };

                test_debug!("Store parent microblocks for tenure {}", tenure_id);
                for mblock in parent_mblock_stream.iter() {
                    let stored = chainstate
                        .preprocess_streamed_microblock(
                            &parent_consensus_hash,
                            &parent_header_hash,
                            mblock,
                        )
                        .unwrap();
                    assert!(stored);
                }

                let mut anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sort_ic,
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                if parent_mblock_stream.is_empty() {
                    assert_eq!(tenure_id, 0);
                } else {
                    // force the block to confirm a microblock stream, even if it would result in
                    // an invalid block.
                    test_debug!(
                        "Force {} to have a microblock parent",
                        &anchored_block.0.block_hash()
                    );
                    anchored_block.0.header.parent_microblock =
                        parent_mblock_stream.last().unwrap().block_hash();
                    anchored_block.0.header.parent_microblock_sequence =
                        (parent_mblock_stream.len() as u16).saturating_sub(1);
                    assert_eq!(
                        anchored_block.0.header.parent_microblock,
                        parent_mblock_stream.last().unwrap().block_hash()
                    );
                    test_debug!("New block hash is {}", &anchored_block.0.block_hash());
                }

                (anchored_block.0, parent_mblock_stream)
            },
        );

        last_block = Some(stacks_block.clone());

        test_debug!("Process tenure {}", tenure_id);
        let (_, _, block_ch) = peer.next_burnchain_block(burn_ops.clone());

        if tenure_id != 5 {
            // should always succeed
            peer.process_stacks_epoch_at_tip_checked(&stacks_block, &[])
                .unwrap();
        } else {
            // should fail at first, since the block won't be available
            // (since validate_anchored_block_burnchain() will fail)
            if let Err(e) = peer.process_stacks_epoch_at_tip_checked(&stacks_block, &[]) {
                match e {
                    CoordinatorError::ChainstateError(ChainstateError::InvalidStacksBlock(_)) => {}
                    x => {
                        panic!("Unexpected error {:?}", &x);
                    }
                }
            } else {
                panic!("processed epoch successfully");
            }

            // the parent of this block crosses the epoch boundary
            let last_block_ch = last_block_ch.clone().unwrap();
            assert!(StacksChainState::block_crosses_epoch_boundary(
                peer.chainstate().db(),
                &last_block_ch,
                &stacks_block.header.parent_block
            )
            .unwrap());

            // forcibly store the block
            store_staging_block(
                peer.chainstate(),
                &block_ch,
                &stacks_block,
                &last_block_ch,
                stacks_block.header.total_work.burn,
                stacks_block.header.total_work.burn,
            );

            // should run to completion, but the block should *not* be processed
            // (this tests append_block())
            peer.process_stacks_epoch_at_tip_checked(&stacks_block, &[])
                .unwrap();
        }

        last_block_ch = Some(
            SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
                .unwrap()
                .consensus_hash,
        );
    }

    let last_block = last_block.unwrap();
    assert_eq!(last_block.header.total_work.work, 10); // mined a chain successfully across the epoch boundary
}

#[test]
/// This test covers two different behaviors added to the block assembly logic:
/// (1) Ordering by estimated fee rate: the test peer uses the "unit" estimator
/// for costs, but this estimator still uses the fee of the transaction to order
/// the mempool. This leads to the behavior in this test where txs are included
/// like 0 -> 1 -> 2 ... -> 25 -> next origin 0 -> 1 ...
/// because the fee goes up with the nonce.
/// (2) Discovery of nonce in the mempool iteration: this behavior allows the miner
/// to consider an origin's "next" transaction immediately. Prior behavior would
/// only do so after processing any other origin's transactions.
fn test_build_anchored_blocks_incrementing_nonces() {
    let private_keys: Vec<_> = (0..10).map(|_| StacksPrivateKey::random()).collect();
    let addresses: Vec<_> = private_keys
        .iter()
        .map(|sk| {
            StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(sk)],
            )
            .unwrap()
        })
        .collect();

    let initial_balances: Vec<_> = addresses
        .iter()
        .map(|addr| (addr.to_account_principal(), 100000000000))
        .collect();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2030, 2031);
    peer_config.initial_balances = initial_balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    // during the tenure, let's push transactions to the mempool
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
        |ref mut miner,
         ref mut sortdb,
         ref mut chainstate,
         vrf_proof,
         ref parent_opt,
         ref parent_microblock_header_opt| {
            let parent_tip = match parent_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(block) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap()
                    .unwrap(); // succeeds because we don't fork
                    StacksChainState::get_anchored_block_header_info(
                        chainstate.db(),
                        &snapshot.consensus_hash,
                        &snapshot.winning_stacks_block_hash,
                    )
                    .unwrap()
                    .unwrap()
                }
            };

            let parent_header_hash = parent_tip.anchored_header.block_hash();
            let parent_consensus_hash = parent_tip.consensus_hash.clone();
            let coinbase_tx = make_coinbase(miner, 0);

            let txs: Vec<_> = private_keys
                .iter()
                .flat_map(|privk| {
                    let privk = privk.clone();
                    (0..25).map(move |tx_nonce| {
                        let contract = "(define-data-var bar int 0)";
                        make_user_contract_publish(
                            &privk,
                            tx_nonce,
                            200 * (tx_nonce + 1),
                            &format!("contract-{}", tx_nonce),
                            contract,
                        )
                    })
                })
                .collect();

            for tx in txs {
                mempool
                    .submit(
                        chainstate,
                        sortdb,
                        &parent_consensus_hash,
                        &parent_header_hash,
                        &tx,
                        None,
                        &ExecutionCost::max_value(),
                        &StacksEpochId::Epoch20,
                    )
                    .unwrap();
            }

            let anchored_block = StacksBlockBuilder::build_anchored_block(
                chainstate,
                &sortdb.index_handle_at_tip(),
                &mut mempool,
                &parent_tip,
                tip.total_burn,
                vrf_proof,
                Hash160([0; 20]),
                &coinbase_tx,
                BlockBuilderSettings::limited(),
                None,
                &burnchain,
            )
            .unwrap();
            (anchored_block.0, vec![])
        },
    );

    peer.next_burnchain_block(burn_ops);
    peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

    // expensive transaction was not mined, but the two stx-transfers were
    assert_eq!(stacks_block.txs.len(), 251);

    // block should be ordered like coinbase, nonce 0, nonce 1, .. nonce 25, nonce 0, ..
    //  because the tx fee for each transaction increases with the nonce
    for (i, tx) in stacks_block.txs.iter().enumerate() {
        if i == 0 {
            let okay = matches!(tx.payload, TransactionPayload::Coinbase(..));
            assert!(okay, "Coinbase should be first tx");
        } else {
            let expected_nonce = (i - 1) % 25;
            assert_eq!(
                tx.get_origin_nonce(),
                expected_nonce as u64,
                "{i}th transaction should have nonce = {expected_nonce}",
            );
        }
    }
}

#[test]
fn test_build_anchored_blocks_skip_too_expensive() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let privk_extra = StacksPrivateKey::from_hex(
        "f67c7437f948ca1834602b28595c12ac744f287a4efaf70d437042a6afed81bc01",
    )
    .unwrap();
    let mut privks_expensive = vec![];
    let mut initial_balances = vec![];
    let num_blocks = 10;
    for i in 0..num_blocks {
        let pk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&pk)],
        )
        .unwrap()
        .to_account_principal();

        privks_expensive.push(pk);
        initial_balances.push((addr, 10000000000));
    }

    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();
    let addr_extra = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk_extra)],
    )
    .unwrap();

    initial_balances.push((addr.to_account_principal(), 100000000000));
    initial_balances.push((addr_extra.to_account_principal(), 200000000000));

    let mut peer_config = TestPeerConfig::new(function_name!(), 2006, 2007);
    peer_config.initial_balances = initial_balances;
    peer_config.epochs = Some(EpochList::new(&[StacksEpoch {
        epoch_id: StacksEpochId::Epoch20,
        start_height: 0,
        end_height: i64::MAX as u64,
        // enough for the first stx-transfer, but not for the analysis of the smart
        // contract.
        block_limit: ExecutionCost {
            write_length: 100,
            write_count: 100,
            read_length: 100,
            read_count: 100,
            runtime: 3350,
        },
        network_epoch: PEER_VERSION_EPOCH_2_0,
    }]));
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
    let mut sender_nonce = 0;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                if tenure_id > 0 {
                    let mut expensive_part = vec![];
                    for i in 0..100 {
                        expensive_part.push(format!("(define-data-var var-{} int 0)", i));
                    }
                    let contract = format!(
                        "{}
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))",
                        expensive_part.join("\n")
                    );

                    // fee high enough to get mined first
                    let stx_transfer = make_user_stacks_transfer(
                        &privk,
                        sender_nonce,
                        (4 * contract.len()) as u64,
                        &recipient.to_account_principal(),
                        1,
                    );
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &stx_transfer,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    // will never get mined
                    let contract_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        0,
                        (2 * contract.len()) as u64,
                        &format!("hello-world-{tenure_id}"),
                        &contract,
                    );

                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &contract_tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    // will get mined last
                    let stx_transfer = make_user_stacks_transfer(
                        &privk_extra,
                        sender_nonce,
                        300,
                        &recipient.to_account_principal(),
                        1,
                    );
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &stx_transfer,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    sender_nonce += 1;
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::limited(),
                    None,
                    &burnchain,
                )
                .unwrap();
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if tenure_id > 0 {
            // expensive transaction was not mined, but the two stx-transfers were
            assert_eq!(stacks_block.txs.len(), 3);
            for tx in stacks_block.txs.iter() {
                match tx.payload {
                    TransactionPayload::Coinbase(..) => {}
                    TransactionPayload::TokenTransfer(ref recipient, ref amount, ref memo) => {}
                    _ => {
                        assert!(false);
                    }
                }
            }
        }
    }
}

#[test]
fn test_build_anchored_blocks_mempool_fee_transaction_too_low() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2032, 2033);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
        |ref mut miner,
         ref mut sortdb,
         ref mut chainstate,
         vrf_proof,
         ref parent_opt,
         ref parent_microblock_header_opt| {
            let parent_tip = match parent_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(block) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                    StacksChainState::get_anchored_block_header_info(
                        chainstate.db(),
                        &snapshot.consensus_hash,
                        &snapshot.winning_stacks_block_hash,
                    )
                    .unwrap()
                    .unwrap()
                }
            };

            let parent_header_hash = parent_tip.anchored_header.block_hash();
            let parent_consensus_hash = parent_tip.consensus_hash.clone();

            let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

            let coinbase_tx = make_coinbase(miner, 0);

            // Create a zero-fee transaction
            let zero_fee_tx = make_user_stacks_transfer(
                &privk,
                0,
                0, // Set fee to 0
                &recipient.to_account_principal(),
                1000,
            );

            let result = mempool.submit(
                chainstate,
                sortdb,
                &parent_consensus_hash,
                &parent_header_hash,
                &zero_fee_tx,
                None,
                &ExecutionCost::max_value(),
                &StacksEpochId::Epoch20,
            );

            match result {
                Ok(_) => panic!("Expected FeeTooLow error but transaction was accepted"),
                Err(e) => match e {
                    MemPoolRejection::FeeTooLow(actual, required) => {
                        assert_eq!(actual, 0);
                        assert_eq!(required, 180);
                    }
                    _ => panic!("Unexpected error: {:?}", e),
                },
            };

            let anchored_block = StacksBlockBuilder::build_anchored_block(
                chainstate,
                &sortdb.index_handle_at_tip(),
                &mut mempool,
                &parent_tip,
                tip.total_burn,
                vrf_proof,
                Hash160([0; 20]),
                &coinbase_tx,
                BlockBuilderSettings::max_value(),
                None,
                &burnchain,
            )
            .unwrap();

            (anchored_block.0, vec![])
        },
    );

    peer.next_burnchain_block(burn_ops);
    peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

    // Check that the block contains only coinbase transactions (coinbase)
    assert_eq!(stacks_block.txs.len(), 1);
}

#[test]
fn test_build_anchored_blocks_zero_fee_transaction() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2032, 2033);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
        |ref mut miner,
         ref mut sortdb,
         ref mut chainstate,
         vrf_proof,
         ref parent_opt,
         ref parent_microblock_header_opt| {
            let parent_tip = match parent_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(block) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                    StacksChainState::get_anchored_block_header_info(
                        chainstate.db(),
                        &snapshot.consensus_hash,
                        &snapshot.winning_stacks_block_hash,
                    )
                    .unwrap()
                    .unwrap()
                }
            };

            let coinbase_tx = make_coinbase(miner, 0);

            // Create a zero-fee transaction
            let zero_fee_tx = make_user_stacks_transfer(
                &privk,
                0,
                0, // Set fee to 0
                &recipient.to_account_principal(),
                1000,
            );

            let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                &burnchain,
                &parent_tip,
                vrf_proof,
                tip.total_burn,
                Hash160([0; 20]),
            )
            .unwrap();

            let anchored_block = StacksBlockBuilder::make_anchored_block_from_txs(
                block_builder,
                chainstate,
                &sortdb.index_handle_at_tip(),
                vec![coinbase_tx, zero_fee_tx],
            )
            .unwrap();

            (anchored_block.0, vec![])
        },
    );

    peer.next_burnchain_block(burn_ops);
    peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

    // Check that the block contains 2 transactions (coinbase + zero-fee transaction)
    assert_eq!(stacks_block.txs.len(), 2);

    // Verify that the zero-fee transaction is in the block
    let zero_fee_tx = &stacks_block.txs[1];
    assert_eq!(zero_fee_tx.get_tx_fee(), 0);
}

#[test]
fn test_build_anchored_blocks_multiple_chaintips() {
    let mut privks = vec![];
    let mut balances = vec![];
    let num_blocks = 10;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        privks.push(privk);
        balances.push((addr.to_account_principal(), 100000000));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2008, 2009);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    // make a blank chainstate and mempool so we can mine empty blocks
    //  without punishing the correspondingly "too expensive" transactions
    let blank_chainstate = instantiate_chainstate(false, 1, function_name!());
    let mut blank_mempool = MemPoolDB::open_test(false, 1, &blank_chainstate.root_path).unwrap();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                if tenure_id > 0 {
                    let contract = "
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        0,
                        (2 * contract.len()) as u64,
                        &format!("hello-world-{tenure_id}"),
                        contract,
                    );
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &contract_tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                let anchored_block = {
                    let mempool_to_use = if tenure_id < num_blocks - 1 {
                        &mut blank_mempool
                    } else {
                        &mut mempool
                    };

                    StacksBlockBuilder::build_anchored_block(
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        mempool_to_use,
                        &parent_tip,
                        tip.total_burn,
                        vrf_proof,
                        Hash160([tenure_id as u8; 20]),
                        &coinbase_tx,
                        BlockBuilderSettings::limited(),
                        None,
                        &burnchain,
                    )
                    .unwrap()
                };
                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if tenure_id < num_blocks - 1 {
            assert_eq!(stacks_block.txs.len(), 1);
        } else {
            assert_eq!(stacks_block.txs.len(), num_blocks);
        }
    }
}

#[test]
fn test_build_anchored_blocks_empty_chaintips() {
    let mut privks = vec![];
    let mut balances = vec![];
    let num_blocks = 10;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        privks.push(privk);
        balances.push((addr.to_account_principal(), 100000000));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2010, 2011);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                // submit a transaction for the _next_ block to pick up
                if tenure_id > 0 {
                    let contract = "
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        0,
                        2000,
                        &format!("hello-world-{tenure_id}"),
                        contract,
                    );
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &contract_tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        test_debug!(
            "\n\ncheck tenure {}: {} transactions\n",
            tenure_id,
            stacks_block.txs.len()
        );

        if tenure_id > 1 {
            // two transactions after the first two tenures
            assert_eq!(stacks_block.txs.len(), 2);
        } else {
            assert_eq!(stacks_block.txs.len(), 1);
        }
    }
}

#[test]
fn test_build_anchored_blocks_too_expensive_transactions() {
    let mut privks = vec![];
    let mut balances = vec![];
    let num_blocks = 3;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        privks.push(privk);
        balances.push((addr.to_account_principal(), 100000000));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2013, 2014);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                if tenure_id == 2 {
                    let contract = "
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                    // should be mined once
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        0,
                        100000000 / 2 + 1,
                        &format!("hello-world-{tenure_id}"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);

                    // should never be mined
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        1,
                        100000000 / 2,
                        &format!("hello-world-{tenure_id}-2"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        test_debug!(
            "\n\ncheck tenure {}: {} transactions\n",
            tenure_id,
            stacks_block.txs.len()
        );

        // assert_eq!(stacks_block.txs.len(), 1);
    }
}

#[test]
fn test_build_anchored_blocks_invalid() {
    let peer_config = TestPeerConfig::new(function_name!(), 2014, 2015);
    let burnchain = peer_config.burnchain.clone();
    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let num_blocks = 10;
    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let mut last_block: Option<StacksBlock> = None;
    let mut last_valid_block: Option<StacksBlock> = None;
    let mut last_parent: Option<StacksBlock> = None;
    let mut last_parent_tip: Option<StacksHeaderInfo> = None;

    let bad_block_tenure = 6;
    let bad_block_ancestor_tenure = 3;
    let resume_parent_tenure = 5;

    let mut bad_block_tip: Option<BlockSnapshot> = None;
    let mut bad_block_parent: Option<StacksBlock> = None;
    let mut bad_block_parent_tip: Option<StacksHeaderInfo> = None;
    let mut bad_block_parent_commit: Option<LeaderBlockCommitOp> = None;

    let mut resume_tenure_parent_commit: Option<LeaderBlockCommitOp> = None;
    let mut resume_tip: Option<BlockSnapshot> = None;

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let mut tip =
            SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
                .unwrap();

        if tenure_id == bad_block_ancestor_tenure {
            bad_block_tip = Some(tip.clone());
        } else if tenure_id == bad_block_tenure {
            tip = bad_block_tip.clone().unwrap();
        } else if tenure_id == resume_parent_tenure {
            resume_tip = Some(tip.clone());
        } else if tenure_id == bad_block_tenure + 1 {
            tip = resume_tip.clone().unwrap();
        }

        let (mut burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
            let parent_opt =
                if tenure_id != bad_block_tenure {
                    if let Some(p) = &last_parent {
                        assert!(tenure_id == bad_block_tenure + 1);
                        Some(p.clone())
                    }
                    else {
                        assert!(tenure_id != bad_block_tenure + 1);
                        match parent_opt {
                            Some(p) => Some((*p).clone()),
                            None => None
                        }
                    }
                }
                else {
                    bad_block_parent.clone()
                };

            let parent_tip =
                if tenure_id != bad_block_tenure {
                    if let Some(tip) = &last_parent_tip {
                        assert!(tenure_id == bad_block_tenure + 1);
                        tip.clone()
                    }
                    else {
                        assert!(tenure_id != bad_block_tenure + 1);
                        match parent_opt {
                            None => {
                                StacksChainState::get_genesis_header_info(chainstate.db()).unwrap()
                            }
                            Some(ref block) => {
                                let ic = sortdb.index_conn();
                                let parent_block_hash =
                                    if let Some(block) = last_valid_block.as_ref() {
                                        block.block_hash()
                                    }
                                    else {
                                        block.block_hash()
                                    };

                                let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(&ic, &tip.sortition_id, &parent_block_hash).unwrap().unwrap();      // succeeds because we don't fork
                                StacksChainState::get_anchored_block_header_info(chainstate.db(), &snapshot.consensus_hash, &snapshot.winning_stacks_block_hash).unwrap().unwrap()
                            }
                        }
                    }
                }
                else {
                    bad_block_parent_tip.clone().unwrap()
                };

            if tenure_id == resume_parent_tenure {
                // resume here
                last_parent = parent_opt.clone();
                last_parent_tip = Some(parent_tip.clone());

                eprintln!("\n\nat resume parent tenure:\nlast_parent: {:?}\nlast_parent_tip: {:?}\n\n", &last_parent, &last_parent_tip);
            }
            else if tenure_id >= bad_block_tenure + 1 {
                last_parent = None;
                last_parent_tip = None;
            }

            if tenure_id == bad_block_ancestor_tenure {
                bad_block_parent_tip = Some(parent_tip.clone());
                bad_block_parent = parent_opt;

                eprintln!("\n\nancestor of corrupt block: {:?}\n", &parent_tip);
            }

            if tenure_id == bad_block_tenure + 1 {
                // prior block was invalid; reset nonce
                miner.set_nonce(resume_parent_tenure as u64);
            }
            else if tenure_id == bad_block_tenure {
                // building off of a long-gone snapshot
                miner.set_nonce(miner.get_nonce() - ((bad_block_tenure - bad_block_ancestor_tenure) as u64));
            }

            let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

            let coinbase_tx = make_coinbase(miner, tenure_id as usize);

            let mut anchored_block = StacksBlockBuilder::build_anchored_block(
                chainstate, &sortdb.index_handle_at_tip(), &mut mempool, &parent_tip, tip.total_burn, vrf_proof, Hash160([tenure_id as u8; 20]), &coinbase_tx, BlockBuilderSettings::max_value(), None, &burnchain,
            ).unwrap();

            if tenure_id == bad_block_tenure {
                // corrupt the block
                eprintln!("\n\ncorrupt block {:?}\nparent: {:?}\n", &anchored_block.0.header, &parent_tip.anchored_header);
                anchored_block.0.header.state_index_root = TrieHash([0xff; 32]);
            }

            (anchored_block.0, vec![])
        });

        if tenure_id == bad_block_tenure + 1 {
            // adjust
            for i in 0..burn_ops.len() {
                if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i] {
                    opdata.parent_block_ptr =
                        (resume_tenure_parent_commit.as_ref().unwrap().block_height as u32) - 1;
                }
            }
        } else if tenure_id == bad_block_tenure {
            // adjust
            for i in 0..burn_ops.len() {
                if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i] {
                    opdata.parent_block_ptr =
                        (bad_block_parent_commit.as_ref().unwrap().block_height as u32) - 1;
                    eprintln!("\n\ncorrupt block commit is now {:?}\n", opdata);
                }
            }
        } else if tenure_id == bad_block_ancestor_tenure {
            // find
            for i in 0..burn_ops.len() {
                if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i] {
                    bad_block_parent_commit = Some(opdata.clone());
                }
            }
        } else if tenure_id == resume_parent_tenure {
            // find
            for i in 0..burn_ops.len() {
                if let BlockstackOperationType::LeaderBlockCommit(ref mut opdata) = burn_ops[i] {
                    resume_tenure_parent_commit = Some(opdata.clone());
                }
            }
        }

        if tenure_id != bad_block_tenure {
            last_block = Some(stacks_block.clone());
            last_valid_block = last_block.clone();
        } else {
            last_block = last_valid_block.clone();
        }

        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch(&stacks_block, &consensus_hash, &microblocks);
    }
}

#[test]
fn test_build_anchored_blocks_bad_nonces() {
    let mut privks = vec![];
    let mut balances = vec![];
    let num_blocks = 10;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        privks.push(privk);
        balances.push((addr.to_account_principal(), 100000000));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2012, 2013);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    for tenure_id in 0..num_blocks {
        eprintln!("Start tenure {:?}", tenure_id);
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_tip_ch = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                if tenure_id == 2 {
                    let contract = "
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                    // should be mined once
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        0,
                        10000,
                        &format!("hello-world-{tenure_id}"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_tip_ch,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("first tx submitted");
                    // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);

                    // should never be mined
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        1,
                        10000,
                        &format!("hello-world-{tenure_id}-2"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_tip_ch,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("second tx submitted");
                    // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);
                }

                if tenure_id == 3 {
                    let contract = "
                (define-data-var bar int 0)
                (define-public (get-bar) (ok (var-get bar)))
                (define-public (set-bar (x int) (y int))
                  (begin (var-set bar (/ x y)) (ok (var-get bar))))";

                    // should be mined once
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        0,
                        10000,
                        &format!("hello-world-{tenure_id}"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_tip_ch,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("third tx submitted");
                    // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);

                    // should never be mined
                    let contract_tx = make_user_contract_publish(
                        &privks[tenure_id],
                        1,
                        10000,
                        &format!("hello-world-{tenure_id}-2"),
                        contract,
                    );
                    let mut contract_tx_bytes = vec![];
                    contract_tx
                        .consensus_serialize(&mut contract_tx_bytes)
                        .unwrap();
                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_tip_ch,
                            &parent_header_hash,
                            contract_tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();

                    eprintln!("fourth tx submitted");
                    // eprintln!("\n\ntransaction:\n{:#?}\n\n", &contract_tx);

                    sleep_ms(2000);
                }

                let estimator = UnitEstimator;
                let metric = UnitMetric;

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                (anchored_block.0, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        test_debug!(
            "\n\ncheck tenure {}: {} transactions\n",
            tenure_id,
            stacks_block.txs.len()
        );

        // assert_eq!(stacks_block.txs.len(), 1);
    }
}

#[test]
fn test_build_microblock_stream_forks() {
    let mut privks = vec![];
    let mut addrs = vec![];
    let mut mblock_privks = vec![];
    let mut balances = vec![];
    let num_blocks = 10;
    let initial_balance = 100000000;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let mblock_privk = StacksPrivateKey::random();

        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        addrs.push(addr.clone());
        privks.push(privk);
        mblock_privks.push(mblock_privk);
        balances.push((addr.to_account_principal(), initial_balance));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2014, 2015);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db())
                        .unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot =
                            SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                &ic,
                                &tip.sortition_id,
                                &block.block_hash(),
                            )
                            .unwrap()
                            .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash);
                let parent_size = parent_tip.anchored_block_size;

                let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let expected_parent_microblock_opt =
                    if tenure_id > 0 {
                        let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                        let parent_mblock_stream = {
                            let parent_cost = StacksChainState::get_stacks_block_anchored_cost(chainstate.db(), &StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash)).unwrap().unwrap();

                            // produce the microblock stream for the parent, which this tenure's anchor
                            // block will confirm.
                            let sort_ic = sortdb.index_handle_at_tip();

                            chainstate
                                .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                .unwrap();

                            let mut microblock_builder = StacksMicroblockBuilder::new(parent_header_hash.clone(), parent_consensus_hash.clone(), chainstate, &sort_ic, BlockBuilderSettings::max_value()).unwrap();

                            let mut microblocks = vec![];
                            for i in 0..5 {
                                let mblock_tx = make_user_contract_publish(
                                    &privks[tenure_id - 1],
                                    i,
                                    0,
                                    &format!("hello-world-{}-{}", i, thread_rng().gen::<u64>()),
                                    &format!("(begin (print \"{}\"))", thread_rng().gen::<u64>())
                                );
                                let mblock_tx_len = {
                                    let mut bytes = vec![];
                                    mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                    bytes.len() as u64
                                };

                                let mblock = microblock_builder.mine_next_microblock_from_txs(vec![(mblock_tx, mblock_tx_len)], &parent_microblock_privkey).unwrap();
                                microblocks.push(mblock);
                            }
                            microblocks
                        };

                        // make a fork at seq 2
                        let mut forked_parent_microblock_stream = parent_mblock_stream.clone();
                        for i in 2..forked_parent_microblock_stream.len() {
                            let forked_mblock_tx = make_user_contract_publish(
                                &privks[tenure_id - 1],
                                i as u64,
                                0,
                                &format!("hello-world-fork-{}-{}", i, thread_rng().gen::<u64>()),
                                &format!("(begin (print \"fork-{}\"))", thread_rng().gen::<u64>())
                            );

                            forked_parent_microblock_stream[i].txs[0] = forked_mblock_tx;

                            // re-calculate merkle root
                            let txid_vecs: Vec<_> = forked_parent_microblock_stream[i].txs
                                .iter()
                                .map(|tx| tx.txid().as_bytes().to_vec())
                                .collect();

                            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
                            let tx_merkle_root = merkle_tree.root();

                            forked_parent_microblock_stream[i].header.tx_merkle_root = tx_merkle_root;
                            forked_parent_microblock_stream[i].header.prev_block = forked_parent_microblock_stream[i-1].block_hash();
                            forked_parent_microblock_stream[i].header.sign(&parent_microblock_privkey).unwrap();

                            test_debug!("parent of microblock {} is {}", &forked_parent_microblock_stream[i].block_hash(), &forked_parent_microblock_stream[i-1].block_hash());
                        }

                        let mut tail = None;

                        // store two forks, which diverge at seq 2
                        for mblock in parent_mblock_stream.into_iter() {
                            if mblock.header.sequence < 2 {
                                tail = Some((mblock.block_hash(), mblock.header.sequence));
                            }
                            let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, &mblock).unwrap();
                            assert!(stored);
                        }
                        for mblock in forked_parent_microblock_stream[2..].iter() {
                            let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, mblock).unwrap();
                            assert!(stored);
                        }

                        // find the poison-microblock at seq 2
                        let (_, poison_opt) = match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                            chainstate.db(),
                            &parent_index_hash,
                            0,
                            u16::MAX
                        ).unwrap() {
                            Some(x) => x,
                            None => (vec![], None)
                        };

                        if let Some(poison_payload) = poison_opt {
                            let mut tx_bytes = vec![];
                            let poison_microblock_tx = make_user_poison_microblock(
                                &privks[tenure_id - 1],
                                2,
                                0,
                                poison_payload
                            );

                            poison_microblock_tx
                                .consensus_serialize(&mut tx_bytes)
                                .unwrap();

                            mempool
                                .submit_raw(
                                    chainstate,
                                    sortdb,
                                    &parent_consensus_hash,
                                    &parent_header_hash,
                                    tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                                )
                                .unwrap();
                        }
                        // the miner will load a microblock stream up to the first detected
                        // fork (which is at sequence 2)
                        tail
                    }
                    else {
                        None
                    };

                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mblock_pubkey_hash = Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privks[tenure_id]));

                let (anchored_block, block_size, block_execution_cost) = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                // miner should have picked up the preprocessed microblocks, but only up to the
                // fork.
                if let Some((mblock_tail_hash, mblock_tail_seq)) = expected_parent_microblock_opt {
                    assert_eq!(anchored_block.header.parent_microblock, mblock_tail_hash);
                    assert_eq!(anchored_block.header.parent_microblock_sequence, mblock_tail_seq);
                    assert_eq!(mblock_tail_seq, 1);
                }

                // block should contain at least one poison-microblock tx
                if tenure_id > 0 {
                    let mut have_poison_microblock = false;
                    for tx in anchored_block.txs.iter() {
                        if let TransactionPayload::PoisonMicroblock(_, _) = &tx.payload {
                            have_poison_microblock = true;
                        }
                    }
                    assert!(have_poison_microblock, "Anchored block has no poison microblock: {:#?}", &anchored_block);
                }

                (anchored_block, vec![])
            },
        );

        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }

    for (i, addr) in addrs.iter().enumerate() {
        let account = get_stacks_account(&mut peer, &addr.to_account_principal());
        let expected_coinbase = 3_600_000_000;
        test_debug!(
            "Test {}: {}",
            &account.principal.to_string(),
            account.stx_balance.get_total_balance().unwrap()
        );
        if (i as u64) < (num_blocks as u64) - MINER_REWARD_MATURITY - 1 {
            assert_eq!(
                account.stx_balance.get_total_balance().unwrap(),
                (initial_balance as u128)
                    + (expected_coinbase * POISON_MICROBLOCK_COMMISSION_FRACTION) / 100
            );
        } else {
            assert_eq!(
                account.stx_balance.get_total_balance().unwrap(),
                initial_balance as u128
            );
        }
    }
}

#[test]
fn test_build_microblock_stream_forks_with_descendants() {
    // creates a chainstate that looks like this:
    //
    //                                                   [mblock] <- [mblock] <- [tenure-2] (Poison-at-2)
    //                                                 /
    //                                          (2)   /
    // [tenure-0] <- [mblock] <- [mblock] <- [mblock] <- [tenure-1] (Poison-at-2)
    //                                                \
    //                                                 \               (4)
    //                                                   [mblock] <- [mblock] <- [tenure-3] (Poison-at-4)
    //
    //  Tenures 1 and 2 can report PoisonMicroblocks for the same point in the mblock stream
    //  fork as long as they themselves are on different branches.
    //
    //  Tenure 3 can report a PoisonMicroblock for a lower point in the fork and have it mined
    //  (seq(4)), as long as the PoisonMicroblock at seq(2) doesn't find its way into its fork
    //  of the chain history.
    let mut privks = vec![];
    let mut addrs = vec![];
    let mut mblock_privks = vec![];
    let mut balances = vec![];
    let num_blocks = 4;
    let initial_balance = 100000000;

    for _ in 0..num_blocks {
        let privk = StacksPrivateKey::random();
        let mblock_privk = StacksPrivateKey::random();

        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk)],
        )
        .unwrap();

        test_debug!("addr: {:?}", &addr);
        addrs.push(addr.clone());
        privks.push(privk);
        mblock_privks.push(mblock_privk);
        balances.push((addr.to_account_principal(), initial_balance));
    }

    let mut peer_config = TestPeerConfig::new(function_name!(), 2014, 2015);
    peer_config.initial_balances = balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let mut microblock_tail_1: Option<StacksMicroblockHeader> = None;
    let mut microblock_tail_2: Option<StacksMicroblockHeader> = None;

    let mut parent_tip_1 = None;

    let parent_block_ptrs = RefCell::new(HashMap::new());
    let discovered_poison_payload = RefCell::new(None);

    let mut reporters = vec![];

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (mut burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let mut parent_tip =
                    if tenure_id == 0 || tenure_id == 1 {
                        let tip = match parent_opt {
                            None => StacksChainState::get_genesis_header_info(chainstate.db())
                                .unwrap(),
                            Some(block) => {
                                let ic = sortdb.index_conn();
                                let snapshot =
                                    SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                        &ic,
                                        &tip.sortition_id,
                                        &block.block_hash(),
                                    )
                                    .unwrap()
                                    .unwrap(); // succeeds because we don't fork
                                StacksChainState::get_anchored_block_header_info(
                                    chainstate.db(),
                                    &snapshot.consensus_hash,
                                    &snapshot.winning_stacks_block_hash,
                                )
                                .unwrap()
                                .unwrap()
                            }
                        };
                        if tenure_id == 1 {
                            // save this for later
                            parent_tip_1 = Some(tip.clone());
                        }
                        tip
                    }
                    else if tenure_id == 2 || tenure_id == 3 {
                        // tenures 2 and 3 build off of microblock forks, but they share the
                        // same parent anchored block.
                        parent_tip_1.clone().unwrap()
                    }
                    else {
                        unreachable!()
                    };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash);
                let parent_size = parent_tip.anchored_block_size;

                let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let (expected_parent_microblock_opt, fork_1, fork_2) =
                    if tenure_id == 1 {
                        // make a microblock fork
                        let parent_microblock_privkey = mblock_privks[tenure_id - 1].clone();

                        let parent_mblock_stream = {
                            let parent_cost = StacksChainState::get_stacks_block_anchored_cost(chainstate.db(), &StacksBlockHeader::make_index_block_hash(&parent_consensus_hash, &parent_header_hash)).unwrap().unwrap();

                            // produce the microblock stream for the parent, which this tenure's anchor
                            // block will confirm.
                            let sort_ic = sortdb.index_handle_at_tip();

                            chainstate
                                .reload_unconfirmed_state(&sort_ic, parent_index_hash.clone())
                                .unwrap();

                            let mut microblock_builder = StacksMicroblockBuilder::new(parent_header_hash.clone(), parent_consensus_hash.clone(), chainstate, &sort_ic, BlockBuilderSettings::max_value()).unwrap();

                            let mut microblocks = vec![];
                            for i in 0..5 {
                                let mblock_tx = make_user_contract_publish(
                                    &privks[tenure_id - 1],
                                    i,
                                    0,
                                    &format!("hello-world-{}-{}", i, thread_rng().gen::<u64>()),
                                    &format!("(begin (print \"{}\"))", thread_rng().gen::<u64>())
                                );
                                let mblock_tx_len = {
                                    let mut bytes = vec![];
                                    mblock_tx.consensus_serialize(&mut bytes).unwrap();
                                    bytes.len() as u64
                                };

                                let mblock = microblock_builder.mine_next_microblock_from_txs(vec![(mblock_tx, mblock_tx_len)], &parent_microblock_privkey).unwrap();
                                microblocks.push(mblock);
                            }
                            microblocks
                        };

                        // make a fork at seq 2
                        let mut forked_parent_microblock_stream = parent_mblock_stream.clone();
                        for i in 2..parent_mblock_stream.len() {
                            let forked_mblock_tx = make_user_contract_publish(
                                &privks[tenure_id - 1],
                                i as u64,
                                0,
                                &format!("hello-world-fork-{}-{}", i, thread_rng().gen::<u64>()),
                                &format!("(begin (print \"fork-{}\"))", thread_rng().gen::<u64>())
                            );

                            forked_parent_microblock_stream[i].txs[0] = forked_mblock_tx;

                            // re-calculate merkle root
                            let txid_vecs: Vec<_> = forked_parent_microblock_stream[i].txs
                                .iter()
                                .map(|tx| tx.txid().as_bytes().to_vec())
                                .collect();

                            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
                            let tx_merkle_root = merkle_tree.root();

                            forked_parent_microblock_stream[i].header.tx_merkle_root = tx_merkle_root;
                            forked_parent_microblock_stream[i].header.prev_block = forked_parent_microblock_stream[i - 1].block_hash();
                            forked_parent_microblock_stream[i].header.sign(&parent_microblock_privkey).unwrap();

                            test_debug!("parent of microblock {} is {}", &forked_parent_microblock_stream[i].block_hash(), &forked_parent_microblock_stream[i-1].block_hash());
                        }

                        let mut tail = None;

                        // store two forks, which diverge at seq 2
                        for mblock in parent_mblock_stream.iter() {
                            if mblock.header.sequence < 2 {
                                tail = Some((mblock.block_hash(), mblock.header.sequence));
                            }
                            let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, mblock).unwrap();
                            assert!(stored);
                        }
                        for mblock in forked_parent_microblock_stream[2..].iter() {
                            let stored = chainstate.preprocess_streamed_microblock(&parent_consensus_hash, &parent_header_hash, mblock).unwrap();
                            assert!(stored);
                        }

                        // find the poison-microblock at seq 2
                        let (_, poison_opt) = match StacksChainState::load_descendant_staging_microblock_stream_with_poison(
                            chainstate.db(),
                            &parent_index_hash,
                            0,
                            u16::MAX
                        ).unwrap() {
                            Some(x) => x,
                            None => (vec![], None)
                        };

                        if let Some(poison_payload) = poison_opt {
                            *discovered_poison_payload.borrow_mut() = Some(poison_payload.clone());

                            let mut tx_bytes = vec![];
                            let poison_microblock_tx = make_user_poison_microblock(
                                &privks[tenure_id - 1],
                                2,
                                0,
                                poison_payload
                            );

                            poison_microblock_tx
                                .consensus_serialize(&mut tx_bytes)
                                .unwrap();

                            mempool
                                .submit_raw(
                                    chainstate,
                                    sortdb,
                                    &parent_consensus_hash,
                                    &parent_header_hash,
                                    tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                                )
                                .unwrap();
                        }

                        // the miner will load a microblock stream up to the first detected
                        // fork (which is at sequence 2 -- the highest common ancestor between
                        // microblock fork #1 and microblock fork #2)
                        (tail, Some(parent_mblock_stream), Some(forked_parent_microblock_stream))
                    }
                    else if tenure_id == 2 {
                        // build off of the end of microblock fork #1
                        (Some((microblock_tail_1.as_ref().unwrap().block_hash(), microblock_tail_1.as_ref().unwrap().sequence)), None, None)
                    }
                    else if tenure_id == 3 {
                        // builds off of the end of microblock fork #2
                        (Some((microblock_tail_2.as_ref().unwrap().block_hash(), microblock_tail_2.as_ref().unwrap().sequence)), None, None)
                    }
                    else {
                        (None, None, None)
                    };

                if tenure_id == 1 {
                    // prep for tenure 2 and 3
                    microblock_tail_1 = Some(fork_1.as_ref().unwrap().last().clone().unwrap().header.clone());
                    microblock_tail_2 = Some(fork_2.as_ref().unwrap().last().clone().unwrap().header.clone());
                }

                let nonce =
                    if tenure_id == 0 || tenure_id == 1 {
                        tenure_id
                    }
                    else if tenure_id == 2 {
                        1
                    }
                    else if tenure_id == 3 {
                        1
                    }
                    else {
                        unreachable!()
                    };

                let coinbase_tx = make_coinbase_with_nonce(miner, tenure_id, nonce as u64, None);

                let mblock_pubkey_hash = Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privks[tenure_id]));

                test_debug!("Produce tenure {} block off of {}/{}", tenure_id, &parent_consensus_hash, &parent_header_hash);

                // force tenures 2 and 3 to mine off of forked siblings deeper than the
                // detected fork
                if tenure_id == 2 {
                    parent_tip.microblock_tail = microblock_tail_1.clone();

                    // submit the _same_ poison microblock transaction, but to a different
                    // fork.
                    let poison_payload = discovered_poison_payload.borrow().as_ref().unwrap().clone();
                    let poison_microblock_tx = make_user_poison_microblock(
                        &privks[tenure_id],
                        0,
                        0,
                        poison_payload
                    );

                    let mut tx_bytes = vec![];
                    poison_microblock_tx
                        .consensus_serialize(&mut tx_bytes)
                        .unwrap();

                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }
                else if tenure_id == 3 {
                    parent_tip.microblock_tail = microblock_tail_2.clone();

                    // submit a different poison microblock transaction
                    let poison_payload = TransactionPayload::PoisonMicroblock(microblock_tail_1.as_ref().unwrap().clone(), microblock_tail_2.as_ref().unwrap().clone());
                    let poison_microblock_tx = make_user_poison_microblock(
                        &privks[tenure_id],
                        0,
                        0,
                        poison_payload
                    );

                    // erase any pending transactions -- this is a "worse" poison-microblock,
                    // and we want to avoid mining the "better" one
                    mempool.clear_before_coinbase_height(10).unwrap();

                    let mut tx_bytes = vec![];
                    poison_microblock_tx
                        .consensus_serialize(&mut tx_bytes)
                        .unwrap();

                    mempool
                        .submit_raw(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            tx_bytes,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch20,
                        )
                        .unwrap();
                }

                let (anchored_block, block_size, block_execution_cost) = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    parent_tip.anchored_header.as_stacks_epoch2().unwrap().total_work.burn + 1000,
                    vrf_proof,
                    mblock_pubkey_hash,
                    &coinbase_tx,
                    BlockBuilderSettings::max_value(),
                    None,
                    &burnchain,
                )
                .unwrap();

                // miner should have picked up the preprocessed microblocks, but only up to the
                // fork tail reported.

                // block should contain at least one poison-microblock tx
                if tenure_id == 1 {
                    if let Some((mblock_tail_hash, mblock_tail_seq)) = expected_parent_microblock_opt {
                        assert_eq!(anchored_block.header.parent_microblock, mblock_tail_hash);
                        assert_eq!(anchored_block.header.parent_microblock_sequence, mblock_tail_seq);
                    }
                }
                if tenure_id > 0 {
                    let mut have_poison_microblock = false;
                    for tx in anchored_block.txs.iter() {
                        if let TransactionPayload::PoisonMicroblock(_, _) = &tx.payload {
                            have_poison_microblock = true;
                            test_debug!("Have PoisonMicroblock for {} reported by {:?}", &anchored_block.block_hash(), &tx.auth);
                        }
                    }
                    assert!(have_poison_microblock, "Anchored block has no poison microblock: {:#?}", &anchored_block);
                }

                // tenures 2 and 3 build off of 1, but build off of the deepest microblock fork
                if tenure_id == 2 {
                    assert_eq!(anchored_block.header.parent_microblock, microblock_tail_1.as_ref().unwrap().block_hash());
                    assert_eq!(anchored_block.header.parent_microblock_sequence, 4);
                }
                if tenure_id == 3 {
                    assert_eq!(anchored_block.header.parent_microblock, microblock_tail_2.as_ref().unwrap().block_hash());
                    assert_eq!(anchored_block.header.parent_microblock_sequence, 4);
                }

                let mut parent_ptrs = parent_block_ptrs.borrow_mut();
                parent_ptrs.insert(anchored_block.header.parent_block.clone(), parent_tip.burn_header_height);

                (anchored_block, vec![])
            },
        );

        for burn_op in burn_ops.iter_mut() {
            if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = burn_op {
                // patch it up
                op.parent_block_ptr = *parent_block_ptrs
                    .borrow()
                    .get(&stacks_block.header.parent_block)
                    .unwrap();
            }
        }

        let (_, burn_header_hash, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch(&stacks_block, &consensus_hash, &microblocks);

        if tenure_id >= 1 {
            let next_tip = StacksChainState::get_anchored_block_header_info(
                peer.chainstate().db(),
                &consensus_hash,
                &stacks_block.block_hash(),
            )
            .unwrap()
            .unwrap();

            let new_tip_hash = StacksBlockHeader::make_index_block_hash(
                &next_tip.consensus_hash,
                &next_tip.anchored_header.block_hash(),
            );

            let reporter = if tenure_id == 1 {
                addrs[0].clone()
            } else {
                addrs[tenure_id].clone()
            };

            let seq = if tenure_id == 1 || tenure_id == 2 {
                2
            } else {
                4
            };

            // check descendant blocks for their poison-microblock commissions
            test_debug!(
                "new tip at height {}: {}",
                next_tip.stacks_block_height,
                &new_tip_hash
            );
            reporters.push((reporter, new_tip_hash, seq));
        }
    }

    // verify that each submitted poison-microblock created a commission
    for (reporter_addr, chain_tip, seq) in reporters.into_iter() {
        test_debug!("Check {} in {} for report", &reporter_addr, &chain_tip);
        peer.with_db_state(|ref mut sortdb, ref mut chainstate, _, _| {
            chainstate
                .with_read_only_clarity_tx(
                    &sortdb.index_handle_at_tip(),
                    &chain_tip,
                    |clarity_tx| {
                        // the key at height 1 should be reported as poisoned
                        let report = StacksChainState::get_poison_microblock_report(clarity_tx, 1)
                            .unwrap()
                            .unwrap();
                        assert_eq!(report.0, reporter_addr);
                        assert_eq!(report.1, seq);
                        Ok(())
                    },
                )
                .unwrap()
        })
        .unwrap();
    }
}

#[test]
fn test_contract_call_across_clarity_versions() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let privk_anchored = StacksPrivateKey::from_hex(
        "f67c7437f948ca1834602b28595c12ac744f287a4efaf70d437042a6afed81bc01",
    )
    .unwrap();

    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let addr_anchored = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk_anchored)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2024, 2025);
    peer_config.initial_balances = vec![
        (addr.to_account_principal(), 1000000000),
        (addr_anchored.to_account_principal(), 1000000000),
    ];
    let burnchain = peer_config.burnchain.clone();

    let epochs = EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: 2, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 2, // effectively already in 2.1
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
    ]);
    peer_config.epochs = Some(epochs);

    let num_blocks = 10;
    let mut anchored_sender_nonce = 0;
    let mut peer = TestPeer::new(peer_config);
    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let acct = get_stacks_account(&mut peer, &addr.to_account_principal());

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &block.block_hash(),
                        )
                        .unwrap()
                        .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let parent_index_hash = StacksBlockHeader::make_index_block_hash(
                    &parent_consensus_hash,
                    &parent_header_hash,
                );

                let coinbase_tx = make_coinbase(miner, tenure_id);
                let mut anchored_txs = vec![coinbase_tx];

                if tenure_id > 0 {
                    let txs = if tenure_id == 1 {
                        let chain_id_trait_v1 = "
                        (define-trait trait-v1
                            (
                                (get-chain-info-v1 () (response { chain-id: uint } uint))
                            )
                        )
                        ";
                        let trait_v1_tx = make_versioned_user_contract_publish(&privk_anchored, anchored_sender_nonce, (2 * chain_id_trait_v1.len()) as u64, "chain-id-trait-v1", chain_id_trait_v1, ClarityVersion::Clarity1);

                        let chain_id_trait_v2 = "
                        (define-trait trait-v2
                            (
                                (get-chain-info-v2 () (response { chain-id: uint } uint))
                            )
                        )
                        ";
                        let trait_v2_tx = make_versioned_user_contract_publish(&privk_anchored, anchored_sender_nonce + 1, (2 * chain_id_trait_v2.len()) as u64, "chain-id-trait-v2", chain_id_trait_v2, ClarityVersion::Clarity2);

                        let contract = format!("
                        (impl-trait .chain-id-trait-v1.trait-v1)
                        (impl-trait .chain-id-trait-v2.trait-v2)

                        (use-trait chain-info-v1 .chain-id-trait-v1.trait-v1)
                        (use-trait chain-info-v2 .chain-id-trait-v2.trait-v2)

                        (define-data-var call-count uint u0)
                        (define-data-var cc-call-count uint u0)
                        (define-data-var at-block-call-count uint u0)
                        (define-public (test-func)
                            (begin
                                (print {{ tenure: u{}, version: u1, func: \"test-func\" }})
                                (var-set call-count (+ u1 (var-get call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-cc-func)
                            (begin
                                (print {{ tenure: u{}, version: u1, func: \"test-cc-func\" }})
                                (var-set cc-call-count (+ u1 (var-get cc-call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-at-block-func)
                            (begin
                                (var-set at-block-call-count (+ u1 (var-get at-block-call-count)))
                                (ok true)
                            )
                        )
                        (define-read-only (test-at-block-recursive)
                            (ok true)
                        )
                        (define-read-only (get-call-count)
                            (var-get call-count)
                        )
                        (define-read-only (get-cc-call-count)
                            (var-get cc-call-count)
                        )
                        (define-read-only (get-at-block-count)
                            (var-get at-block-call-count)
                        )
                        (define-read-only (get-chain-info)
                            u0
                        )
                        (define-public (get-chain-info-v1)
                            (begin
                                (print \"get-chain-info-v1\")
                                (ok {{ chain-id: u0 }})
                            )
                        )
                        (define-public (get-chain-info-v2)
                            (begin
                                (print \"get-chain-info-v2\")
                                (ok {{ chain-id: u0 }})
                            )
                        )
                        (define-public (get-chain-info-dispatch-1 (trait <chain-info-v1>))
                            (contract-call? trait get-chain-info-v1)
                        )
                        (define-public (get-chain-info-dispatch-2 (trait <chain-info-v2>))
                            (contract-call? trait get-chain-info-v2)
                        )
                        ",
                        tenure_id,
                        tenure_id);
                        let contract_tx = make_versioned_user_contract_publish(&privk_anchored, anchored_sender_nonce + 2, (2 * contract.len()) as u64, &format!("test-{}", tenure_id), &contract, ClarityVersion::Clarity1);
                        vec![trait_v1_tx, trait_v2_tx, contract_tx]
                    }
                    else if tenure_id % 2 == 0 {
                        // send a clarity2 contract that calls the last tenure's contract's test
                        // methods
                        let contract = format!("
                        (impl-trait .chain-id-trait-v1.trait-v1)
                        (impl-trait .chain-id-trait-v2.trait-v2)

                        (use-trait chain-info-v1 .chain-id-trait-v1.trait-v1)
                        (use-trait chain-info-v2 .chain-id-trait-v2.trait-v2)

                        (define-data-var call-count uint u0)
                        (define-data-var cc-call-count uint u0)
                        (define-data-var at-block-call-count uint u0)
                        (define-public (test-func)
                            (begin
                                ;; this only works in clarity2
                                (print {{ tenure: u{}, version: u2, chain: chain-id, func: \"test-func\" }})
                                (unwrap-panic (contract-call? .test-{} test-func))
                                (var-set call-count (+ u1 (var-get call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-cc-func)
                            (begin
                                ;; this only works in clarity2
                                (print {{ tenure: u{}, version: u2, chain: chain-id, func: \"test-cc-func\" }})
                                (unwrap-panic (contract-call? .test-{} test-cc-func))
                                (var-set cc-call-count (+ u1 (var-get cc-call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-at-block-func)
                            (begin
                                (print (at-block 0x{}
                                    (begin
                                        ;; this only works in clarity2
                                        (print {{ tenure: u{}, version: u2, chain: chain-id, func: \"test-at-block-func-v2\" }})
                                        {{ chain-info: (contract-call? .test-{} get-chain-info), calls: (contract-call? .test-{} get-call-count), cc-calls: (contract-call? .test-{} get-cc-call-count) }}
                                    )
                                ))
                                (var-set at-block-call-count (+ u1 (var-get at-block-call-count)))
                                (ok true)
                            )
                        )
                        (define-read-only (test-at-block-recursive)
                            (at-block 0x{}
                                (begin
                                    ;; this only works in clarity2
                                    (print {{ tenure: u{}, version: u2, chain: chain-id, func: \"test-at-block-func-recursive-v2\" }})
                                    (contract-call? .test-{} test-at-block-recursive)
                                )
                            )
                        )

                        (define-read-only (get-call-count)
                            (var-get call-count)
                        )
                        (define-read-only (get-cc-call-count)
                            (var-get cc-call-count)
                        )
                        (define-read-only (get-at-block-count)
                            (var-get at-block-call-count)
                        )
                        (define-read-only (get-chain-info)
                            ;; this only works in clarity2
                            chain-id
                        )
                        (define-public (get-chain-info-v1)
                            (begin
                                ;; this only works in clarity2
                                (print \"get-chain-info-v1\")
                                (ok {{ chain-id: chain-id }})
                            )
                        )
                        (define-public (get-chain-info-v2)
                            (begin
                                ;; this only works in clarity2
                                (print \"get-chain-info-v2\")
                                (ok {{ chain-id: chain-id }})
                            )
                        )
                        (define-public (get-chain-info-dispatch-1 (trait <chain-info-v1>))
                            (contract-call? trait get-chain-info-v1)
                        )
                        (define-public (get-chain-info-dispatch-2 (trait <chain-info-v2>))
                            (contract-call? trait get-chain-info-v2)
                        )
                        (print (get-chain-info-dispatch-1 .test-{}))
                        (print (get-chain-info-dispatch-2 .test-{}))
                        (contract-call? .test-{} test-func)
                        ",
                        tenure_id,
                        tenure_id - 1,
                        tenure_id,
                        tenure_id - 1,
                        &parent_index_hash,
                        tenure_id,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1,
                        &parent_index_hash,
                        tenure_id,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1);

                        let contract_tx = make_versioned_user_contract_publish(&privk_anchored, anchored_sender_nonce, (2 * contract.len()) as u64, &format!("test-{}", tenure_id), &contract, ClarityVersion::Clarity2);
                        let cc_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 1, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-cc-func", vec![]);
                        let at_block_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 2, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-at-block-func", vec![]);
                        let at_block_recursive_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 3, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-at-block-recursive", vec![]);
                        let get_chain_info_dispatch_1 = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 4, 2000, &addr_anchored, &format!("test-{}", tenure_id), "get-chain-info-dispatch-1",
                                                                                vec![Value::Principal(PrincipalData::parse(&format!("{}.test-{}", &addr_anchored, tenure_id - 1)).unwrap())]);
                        let get_chain_info_dispatch_2 = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 5, 2000, &addr_anchored, &format!("test-{}", tenure_id), "get-chain-info-dispatch-2",
                                                                                vec![Value::Principal(PrincipalData::parse(&format!("{}.test-{}", &addr_anchored, tenure_id - 1)).unwrap())]);

                        vec![contract_tx, cc_tx, at_block_tx, at_block_recursive_tx, get_chain_info_dispatch_1, get_chain_info_dispatch_2]
                    }
                    else {
                        // send a clarity1 contract that calls the last tenure's contract's test
                        // methods
                        let contract = format!("
                        (impl-trait .chain-id-trait-v1.trait-v1)
                        (impl-trait .chain-id-trait-v2.trait-v2)

                        (use-trait chain-info-v1 .chain-id-trait-v1.trait-v1)
                        (use-trait chain-info-v2 .chain-id-trait-v2.trait-v2)

                        (define-data-var call-count uint u0)
                        (define-data-var cc-call-count uint u0)
                        (define-data-var at-block-call-count uint u0)
                        (define-public (test-func)
                            (begin
                                (print {{ tenure: u{}, version: u1 }})
                                (unwrap-panic (contract-call? .test-{} test-cc-func))
                                (var-set call-count (+ u1 (var-get call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-cc-func)
                            (begin
                                (print {{ tenure: u{}, version: u1 }})
                                (unwrap-panic (contract-call? .test-{} test-func))
                                (var-set cc-call-count (+ u1 (var-get cc-call-count)))
                                (ok true)
                            )
                        )
                        (define-public (test-at-block-func)
                            (begin
                                (print (at-block 0x{}
                                    (begin
                                        (print {{ tenure: u{}, version: u1, func: \"test-at-block-func-v1\" }})
                                        {{ chain-info: (contract-call? .test-{} get-chain-info), calls: (contract-call? .test-{} get-call-count), cc-calls: (contract-call? .test-{} get-cc-call-count) }}
                                    )
                                ))
                                (var-set at-block-call-count (+ u1 (var-get at-block-call-count)))
                                (ok true)
                            )
                        )
                        (define-read-only (test-at-block-recursive)
                            (at-block 0x{}
                                (begin
                                    (print {{ tenure: u{}, version: u1, func: \"test-at-block-func-recursive-v1\" }})
                                    (contract-call? .test-{} test-at-block-recursive)
                                )
                            )
                        )

                        (define-read-only (get-call-count)
                            (var-get call-count)
                        )
                        (define-read-only (get-cc-call-count)
                            (var-get cc-call-count)
                        )
                        (define-read-only (get-at-block-count)
                            (var-get at-block-call-count)
                        )
                        (define-read-only (get-chain-info)
                            u0
                        )
                        (define-public (get-chain-info-v1)
                            (begin
                                (print \"get-chain-info-v1\")
                                (ok {{ chain-id: u0 }})
                            )
                        )
                        (define-public (get-chain-info-v2)
                            (begin
                                (print \"get-chain-info-v2\")
                                (ok {{ chain-id: u0 }})
                            )
                        )
                        (define-public (get-chain-info-dispatch-1 (trait <chain-info-v1>))
                            (contract-call? trait get-chain-info-v1)
                        )
                        (define-public (get-chain-info-dispatch-2 (trait <chain-info-v2>))
                            (contract-call? trait get-chain-info-v2)
                        )
                        (print (get-chain-info-dispatch-1 .test-{}))
                        (print (get-chain-info-dispatch-2 .test-{}))
                        (contract-call? .test-{} test-func)
                        ",
                        tenure_id,
                        tenure_id - 1,
                        tenure_id,
                        tenure_id - 1,
                        &parent_index_hash,
                        tenure_id,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1,
                        &parent_index_hash,
                        tenure_id,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1,
                        tenure_id - 1);

                        let contract_tx = make_versioned_user_contract_publish(&privk_anchored, anchored_sender_nonce, (2 * contract.len()) as u64, &format!("test-{}", tenure_id), &contract, ClarityVersion::Clarity1);
                        let cc_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 1, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-cc-func", vec![]);
                        let at_block_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 2, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-at-block-func", vec![]);
                        let at_block_recursive_tx = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 3, 2000, &addr_anchored, &format!("test-{}", tenure_id - 1), "test-at-block-recursive", vec![]);
                        let get_chain_info_dispatch_1 = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 4, 2000, &addr_anchored, &format!("test-{}", tenure_id), "get-chain-info-dispatch-1",
                                                                                vec![Value::Principal(PrincipalData::parse(&format!("{}.test-{}", &addr_anchored, tenure_id - 1)).unwrap())]);
                        let get_chain_info_dispatch_2 = make_user_contract_call(&privk_anchored, anchored_sender_nonce + 5, 2000, &addr_anchored, &format!("test-{}", tenure_id), "get-chain-info-dispatch-2",
                                                                                vec![Value::Principal(PrincipalData::parse(&format!("{}.test-{}", &addr_anchored, tenure_id - 1)).unwrap())]);

                        vec![contract_tx, cc_tx, at_block_tx, at_block_recursive_tx, get_chain_info_dispatch_1, get_chain_info_dispatch_2]
                    };

                    for tx in txs.into_iter() {
                        anchored_sender_nonce += 1;
                        anchored_txs.push(tx);
                    }
                }

                let sort_ic = sortdb.index_handle_at_tip();

                let builder = StacksBlockBuilder::make_block_builder(
                    &burnchain,
                    chainstate.mainnet,
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    Hash160([tenure_id as u8; 20]),
                )
                .unwrap();

                let anchored_block = StacksBlockBuilder::make_anchored_block_from_txs(
                    builder,
                    chainstate,
                    &sort_ic,
                    anchored_txs,
                )
                .unwrap();

                // coinbase
                (anchored_block.0, vec![])
            },
        );

        test_debug!("Process tenure {}", tenure_id);

        // should always succeed
        peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip_checked(&stacks_block, &[])
            .unwrap();
    }

    // all contracts deployed and called the right number of times, indicating that
    // cross-clarity-version contract calls are doable
    let sortdb = peer.sortdb.take().unwrap();
    let (consensus_hash, block_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
    let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);

    peer.chainstate().with_read_only_clarity_tx(
        &sortdb.index_handle_at_tip(),
        &stacks_block_id,
        |clarity_tx| {
            for tenure_id in 1..num_blocks {
                clarity_tx
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity2,
                        PrincipalData::parse(&format!("{}", &addr_anchored)).unwrap(),
                        Some(PrincipalData::parse(&format!("{}", &addr_anchored)).unwrap()),
                        LimitedCostTracker::new_free(),
                        |env| {
                            test_debug!("check tenure {}", tenure_id);

                            // .contract-call? worked
                            let call_count_value = env
                                .eval_raw(&format!(
                                    "(contract-call? '{}.test-{} get-call-count)",
                                    &addr_anchored, tenure_id
                                ))
                                .unwrap();
                            let call_count = call_count_value.expect_u128().unwrap();
                            assert_eq!(call_count, (num_blocks - tenure_id - 1) as u128);

                            // contract-call transaction worked
                            let call_count_value = env
                                .eval_raw(&format!(
                                    "(contract-call? '{}.test-{} get-cc-call-count)",
                                    &addr_anchored, tenure_id
                                ))
                                .unwrap();
                            let call_count = call_count_value.expect_u128().unwrap();
                            assert_eq!(call_count, (num_blocks - tenure_id - 1) as u128);

                            // at-block transaction worked
                            let at_block_count_value = env
                                .eval_raw(&format!(
                                    "(contract-call? '{}.test-{} get-at-block-count)",
                                    &addr_anchored, tenure_id
                                ))
                                .unwrap();
                            let call_count = at_block_count_value.expect_u128().unwrap();

                            if tenure_id < num_blocks - 1 {
                                assert_eq!(call_count, 1);
                            } else {
                                assert_eq!(call_count, 0);
                            }

                            Ok(())
                        },
                    )
                    .unwrap();
            }
        },
    );
}

// verify that the problematic checker works
#[test]
fn test_is_tx_problematic() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let privk_extra = StacksPrivateKey::from_hex(
        "f67c7437f948ca1834602b28595c12ac744f287a4efaf70d437042a6afed81bc01",
    )
    .unwrap();
    let mut privks_expensive = vec![];
    let mut addrs_expensive = vec![];
    let mut initial_balances = vec![];
    let num_blocks = 10;
    for i in 0..num_blocks {
        let pk = StacksPrivateKey::random();
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&pk)],
        )
        .unwrap();

        privks_expensive.push(pk);
        addrs_expensive.push(addr.clone());
        initial_balances.push((addr.to_account_principal(), 10000000000));
    }

    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();
    let addr_extra = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk_extra)],
    )
    .unwrap();

    initial_balances.push((addr.to_account_principal(), 100000000000));
    initial_balances.push((addr_extra.to_account_principal(), 200000000000));

    let mut peer_config = TestPeerConfig::new(function_name!(), 2018, 2019);
    peer_config.initial_balances = initial_balances;
    peer_config.epochs = Some(EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: i64::MAX as u64,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
    ]));
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let mut last_block = None;
    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = match parent_opt {
                    None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                    Some(block) => {
                        let ic = sortdb.index_conn();
                        let snapshot =
                            SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                &ic,
                                &tip.sortition_id,
                                &block.block_hash(),
                            )
                            .unwrap()
                            .unwrap(); // succeeds because we don't fork
                        StacksChainState::get_anchored_block_header_info(
                            chainstate.db(),
                            &snapshot.consensus_hash,
                            &snapshot.winning_stacks_block_hash,
                        )
                        .unwrap()
                        .unwrap()
                    }
                };

                let parent_header_hash = parent_tip.anchored_header.block_hash();
                let parent_consensus_hash = parent_tip.consensus_hash.clone();
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut mempool =
                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                let mut expected_txids = vec![];
                expected_txids.push(coinbase_tx.txid());

                let mut problematic_txids = vec![];

                if tenure_id == 2 {
                    // make a contract that, when instantiated, spends way too much STX.
                    // Should result in an Error::InvalidFee, causing the tx to get evicted
                    // from the mempool.
                    let contract_spends_too_much =
                        "(begin
                            (stx-transfer? (stx-get-balance tx-sender) tx-sender 'ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV)
                        )".to_string();

                    let contract_spends_too_much_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        0,
                        (2 * contract_spends_too_much.len()) as u64,
                        &format!("hello-world-{tenure_id}"),
                        &contract_spends_too_much
                    );
                    let contract_spends_too_much_txid = contract_spends_too_much_tx.txid();

                    // attempting to build an anchored block with this tx should cause this tx
                    // to get flagged as problematic
                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof.clone(),
                        tip.total_burn,
                        Hash160::from_node_public_key(&StacksPublicKey::from_private(&miner.next_microblock_privkey()))
                    )
                    .unwrap();

                    if let Err(ChainstateError::ProblematicTransaction(txid)) = StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![coinbase_tx.clone(), contract_spends_too_much_tx]
                    ) {
                        assert_eq!(txid, contract_spends_too_much_txid);
                    }
                    else {
                        panic!("Did not get Error::ProblematicTransaction");
                    }

                    // for tenure_id == 3:
                    // make a contract that, when called, will cause the caller to spend too
                    // much stx
                    let contract_call_spends_too_much =
                        "(define-public (spend-too-much)
                            (begin
                                (print { balance: (stx-get-balance tx-sender) })
                                (stx-transfer? (stx-get-balance tx-sender) tx-sender 'ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV)
                            )
                        )".to_string();

                    let contract_call_spends_too_much_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        0,
                        (2 * contract_call_spends_too_much.len()) as u64,
                        "spend-too-much",
                        &contract_call_spends_too_much
                    );

                    expected_txids.push(contract_call_spends_too_much_tx.txid());

                    // for tenure_id == 4:
                    // make a contract that, when called, will result in a CheckError at
                    // runtime
                    let runtime_checkerror_trait =
                        "
                        (define-trait foo
                            (
                                (lolwut () (response bool uint))
                            )
                        )
                        ".to_string();

                    let runtime_checkerror_impl =
                        "
                        (impl-trait .foo.foo)

                        (define-public (lolwut)
                            (ok true)
                        )
                        ".to_string();

                    let runtime_checkerror = format!(
                        "
                        (use-trait trait .foo.foo)

                        (define-data-var mutex bool true)

                        (define-public (flip)
                          (ok (var-set mutex (not (var-get mutex))))
                        )

                        ;; triggers checkerror at runtime because <trait> gets coerced
                        ;; into a principal when `internal` is called.
                        (define-public (test (ref <trait>))
                            (ok (internal (if (var-get mutex)
                                (some ref)
                                none
                            )))
                        )

                        ;; triggers a checkerror at runtime because the code in
                        ;; `at-block` is buggy
                        (define-public (test-past (ref <trait>))
                            (at-block 0x{} (test ref))
                        )

                        (define-private (internal (ref (optional <trait>))) true)
                        ",
                        &last_block.clone().unwrap()
                    );

                    let runtime_checkerror_trait_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        1,
                        (2 * runtime_checkerror_trait.len()) as u64,
                        "foo",
                        &runtime_checkerror_trait
                    );

                    let runtime_checkerror_impl_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        2,
                        (2 * runtime_checkerror_impl.len()) as u64,
                        "foo-impl",
                        &runtime_checkerror_impl
                    );

                    let runtime_checkerror_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        3,
                        (2 * runtime_checkerror.len()) as u64,
                        "trait-checkerror",
                        &runtime_checkerror
                    );

                    expected_txids.push(runtime_checkerror_trait_tx.txid());
                    expected_txids.push(runtime_checkerror_impl_tx.txid());
                    expected_txids.push(runtime_checkerror_tx.txid());

                    for tx in &[&contract_call_spends_too_much_tx, &runtime_checkerror_trait_tx, &runtime_checkerror_impl_tx, &runtime_checkerror_tx] {
                        mempool
                            .submit(
                                chainstate,
                                sortdb,
                                &parent_consensus_hash,
                                &parent_header_hash,
                                tx,
                                None,
                                &ExecutionCost::max_value(),
                                &StacksEpochId::Epoch2_05,
                            )
                            .unwrap();
                    }

                    // the same tx, but with nonce 4 (since we expect the `spends-too-much` contract to get
                    // mined, as well as the other problem setup txs)
                    let contract_spends_too_much_tx = make_user_contract_publish(
                        &privks_expensive[tenure_id],
                        4,
                        (2 * contract_spends_too_much.len()) as u64,
                        &format!("hello-world-{tenure_id}"),
                        &contract_spends_too_much
                    );
                    let contract_spends_too_much_txid = contract_spends_too_much_tx.txid();
                    problematic_txids.push(contract_spends_too_much_txid);

                    // put this into the mempool anyway, so we can verify it gets rejected
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &contract_spends_too_much_tx,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch2_05,
                        )
                        .unwrap();
                }

                if tenure_id == 3 {
                    // call spend-too-much and verify that it's flagged as problematic
                    let spend_too_much = make_user_contract_call(
                        &privks_expensive[tenure_id],
                        0,
                        2000,
                        &addrs_expensive[2],
                        "spend-too-much",
                        "spend-too-much",
                        vec![]
                    );

                    // attempting to build an anchored block with this tx should cause this tx
                    // to get flagged as problematic
                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof.clone(),
                        tip.total_burn,
                        Hash160::from_node_public_key(&StacksPublicKey::from_private(&miner.next_microblock_privkey()))
                    )
                    .unwrap();

                    if let Err(ChainstateError::ProblematicTransaction(txid)) = StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![coinbase_tx.clone(), spend_too_much.clone()]
                    ) {
                        assert_eq!(txid, spend_too_much.txid());
                    }
                    else {
                        panic!("Did not get Error::ProblematicTransaction");
                    }

                    problematic_txids.push(spend_too_much.txid());
                    mempool
                        .submit(
                            chainstate,
                           sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &spend_too_much,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch2_05,
                        )
                        .unwrap();
                }

                if tenure_id == 4 {
                    // call trait-checkerror.test and verify that it's flagged as problematic
                    let runtime_checkerror_problematic = make_user_contract_call(
                        &privks_expensive[tenure_id],
                        0,
                        2000,
                        &addrs_expensive[2],
                        "trait-checkerror",
                        "test",
                        vec![Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::parse(&format!("{}.foo-impl", &addrs_expensive[2])).unwrap()))],
                    );

                    // attempting to build an anchored block with this tx should cause this tx
                    // to get flagged as problematic
                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof.clone(),
                        tip.total_burn,
                        Hash160::from_node_public_key(&StacksPublicKey::from_private(&miner.next_microblock_privkey()))
                    )
                    .unwrap();

                    let err = StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![coinbase_tx.clone(), runtime_checkerror_problematic.clone()]
                    );

                    if let Err(ChainstateError::ProblematicTransaction(ref txid)) = &err {
                        assert_eq!(txid, &runtime_checkerror_problematic.txid());
                    }
                    else {
                        panic!("Did not get Error::ProblematicTransaction, but got {:?}", &err);
                    }

                    problematic_txids.push(runtime_checkerror_problematic.txid());
                    mempool
                        .submit(
                            chainstate,
                            sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &runtime_checkerror_problematic,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch2_05,
                        )
                        .unwrap();
                }

                if tenure_id == 5 {
                    // call trait-checkerror.test-past and verify that it's flagged as problematic
                    let runtime_checkerror_problematic = make_user_contract_call(
                        &privks_expensive[tenure_id],
                        0,
                        2000,
                        &addrs_expensive[2],
                        "trait-checkerror",
                        "test-past",
                        vec![Value::Principal(PrincipalData::Contract(QualifiedContractIdentifier::parse(&format!("{}.foo-impl", &addrs_expensive[2])).unwrap()))],
                    );

                    // attempting to build an anchored block with this tx should cause this tx
                    // to get flagged as problematic
                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof.clone(),
                        tip.total_burn,
                        Hash160::from_node_public_key(&StacksPublicKey::from_private(&miner.next_microblock_privkey()))
                    )
                    .unwrap();

                    if let Err(ChainstateError::ProblematicTransaction(txid)) = StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![coinbase_tx.clone(), runtime_checkerror_problematic.clone()]
                    ) {
                        assert_eq!(txid, runtime_checkerror_problematic.txid());
                    }
                    else {
                        panic!("Did not get Error::ProblematicTransaction");
                    }

                    problematic_txids.push(runtime_checkerror_problematic.txid());
                    mempool
                        .submit(
                            chainstate,
                                sortdb,
                            &parent_consensus_hash,
                            &parent_header_hash,
                            &runtime_checkerror_problematic,
                            None,
                            &ExecutionCost::max_value(),
                            &StacksEpochId::Epoch2_05,
                        )
                        .unwrap();
                }

                // all problematic txids are present
                for problematic_txid in problematic_txids.iter() {
                    assert!(mempool.has_tx(problematic_txid));
                }

                let anchored_block = StacksBlockBuilder::build_anchored_block(
                    chainstate,
                    &sortdb.index_handle_at_tip(),
                    &mut mempool,
                    &parent_tip,
                    tip.total_burn,
                    vrf_proof,
                    Hash160([tenure_id as u8; 20]),
                    &coinbase_tx,
                    BlockBuilderSettings::limited(),
                    None,
                    &burnchain,
                )
                .unwrap();

                // all problematic txids are absent
                for problematic_txid in problematic_txids.iter() {
                    assert!(!mempool.has_tx(problematic_txid));
                }

                // make sure the right txs get included
                let txids : Vec<_> = anchored_block.0.txs.iter().map(|tx| tx.txid()).collect();
                assert_eq!(txids, expected_txids);

                (anchored_block.0, vec![])
            },
        );

        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        last_block = Some(StacksBlockHeader::make_index_block_hash(
            &consensus_hash,
            &stacks_block.block_hash(),
        ));
    }
}

#[test]
fn mempool_incorporate_pox_unlocks() {
    let mut initial_balances = vec![];
    let total_balance = 10_000_000_000;
    let pk = StacksPrivateKey::random();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&pk)],
    )
    .unwrap();
    initial_balances.push((addr.to_account_principal(), total_balance));
    let principal = PrincipalData::from(addr.clone());

    let mut peer_config = TestPeerConfig::new(function_name!(), 2020, 2021);
    peer_config.initial_balances = initial_balances;
    peer_config.epochs = Some(EpochList::new(&[
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: 36,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 36,
            end_height: i64::MAX as u64,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
    ]));
    peer_config.burnchain.pox_constants.v1_unlock_height =
        peer_config.epochs.as_ref().unwrap()[StacksEpochId::Epoch2_05].end_height as u32 + 1;
    let pox_constants = peer_config.burnchain.pox_constants.clone();
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let first_block_height = peer.sortdb.as_ref().unwrap().first_block_height;
    let first_pox_cycle = pox_constants
        .block_height_to_reward_cycle(first_block_height, first_stacks_block_height)
        .unwrap();
    let active_pox_cycle_start =
        pox_constants.reward_cycle_to_block_height(first_block_height, first_pox_cycle + 1);
    let lockup_end = pox_constants.v1_unlock_height as u64;

    // test for two PoX cycles
    let num_blocks = 3 + lockup_end - first_stacks_block_height;
    info!(
        "Starting test";
        "num_blocks" => num_blocks,
        "first_stacks_block_height" => first_stacks_block_height,
        "active_pox_cycle_start" => active_pox_cycle_start,
        "active_pox_cycle_end" => lockup_end,
        "first_block_height" => first_block_height,
    );

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    for tenure_id in 0..num_blocks {
        // send transactions to the mempool
        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                 let parent_tip = match parent_opt {
                     None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                     Some(block) => {
                         let ic = sortdb.index_conn();
                         let snapshot =
                             SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                 &ic,
                                 &tip.sortition_id,
                                 &block.block_hash(),
                             )
                             .unwrap()
                             .unwrap(); // succeeds because we don't fork
                         StacksChainState::get_anchored_block_header_info(
                             chainstate.db(),
                             &snapshot.consensus_hash,
                             &snapshot.winning_stacks_block_hash,
                         )
                             .unwrap()
                             .unwrap()
                     }
                 };

                 let parent_height = parent_tip.burn_header_height;

                 let parent_header_hash = parent_tip.anchored_header.block_hash();
                 let parent_consensus_hash = parent_tip.consensus_hash.clone();
                 let coinbase_tx = make_coinbase(miner, tenure_id as usize);

                 let mut mempool =
                     MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

                 let mut expected_txids = vec![];
                 expected_txids.push(coinbase_tx.txid());

                 // this will be the height of the block that includes this new tenure
                 let my_height = first_stacks_block_height + 1 + tenure_id;

                 let available_balance = chainstate.with_read_only_clarity_tx(&sortdb.index_handle_at_tip(), &parent_tip.index_block_hash(), |clarity_tx| {
                     clarity_tx.with_clarity_db_readonly(|db| {
                         let burn_block_height = db.get_current_burnchain_block_height().unwrap() as u64;
                         let v1_unlock_height = db.get_v1_unlock_height();
                         let v2_unlock_height = db.get_v2_unlock_height().unwrap();
                         let v3_unlock_height = db.get_v3_unlock_height().unwrap();
                         let balance = db.get_account_stx_balance(&principal).unwrap();
                         info!("Checking balance"; "v1_unlock_height" => v1_unlock_height, "burn_block_height" => burn_block_height);
                         balance.get_available_balance_at_burn_block(burn_block_height, v1_unlock_height, v2_unlock_height, v3_unlock_height).unwrap()
                     })
                 }).unwrap();

                 if tenure_id <= 1 {
                     assert_eq!(available_balance, total_balance as u128, "Failed at tenure_id={}", tenure_id);
                 } else if my_height <= lockup_end + 1 {
                     assert_eq!(available_balance, 0, "Failed at tenure_id={}", tenure_id);
                 } else if my_height == lockup_end + 2 {
                     assert_eq!(available_balance, total_balance as u128 - 10_000, "Failed at tenure_id={}", tenure_id);
                 } else {
                     assert_eq!(available_balance, 0, "Failed at tenure_id={}", tenure_id);
                 }

                 if tenure_id == 1 {
                     let stack_stx = make_user_contract_call(
                         &pk,
                         0,
                         10_000,
                         &StacksAddress::burn_address(false),
                         "pox",
                         "stack-stx",
                         vec![
                             Value::UInt(total_balance as u128 - 10_000),
                             Value::Tuple(
                                 TupleData::from_data(vec![
                                     ("version".into(), Value::buff_from(vec![0x00]).unwrap()),
                                     ("hashbytes".into(), Value::buff_from(vec![0; 20]).unwrap()),
                                 ]).unwrap(),
                             ),
                             Value::UInt(my_height as u128),
                             Value::UInt(10)
                         ],
                     );
                     mempool
                         .submit(
                             chainstate,
                             sortdb,
                             &parent_consensus_hash,
                             &parent_header_hash,
                             &stack_stx,
                             None,
                             &ExecutionCost::max_value(),
                             &StacksEpochId::Epoch2_05,
                         )
                         .unwrap();
                     expected_txids.push(stack_stx.txid());
                 } else if my_height == lockup_end + 2 {
                     let stx_transfer = make_user_stacks_transfer(
                         &pk,
                         1,
                         10_000,
                         &StacksAddress::burn_address(false).into(),
                         total_balance - 10_000 - 10_000,
                     );
                     mempool
                         .submit(
                             chainstate,
                             sortdb,
                             &parent_consensus_hash,
                             &parent_header_hash,
                             &stx_transfer,
                             None,
                             &ExecutionCost::max_value(),
                             &StacksEpochId::Epoch2_05,
                         )
                         .unwrap();
                     expected_txids.push(stx_transfer.txid());
                 }

                 let anchored_block = StacksBlockBuilder::build_anchored_block(
                     chainstate,
                     &sortdb.index_handle_at_tip(),
                     &mut mempool,
                     &parent_tip,
                     tip.total_burn,
                     vrf_proof,
                     Hash160([tenure_id as u8; 20]),
                     &coinbase_tx,
                     BlockBuilderSettings::limited(),
                     None,
                     &burnchain,
                 )
                 .unwrap();

                 // make sure the right txs get included
                 let txids : Vec<_> = anchored_block.0.txs.iter().map(|tx| tx.txid()).collect();
                 assert_eq!(txids, expected_txids);

                 (anchored_block.0, vec![])
             },
        );

        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
    }
}

#[test]
/// Test the situation in which the nonce order of transactions from a user. That is,
/// nonce 1 has a higher fee than nonce 0.
/// Want to see that both transactions can go into the same block, because the miner
/// should make multiple passes.
fn test_fee_order_mismatch_nonce_order() {
    let privk = StacksPrivateKey::from_hex(
        "42faca653724860da7a41bfcef7e6ba78db55146f6900de8cb2a9f760ffac70c01",
    )
    .unwrap();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&privk)],
    )
    .unwrap();

    let mut peer_config = TestPeerConfig::new(function_name!(), 2002, 2003);
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1000000000)];
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();
    let sender_nonce = 0;

    // send transactions to the mempool
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
        |ref mut miner,
         ref mut sortdb,
         ref mut chainstate,
         vrf_proof,
         ref parent_opt,
         ref parent_microblock_header_opt| {
            let parent_tip = match parent_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(block) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap()
                    .unwrap(); // succeeds because we don't fork
                    StacksChainState::get_anchored_block_header_info(
                        chainstate.db(),
                        &snapshot.consensus_hash,
                        &snapshot.winning_stacks_block_hash,
                    )
                    .unwrap()
                    .unwrap()
                }
            };

            let parent_header_hash = parent_tip.anchored_header.block_hash();
            let parent_consensus_hash = parent_tip.consensus_hash.clone();

            let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

            let coinbase_tx = make_coinbase(miner, 0);

            let stx_transfer0 =
                make_user_stacks_transfer(&privk, 0, 200, &recipient.to_account_principal(), 1);
            let stx_transfer1 =
                make_user_stacks_transfer(&privk, 1, 400, &recipient.to_account_principal(), 1);

            mempool
                .submit(
                    chainstate,
                    sortdb,
                    &parent_consensus_hash,
                    &parent_header_hash,
                    &stx_transfer0,
                    None,
                    &ExecutionCost::max_value(),
                    &StacksEpochId::Epoch20,
                )
                .unwrap();

            mempool
                .submit(
                    chainstate,
                    sortdb,
                    &parent_consensus_hash,
                    &parent_header_hash,
                    &stx_transfer1,
                    None,
                    &ExecutionCost::max_value(),
                    &StacksEpochId::Epoch20,
                )
                .unwrap();

            let anchored_block = StacksBlockBuilder::build_anchored_block(
                chainstate,
                &sortdb.index_handle_at_tip(),
                &mut mempool,
                &parent_tip,
                tip.total_burn,
                vrf_proof,
                Hash160([0; 20]),
                &coinbase_tx,
                BlockBuilderSettings::max_value(),
                None,
                &burnchain,
            )
            .unwrap();
            (anchored_block.0, vec![])
        },
    );

    peer.next_burnchain_block(burn_ops);
    peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

    // Both user transactions and the coinbase should have been mined.
    assert_eq!(stacks_block.txs.len(), 3);
}

#[test]
fn mempool_walk_test_users_1_rounds_10_cache_size_2_null_prob_0() {
    paramaterized_mempool_walk_test(1, 10, 2, 0, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2_null_prob_0() {
    paramaterized_mempool_walk_test(10, 3, 2, 0, 30000)
}

#[test]
fn mempool_walk_test_users_1_rounds_10_cache_size_2_null_prob_50() {
    paramaterized_mempool_walk_test(1, 10, 2, 50, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2_null_prob_50() {
    paramaterized_mempool_walk_test(10, 3, 2, 50, 30000)
}

#[test]
fn mempool_walk_test_users_1_rounds_10_cache_size_2_null_prob_100() {
    paramaterized_mempool_walk_test(1, 10, 2, 100, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2_null_prob_100() {
    paramaterized_mempool_walk_test(10, 3, 2, 100, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2000_null_prob_0() {
    paramaterized_mempool_walk_test(10, 3, 2000, 0, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2000_null_prob_50() {
    paramaterized_mempool_walk_test(10, 3, 2000, 50, 30000)
}

#[test]
fn mempool_walk_test_users_10_rounds_3_cache_size_2000_null_prob_100() {
    paramaterized_mempool_walk_test(10, 3, 2000, 100, 30000)
}

/// With the parameters given, create `num_rounds` transactions per each user in `num_users`.
/// `nonce_and_candidate_cache_size` is the cache size used for both of the nonce cache
/// and the candidate cache.
fn paramaterized_mempool_walk_test(
    num_users: usize,
    num_rounds: usize,
    nonce_and_candidate_cache_size: usize,
    consider_no_estimate_tx_prob: u8,
    timeout_ms: u128,
) {
    let key_address_pairs: Vec<(Secp256k1PrivateKey, StacksAddress)> = (0..num_users)
        .map(|_user_index| {
            let privk = StacksPrivateKey::random();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&privk)],
            )
            .unwrap();
            (privk, addr)
        })
        .collect();

    let test_name = format!(
        "mempool_walk_test_users_{}_rounds_{}_cache_size_{}_null_prob_{}",
        num_users, num_rounds, nonce_and_candidate_cache_size, consider_no_estimate_tx_prob
    );
    let mut peer_config = TestPeerConfig::new(&test_name, 2002, 2003);

    peer_config.initial_balances = vec![];
    for (privk, addr) in &key_address_pairs {
        peer_config
            .initial_balances
            .push((addr.to_account_principal(), 1000000000));
    }

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, &test_name, vec![]);
    let chainstate_path = chainstate_path(&test_name);
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mut mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    let mut transaction_counter = 0;
    for round_index in 0..num_rounds {
        for user_index in 0..num_users {
            transaction_counter += 1;
            let mut tx = make_user_stacks_transfer(
                &key_address_pairs[user_index].0,
                round_index as u64,
                200,
                &recipient.to_account_principal(),
                1,
            );

            let mut mempool_tx = mempool.tx_begin().unwrap();

            let origin_address = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_address = tx.sponsor_address().unwrap_or(origin_address);
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

            tx.set_tx_fee(100);
            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let tx_fee = tx.get_tx_fee();
            let height = 100;

            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &b_1.0,
                &b_1.1,
                true,
                txid,
                tx_bytes,
                tx_fee,
                height,
                &origin_address,
                round_index.try_into().unwrap(),
                &sponsor_address,
                round_index.try_into().unwrap(),
                None,
            )
            .unwrap();

            if transaction_counter & 1 == 0 {
                mempool_tx
                    .execute(
                        "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                        params![Some(123.0), &txid],
                    )
                    .unwrap();
            } else {
                let none: Option<f64> = None;
                mempool_tx
                    .execute(
                        "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                        params![none, &txid],
                    )
                    .unwrap();
            }

            mempool_tx.commit().unwrap();
        }
    }

    mempool_settings.nonce_cache_size = nonce_and_candidate_cache_size;
    mempool_settings.candidate_retry_cache_size = nonce_and_candidate_cache_size;
    mempool_settings.consider_no_estimate_tx_prob = consider_no_estimate_tx_prob;
    let deadline = get_epoch_time_ms() + timeout_ms;
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            // When the candidate cache fills, one pass cannot process all transactions
            loop {
                if mempool
                    .iterate_candidates::<_, ChainstateError, _>(
                        clarity_conn,
                        &mut tx_events,
                        mempool_settings.clone(),
                        |_, available_tx, _| {
                            count_txs += 1;
                            Ok(Some(
                                // Generate any success result
                                TransactionResult::success(
                                    &available_tx.tx.tx,
                                    available_tx.tx.metadata.tx_fee,
                                    StacksTransactionReceipt::from_stx_transfer(
                                        available_tx.tx.tx.clone(),
                                        vec![],
                                        Value::okay(Value::Bool(true)).unwrap(),
                                        ExecutionCost::ZERO,
                                    ),
                                )
                                .convert_to_event(),
                            ))
                        },
                    )
                    .unwrap()
                    .0
                    == 0
                {
                    break;
                }
                assert!(get_epoch_time_ms() < deadline, "test timed out");
            }
            assert_eq!(
                count_txs, transaction_counter,
                "Mempool should find all {} transactions",
                transaction_counter
            );
        },
    );
}
