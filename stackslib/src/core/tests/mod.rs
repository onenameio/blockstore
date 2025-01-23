// Copyright (C) 2013-2021 Blockstack PBC, a public benefit corporation
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
use std::time::Duration;
use std::{cmp, io};

use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::HeadersDB;
use clarity::vm::errors::{Error as ClarityError, RuntimeErrorType};
use clarity::vm::test_util::TEST_BURN_STATE_DB;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityName, ContractName, Value};
use rand::prelude::*;
use rand::thread_rng;
use rusqlite::params;
use stacks_common::address::AddressHashMode;
use stacks_common::codec::{read_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, StacksWorkScore, TrieHash,
    VRFSeed,
};
use stacks_common::types::{MempoolCollectionBehavior, StacksEpochId};
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, *};
use stacks_common::util::secp256k1::{MessageSignature, *};
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log, sleep_ms};

use super::MemPoolDB;
use crate::burnchains::{Address, Txid};
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::blocks::MemPoolRejection;
use crate::chainstate::stacks::db::test::{
    chainstate_path, instantiate_chainstate, instantiate_chainstate_with_balances,
};
use crate::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::miner::TransactionResult;
use crate::chainstate::stacks::test::codec_all_transactions;
use crate::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, SinglesigHashMode, SinglesigSpendingCondition,
    StacksBlockHeader, StacksMicroblockHeader, StacksPrivateKey, StacksPublicKey,
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionPublicKeyEncoding, TransactionSmartContract, TransactionSpendingCondition,
    TransactionVersion, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::core::mempool::{
    db_get_all_nonces, MemPoolSyncData, MemPoolWalkSettings, MemPoolWalkTxTypes, TxTag,
    BLOOM_COUNTER_DEPTH, BLOOM_COUNTER_ERROR_RATE, MAX_BLOOM_COUNTER_TXS,
};
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use crate::net::Error as NetError;
use crate::util_lib::bloom::test::setup_bloom_counter;
use crate::util_lib::bloom::*;
use crate::util_lib::db::{tx_begin_immediate, DBConn, FromRow};
use crate::util_lib::strings::StacksString;

const FOO_CONTRACT: &str = "(define-public (foo) (ok 1))
                                    (define-public (bar (x uint)) (ok x))";
const SK_1: &str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
const SK_2: &str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
const SK_3: &str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

#[test]
fn mempool_db_init() {
    let _chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let _mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
}

pub fn make_block(
    chainstate: &mut StacksChainState,
    block_consensus: ConsensusHash,
    parent: &(ConsensusHash, BlockHeaderHash),
    burn_height: u64,
    block_height: u64,
) -> (ConsensusHash, BlockHeaderHash) {
    let (mut chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin().unwrap();

    let anchored_header = StacksBlockHeader {
        version: 1,
        total_work: StacksWorkScore {
            work: block_height,
            burn: 1,
        },
        proof: VRFProof::empty(),
        parent_block: parent.1.clone(),
        parent_microblock: BlockHeaderHash([0; 32]),
        parent_microblock_sequence: 0,
        tx_merkle_root: Sha512Trunc256Sum::empty(),
        state_index_root: TrieHash::from_empty_data(),
        microblock_pubkey_hash: Hash160([0; 20]),
    };

    let block_hash = anchored_header.block_hash();

    let c_tx = StacksChainState::chainstate_block_begin(
        &chainstate_tx,
        clar_tx,
        &TEST_BURN_STATE_DB,
        &parent.0,
        &parent.1,
        &block_consensus,
        &block_hash,
    );

    let new_tip_info = StacksHeaderInfo {
        anchored_header: anchored_header.into(),
        microblock_tail: None,
        index_root: TrieHash::from_empty_data(),
        stacks_block_height: block_height,
        consensus_hash: block_consensus.clone(),
        burn_header_hash: BurnchainHeaderHash([0; 32]),
        burn_header_height: burn_height as u32,
        burn_header_timestamp: 0,
        anchored_block_size: 1,
        burn_view: None,
    };

    c_tx.commit_block();

    let new_index_hash = StacksBlockId::new(&block_consensus, &block_hash);

    // instantiate the inner MARF
    chainstate_tx
        .put_indexed_all(
            &StacksBlockId::new(&parent.0, &parent.1),
            &new_index_hash,
            &[],
            &[],
        )
        .unwrap();

    StacksChainState::insert_stacks_block_header(
        &chainstate_tx,
        &new_index_hash,
        &new_tip_info,
        &ExecutionCost::ZERO,
        block_height,
    )
    .unwrap();

    chainstate_tx.commit().unwrap();

    (block_consensus, block_hash)
}

#[test]
fn mempool_walk_over_fork() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);

    // genesis -> b_1* -> b_2*
    //               \-> b_3 -> b_4
    //
    // *'d blocks accept transactions,
    //   try to walk at b_4, we should be able to find
    //   the transaction at b_1

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
    let b_5 = make_block(&mut chainstate, ConsensusHash([0x5; 20]), &b_2, 5, 3);
    let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 3, 2);
    let b_4 = make_block(&mut chainstate, ConsensusHash([0x4; 20]), &b_3, 4, 3);

    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let mut all_txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    let blocks_to_broadcast_in = [&b_1, &b_2, &b_4];
    let mut txs = [
        all_txs.pop().unwrap(),
        all_txs.pop().unwrap(),
        all_txs.pop().unwrap(),
    ];
    for tx in txs.iter_mut() {
        tx.set_tx_fee(123);
    }

    for ix in 0..3 {
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let block = &blocks_to_broadcast_in[ix];
        let good_tx = &txs[ix];

        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[ix as u8; 32]),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&[0x80 | (ix as u8); 32]),
        };

        let txid = good_tx.txid();
        let tx_bytes = good_tx.serialize_to_vec();
        let tx_fee = good_tx.get_tx_fee();

        let height = 1 + ix as u64;

        let origin_nonce = 0; // (2 * ix + i) as u64;
        let sponsor_nonce = 0; // (2 * ix + i) as u64;

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &block.0,
            &block.1,
            true,
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        mempool_tx.commit().unwrap();
    }

    // genesis -> b_1* -> b_2* -> b_5
    //               \-> b_3 -> b_4
    //
    // *'d blocks accept transactions,
    //   try to walk at b_4, we should be able to find
    //   the transaction at b_1

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_2"
            );
        },
    );

    // Now that the mempool has iterated over those transactions, its view of the
    //  nonce for the origin address should have changed. Now it should find *no* transactions.
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 0, "Mempool should find no transactions");
        },
    );

    mempool
        .reset_nonce_cache()
        .expect("Should be able to reset nonces");

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_5.0, &b_5.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_5"
            );
        },
    );

    mempool
        .reset_nonce_cache()
        .expect("Should be able to reset nonces");

    // The mempool iterator no longer does any consideration of what block accepted
    //  the transaction, so b_3 should have the same view.
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_3.0, &b_3.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_3"
            );
        },
    );

    mempool
        .reset_nonce_cache()
        .expect("Should be able to reset nonces");

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_4.0, &b_4.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_4"
            );
        },
    );

    mempool
        .reset_nonce_cache()
        .expect("Should be able to reset nonces");

    // let's test replace-across-fork while we're here.
    // first try to replace a tx in b_2 in b_1 - should fail because they are in the same fork
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let block = &b_1;
    let tx = &txs[1];
    let origin_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[1; 32]),
    };
    let sponsor_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[0x81; 32]),
    };

    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();

    let height = 3;
    let origin_nonce = 0;
    let sponsor_nonce = 0;

    // make sure that we already have the transaction we're testing for replace-across-fork
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    assert!(MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &block.0,
        &block.1,
        true,
        txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .is_err());

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    mempool_tx.commit().unwrap();

    // now try replace-across-fork from b_2 to b_4
    // check that the number of transactions at b_2 and b_4 starts at 1 each
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
        1
    );
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
        1
    );
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let block = &b_4;
    let tx = &txs[1];
    let origin_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[0; 32]),
    };
    let sponsor_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[1; 32]),
    };

    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();

    let height = 3;
    let origin_nonce = 1;
    let sponsor_nonce = 1;

    // make sure that we already have the transaction we're testing for replace-across-fork
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &block.0,
        &block.1,
        true,
        txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    mempool_tx.commit().unwrap();

    // after replace-across-fork, tx[1] should have moved from the b_2->b_5 fork to b_4
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
        2
    );
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
        0
    );
}

#[test]
/// This test verifies that all transactions are visited, regardless of the
/// setting for `consider_no_estimate_tx_prob`.
fn test_iterate_candidates_consider_no_estimate_tx_prob() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);
    let chainstate_path = chainstate_path(function_name!());
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

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 24 transactions into the mempool, alternating whether or not they have a fee-rate.
    for nonce in 0..24 {
        let mut tx = txs.pop().unwrap();
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
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        if nonce & 1 == 0 {
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![Some(123.0), txid],
                )
                .unwrap();
        } else {
            let none: Option<f64> = None;
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![none, txid],
                )
                .unwrap();
        }

        mempool_tx.commit().unwrap();
    }

    // First, with default (5%)
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    // Next with 0%
    let _ = mempool.reset_nonce_cache();
    mempool_settings.consider_no_estimate_tx_prob = 0;

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    // Then with with 100%
    let _ = mempool.reset_nonce_cache();
    mempool_settings.consider_no_estimate_tx_prob = 100;

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );
}

#[test]
/// This test verifies that when a transaction is skipped, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_skipped_transaction() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);
    let chainstate_path = chainstate_path(function_name!());
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

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
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
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::skipped(
                                &available_tx.tx.tx,
                                "event not relevant to test".to_string(),
                            )
                            .convert_to_event()
                        } else {
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
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that when a transaction reports a processing error, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_processing_error_transaction() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);
    let chainstate_path = chainstate_path(function_name!());
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

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
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
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::error(
                                &available_tx.tx.tx,
                                crate::chainstate::stacks::Error::StacksTransactionSkipped(
                                    "error for testing".to_string(),
                                ),
                            )
                            .convert_to_event()
                        } else {
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
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that when a transaction is skipped, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_problematic_transaction() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);
    let chainstate_path = chainstate_path(function_name!());
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

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
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
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::problematic(
                                &available_tx.tx.tx,
                                crate::chainstate::stacks::Error::StacksTransactionSkipped(
                                    "problematic for testing".to_string(),
                                ),
                            )
                            .convert_to_event()
                        } else {
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
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that all transactions are visited, and nonce cache on disk updated, even if
/// there's a concurrent write-lock on the mempool DB.
fn test_iterate_candidates_concurrent_write_lock() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);
    let chainstate_path = chainstate_path(function_name!());
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

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    let mut expected_addr_nonces = HashMap::new();

    // Load 24 transactions into the mempool, alternating whether or not they have a fee-rate.
    for nonce in 0..24 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address);
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        if let Some(nonce) = expected_addr_nonces.get_mut(&origin_address) {
            *nonce = cmp::max(*nonce, origin_nonce);
        } else {
            expected_addr_nonces.insert(origin_address.clone(), origin_nonce);
        }

        if let Some(nonce) = expected_addr_nonces.get_mut(&sponsor_address) {
            *nonce = cmp::max(*nonce, sponsor_nonce);
        } else {
            expected_addr_nonces.insert(sponsor_address.clone(), sponsor_nonce);
        }

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
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        if nonce & 1 == 0 {
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![Some(123.0), txid],
                )
                .unwrap();
        } else {
            let none: Option<f64> = None;
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![none, txid],
                )
                .unwrap();
        }

        mempool_tx.commit().unwrap();
    }
    assert!(!expected_addr_nonces.is_empty());

    let all_addr_nonces = db_get_all_nonces(mempool.conn()).unwrap();
    assert!(all_addr_nonces.is_empty());

    // start a thread that holds a write-lock on the mempool
    let write_thread = std::thread::spawn(move || {
        let mut thread_mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
        let mempool_tx = thread_mempool.tx_begin().unwrap();
        sleep_ms(10_000);
    });

    sleep_ms(1_000);

    // 50% chance of considering a transaction with unknown fee estimate
    mempool_settings.consider_no_estimate_tx_prob = 50;
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    write_thread.join().unwrap();

    let all_addr_nonces = db_get_all_nonces(mempool.conn()).unwrap();
    assert_eq!(all_addr_nonces.len(), expected_addr_nonces.len());

    for (addr, nonce) in all_addr_nonces {
        assert!(expected_addr_nonces.contains_key(&addr));
        assert_eq!(nonce, 24);
    }
}

#[test]
fn mempool_do_not_replace_tx() {
    let mut chainstate =
        instantiate_chainstate_with_balances(false, 0x80000000, function_name!(), vec![]);

    // genesis -> b_1 -> b_2
    //      \-> b_3
    //
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
    let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 1, 1);

    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    let mut tx = txs.pop().unwrap();

    let mut mempool_tx = mempool.tx_begin().unwrap();

    // do an initial insert
    let origin_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[0; 32]),
    };
    let sponsor_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&[1; 32]),
    };

    tx.set_tx_fee(123);

    // test insert
    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();

    let tx_fee = tx.get_tx_fee();
    let height = 100;

    let origin_nonce = tx.get_origin_nonce();
    let sponsor_nonce = match tx.get_sponsor_nonce() {
        Some(n) => n,
        None => origin_nonce,
    };

    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

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
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let prior_txid = txid.clone();

    // now, let's try inserting again, with a lower fee, but at a different block hash
    tx.set_tx_fee(100);
    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();
    let height = 100;

    let err_resp = MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &b_2.0,
        &b_2.1,
        true,
        txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap_err();
    assert!(match err_resp {
        MemPoolRejection::ConflictingNonceInMempool => true,
        e => panic!("Failed: {e:?}"),
    });

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &prior_txid).unwrap());
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
}

#[rstest]
#[case(MempoolCollectionBehavior::ByStacksHeight)]
#[case(MempoolCollectionBehavior::ByReceiveTime)]
fn mempool_db_load_store_replace_tx(#[case] behavior: MempoolCollectionBehavior) {
    let path_name = format!("{}::{:?}", function_name!(), behavior);
    let mut chainstate = instantiate_chainstate(false, 0x80000000, &path_name);
    let chainstate_path = chainstate_path(&path_name);
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    let num_txs = txs.len() as u64;

    let mut mempool_tx = mempool.tx_begin().unwrap();

    eprintln!("add all txs");
    for (i, mut tx) in txs.into_iter().enumerate() {
        // make sure each address is unique per tx (not the case in codec_all_transactions)
        let origin_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&i.to_be_bytes()),
        };
        let sponsor_address = StacksAddress {
            version: 22,
            bytes: Hash160::from_data(&(i + 1).to_be_bytes()),
        };

        tx.set_tx_fee(123);

        // test insert

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();

        let tx_fee = tx.get_tx_fee();
        let height = 100;
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_nonce = match tx.get_sponsor_nonce() {
            Some(n) => n,
            None => origin_nonce,
        };
        let len = tx_bytes.len() as u64;

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        // test retrieval
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
        let tx_info = tx_info_opt.unwrap();

        assert_eq!(tx_info.tx, expected_tx);
        assert_eq!(tx_info.metadata.len, len);
        assert_eq!(tx_info.metadata.tx_fee, 123);
        assert_eq!(tx_info.metadata.origin_address, origin_address);
        assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
        assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
        assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
        assert_eq!(
            tx_info.metadata.tenure_consensus_hash,
            ConsensusHash([0x1; 20])
        );
        assert_eq!(
            tx_info.metadata.tenure_block_header_hash,
            BlockHeaderHash([0x2; 32])
        );
        assert_eq!(tx_info.metadata.coinbase_height, height);

        // test replace-by-fee with a higher fee
        let old_txid = txid;

        tx.set_tx_fee(124);
        assert!(txid != tx.txid());

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_before =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert_eq!(tx_info_before, tx_info.metadata);

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        // was replaced
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_after =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert!(tx_info_after != tx_info.metadata);

        // test retrieval -- transaction should have been replaced because it has a higher
        // estimated fee
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();

        let tx_info = tx_info_opt.unwrap();
        assert_eq!(tx_info.metadata, tx_info_after);

        assert_eq!(tx_info.tx, expected_tx);
        assert_eq!(tx_info.metadata.len, len);
        assert_eq!(tx_info.metadata.tx_fee, 124);
        assert_eq!(tx_info.metadata.origin_address, origin_address);
        assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
        assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
        assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
        assert_eq!(
            tx_info.metadata.tenure_consensus_hash,
            ConsensusHash([0x1; 20])
        );
        assert_eq!(
            tx_info.metadata.tenure_block_header_hash,
            BlockHeaderHash([0x2; 32])
        );
        assert_eq!(tx_info.metadata.coinbase_height, height);

        // test replace-by-fee with a lower fee
        let old_txid = txid;

        tx.set_tx_fee(122);
        assert!(txid != tx.txid());

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let _expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();

        assert!(match MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap_err()
        {
            MemPoolRejection::ConflictingNonceInMempool => true,
            _ => false,
        });

        // was NOT replaced
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    }
    mempool_tx.commit().unwrap();

    eprintln!("get all txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert_eq!(txs.len() as u64, num_txs);

    eprintln!("get empty txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x3; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert_eq!(txs.len(), 0);

    eprintln!("get empty txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x2; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert_eq!(txs.len(), 0);

    eprintln!("garbage-collect");
    let mempool_tx = mempool.tx_begin().unwrap();
    match behavior {
        MempoolCollectionBehavior::ByStacksHeight => {
            MemPoolDB::garbage_collect_by_coinbase_height(&mempool_tx, 101, None)
        }
        MempoolCollectionBehavior::ByReceiveTime => {
            let test_max_age = Duration::from_secs(1);
            std::thread::sleep(2 * test_max_age);
            MemPoolDB::garbage_collect_by_time(&mempool_tx, &test_max_age, None)
        }
    }
    .unwrap();
    mempool_tx.commit().unwrap();

    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert_eq!(txs.len(), 0);
}

#[test]
fn mempool_db_test_rbf() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    // create initial transaction
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let spending_condition = TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
        signer: Hash160([0x11; 20]),
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Uncompressed,
        nonce: 123,
        tx_fee: 456,
        signature: MessageSignature::from_raw(&[0xff; 65]),
    });
    let stx_address = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };
    let payload = TransactionPayload::TokenTransfer(
        PrincipalData::from(QualifiedContractIdentifier {
            issuer: stx_address.into(),
            name: "hello-contract-name".into(),
        }),
        123,
        TokenTransferMemo([0u8; 34]),
    );
    let mut tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 0x80000000,
        auth: TransactionAuth::Standard(spending_condition.clone()),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: Vec::new(),
        payload,
    };

    let i: usize = 0;
    let origin_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&i.to_be_bytes()),
    };
    let sponsor_address = StacksAddress {
        version: 22,
        bytes: Hash160::from_data(&(i + 1).to_be_bytes()),
    };

    tx.set_tx_fee(123);
    let txid = tx.txid();
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    let expected_tx = tx.clone();
    let tx_fee = tx.get_tx_fee();
    let height = 100;
    let origin_nonce = tx.get_origin_nonce();
    let sponsor_nonce = match tx.get_sponsor_nonce() {
        Some(n) => n,
        None => origin_nonce,
    };
    let first_len = tx_bytes.len() as u64;

    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        false, // don't resolve the above chain tip since it doesn't exist
        txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    // test retrieval of initial transaction
    let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
    let tx_info = tx_info_opt.unwrap();

    // test replace-by-fee with a higher fee, where the payload is smaller
    let old_txid = txid;
    let old_tx_fee = tx_fee;

    tx.set_tx_fee(124);
    tx.payload =
        TransactionPayload::TokenTransfer(stx_address.into(), 123, TokenTransferMemo([0u8; 34]));
    assert!(txid != tx.txid());
    let txid = tx.txid();
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    let expected_tx = tx.clone();
    let tx_fee = tx.get_tx_fee();
    let second_len = tx_bytes.len() as u64;

    // these asserts are to ensure we are using the fee directly, not the fee rate
    assert!(second_len < first_len);
    assert!(second_len * tx_fee < first_len * old_tx_fee);
    assert!(tx_fee > old_tx_fee);
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let tx_info_before =
        MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
            .unwrap()
            .unwrap();
    assert_eq!(tx_info_before, tx_info.metadata);

    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        false, // don't resolve the above chain tip since it doesn't exist
        txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    // check that the transaction was replaced
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let tx_info_after =
        MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
            .unwrap()
            .unwrap();
    assert!(tx_info_after != tx_info.metadata);

    // test retrieval -- transaction should have been replaced because it has a higher fee
    let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
    let tx_info = tx_info_opt.unwrap();
    assert_eq!(tx_info.metadata, tx_info_after);
    assert_eq!(tx_info.metadata.len, second_len);
    assert_eq!(tx_info.metadata.tx_fee, 124);
}

#[test]
fn test_add_txs_bloom_filter() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };

    let mut all_txids: Vec<Vec<Txid>> = vec![];

    // none conflict
    for block_height in 10..(10 + 10 * BLOOM_COUNTER_DEPTH) {
        let mut txids: Vec<Txid> = vec![];
        let mut fp_count = 0;

        let bf = mempool.get_txid_bloom_filter().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();
        for i in 0..128 {
            let pk = StacksPrivateKey::new();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                anchor_mode: TransactionAnchorMode::Any,
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: vec![],
                payload: TransactionPayload::TokenTransfer(
                    addr.to_account_principal(),
                    (block_height + i * 128) as u64,
                    TokenTransferMemo([0u8; 34]),
                ),
            };
            tx.set_tx_fee(1000);
            tx.set_origin_nonce(0);

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            // should succeed
            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1 + (block_height as u8); 20]),
                &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                false, // don't resolve the above chain tip since it doesn't exist
                txid,
                tx_bytes,
                tx_fee,
                block_height as u64,
                &origin_addr,
                origin_nonce,
                &sponsor_addr,
                sponsor_nonce,
                None,
            )
            .unwrap();

            if bf.contains_raw(&tx.txid().0) {
                fp_count += 1;
            }

            txids.push(txid);
        }

        mempool_tx.commit().unwrap();

        // nearly all txs should be new
        assert!((fp_count as f64) / (MAX_BLOOM_COUNTER_TXS as f64) <= BLOOM_COUNTER_ERROR_RATE);

        let bf = mempool.get_txid_bloom_filter().unwrap();
        for txid in txids.iter() {
            assert!(
                bf.contains_raw(&txid.0),
                "Bloom filter does not contain {}",
                &txid
            );
        }

        all_txids.push(txids);

        if block_height > 10 + BLOOM_COUNTER_DEPTH {
            let expired_block_height = block_height - BLOOM_COUNTER_DEPTH;
            let bf = mempool.get_txid_bloom_filter().unwrap();
            for i in 0..(block_height - 10 - BLOOM_COUNTER_DEPTH) {
                let txids = &all_txids[i];
                let mut fp_count = 0;
                for txid in txids {
                    if bf.contains_raw(&txid.0) {
                        fp_count += 1;
                    }
                }

                // these expired txids should mostly be absent
                assert!(
                    (fp_count as f64) / (MAX_BLOOM_COUNTER_TXS as f64) <= BLOOM_COUNTER_ERROR_RATE
                );
            }
        }
    }
}

#[test]
fn test_txtags() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };

    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    let mut all_txtags: Vec<Vec<TxTag>> = vec![];

    for block_height in 10..(10 + 10 * BLOOM_COUNTER_DEPTH) {
        let mut txtags: Vec<TxTag> = vec![];

        let mut mempool_tx = mempool.tx_begin().unwrap();
        for i in 0..128 {
            let pk = StacksPrivateKey::new();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                anchor_mode: TransactionAnchorMode::Any,
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: vec![],
                payload: TransactionPayload::TokenTransfer(
                    addr.to_account_principal(),
                    (block_height + i * 128) as u64,
                    TokenTransferMemo([0u8; 34]),
                ),
            };
            tx.set_tx_fee(1000);
            tx.set_origin_nonce(0);

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            let txtag = TxTag::from(&seed, &txid);

            // should succeed
            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1 + (block_height as u8); 20]),
                &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                false, // don't resolve the above chain tip since it doesn't exist
                txid,
                tx_bytes,
                tx_fee,
                block_height as u64,
                &origin_addr,
                origin_nonce,
                &sponsor_addr,
                sponsor_nonce,
                None,
            )
            .unwrap();

            txtags.push(txtag);
        }

        mempool_tx.commit().unwrap();
        all_txtags.push(txtags);

        if block_height - 10 >= BLOOM_COUNTER_DEPTH {
            assert_eq!(
                MemPoolDB::get_num_recent_txs(mempool.conn()).unwrap(),
                (BLOOM_COUNTER_DEPTH * 128) as u64
            );
        }

        let txtags = mempool.get_txtags(&seed).unwrap();
        let len_txtags = all_txtags.len();
        let last_txtags = &all_txtags[len_txtags.saturating_sub(BLOOM_COUNTER_DEPTH)..len_txtags];

        let mut expected_txtag_set = HashSet::new();
        for txtags in last_txtags.iter() {
            for txtag in txtags.iter() {
                expected_txtag_set.insert(txtag.clone());
            }
        }

        assert_eq!(expected_txtag_set.len(), txtags.len());
        for txtag in txtags.into_iter() {
            assert!(expected_txtag_set.contains(&txtag));
        }
    }
}

#[test]
#[ignore]
fn test_make_mempool_sync_data() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };

    let mut txids = vec![];
    let mut nonrecent_fp_rates = vec![];
    for block_height in 10..(10 + BLOOM_COUNTER_DEPTH + 1) {
        for i in 0..((MAX_BLOOM_COUNTER_TXS + 128) as usize) {
            let mut mempool_tx = mempool.tx_begin().unwrap();
            for j in 0..128 {
                let pk = StacksPrivateKey::new();
                let mut tx = StacksTransaction {
                    version: TransactionVersion::Testnet,
                    chain_id: 0x80000000,
                    auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                    anchor_mode: TransactionAnchorMode::Any,
                    post_condition_mode: TransactionPostConditionMode::Allow,
                    post_conditions: vec![],
                    payload: TransactionPayload::TokenTransfer(
                        addr.to_account_principal(),
                        123,
                        TokenTransferMemo([0u8; 34]),
                    ),
                };
                tx.set_tx_fee(1000);
                tx.set_origin_nonce(0);

                let txid = tx.txid();
                let tx_bytes = tx.serialize_to_vec();
                let origin_addr = tx.origin_address();
                let origin_nonce = tx.get_origin_nonce();
                let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
                let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
                let tx_fee = tx.get_tx_fee();

                // should succeed
                MemPoolDB::try_add_tx(
                    &mut mempool_tx,
                    &mut chainstate,
                    &ConsensusHash([0x1 + (block_height as u8); 20]),
                    &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                    false, // don't resolve the above chain tip since it doesn't exist
                    txid.clone(),
                    tx_bytes,
                    tx_fee,
                    block_height as u64,
                    &origin_addr,
                    origin_nonce,
                    &sponsor_addr,
                    sponsor_nonce,
                    None,
                )
                .unwrap();

                txids.push(txid);
            }
            mempool_tx.commit().unwrap();

            let ts_1 = get_epoch_time_ms();
            let ms = mempool.make_mempool_sync_data().unwrap();
            let ts_2 = get_epoch_time_ms();
            eprintln!(
                "make_mempool_sync_data({}): {} ms",
                txids.len(),
                ts_2.saturating_sub(ts_1)
            );

            let mut present_count: u32 = 0;
            let mut absent_count: u32 = 0;
            let mut fp_count: u32 = 0;
            match ms {
                MemPoolSyncData::BloomFilter(ref bf) => {
                    eprintln!(
                        "bloomfilter({}); txids.len() == {}",
                        block_height,
                        txids.len()
                    );
                    let recent_txids = mempool.get_bloom_txids().unwrap();
                    assert!(recent_txids.len() <= MAX_BLOOM_COUNTER_TXS as usize);

                    let max_height = MemPoolDB::get_max_coinbase_height(mempool.conn())
                        .unwrap()
                        .unwrap_or(0);
                    eprintln!(
                        "bloomfilter({}): recent_txids.len() == {}, max height is {}",
                        block_height,
                        recent_txids.len(),
                        max_height
                    );

                    let mut recent_set = HashSet::new();
                    let mut in_bf = 0;
                    for txid in recent_txids.iter() {
                        if bf.contains_raw(&txid.0) {
                            in_bf += 1;
                        }
                        recent_set.insert(txid.clone());
                    }

                    eprintln!("in bloom filter: {}", in_bf);
                    assert!(in_bf >= recent_txids.len());

                    for txid in txids.iter() {
                        if !recent_set.contains(&txid) && bf.contains_raw(&txid.0) {
                            fp_count += 1;
                        }
                        if bf.contains_raw(&txid.0) {
                            present_count += 1;
                        } else {
                            absent_count += 1;
                        }
                    }

                    // all recent transactions should be present
                    assert!(present_count >= cmp::min(MAX_BLOOM_COUNTER_TXS, txids.len() as u32));
                }
                MemPoolSyncData::TxTags(ref seed, ref tags) => {
                    eprintln!("txtags({}); txids.len() == {}", block_height, txids.len());
                    let recent_txids = mempool.get_bloom_txids().unwrap();

                    // all tags are present in the recent set
                    let mut recent_set = HashSet::new();
                    for txid in recent_txids {
                        recent_set.insert(TxTag::from(seed, &txid));
                    }

                    for tag in tags.iter() {
                        assert!(recent_set.contains(tag));
                    }
                }
            }

            let mut nonrecent_fp_rate = 0.0f64;
            let recent_txids = mempool.get_bloom_txids().unwrap();
            if recent_txids.len() < (present_count + absent_count) as usize {
                nonrecent_fp_rate = (fp_count as f64)
                    / ((present_count + absent_count - (recent_txids.len() as u32)) as f64);
                eprintln!(
                    "Nonrecent false positive rate: {} / ({} + {} - {} = {}) = {}",
                    fp_count,
                    present_count,
                    absent_count,
                    recent_txids.len(),
                    present_count + absent_count - (recent_txids.len() as u32),
                    nonrecent_fp_rate
                );
            }

            let total_count = MemPoolDB::get_num_recent_txs(&mempool.conn()).unwrap();
            eprintln!(
                "present_count: {}, absent count: {}, total sent: {}, total recent: {}",
                present_count,
                absent_count,
                txids.len(),
                total_count
            );

            nonrecent_fp_rates.push(nonrecent_fp_rate);
        }
    }

    // average false positive rate for non-recent transactions should be around the bloom
    // counter false positive rate
    let num_nonrecent_fp_samples = nonrecent_fp_rates.len() as f64;
    let avg_nonrecent_fp_rate =
        nonrecent_fp_rates.iter().fold(0.0f64, |acc, x| acc + x) / num_nonrecent_fp_samples;

    assert!((avg_nonrecent_fp_rate - BLOOM_COUNTER_ERROR_RATE).abs() < 0.001);
}

#[test]
fn test_find_next_missing_transactions() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };

    let block_height = 10;
    let mut txids = vec![];

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..(2 * MAX_BLOOM_COUNTER_TXS) {
        let pk = StacksPrivateKey::new();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid.clone(),
            tx_bytes,
            tx_fee,
            block_height,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txids.push(txid);
    }
    mempool_tx.commit().unwrap();

    let mut txid_set = HashSet::new();
    for txid in txids.iter() {
        txid_set.insert(txid.clone());
    }

    eprintln!("Find next missing transactions");

    let txtags = mempool.get_txtags(&[0u8; 32]).unwrap();

    // no txs returned for a full txtag set
    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], txtags.clone()),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            MAX_BLOOM_COUNTER_TXS as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with full txtag set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    assert_eq!(txs.len(), 0);
    assert!(next_page_opt.is_some());

    // all txs returned for an empty txtag set
    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], vec![]),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            MAX_BLOOM_COUNTER_TXS as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with empty txtag set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    for tx in txs {
        assert!(txid_set.contains(&tx.txid()));
    }
    assert!(next_page_opt.is_some());

    // all bloom-filter-absent txids should be returned
    let ts_before = get_epoch_time_ms();
    let txid_bloom = mempool.get_txid_bloom_filter().unwrap();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(txid_bloom),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with full bloom filter set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    assert_eq!(txs.len(), 0);
    assert!(next_page_opt.is_some());

    let mut empty_bloom_conn = setup_bloom_counter(function_name!());
    let mut empty_tx = tx_begin_immediate(&mut empty_bloom_conn).unwrap();
    let hasher = BloomNodeHasher::new(&[0u8; 32]);
    let empty_bloom = BloomCounter::new(
        &mut empty_tx,
        "bloom_counter",
        BLOOM_COUNTER_ERROR_RATE,
        MAX_BLOOM_COUNTER_TXS,
        hasher,
    )
    .unwrap();
    empty_tx.commit().unwrap();

    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap()),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with empty bloom filter set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    for tx in txs {
        assert!(txid_set.contains(&tx.txid()));
    }
    assert!(next_page_opt.is_some());

    // paginated access works too
    let mut last_txid = Txid([0u8; 32]);
    let page_size = 128;
    let mut all_txs = vec![];
    for i in 0..(txtags.len() / (page_size as usize)) + 1 {
        let (mut txs, next_page_opt, num_visited) = mempool
            .find_next_missing_transactions(
                &MemPoolSyncData::TxTags([0u8; 32], vec![]),
                block_height,
                &last_txid,
                (2 * MAX_BLOOM_COUNTER_TXS) as u64,
                page_size,
            )
            .unwrap();
        assert!(txs.len() <= page_size as usize);
        assert!(num_visited <= page_size);

        if txs.is_empty() {
            assert!(next_page_opt.is_none());
            break;
        }

        last_txid = mempool
            .get_randomized_txid(&txs.last().clone().unwrap().txid())
            .unwrap()
            .unwrap();

        assert_eq!(last_txid, next_page_opt.unwrap());
        all_txs.append(&mut txs);
    }

    for tx in all_txs {
        assert!(txid_set.contains(&tx.txid()));
    }

    last_txid = Txid([0u8; 32]);
    all_txs = vec![];
    for i in 0..(txtags.len() / (page_size as usize)) + 1 {
        let ts_before = get_epoch_time_ms();
        let (mut txs, next_page_opt, num_visited) = mempool
            .find_next_missing_transactions(
                &MemPoolSyncData::BloomFilter(
                    empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap(),
                ),
                block_height,
                &last_txid,
                (2 * MAX_BLOOM_COUNTER_TXS) as u64,
                page_size,
            )
            .unwrap();
        let ts_after = get_epoch_time_ms();
        eprintln!("find_next_missing_transactions with empty bloom filter took {} ms to serve {} transactions", ts_after.saturating_sub(ts_before), page_size);

        assert!(txs.len() <= page_size as usize);
        assert!(num_visited <= page_size);

        if txs.is_empty() {
            assert!(next_page_opt.is_none());
            break;
        }

        last_txid = mempool
            .get_randomized_txid(&txs.last().clone().unwrap().txid())
            .unwrap()
            .unwrap();

        assert_eq!(last_txid, next_page_opt.unwrap());
        all_txs.append(&mut txs);
    }

    for tx in all_txs {
        assert!(txid_set.contains(&tx.txid()));
    }

    // old transactions are ignored
    let (old_txs, next_page_opt, num_visited) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], vec![]),
            block_height + (BLOOM_COUNTER_DEPTH as u64) + 1,
            &last_txid,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    assert_eq!(old_txs.len(), 0);
    assert!(next_page_opt.is_none());

    let (old_txs, next_page_opt, num_visited) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap()),
            block_height + (BLOOM_COUNTER_DEPTH as u64) + 1,
            &last_txid,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    assert_eq!(old_txs.len(), 0);
    assert!(next_page_opt.is_none());
}

#[test]
fn test_drop_and_blacklist_txs_by_time() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };
    let mut txs = vec![];
    let block_height = 10;

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::new();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid.clone(),
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txs.push(tx);
    }
    mempool_tx.commit().unwrap();
    let txids: Vec<_> = txs.iter().map(|tx| tx.txid()).collect();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // blacklist some txs
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::inner_blacklist_txs(&mempool_tx, &txids, get_epoch_time_secs()).unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by time
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 1,
        0,
        i64::MAX as u64,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    mempool.drop_and_blacklist_txs(&txids).unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(!mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by time
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 2,
        0,
        i64::MAX as u64,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(!mempool.has_tx(&tx.txid()));
    }
}

#[test]
fn test_drop_and_blacklist_txs_by_size() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };
    let mut txs = vec![];
    let block_height = 10;

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::new();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            txid.clone(),
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txs.push(tx);
    }
    mempool_tx.commit().unwrap();
    let txids: Vec<_> = txs.iter().map(|tx| tx.txid()).collect();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // blacklist some txs
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::inner_blacklist_txs(&mempool_tx, &txids, get_epoch_time_secs()).unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by size
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 1,
        i64::MAX as u64,
        5,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    // 5 txs remain blacklisted
    let mut num_blacklisted = 0;
    for tx in txs.iter() {
        if mempool.is_tx_blacklisted(&tx.txid()).unwrap() {
            num_blacklisted += 1;
        }
        assert!(mempool.has_tx(&tx.txid()));
    }

    assert_eq!(num_blacklisted, 5);
}

#[test]
fn test_filter_txs_by_type() {
    let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress {
        version: 1,
        bytes: Hash160([0xff; 20]),
    };
    let mut txs = vec![];
    let block_height = 10;
    let mut total_len = 0;

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

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::new();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        total_len += tx_bytes.len();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_2.0,
            &b_2.1,
            true,
            txid.clone(),
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txs.push(tx);
    }
    mempool_tx.commit().unwrap();

    let mut mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();
    mempool_settings.txs_to_consider = [
        MemPoolWalkTxTypes::SmartContract,
        MemPoolWalkTxTypes::ContractCall,
    ]
    .into_iter()
    .collect();

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 0);
        },
    );

    mempool_settings.txs_to_consider = [MemPoolWalkTxTypes::TokenTransfer].into_iter().collect();

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
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
                .unwrap();
            assert_eq!(count_txs, 10);
        },
    );
}
