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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::contracts::Contract;
use clarity::vm::costs::{CostOverflowingMath, LimitedCostTracker};
use clarity::vm::database::*;
use clarity::vm::errors::{
    CheckErrors, Error, IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use clarity::vm::eval;
use clarity::vm::events::{STXEventType, STXLockEventData, StacksTransactionEvent};
use clarity::vm::functions::principals;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::tests::{execute, is_committed, is_err_code, symbols_from_values};
use clarity::vm::types::Value::Response;
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    StacksAddressExtensions, StandardPrincipalData, TupleData, TupleTypeSignature, TypeSignature,
    Value, NONE,
};
use clarity::vm::Value::Optional;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::{Address, PrivateKey};
use stacks_common::util::hash::{hex_bytes, to_hex, Sha256Sum, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stdext::num::integer::Integer;

use super::test::*;
use super::RawRewardSetEntry;
use crate::burnchains::{Burnchain, PoxConstants};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::coordinator::tests::pox_addr_from;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::pox_2_tests::{
    check_pox_print_event, generate_pox_clarity_value, get_partial_stacked, get_reward_cycle_total,
    get_reward_set_entries_at, get_stacking_state_pox, get_stx_account_at, with_clarity_db_ro,
    PoxPrintFields, StackingStateCheckData,
};
use crate::chainstate::stacks::boot::signers_tests::{
    get_signer_index, prepare_signers_test, readonly_call,
};
use crate::chainstate::stacks::boot::{
    PoxVersions, BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET,
    MINERS_NAME, POX_2_NAME, POX_3_NAME,
};
use crate::chainstate::stacks::db::{
    MinerPaymentSchedule, StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::tests::make_coinbase;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::{ClarityBlockConnection, Error as ClarityError};
use crate::clarity_vm::database::marf::{MarfedKV, WritableMarfStore};
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::net::test::{TestEventObserver, TestEventObserverBlock, TestPeer, TestPeerConfig};
use crate::net::tests::NakamotoBootPlan;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{DBConn, FromRow};
use crate::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;
use crate::util_lib::signed_structured_data::structured_data_message_hash;

const USTX_PER_HOLDER: u128 = 1_000_000;

const ERR_REUSED_SIGNER_KEY: i128 = 33;

/// Return the BlockSnapshot for the latest sortition in the provided
///  SortitionDB option-reference. Panics on any errors.
pub fn get_tip(sortdb: Option<&SortitionDB>) -> BlockSnapshot {
    SortitionDB::get_canonical_burn_chain_tip(&sortdb.unwrap().conn()).unwrap()
}

/// Helper rstest template for running tests in both 2.5
/// and 3.0 epochs.
#[template]
#[rstest]
#[case::epoch_30(true)]
#[case::epoch_25(false)]
fn nakamoto_cases(#[case] use_nakamoto: bool) {}

fn make_simple_pox_4_lock(
    key: &StacksPrivateKey,
    peer: &mut TestPeer,
    amount: u128,
    lock_period: u128,
) -> StacksTransaction {
    let addr = key_to_stacks_addr(key);
    let pox_addr = PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, addr.bytes.clone());
    let signer_pk = StacksPublicKey::from_private(&key);
    let tip = get_tip(peer.sortdb.as_ref());
    let next_reward_cycle = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();
    let nonce = get_account(peer, &addr.into()).nonce;
    let auth_id = u128::from(nonce);

    let signature = make_signer_key_signature(
        &pox_addr,
        &key,
        next_reward_cycle.into(),
        &Pox4SignatureTopic::StackStx,
        lock_period,
        amount,
        auth_id,
    );

    make_pox_4_lockup(
        key,
        nonce,
        amount,
        &pox_addr,
        lock_period,
        &signer_pk,
        tip.block_height,
        Some(signature),
        amount,
        auth_id,
    )
}

pub fn make_test_epochs_pox(use_nakamoto: bool) -> (EpochList, PoxConstants) {
    let EMPTY_SORTITIONS = 25;
    let EPOCH_2_1_HEIGHT = EMPTY_SORTITIONS + 11; // 36
    let EPOCH_2_2_HEIGHT = EPOCH_2_1_HEIGHT + 14; // 50
    let EPOCH_2_3_HEIGHT = EPOCH_2_2_HEIGHT + 2; // 52
                                                 // epoch-2.4 will start at the first block of cycle 11!
                                                 //  this means that cycle 11 should also be treated like a "burn"
    let EPOCH_2_4_HEIGHT = EPOCH_2_3_HEIGHT + 4; // 56
    let EPOCH_2_5_HEIGHT = EPOCH_2_4_HEIGHT + 44; // 100
    let EPOCH_3_0_HEIGHT = EPOCH_2_5_HEIGHT + 23; // 123

    let mut epochs = EpochList::new(&[
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
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: EPOCH_2_1_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: EPOCH_2_1_HEIGHT,
            end_height: EPOCH_2_2_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: EPOCH_2_2_HEIGHT,
            end_height: EPOCH_2_3_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: EPOCH_2_3_HEIGHT,
            end_height: EPOCH_2_4_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: EPOCH_2_4_HEIGHT,
            end_height: EPOCH_2_5_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: EPOCH_2_5_HEIGHT,
            end_height: {
                if use_nakamoto {
                    EPOCH_3_0_HEIGHT
                } else {
                    STACKS_EPOCH_MAX
                }
            },
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
    ]);

    if use_nakamoto {
        epochs.push(StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: EPOCH_3_0_HEIGHT,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_3_0,
        });
    }

    let mut pox_constants = PoxConstants::mainnet_default();
    pox_constants.reward_cycle_length = 5;
    pox_constants.prepare_length = 2;
    pox_constants.anchor_threshold = 1;
    pox_constants.v1_unlock_height = (EPOCH_2_1_HEIGHT + 1) as u32;
    pox_constants.v2_unlock_height = (EPOCH_2_2_HEIGHT + 1) as u32;
    pox_constants.v3_unlock_height = (EPOCH_2_5_HEIGHT + 1) as u32;
    pox_constants.pox_3_activation_height = (EPOCH_2_4_HEIGHT + 1) as u32;
    // Activate pox4 2 cycles into epoch 2.5
    // Don't use Epoch 3.0 in order to avoid nakamoto blocks
    pox_constants.pox_4_activation_height =
        (EPOCH_2_5_HEIGHT as u32) + 1 + (2 * pox_constants.reward_cycle_length);

    (epochs, pox_constants)
}

#[test]
fn pox_extend_transition() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    let first_v3_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_3_activation_height as u64)
        .unwrap()
        + 1;

    let first_v4_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_4_activation_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;
    let mut coinbase_nonce = 0;

    let INITIAL_BALANCE = 1024 * POX_THRESHOLD_STEPS_USTX;
    let ALICE_LOCKUP = 1024 * POX_THRESHOLD_STEPS_USTX;
    let BOB_LOCKUP = 512 * POX_THRESHOLD_STEPS_USTX;

    // these checks should pass between Alice's first reward cycle,
    //  and the start of V2 reward cycles
    let alice_rewards_to_v2_start_checks = |tip_index_block, peer: &mut TestPeer| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) = with_sortdb(peer, |ref mut c, ref sortdb| {
            (
                c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block).unwrap(),
                c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                    .unwrap(),
            )
        });

        assert!(
            cur_reward_cycle >= EXPECTED_ALICE_FIRST_REWARD_CYCLE
                && cur_reward_cycle < first_v2_cycle as u128
        );
        //  Alice is the only Stacker, so check that.
        let (amount_ustx, pox_addr, lock_period, first_reward_cycle) =
            get_stacker_info(peer, &key_to_stacks_addr(&alice).into()).unwrap();
        eprintln!(
            "\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n",
            amount_ustx, lock_period, &pox_addr, first_reward_cycle
        );

        // one reward address, and it's Alice's
        // either way, there's a single reward address
        assert_eq!(reward_addrs.len(), 1);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[0].0).hash160(),
            key_to_stacks_addr(&alice).bytes
        );
        assert_eq!(reward_addrs[0].1, ALICE_LOCKUP);
    };

    // these checks should pass after the start of V2 reward cycles
    let v2_rewards_checks = |tip_index_block, peer: &mut TestPeer| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) = with_sortdb(peer, |ref mut c, ref sortdb| {
            (
                c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block).unwrap(),
                c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                    .unwrap(),
            )
        });

        eprintln!(
            "reward_cycle = {}, reward_addrs = {}, total_stacked = {}",
            cur_reward_cycle,
            reward_addrs.len(),
            total_stacked
        );

        assert!(cur_reward_cycle >= first_v2_cycle as u128);
        // v2 reward cycles have begun, so reward addrs should be read from PoX2 which is Bob + Alice
        assert_eq!(reward_addrs.len(), 2);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[0].0).hash160(),
            key_to_stacks_addr(&bob).bytes
        );
        assert_eq!(reward_addrs[0].1, BOB_LOCKUP);

        assert_eq!(
            (reward_addrs[1].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[1].0).hash160(),
            key_to_stacks_addr(&alice).bytes
        );
        assert_eq!(reward_addrs[1].1, ALICE_LOCKUP);
    };

    // first tenure is empty
    let mut latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_account.stx_balance.amount_unlocked(), INITIAL_BALANCE);
    assert_eq!(alice_account.stx_balance.amount_locked(), 0);
    assert_eq!(alice_account.stx_balance.unlock_height(), 0);

    // next tenure include Alice's lockup
    let tip = get_tip(peer.sortdb.as_ref());
    let alice_lockup = make_pox_lockup(
        &alice,
        0,
        ALICE_LOCKUP,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        4,
        tip.block_height,
    );

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |chainstate, sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |chainstate, sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap();

    assert_eq!(
        alice_first_reward_cycle as u128,
        EXPECTED_ALICE_FIRST_REWARD_CYCLE
    );
    let height_target = burnchain.reward_cycle_to_block_height(alice_first_reward_cycle) + 1;

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // produce blocks until epoch 2.1
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[StacksEpochId::Epoch21].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        alice_rewards_to_v2_start_checks(latest_block, &mut peer);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        BOB_LOCKUP,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        3,
        tip.block_height,
    );

    // Alice _will_ auto-unlock: she can stack-extend in PoX v2
    let alice_lockup = make_pox_2_extend(
        &alice,
        1,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
    );

    latest_block = peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);
    alice_rewards_to_v2_start_checks(latest_block, &mut peer);

    // Extend bob's lockup via `stack-extend` for 1 more cycle
    let bob_extend = make_pox_2_extend(
        &bob,
        1,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        1,
    );

    latest_block = peer.tenure_with_txs(&[bob_extend], &mut coinbase_nonce);

    alice_rewards_to_v2_start_checks(latest_block, &mut peer);

    // produce blocks until the v2 reward cycles start
    let height_target = burnchain.reward_cycle_to_block_height(first_v2_cycle) - 1;
    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(latest_block, &mut peer);
    }

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    v2_rewards_checks(latest_block, &mut peer);

    // roll the chain forward until just before Epoch-2.2
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[StacksEpochId::Epoch22].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should be locked, and so should bob's
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
        let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
        assert_eq!(bob_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // this block is mined in epoch-2.2
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);
    let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
    assert_eq!(bob_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // this block should unlock alice and bob's balance

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_account = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    let bob_account = get_stx_account_at(&mut peer, &latest_block, &bob_principal);
    assert_eq!(alice_account.amount_locked(), 0);
    assert_eq!(alice_account.amount_unlocked(), INITIAL_BALANCE);
    assert_eq!(bob_account.amount_locked(), 0);
    assert_eq!(bob_account.amount_unlocked(), INITIAL_BALANCE);

    // Roll to pox4 activation and re-do the above stack-extend tests
    while get_tip(peer.sortdb.as_ref()).block_height
        < u64::from(burnchain.pox_constants.pox_4_activation_height)
    {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());

    let alice_signer_private = Secp256k1PrivateKey::new();
    let alice_signer_key = Secp256k1PublicKey::from_private(&alice_signer_private);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let alice_pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
    );
    let auth_id = 1;

    let alice_signature = make_signer_key_signature(
        &alice_pox_addr,
        &alice_signer_private,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        4_u128,
        u128::MAX,
        auth_id,
    );
    let alice_stack_signature = alice_signature.clone();
    let alice_stack_signer_key = alice_signer_key.clone();
    let alice_lockup = make_pox_4_lockup(
        &alice,
        2,
        ALICE_LOCKUP,
        &PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        4,
        &alice_signer_key,
        tip.block_height,
        Some(alice_signature),
        u128::MAX,
        auth_id,
    );
    let alice_pox_4_lock_nonce = 2;
    let alice_first_pox_4_unlock_height =
        burnchain.reward_cycle_to_block_height(first_v4_cycle + 4) - 1;
    let alice_pox_4_start_burn_height = tip.block_height;

    latest_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v4_cycle..(first_v4_cycle + 4) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);

        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP,);
    }

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &latest_block);
    let alice_first_v4_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap();

    let height_target = burnchain.reward_cycle_to_block_height(alice_first_v4_reward_cycle) + 1;

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &alice_principal);
    assert_eq!(alice_balance, 0);

    // advance to the first v3 reward cycle
    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let bob_signer_private = Secp256k1PrivateKey::new();

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let bob_pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
    );

    let bob_signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob_signer_private,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        3_u128,
        u128::MAX,
        2,
    );

    let tip = get_tip(peer.sortdb.as_ref());
    let bob_lockup = make_pox_4_lockup(
        &bob,
        2,
        BOB_LOCKUP,
        &bob_pox_addr,
        3,
        &StacksPublicKey::from_private(&bob_signer_private),
        tip.block_height,
        Some(bob_signature),
        u128::MAX,
        2,
    );

    // new signing key needed
    let alice_signer_private = Secp256k1PrivateKey::default();
    let alice_signer_key = StacksPublicKey::from_private(&alice_signer_private);

    let alice_signature = make_signer_key_signature(
        &alice_pox_addr,
        &alice_signer_private,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        6_u128,
        u128::MAX,
        3,
    );

    // Alice can stack-extend in PoX v2
    let alice_lockup = make_pox_4_extend(
        &alice,
        3,
        alice_pox_addr.clone(),
        6,
        alice_signer_key.clone(),
        Some(alice_signature.clone()),
        u128::MAX,
        3,
    );

    let alice_pox_4_extend_nonce = 3;
    let alice_extend_pox_4_unlock_height =
        burnchain.reward_cycle_to_block_height(first_v4_cycle + 10) - 1;

    latest_block = peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v4_cycle..(first_v4_cycle + 1) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP);
    }

    for cycle_number in (first_v4_cycle + 1)..(first_v4_cycle + 4) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[1].amount_stacked, ALICE_LOCKUP);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&bob).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, BOB_LOCKUP);
    }

    for cycle_number in (first_v4_cycle + 4)..(first_v4_cycle + 10) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);

        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP);
    }

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len(), 4);
    assert_eq!(bob_txs.len(), 3);

    for tx in alice_txs.iter() {
        assert!(
            if let Value::Response(ref r) = tx.1.result {
                r.committed
            } else {
                false
            },
            "Alice txs should all have committed okay"
        );
    }

    for tx in bob_txs.iter() {
        assert!(
            if let Value::Response(ref r) = tx.1.result {
                r.committed
            } else {
                false
            },
            "Bob txs should all have committed okay"
        );
    }

    // Check that the call to `stack-stx` has a well-formed print event.
    let stack_tx = &alice_txs
        .get(&alice_pox_4_lock_nonce)
        .unwrap()
        .clone()
        .events[0];
    let pox_addr_val = generate_pox_clarity_value("ae1593226f85e49a7eaff5b633ff687695438cc9");
    let stack_op_data = HashMap::from([
        ("lock-amount", Value::UInt(ALICE_LOCKUP)),
        (
            "unlock-burn-height",
            Value::UInt(alice_first_pox_4_unlock_height.into()),
        ),
        (
            "start-burn-height",
            Value::UInt(alice_pox_4_start_burn_height.into()),
        ),
        ("pox-addr", pox_addr_val.clone()),
        ("lock-period", Value::UInt(4)),
        (
            "signer-sig",
            Value::some(Value::buff_from(alice_stack_signature).unwrap()).unwrap(),
        ),
        (
            "signer-key",
            Value::buff_from(alice_stack_signer_key.to_bytes_compressed()).unwrap(),
        ),
        ("max-amount", Value::UInt(u128::MAX)),
        ("auth-id", Value::UInt(1)),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: Value::Principal(alice_principal.clone()),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(stack_tx, common_data, stack_op_data);

    // Check that the call to `stack-extend` has a well-formed print event.
    let stack_extend_tx = &alice_txs
        .get(&alice_pox_4_extend_nonce)
        .unwrap()
        .clone()
        .events[0];
    let stack_ext_op_data = HashMap::from([
        ("extend-count", Value::UInt(6)),
        ("pox-addr", pox_addr_val),
        (
            "unlock-burn-height",
            Value::UInt(alice_extend_pox_4_unlock_height.into()),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-extend".to_string(),
        stacker: Value::Principal(alice_principal.clone()),
        balance: Value::UInt(0),
        locked: Value::UInt(ALICE_LOCKUP),
        burnchain_unlock_height: Value::UInt(alice_first_pox_4_unlock_height.into()),
    };
    check_pox_print_event(stack_extend_tx, common_data, stack_ext_op_data);
}

fn get_burn_pox_addr_info(peer: &mut TestPeer) -> (Vec<PoxAddress>, u128) {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;
    let addrs_and_payout = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
        let addrs = chainstate
            .maybe_read_only_clarity_tx(
                &sortdb.index_handle_at_tip(),
                &tip_index_block,
                |clarity_tx| {
                    clarity_tx
                        .with_readonly_clarity_env(
                            false,
                            0x80000000,
                            ClarityVersion::Clarity2,
                            PrincipalData::Standard(StandardPrincipalData::transient()),
                            None,
                            LimitedCostTracker::new_free(),
                            |env| {
                                env.eval_read_only(
                                    &boot_code_id("pox-2", false),
                                    &format!("(get-burn-block-info? pox-addrs u{})", &burn_height),
                                )
                            },
                        )
                        .unwrap()
                },
            )
            .unwrap();
        addrs
    })
    .unwrap()
    .expect_optional()
    .unwrap()
    .unwrap()
    .expect_tuple()
    .unwrap();

    let addrs = addrs_and_payout
        .get("addrs")
        .unwrap()
        .to_owned()
        .expect_list()
        .unwrap()
        .into_iter()
        .map(|tuple| PoxAddress::try_from_pox_tuple(false, &tuple).unwrap())
        .collect();

    let payout = addrs_and_payout
        .get("payout")
        .unwrap()
        .to_owned()
        .expect_u128()
        .unwrap();
    (addrs, payout)
}

/// Test that we can lock STX for a couple cycles after pox4 starts,
/// and that it unlocks after the desired number of cycles
#[test]
fn pox_lock_unlock() {
    // Config for this test
    // We are going to try locking for 2 reward cycles (10 blocks)
    let lock_period = 2;
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, function_name!(), Some(epochs.clone()), None);

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[StacksEpochId::Epoch21].start_height
        {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let reward_cycle = burnchain.block_height_to_reward_cycle(tip_height).unwrap() as u128;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .enumerate()
        .map(|(ix, (key, hash_mode))| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            let lock_period = if ix == 3 { 12 } else { lock_period };
            let signer_key = key;
            let signature = make_signer_key_signature(
                &pox_addr,
                &signer_key,
                reward_cycle,
                &Pox4SignatureTopic::StackStx,
                lock_period,
                u128::MAX,
                1,
            );
            txs.push(make_pox_4_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                &pox_addr,
                lock_period,
                &StacksPublicKey::from_private(&signer_key),
                tip_height,
                Some(signature),
                u128::MAX,
                1,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs");
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // Advance to start of rewards cycle stackers are participating in
    let target_height = burnchain.pox_constants.pox_4_activation_height + 5;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;
    let mut rewarded = HashSet::new();

    // Check that STX are locked for 2 reward cycles
    for _ in 0..lock_period {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert!(balances[0].amount_locked() > 0);
        assert!(balances[1].amount_locked() > 0);
        assert!(balances[2].amount_locked() > 0);
        assert!(balances[3].amount_locked() > 0);

        info!("Checking we have 2 stackers for cycle {cycle}");
        for i in 0..reward_blocks {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // only the first 2 reward blocks contain pox outputs, because there are 6 slots and only 4 are occuppied
            if i < 2 {
                assert_latest_was_pox(&mut peer)
                    .into_iter()
                    .filter(|addr| !addr.is_burn())
                    .for_each(|addr| {
                        rewarded.insert(addr);
                    });
            } else {
                assert_latest_was_burn(&mut peer);
            }
        }

        assert_eq!(rewarded.len(), 4);
        for stacker in stackers.iter() {
            assert!(
                rewarded.contains(stacker),
                "Reward cycle should include {stacker}"
            );
        }

        // now we should be back in a prepare phase
        info!("Checking we are in prepare phase");
        for _ in 0..burnchain.pox_constants.prepare_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }
    }

    info!("Checking STX unlocked after {lock_period} cycles");
    let mut rewarded = HashSet::new();
    for i in 0..burnchain.pox_constants.reward_cycle_length {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // only 1 entry in reward set now, but they get 5 slots -- so that's 3 blocks
        info!("Checking {i}th block of next reward cycle");
        if i < 3 {
            assert_latest_was_pox(&mut peer)
                .into_iter()
                .filter(|addr| !addr.is_burn())
                .for_each(|addr| {
                    rewarded.insert(addr);
                });
        } else {
            assert_latest_was_burn(&mut peer);
        }
    }

    assert_eq!(rewarded.len(), 1);
    assert!(
        rewarded.contains(&stackers[3]),
        "Reward set should include the index-3 stacker"
    );

    info!("Checking that stackers[0..2] have no STX locked");
    let balances = balances_from_keys(&mut peer, &latest_block, &keys);
    assert_eq!(balances[0].amount_locked(), 0);
    assert_eq!(balances[1].amount_locked(), 0);
    assert_eq!(balances[2].amount_locked(), 0);
}

/// Test that pox3 methods fail once pox4 is activated
#[test]
fn pox_3_defunct() {
    // Config for this test
    // We are going to try locking for 2 reward cycles (10 blocks)
    let lock_period = 2;
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[StacksEpochId::Epoch21].start_height
        {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .map(|(key, hash_mode)| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            txs.push(make_pox_3_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr.clone(),
                lock_period,
                tip_height,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs with pox3");
    latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    info!("Checking that stackers have no STX locked");
    let balances = balances_from_keys(&mut peer, &latest_block, &keys);
    assert_eq!(balances[0].amount_locked(), 0);
    assert_eq!(balances[1].amount_locked(), 0);

    info!("Checking tx receipts, all `pox3` calls should have returned `(err none)`");
    let last_observer_block = observer.get_blocks().last().unwrap().clone();

    let receipts = last_observer_block
        .receipts
        .iter()
        .filter(|receipt| match &receipt.result {
            Value::Response(r) => !r.committed,
            _ => false,
        })
        .collect::<Vec<_>>();

    assert_eq!(receipts.len(), txs.len());
    for r in receipts.iter() {
        let err = r
            .result
            .clone()
            .expect_result_err()
            .unwrap()
            .expect_optional()
            .unwrap();
        assert!(err.is_none());
    }

    // Advance to start of rewards cycle stackers are participating in
    let target_height = burnchain.pox_constants.pox_4_activation_height + 5;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;

    // Check next 3 reward cycles
    for _ in 0..=lock_period {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have no STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert_eq!(balances[0].amount_locked(), 0);
        assert_eq!(balances[1].amount_locked(), 0);

        info!("Checking no stackers for cycle {cycle}");
        for _ in 0..burnchain.pox_constants.reward_cycle_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // Should all be burn because no stackers
            assert_latest_was_burn(&mut peer);
        }
    }
}

// Test that STX locked in pox3 automatically unlocks at `v3_unlock_height`
#[test]
fn pox_3_unlocks() {
    // Config for this test
    // We are going to try locking for 4 reward cycles (20 blocks)
    let lock_period = 4;
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, function_name!(), Some(epochs.clone()), None);

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block;

    // Advance to a few blocks before pox 3 unlock
    let target_height = burnchain.pox_constants.v3_unlock_height - 14;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[StacksEpochId::Epoch21].start_height
        {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .map(|(key, hash_mode)| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            txs.push(make_pox_3_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr.clone(),
                lock_period,
                tip_height,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs");
    latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // Advance a couple more blocks
    for _ in 0..3 {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;
    let mut rewarded = HashSet::new();

    // Check that STX are locked for 2 reward cycles
    for _ in 0..2 {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert!(balances[0].amount_locked() > 0);
        assert!(balances[1].amount_locked() > 0);

        info!("Checking STX locked for cycle {cycle}");
        for i in 0..reward_blocks {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // only the first 2 reward blocks contain pox outputs, because there are 6 slots and only 4 are occuppied
            if i < 2 {
                assert_latest_was_pox(&mut peer)
                    .into_iter()
                    .filter(|addr| !addr.is_burn())
                    .for_each(|addr| {
                        rewarded.insert(addr);
                    });
            } else {
                assert_latest_was_burn(&mut peer);
            }
        }

        assert_eq!(rewarded.len(), 4);
        for stacker in stackers.iter() {
            assert!(
                rewarded.contains(stacker),
                "Reward cycle should include {stacker}"
            );
        }

        // now we should be back in a prepare phase
        info!("Checking we are in prepare phase");
        for _ in 0..burnchain.pox_constants.prepare_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }
    }

    // Advance to v3 unlock
    let target_height = burnchain.pox_constants.v3_unlock_height;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // Check that STX are not locked for 3 reward cycles after pox4 starts
    for _ in 0..3 {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking no stackers for cycle {cycle}");
        for _ in 0..burnchain.pox_constants.reward_cycle_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }

        info!("Checking that stackers have no STX locked after cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert_eq!(balances[0].amount_locked(), 0);
        assert_eq!(balances[1].amount_locked(), 0);
    }
}

// This test calls most pox-4 Clarity functions to check the existence of `start-cycle-id` and `end-cycle-id`
// in emitted pox events.
// In this set up, Steph is a solo stacker and invokes `stack-stx`, `stack-increase` and `stack-extend` functions
// Alice delegates to Bob via `delegate-stx`
// Bob as the delegate, invokes 'delegate-stack-stx' and 'stack-aggregation-commit-indexed'
#[test]
fn pox_4_check_cycle_id_range_in_print_events_pool() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let alice_pox_addr = pox_addr_from(&alice);

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = pox_addr_from(&bob);
    let bob_signing_key = Secp256k1PublicKey::from_private(&bob);
    let bob_pox_addr_val = Value::Tuple(bob_pox_addr.as_clarity_tuple().unwrap());

    // steph the solo stacker stacks stx so nakamoto signer set stays stacking.
    let steph_key = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph_key);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr_val =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());
    let steph_pox_addr = pox_addr_from(&steph_key);
    let steph_signing_key = Secp256k1PublicKey::from_private(&steph_key);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut alice_nonce = 0;
    let mut steph_nonce = 0;
    let mut bob_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_reward_cycle = reward_cycle + 1;

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let lock_period = 1;
    let block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap());

    // stack-stx
    let steph_stack_stx_nonce = steph_nonce;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let steph_stacking = make_pox_4_lockup(
        &steph_key,
        steph_stack_stx_nonce,
        min_ustx,
        &steph_pox_addr.clone(),
        lock_period,
        &steph_signing_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // stack-increase
    let steph_stack_increase_nonce = steph_nonce;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        lock_period,
        u128::MAX,
        1,
    );
    let steph_stack_increase = make_pox_4_stack_increase(
        &steph_key,
        steph_stack_increase_nonce,
        100,
        &steph_signing_key,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // stack-extend
    let steph_stack_extend_nonce = steph_nonce;
    let stack_extend_signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        1_u128,
        u128::MAX,
        1,
    );
    let steph_stack_extend = make_pox_4_extend(
        &steph_key,
        steph_stack_extend_nonce,
        steph_pox_addr,
        lock_period,
        steph_signing_key,
        Some(stack_extend_signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // alice delegates STX to bob
    let target_height = get_tip(peer.sortdb.as_ref()).block_height
        + (3 * pox_constants.reward_cycle_length as u64) // 3 cycles (next cycle + 2)
        + 1; // additional few blocks shouldn't matter to unlock-cycle
    let alice_delegate = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        min_ustx,
        bob_principal.clone(),
        Some(target_height as u128),
        Some(bob_pox_addr.clone()),
    );
    let alice_delegate_nonce = alice_nonce;
    alice_nonce += 1;

    let curr_height = get_tip(peer.sortdb.as_ref()).block_height;
    let bob_delegate_stack_nonce = bob_nonce;
    let bob_delegate_stack = make_pox_4_delegate_stack_stx(
        &bob,
        bob_nonce,
        alice_principal.clone(),
        min_ustx,
        bob_pox_addr.clone(),
        curr_height as u128,
        lock_period,
    );
    bob_nonce += 1;

    let bob_aggregation_commit_nonce = bob_nonce;
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        lock_period,
        u128::MAX,
        1,
    );
    let bob_aggregation_commit = make_pox_4_aggregation_commit_indexed(
        &bob,
        bob_aggregation_commit_nonce,
        &bob_pox_addr,
        next_reward_cycle,
        Some(signature),
        &bob_signing_key,
        u128::MAX,
        1,
    );
    bob_nonce += 1;

    latest_block = Some(peer.tenure_with_txs(
        &[
            steph_stacking,
            steph_stack_increase,
            steph_stack_extend,
            alice_delegate,
            bob_delegate_stack,
            bob_aggregation_commit,
        ],
        &mut coinbase_nonce,
    ));

    let tip = get_tip(peer.sortdb.as_ref());
    let tipId = StacksBlockId::new(&tip.consensus_hash, &tip.canonical_stacks_tip_hash);
    assert_eq!(tipId, latest_block.unwrap());

    let in_prepare_phase = burnchain.is_in_prepare_phase(tip.block_height);
    assert_eq!(in_prepare_phase, false);

    let blocks = observer.get_blocks();
    let mut steph_txs = HashMap::new();
    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == steph_address {
                    steph_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(steph_txs.len() as u64, 3);
    assert_eq!(alice_txs.len() as u64, 1);
    assert_eq!(bob_txs.len() as u64, 2);

    let steph_stack_stx_tx = &steph_txs.get(&steph_stack_stx_nonce);
    let steph_stack_extend_tx = &steph_txs.get(&steph_stack_extend_nonce);
    let steph_stack_increase_tx = &steph_txs.get(&steph_stack_increase_nonce);
    let bob_delegate_stack_stx_tx = &bob_txs.get(&bob_delegate_stack_nonce);
    let bob_aggregation_commit_tx = &bob_txs.get(&bob_aggregation_commit_nonce);
    let alice_delegate_tx = &alice_txs.get(&alice_delegate_nonce);

    // Check event for stack-stx tx
    let steph_stacking_tx_events = &steph_stack_stx_tx.unwrap().clone().events;
    assert_eq!(steph_stacking_tx_events.len() as u64, 2);
    let steph_stacking_tx_event = &steph_stacking_tx_events[0];
    let steph_stacking_op_data = HashMap::from([
        // matches the expected cycle, since we're not in a prepare phase
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(steph_stacking_tx_event, common_data, steph_stacking_op_data);

    // Check event for stack-increase tx
    let steph_stack_increase_tx_events = &steph_stack_increase_tx.unwrap().clone().events;
    assert_eq!(steph_stack_increase_tx_events.len() as u64, 2);
    let steph_stack_increase_tx_event = &steph_stack_increase_tx_events[0];
    let steph_stack_increase_op_data = HashMap::from([
        // `stack-increase` is in the same block as `stack-stx`, so we essentially want to be able to override the first event
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-increase".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10234866375000),
        locked: Value::UInt(5133625000),
        burnchain_unlock_height: Value::UInt(120),
    };
    check_pox_print_event(
        steph_stack_increase_tx_event,
        common_data,
        steph_stack_increase_op_data,
    );

    // Check event for stack-extend tx
    let steph_stack_extend_tx_events = &steph_stack_extend_tx.unwrap().clone().events;
    assert_eq!(steph_stack_extend_tx_events.len() as u64, 2);
    let steph_stack_extend_tx_event = &steph_stack_extend_tx_events[0];
    let steph_stacking_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period + 1)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-extend".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10234866374900),
        locked: Value::UInt(5133625100),
        burnchain_unlock_height: Value::UInt(120),
    };
    check_pox_print_event(
        steph_stack_extend_tx_event,
        common_data,
        steph_stacking_op_data,
    );

    // Check event for delegate-stx tx
    let alice_delegation_tx_events = &alice_delegate_tx.unwrap().clone().events;
    assert_eq!(alice_delegation_tx_events.len() as u64, 1);
    let alice_delegation_tx_event = &alice_delegation_tx_events[0];
    let alice_delegate_stx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + 2)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        alice_delegation_tx_event,
        common_data,
        alice_delegate_stx_op_data,
    );

    // Check event for delegate-stack-stx tx
    let bob_delegate_stack_stx_tx_events = &bob_delegate_stack_stx_tx.unwrap().clone().events;
    assert_eq!(bob_delegate_stack_stx_tx_events.len() as u64, 2);
    let bob_delegate_stack_stx_tx_event = &bob_delegate_stack_stx_tx_events[0];
    let bob_delegate_stack_stx_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_delegate_stack_stx_tx_event,
        common_data,
        bob_delegate_stack_stx_tx_op_data,
    );

    // Check event for aggregation_commit tx
    let bob_aggregation_commit_tx_events = &bob_aggregation_commit_tx.unwrap().clone().events;
    assert_eq!(bob_aggregation_commit_tx_events.len() as u64, 1);
    let bob_aggregation_commit_tx_event = &bob_aggregation_commit_tx_events[0];
    let bob_aggregation_commit_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + 1)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-aggregation-commit-indexed".to_string(),
        stacker: bob_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_aggregation_commit_tx_event,
        common_data,
        bob_aggregation_commit_tx_op_data,
    );
}

// This test calls most pox-4 Clarity functions to check the existence of `start-cycle-id` and `end-cycle-id`
// in emitted pox events. This tests for the correct offset in the prepare phase.
// In this set up, Steph is a solo stacker and invokes `stack-stx`, `stack-increase` and `stack-extend` functions
// Alice delegates to Bob via `delegate-stx`
// Bob as the delegate, invokes 'delegate-stack-stx' and 'stack-aggregation-commit-indexed'
#[test]
fn pox_4_check_cycle_id_range_in_print_events_pool_in_prepare_phase() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let alice_pox_addr = pox_addr_from(&alice);

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = pox_addr_from(&bob);
    let bob_signing_key = Secp256k1PublicKey::from_private(&bob);
    let bob_pox_addr_val = Value::Tuple(bob_pox_addr.as_clarity_tuple().unwrap());

    // steph the solo stacker stacks stx so nakamoto signer set stays stacking.
    let steph_key = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph_key);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr_val =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());
    let steph_pox_addr = pox_addr_from(&steph_key);
    let steph_signing_key = Secp256k1PublicKey::from_private(&steph_key);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut alice_nonce = 0;
    let mut steph_nonce = 0;
    let mut bob_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }
    // produce blocks until the we're in the prepare phase (first block of prepare-phase was mined, i.e. pox-set for next cycle determined)
    while !burnchain.is_in_prepare_phase(get_tip(peer.sortdb.as_ref()).block_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_reward_cycle = reward_cycle + 1;

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height,
    );

    let lock_period = 1;
    let block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap());

    // stack-stx
    let steph_stack_stx_nonce = steph_nonce;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let steph_stacking = make_pox_4_lockup(
        &steph_key,
        steph_stack_stx_nonce,
        min_ustx,
        &steph_pox_addr.clone(),
        lock_period,
        &steph_signing_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // stack-increase
    let steph_stack_increase_nonce = steph_nonce;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        lock_period,
        u128::MAX,
        1,
    );
    let steph_stack_increase = make_pox_4_stack_increase(
        &steph_key,
        steph_stack_increase_nonce,
        100,
        &steph_signing_key,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // stack-extend
    let steph_stack_extend_nonce = steph_nonce;
    let stack_extend_signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        1_u128,
        u128::MAX,
        1,
    );
    let steph_stack_extend = make_pox_4_extend(
        &steph_key,
        steph_stack_extend_nonce,
        steph_pox_addr.clone(),
        lock_period,
        steph_signing_key,
        Some(stack_extend_signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    // alice delegates STX to bob
    let target_height = get_tip(peer.sortdb.as_ref()).block_height
        + (3 * pox_constants.reward_cycle_length as u64) // 3 cycles (next cycle + 2)
        + 1; // additional few blocks shouldn't matter to unlock-cycle
    let alice_delegate = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        min_ustx,
        bob_principal.clone(),
        Some(target_height as u128),
        Some(bob_pox_addr.clone()),
    );
    let alice_delegate_nonce = alice_nonce;
    alice_nonce += 1;

    let curr_height = get_tip(peer.sortdb.as_ref()).block_height;
    let bob_delegate_stack_nonce = bob_nonce;
    let bob_delegate_stack = make_pox_4_delegate_stack_stx(
        &bob,
        bob_nonce,
        alice_principal.clone(),
        min_ustx,
        bob_pox_addr.clone(),
        curr_height as u128,
        lock_period,
    );
    bob_nonce += 1;

    let bob_aggregation_commit_nonce = bob_nonce;
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        lock_period,
        u128::MAX,
        1,
    );
    let bob_aggregation_commit = make_pox_4_aggregation_commit_indexed(
        &bob,
        bob_aggregation_commit_nonce,
        &bob_pox_addr,
        next_reward_cycle,
        Some(signature),
        &bob_signing_key,
        u128::MAX,
        1,
    );
    bob_nonce += 1;

    latest_block = Some(peer.tenure_with_txs(
        &[
            steph_stacking,
            steph_stack_increase,
            steph_stack_extend,
            alice_delegate,
            bob_delegate_stack,
            bob_aggregation_commit,
        ],
        &mut coinbase_nonce,
    ));

    let tip = get_tip(peer.sortdb.as_ref());
    let tipId = StacksBlockId::new(&tip.consensus_hash, &tip.canonical_stacks_tip_hash);
    assert_eq!(tipId, latest_block.unwrap());

    let in_prepare_phase = burnchain.is_in_prepare_phase(tip.block_height);
    assert_eq!(in_prepare_phase, true);

    let blocks = observer.get_blocks();
    let mut steph_txs = HashMap::new();
    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == steph_address {
                    steph_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(steph_txs.len() as u64, 3);
    assert_eq!(alice_txs.len() as u64, 1);
    assert_eq!(bob_txs.len() as u64, 2);

    let steph_stack_stx_tx = &steph_txs.get(&steph_stack_stx_nonce);
    let steph_stack_extend_tx = &steph_txs.get(&steph_stack_extend_nonce);
    let steph_stack_increase_tx = &steph_txs.get(&steph_stack_increase_nonce);
    let bob_delegate_stack_stx_tx = &bob_txs.get(&bob_delegate_stack_nonce);
    let bob_aggregation_commit_tx = &bob_txs.get(&bob_aggregation_commit_nonce);
    let alice_delegate_tx = &alice_txs.get(&alice_delegate_nonce);

    // Check event for stack-stx tx
    let steph_stacking_tx_events = &steph_stack_stx_tx.unwrap().clone().events;
    assert_eq!(steph_stacking_tx_events.len() as u64, 2);
    let steph_stacking_tx_event = &steph_stacking_tx_events[0];
    let steph_stacking_op_data = HashMap::from([
        // +1, since we're in a prepare phase
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(steph_stacking_tx_event, common_data, steph_stacking_op_data);

    // Check event for stack-increase tx
    let steph_stack_increase_tx_events = &steph_stack_increase_tx.unwrap().clone().events;
    assert_eq!(steph_stack_increase_tx_events.len() as u64, 2);
    let steph_stack_increase_tx_event = &steph_stack_increase_tx_events[0];
    let steph_stack_increase_op_data = HashMap::from([
        // `stack-increase` is in the same block as `stack-stx`, so we essentially want to be able to override the first event
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-increase".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10234866000000),
        locked: Value::UInt(5134000000),
        burnchain_unlock_height: Value::UInt(120),
    };
    check_pox_print_event(
        steph_stack_increase_tx_event,
        common_data,
        steph_stack_increase_op_data,
    );

    // Check event for stack-extend tx
    let steph_stack_extend_tx_events = &steph_stack_extend_tx.unwrap().clone().events;
    assert_eq!(steph_stack_extend_tx_events.len() as u64, 2);
    let steph_stack_extend_tx_event = &steph_stack_extend_tx_events[0];
    let steph_stacking_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period + 1)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-extend".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(10234865999900),
        locked: Value::UInt(5134000100),
        burnchain_unlock_height: Value::UInt(120),
    };
    check_pox_print_event(
        steph_stack_extend_tx_event,
        common_data,
        steph_stacking_op_data,
    );

    // Check event for delegate-stx tx
    let alice_delegation_tx_events = &alice_delegate_tx.unwrap().clone().events;
    assert_eq!(alice_delegation_tx_events.len() as u64, 1);
    let alice_delegation_tx_event = &alice_delegation_tx_events[0];
    let alice_delegate_stx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(
                burnchain
                    .block_height_to_reward_cycle(target_height)
                    .unwrap() as u128,
            ))
            .unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        alice_delegation_tx_event,
        common_data,
        alice_delegate_stx_op_data,
    );

    // Check event for delegate-stack-stx tx
    let bob_delegate_stack_stx_tx_events = &bob_delegate_stack_stx_tx.unwrap().clone().events;
    assert_eq!(bob_delegate_stack_stx_tx_events.len() as u64, 2);
    let bob_delegate_stack_stx_tx_event = &bob_delegate_stack_stx_tx_events[0];
    let bob_delegate_stack_stx_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_delegate_stack_stx_tx_event,
        common_data,
        bob_delegate_stack_stx_tx_op_data,
    );

    // Check event for aggregation_commit tx
    let bob_aggregation_commit_tx_events = &bob_aggregation_commit_tx.unwrap().clone().events;
    assert_eq!(bob_aggregation_commit_tx_events.len() as u64, 1);
    let bob_aggregation_commit_tx_event = &bob_aggregation_commit_tx_events[0];
    let bob_aggregation_commit_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + 1)).unwrap(), // end is same as start, which means this missed the pox-set
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-aggregation-commit-indexed".to_string(),
        stacker: bob_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_aggregation_commit_tx_event,
        common_data,
        bob_aggregation_commit_tx_op_data,
    );

    with_sortdb(&mut peer, |chainstate, sortdb| {
        let mut check_cycle = next_reward_cycle as u64;
        let reward_set = chainstate
            .get_reward_addresses_in_cycle(&burnchain, sortdb, check_cycle, &latest_block.unwrap())
            .unwrap();
        assert_eq!(reward_set.len(), 2);
        assert_eq!(reward_set[0].stacker.as_ref(), Some(&steph_principal));
        assert_eq!(reward_set[0].reward_address, steph_pox_addr);
        assert_eq!(reward_set[0].amount_stacked, min_ustx + 100);
        assert_eq!(reward_set[1].stacker, None);
        assert_eq!(reward_set[1].reward_address, bob_pox_addr);
        assert_eq!(reward_set[1].amount_stacked, min_ustx);

        check_cycle += 1;
        let reward_set = chainstate
            .get_reward_addresses_in_cycle(&burnchain, sortdb, check_cycle, &latest_block.unwrap())
            .unwrap();
        assert_eq!(reward_set.len(), 1);
        assert_eq!(reward_set[0].stacker.as_ref(), Some(&steph_principal));
        assert_eq!(reward_set[0].reward_address, steph_pox_addr);
        assert_eq!(reward_set[0].amount_stacked, min_ustx + 100);

        check_cycle += 1;
        let reward_set = chainstate
            .get_reward_addresses_in_cycle(&burnchain, sortdb, check_cycle, &latest_block.unwrap())
            .unwrap();
        assert!(reward_set.is_empty());
    });
}

// This test calls most pox-4 Clarity functions to check the existence of `start-cycle-id` and `end-cycle-id`
// in emitted pox events. This tests for the correct offset in the prepare phase, when skipping a cycle for commit.
// In this set up, Alice delegates to Bob via `delegate-stx`
// Bob as the delegate, invokes 'delegate-stack-stx' and 'stack-aggregation-commit-indexed'
// for one after the next cycle, so there should be no prepare-offset in the commit start.
#[test]
fn pox_4_check_cycle_id_range_in_print_events_pool_in_prepare_phase_skip_cycle() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let alice_pox_addr = pox_addr_from(&alice);

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = pox_addr_from(&bob);
    let bob_signing_key = Secp256k1PublicKey::from_private(&bob);
    let bob_pox_addr_val = Value::Tuple(bob_pox_addr.as_clarity_tuple().unwrap());

    let mut alice_nonce = 0;
    let mut bob_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }
    // produce blocks until the we're in the prepare phase (first block of prepare-phase was mined, i.e. pox-set for next cycle determined)
    while !burnchain.is_in_prepare_phase(get_tip(peer.sortdb.as_ref()).block_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_reward_cycle = reward_cycle + 1;

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let lock_period = 2;
    let block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap());

    // alice delegates STX to bob
    let target_height = get_tip(peer.sortdb.as_ref()).block_height
        + (3 * pox_constants.reward_cycle_length as u64) // 3 cycles (next cycle + 2)
        + 1; // additional few blocks shouldn't matter to unlock-cycle
    let alice_delegate = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        min_ustx,
        bob_principal.clone(),
        Some(target_height as u128),
        Some(bob_pox_addr.clone()),
    );
    let alice_delegate_nonce = alice_nonce;
    alice_nonce += 1;

    let curr_height = get_tip(peer.sortdb.as_ref()).block_height;
    let bob_delegate_stack_nonce = bob_nonce;
    let bob_delegate_stack = make_pox_4_delegate_stack_stx(
        &bob,
        bob_nonce,
        alice_principal.clone(),
        min_ustx,
        bob_pox_addr.clone(),
        curr_height as u128,
        lock_period,
    );
    bob_nonce += 1;

    let target_cycle = next_reward_cycle + 1;
    let bob_aggregation_commit_nonce = bob_nonce;
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        target_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        1,
    );
    let bob_aggregation_commit = make_pox_4_aggregation_commit_indexed(
        &bob,
        bob_aggregation_commit_nonce,
        &bob_pox_addr,
        target_cycle,
        Some(signature),
        &bob_signing_key,
        u128::MAX,
        1,
    );
    bob_nonce += 1;

    latest_block = Some(peer.tenure_with_txs(
        &[alice_delegate, bob_delegate_stack, bob_aggregation_commit],
        &mut coinbase_nonce,
    ));

    let tip = get_tip(peer.sortdb.as_ref());
    let tipId = StacksBlockId::new(&tip.consensus_hash, &tip.canonical_stacks_tip_hash);
    assert_eq!(tipId, latest_block.unwrap());

    let in_prepare_phase = burnchain.is_in_prepare_phase(tip.block_height);
    assert_eq!(in_prepare_phase, true);

    let blocks = observer.get_blocks();
    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len() as u64, 1);
    assert_eq!(bob_txs.len() as u64, 2);

    let bob_delegate_stack_stx_tx = &bob_txs.get(&bob_delegate_stack_nonce);
    let bob_aggregation_commit_tx = &bob_txs.get(&bob_aggregation_commit_nonce);
    let alice_delegate_tx = &alice_txs.get(&alice_delegate_nonce);

    // Check event for delegate-stx tx
    let alice_delegation_tx_events = &alice_delegate_tx.unwrap().clone().events;
    assert_eq!(alice_delegation_tx_events.len() as u64, 1);
    let alice_delegation_tx_event = &alice_delegation_tx_events[0];
    let alice_delegate_stx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(
                burnchain
                    .block_height_to_reward_cycle(target_height)
                    .unwrap() as u128,
            ))
            .unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        alice_delegation_tx_event,
        common_data,
        alice_delegate_stx_op_data,
    );

    // Check event for delegate-stack-stx tx
    let bob_delegate_stack_stx_tx_events = &bob_delegate_stack_stx_tx.unwrap().clone().events;
    assert_eq!(bob_delegate_stack_stx_tx_events.len() as u64, 2);
    let bob_delegate_stack_stx_tx_event = &bob_delegate_stack_stx_tx_events[0];
    let bob_delegate_stack_stx_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_reward_cycle + 1)),
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_reward_cycle + lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_delegate_stack_stx_tx_event,
        common_data,
        bob_delegate_stack_stx_tx_op_data,
    );

    // Check event for aggregation_commit tx
    let bob_aggregation_commit_tx_events = &bob_aggregation_commit_tx.unwrap().clone().events;
    assert_eq!(bob_aggregation_commit_tx_events.len() as u64, 1);
    let bob_aggregation_commit_tx_event = &bob_aggregation_commit_tx_events[0];
    let bob_aggregation_commit_tx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(target_cycle)), // no prepare-offset, since target is not next cycle
        (
            "end-cycle-id",
            Value::some(Value::UInt(target_cycle + 1)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-aggregation-commit-indexed".to_string(),
        stacker: bob_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        bob_aggregation_commit_tx_event,
        common_data,
        bob_aggregation_commit_tx_op_data,
    );
}

// This test calls some pox-4 Clarity functions to check the existence of `start-cycle-id` and `end-cycle-id`
// in emitted pox events. This test checks that the prepare-offset isn't used before its time.
// In this setup, Steph solo stacks in the prepare phase
#[test]
fn pox_4_check_cycle_id_range_in_print_events_before_prepare_phase() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    let steph_key = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph_key);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr_val =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());
    let steph_pox_addr = pox_addr_from(&steph_key);
    let steph_signing_key = Secp256k1PublicKey::from_private(&steph_key);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut steph_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }
    // produce blocks until the we're 1 before the prepare phase (first block of prepare-phase not yet mined, whatever txs we create now won't be included in the reward set)
    while !burnchain.is_in_prepare_phase(get_tip(peer.sortdb.as_ref()).block_height + 1) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    let steph_balance = get_balance(&mut peer, &steph_principal);

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap()) * 120 / 100; // * 1.2

    // stack-stx
    let steph_lock_period = 2;
    let current_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_cycle = current_cycle + 1;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        current_cycle,
        &Pox4SignatureTopic::StackStx,
        steph_lock_period,
        u128::MAX,
        1,
    );
    let steph_stacking = make_pox_4_lockup(
        &steph_key,
        steph_nonce,
        min_ustx,
        &steph_pox_addr.clone(),
        steph_lock_period,
        &steph_signing_key,
        get_tip(peer.sortdb.as_ref()).block_height,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    latest_block = Some(peer.tenure_with_txs(&[steph_stacking.clone()], &mut coinbase_nonce));

    let txs: HashMap<_, _> = observer
        .get_blocks()
        .into_iter()
        .flat_map(|b| b.receipts)
        .filter_map(|r| match r.transaction {
            TransactionOrigin::Stacks(ref t) => Some((t.txid(), r.clone())),
            _ => None,
        })
        .collect();

    // Check event for stack-stx tx
    let steph_stacking_receipt = txs.get(&steph_stacking.txid()).unwrap().clone();
    assert_eq!(steph_stacking_receipt.events.len(), 2);
    let steph_stacking_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_cycle + 1)), // +1 because steph stacked in the block before the prepare phase (too late)
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_cycle + steph_lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(steph_balance),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        &steph_stacking_receipt.events[0],
        common_data,
        steph_stacking_op_data,
    );
}

// This test calls some pox-4 Clarity functions to check the existence of `start-cycle-id` and `end-cycle-id`
// in emitted pox events. This test checks that the prepare-offset is used for the pox-anchor-block.
// In this setup, Steph solo stacks in the prepare phase
#[test]
fn pox_4_check_cycle_id_range_in_print_events_in_prepare_phase() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    let steph_key = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph_key);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr_val =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());
    let steph_pox_addr = pox_addr_from(&steph_key);
    let steph_signing_key = Secp256k1PublicKey::from_private(&steph_key);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut steph_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }
    // produce blocks until the we're in the prepare phase (first block of prepare-phase was mined, i.e. pox-set for next cycle determined)
    while !burnchain.is_in_prepare_phase(get_tip(peer.sortdb.as_ref()).block_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    let steph_balance = get_balance(&mut peer, &steph_principal);

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap()) * 120 / 100; // * 1.2

    // stack-stx
    let steph_lock_period = 2;
    let current_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_cycle = current_cycle + 1;
    let signature = make_signer_key_signature(
        &steph_pox_addr,
        &steph_key,
        current_cycle,
        &Pox4SignatureTopic::StackStx,
        steph_lock_period,
        u128::MAX,
        1,
    );
    let steph_stacking = make_pox_4_lockup(
        &steph_key,
        steph_nonce,
        min_ustx,
        &steph_pox_addr.clone(),
        steph_lock_period,
        &steph_signing_key,
        get_tip(peer.sortdb.as_ref()).block_height,
        Some(signature),
        u128::MAX,
        1,
    );
    steph_nonce += 1;

    latest_block = Some(peer.tenure_with_txs(&[steph_stacking.clone()], &mut coinbase_nonce));

    let txs: HashMap<_, _> = observer
        .get_blocks()
        .into_iter()
        .flat_map(|b| b.receipts)
        .filter_map(|r| match r.transaction {
            TransactionOrigin::Stacks(ref t) => Some((t.txid(), r.clone())),
            _ => None,
        })
        .collect();

    // Check event for stack-stx tx
    let steph_stacking_receipt = txs.get(&steph_stacking.txid()).unwrap().clone();
    assert_eq!(steph_stacking_receipt.events.len(), 2);
    let steph_stacking_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_cycle + 1)), // +1 because steph stacked during the prepare phase
        (
            "end-cycle-id",
            Value::some(Value::UInt(next_cycle + steph_lock_period)).unwrap(),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: steph_principal.clone().into(),
        balance: Value::UInt(steph_balance),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        &steph_stacking_receipt.events[0],
        common_data,
        steph_stacking_op_data,
    );
}

// test that delegate-stack-increase calls emit and event
#[test]
fn pox_4_delegate_stack_increase_events() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    let alice_key = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice_key);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let alice_pox_addr = pox_addr_from(&alice_key);

    let bob_key = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob_key);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = pox_addr_from(&bob_key);
    let bob_pox_addr_val = Value::Tuple(bob_pox_addr.as_clarity_tuple().unwrap());

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    // alice delegate to bob
    let next_cycle = get_current_reward_cycle(&peer, &burnchain) + 1;
    let amount = 100_000_000;
    let alice_delegate =
        make_pox_4_delegate_stx(&alice_key, 0, amount, bob_principal.clone(), None, None);

    // bob delegate-stack-stx
    let bob_delegate_stack_stx = make_pox_4_delegate_stack_stx(
        &bob_key,
        0,
        alice_principal.clone(),
        amount / 2,
        bob_pox_addr.clone(),
        get_tip(peer.sortdb.as_ref()).block_height as u128,
        2,
    );

    // bob delegate-stack-increase
    let bob_delegate_stack_increase = make_pox_4_delegate_stack_increase(
        &bob_key,
        1,
        &alice_principal,
        bob_pox_addr.clone(),
        amount / 2,
    );

    latest_block = Some(peer.tenure_with_txs(
        &[
            alice_delegate.clone(),
            bob_delegate_stack_stx.clone(),
            bob_delegate_stack_increase.clone(),
        ],
        &mut coinbase_nonce,
    ));

    let txs: HashMap<_, _> = observer
        .get_blocks()
        .into_iter()
        .flat_map(|b| b.receipts)
        .filter_map(|r| match r.transaction {
            TransactionOrigin::Stacks(ref t) => Some((t.txid(), r.clone())),
            _ => None,
        })
        .collect();

    let bob_delegate_stack_increase_tx = txs
        .get(&bob_delegate_stack_increase.txid())
        .unwrap()
        .clone();

    // Check event for delegate-stack-increase tx
    let bob_delegate_stack_increase_tx_events = &bob_delegate_stack_increase_tx.events;
    assert_eq!(bob_delegate_stack_increase_tx_events.len() as u64, 2);
    let bob_delegate_stack_increase_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_cycle)),
        ("end-cycle-id", Optional(OptionalData { data: None })),
        ("increase-by", Value::UInt(amount / 2)),
        ("pox-addr", bob_pox_addr_val.clone()),
        ("delegator", alice_principal.clone().into()),
    ]);
}

// test that revoke-delegate-stx calls emit an event and
// test that revoke-delegate-stx is only successfull if user has delegated.
#[test]
fn pox_4_revoke_delegate_stx_events() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());

    // steph the solo stacker stacks stx so nakamoto signer set stays stacking.
    let steph = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());

    let steph_signing_key = Secp256k1PublicKey::from_private(&steph);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut alice_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );
    let block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let current_cycle = get_current_reward_cycle(&peer, &burnchain);
    let next_cycle = current_cycle + 1;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap());

    let steph_stacking = make_pox_4_contract_call(
        &steph,
        0,
        "stack-stx",
        vec![
            Value::UInt(min_ustx),
            steph_pox_addr,
            Value::UInt(block_height as u128),
            Value::UInt(12),
            steph_key_val,
        ],
    );

    // alice delegates 100 STX to Bob
    let alice_delegation_amount = 100_000_000;
    let alice_delegate = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        alice_delegation_amount,
        bob_principal,
        None,
        None,
    );
    let alice_delegate_nonce = alice_nonce;
    alice_nonce += 1;

    let alice_revoke = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_nonce = alice_nonce;
    alice_nonce += 1;

    let alice_revoke_2 = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_2_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(
        &[steph_stacking, alice_delegate, alice_revoke, alice_revoke_2],
        &mut coinbase_nonce,
    );

    // check delegate with expiry

    let target_height = get_tip(peer.sortdb.as_ref()).block_height + 10;
    let alice_delegate_2 = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        alice_delegation_amount,
        PrincipalData::from(bob_address.clone()),
        Some(target_height as u128),
        None,
    );
    let alice_delegate_2_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(&[alice_delegate_2], &mut coinbase_nonce);

    // produce blocks until delegation expired
    while get_tip(peer.sortdb.as_ref()).block_height <= target_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_revoke_3 = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_3_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(&[alice_revoke_3], &mut coinbase_nonce);

    let blocks = observer.get_blocks();
    let mut alice_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }
    assert_eq!(alice_txs.len() as u64, 5);

    let first_delegate_tx = &alice_txs.get(&alice_delegate_nonce);
    assert_eq!(
        first_delegate_tx.unwrap().clone().result,
        Value::okay_true()
    );

    // check event for first revoke delegation tx
    let revoke_delegation_tx_events = &alice_txs.get(&alice_revoke_nonce).unwrap().clone().events;
    assert_eq!(revoke_delegation_tx_events.len() as u64, 1);
    let revoke_delegation_tx_event = &revoke_delegation_tx_events[0];
    let revoke_delegate_stx_op_data = HashMap::from([
        ("start-cycle-id", Value::UInt(next_cycle)),
        ("end-cycle-id", Optional(OptionalData { data: None })),
        (
            "delegate-to",
            Value::Principal(PrincipalData::from(bob_address.clone())),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "revoke-delegate-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        revoke_delegation_tx_event,
        common_data,
        revoke_delegate_stx_op_data,
    );

    // second revoke transaction should fail
    assert_eq!(
        &alice_txs[&alice_revoke_2_nonce].result.to_string(),
        "(err 34)"
    );

    // second delegate transaction should succeed
    assert_eq!(
        &alice_txs[&alice_delegate_2_nonce].result.to_string(),
        "(ok true)"
    );
    // third revoke transaction should fail
    assert_eq!(
        &alice_txs[&alice_revoke_3_nonce].result.to_string(),
        "(err 34)"
    );
}

fn verify_signer_key_sig(
    signature: &[u8],
    signing_key: &Secp256k1PublicKey,
    pox_addr: &PoxAddress,
    peer: &mut TestPeer,
    latest_block: &StacksBlockId,
    reward_cycle: u128,
    period: u128,
    topic: &Pox4SignatureTopic,
    amount: u128,
    max_amount: u128,
    auth_id: u128,
) -> Value {
    let result: Value = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
        chainstate
            .with_read_only_clarity_tx(&sortdb.index_handle_at_tip(), &latest_block, |clarity_tx| {
                clarity_tx
                    .with_readonly_clarity_env(
                        false,
                        0x80000000,
                        ClarityVersion::Clarity2,
                        PrincipalData::Standard(StandardPrincipalData::transient()),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| {
                            let program = format!(
                                "(verify-signer-key-sig {} u{} \"{}\" u{} (some 0x{}) 0x{} u{} u{} u{})",
                                Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap()),
                                reward_cycle,
                                topic.get_name_str(),
                                period,
                                to_hex(&signature),
                                signing_key.to_hex(),
                                amount,
                                max_amount,
                                auth_id
                            );
                            env.eval_read_only(&boot_code_id("pox-4", false), &program)
                        },
                    )
                    .unwrap()
            })
            .unwrap()
    });
    result
}

#[test]
fn verify_signer_key_signatures() {
    let (epochs, pox_constants) = make_test_epochs_pox(false);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_public_key = StacksPublicKey::from_private(&bob);

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let expected_error = Value::error(Value::Int(35)).unwrap();

    let alice_pox_addr =
        PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, alice_address.bytes.clone());
    let bob_pox_addr = PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, bob_address.bytes);

    let period = 1_u128;

    let topic = Pox4SignatureTopic::StackStx;

    // Test 1: invalid reward cycle used in signature

    let last_reward_cycle = reward_cycle - 1;
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        last_reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );

    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        u128::MAX,
        1,
    );
    assert_eq!(result, expected_error);

    // Test 2: Invalid pox-addr used in signature

    let signature = make_signer_key_signature(
        &alice_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );

    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr, // wrong pox-addr
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        u128::MAX,
        1,
    );

    assert_eq!(result, expected_error);

    // Test 3: Invalid signer key used in signature

    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &alice,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );

    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key, // different key
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        u128::MAX,
        1,
    );

    assert_eq!(result, expected_error);

    // Test 4: invalid topic
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        period,
        u128::MAX,
        1,
    );
    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &Pox4SignatureTopic::StackExtend, // different
        1,
        u128::MAX,
        1,
    );

    assert_eq!(result, expected_error);

    // Test 5: invalid period
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );
    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period + 1, // different
        &topic,
        1,
        u128::MAX,
        1,
    );

    assert_eq!(result, expected_error);

    // Test incorrect auth-id
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );
    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        u128::MAX,
        2, // different
    );
    assert_eq!(result, expected_error);

    // Test incorrect max-amount
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );
    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        11111, // different
        1,
    );
    assert_eq!(result, expected_error);

    // Test amount > max-amount
    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        4, // less than max to invalidate `amount`
        1,
    );
    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        5, // different
        4, // less than amount
        1,
    );
    // Different error code
    assert_eq!(result, Value::error(Value::Int(38)).unwrap());

    // Test using a valid signature

    let signature = make_signer_key_signature(
        &bob_pox_addr,
        &bob,
        reward_cycle,
        &topic,
        period,
        u128::MAX,
        1,
    );

    let result = verify_signer_key_sig(
        &signature,
        &bob_public_key,
        &bob_pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        period,
        &topic,
        1,
        u128::MAX,
        1,
    );

    assert_eq!(result, Value::okay_true());
}

#[apply(nakamoto_cases)]
fn stack_stx_verify_signer_sig(use_nakamoto: bool) {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let stacker_addr = key_to_stacks_addr(&stacker_key);
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let pox_addr = pox_addr_from(&stacker_key);

    let second_stacker = &keys[2];
    let second_stacker_addr = key_to_stacks_addr(second_stacker);
    let second_stacker_pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        second_stacker_addr.bytes.clone(),
    );

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let topic = Pox4SignatureTopic::StackStx;

    // Test 1: invalid reward cycle
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle - 1,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_cycle_nonce = stacker_nonce;
    let invalid_cycle_stack = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // test 2: invalid pox addr
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &second_stacker_pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_pox_addr_nonce = stacker_nonce;
    let invalid_pox_addr_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Test 3: invalid key used to sign
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &second_stacker,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_key_nonce = stacker_nonce;
    let invalid_key_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Test 4: invalid topic
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend, // wrong topic
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_topic_nonce = stacker_nonce;
    let invalid_topic_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Test 5: invalid period
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period + 1, // wrong period
        u128::MAX,
        1,
    );
    let invalid_period_nonce = stacker_nonce;
    let invalid_period_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Test invalid auth-id
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_auth_id_nonce = stacker_nonce;
    let invalid_auth_id_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        2, // wrong auth-id
    );

    // Test invalid amount
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        min_ustx.saturating_sub(1),
        1,
    );
    let invalid_amount_nonce = stacker_nonce;
    let invalid_amount_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        min_ustx.saturating_sub(1),
        1,
    );

    // Test invalid max-amount
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX.saturating_sub(1),
        1,
    );
    let invalid_max_amount_nonce = stacker_nonce;
    let invalid_max_amount_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX, // different than signature
        1,
    );

    // Test: valid signature
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let valid_nonce = stacker_nonce;
    let valid_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature.clone()),
        u128::MAX,
        1,
    );

    let txs = vec![
        invalid_cycle_stack,
        invalid_pox_addr_tx,
        invalid_key_tx,
        invalid_topic_tx,
        invalid_period_tx,
        invalid_auth_id_tx,
        invalid_amount_tx,
        invalid_max_amount_tx,
        valid_tx,
    ];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let stacker_txs = get_last_block_sender_transactions(&observer, stacker_addr);
    let expected_error = Value::error(Value::Int(35)).unwrap();

    assert_eq!(stacker_txs.len(), (valid_nonce + 1) as usize);
    let tx_result =
        |nonce: u64| -> Value { stacker_txs.get(nonce as usize).unwrap().result.clone() };
    assert_eq!(tx_result(invalid_cycle_nonce), expected_error);
    assert_eq!(tx_result(invalid_pox_addr_nonce), expected_error);
    assert_eq!(tx_result(invalid_key_nonce), expected_error);
    assert_eq!(tx_result(invalid_period_nonce), expected_error);
    assert_eq!(tx_result(invalid_topic_nonce), expected_error);
    assert_eq!(tx_result(invalid_auth_id_nonce), expected_error);
    assert_eq!(tx_result(invalid_max_amount_nonce), expected_error);
    assert_eq!(
        tx_result(invalid_amount_nonce),
        Value::error(Value::Int(38)).unwrap()
    );

    // valid tx should succeed
    tx_result(valid_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");

    // Ensure that the used signature cannot be re-used
    let result = verify_signer_key_sig(
        &signature,
        &signer_public_key,
        &pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        lock_period,
        &topic,
        min_ustx,
        u128::MAX,
        1,
    );
    let expected_error = Value::error(Value::Int(39)).unwrap();
    assert_eq!(result, expected_error);

    // Ensure the authorization is stored as used
    let entry = get_signer_key_authorization_used_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        reward_cycle.try_into().unwrap(),
        &topic,
        lock_period,
        &signer_public_key,
        u128::MAX,
        1,
    );
}

#[test]
fn stack_extend_verify_sig() {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), false);

    let mut coinbase_nonce = coinbase_nonce;

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let stacker_addr = key_to_stacks_addr(&stacker_key);
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let pox_addr = pox_addr_from(&signer_key);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let topic = Pox4SignatureTopic::StackExtend;

    // Setup: stack-stx
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let stack_nonce = stacker_nonce;
    let stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // We need a new signer-key for the extend tx
    let signer_key = Secp256k1PrivateKey::new();
    let signer_public_key = StacksPublicKey::from_private(&signer_key);

    // Test 1: invalid reward cycle
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle - 1,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    stacker_nonce += 1;
    let invalid_cycle_nonce = stacker_nonce;
    let invalid_cycle_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature),
        u128::MAX,
        1,
    );

    // Test 2: invalid pox-addr
    stacker_nonce += 1;
    let other_pox_addr = pox_addr_from(&Secp256k1PrivateKey::new());
    let signature = make_signer_key_signature(
        &other_pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_pox_addr_nonce = stacker_nonce;
    let invalid_pox_addr_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature),
        u128::MAX,
        1,
    );

    // Test 3: invalid key used to sign
    stacker_nonce += 1;
    let other_key = Secp256k1PrivateKey::new();
    let signature = make_signer_key_signature(
        &pox_addr,
        &other_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_key_nonce = stacker_nonce;
    let invalid_key_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature),
        u128::MAX,
        1,
    );

    // Test invalid auth-id
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_auth_id_nonce = stacker_nonce;
    let invalid_auth_id_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature),
        u128::MAX,
        2, // wrong auth-id
    );

    // Test invalid max-amount
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX.saturating_sub(1),
        1,
    );
    let invalid_max_amount_nonce = stacker_nonce;
    let invalid_max_amount_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature),
        u128::MAX, // different than signature
        1,
    );

    // Test: valid stack-extend
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let valid_nonce = stacker_nonce;
    let valid_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        Some(signature.clone()),
        u128::MAX,
        1,
    );

    let latest_block = peer.tenure_with_txs(
        &[
            stack_tx,
            invalid_cycle_tx,
            invalid_pox_addr_tx,
            invalid_key_tx,
            invalid_auth_id_tx,
            invalid_max_amount_tx,
            valid_tx,
        ],
        &mut coinbase_nonce,
    );

    let stacker_txs = get_last_block_sender_transactions(&observer, stacker_addr);

    let tx_result =
        |nonce: u64| -> Value { stacker_txs.get(nonce as usize).unwrap().result.clone() };

    let expected_error = Value::error(Value::Int(35)).unwrap();
    tx_result(stack_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
    assert_eq!(tx_result(invalid_cycle_nonce), expected_error);
    assert_eq!(tx_result(invalid_pox_addr_nonce), expected_error);
    assert_eq!(tx_result(invalid_key_nonce), expected_error);
    assert_eq!(tx_result(invalid_auth_id_nonce), expected_error);
    assert_eq!(tx_result(invalid_max_amount_nonce), expected_error);

    // valid tx should succeed
    tx_result(valid_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");

    // Ensure that the used signature cannot be re-used
    let result = verify_signer_key_sig(
        &signature,
        &signer_public_key,
        &pox_addr,
        &mut peer,
        &latest_block,
        reward_cycle,
        lock_period,
        &topic,
        min_ustx,
        u128::MAX,
        1,
    );
    let expected_error = Value::error(Value::Int(39)).unwrap();
    assert_eq!(result, expected_error);

    // Ensure the authorization is stored as used
    let entry = get_signer_key_authorization_used_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        reward_cycle.try_into().unwrap(),
        &topic,
        lock_period,
        &signer_public_key,
        u128::MAX,
        1,
    );
}

#[test]
/// Tests for verifying signatures in `stack-aggregation-commit`
fn stack_agg_commit_verify_sig() {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), false);

    let mut coinbase_nonce = coinbase_nonce;

    let mut delegate_nonce = 0;
    let stacker_nonce = 0;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    let stacker_key = &keys[0];
    let stacker_addr = PrincipalData::from(key_to_stacks_addr(&stacker_key));

    let signer_sk = &keys[1];
    let signer_pk = StacksPublicKey::from_private(signer_sk);

    let delegate_key = &keys[2];
    let delegate_addr = key_to_stacks_addr(&delegate_key);

    let pox_addr = pox_addr_from(&delegate_key);

    let reward_cycle = burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap() as u128;
    let next_reward_cycle = reward_cycle + 1;

    // Setup: delegate-stx and delegate-stack-stx

    let delegate_tx = make_pox_4_delegate_stx(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        delegate_addr.clone().into(),
        None,
        None,
    );

    let delegate_stack_stx_nonce = delegate_nonce;
    let delegate_stack_stx_tx = make_pox_4_delegate_stack_stx(
        &delegate_key,
        delegate_nonce,
        stacker_addr,
        min_ustx,
        pox_addr.clone(),
        block_height.into(),
        lock_period,
    );

    let topic = Pox4SignatureTopic::AggregationCommit;

    // Test 1: invalid reward cycle
    delegate_nonce += 1;
    let next_reward_cycle = reward_cycle + 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle, // wrong cycle
        &topic,
        1_u128,
        u128::MAX,
        1,
    );
    let invalid_cycle_nonce = delegate_nonce;
    let invalid_cycle_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    // Test 2: invalid pox addr
    delegate_nonce += 1;
    let other_pox_addr = pox_addr_from(&Secp256k1PrivateKey::new());
    let signature = make_signer_key_signature(
        &other_pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1_u128,
        u128::MAX,
        1,
    );
    let invalid_pox_addr_nonce = delegate_nonce;
    let invalid_pox_addr_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    // Test 3: invalid private key
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &delegate_key,
        next_reward_cycle,
        &topic,
        1_u128,
        u128::MAX,
        1,
    );
    let invalid_key_nonce = delegate_nonce;
    let invalid_key_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    // Test 4: invalid period in signature
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        2_u128, // wrong period
        u128::MAX,
        1,
    );
    let invalid_period_nonce = delegate_nonce;
    let invalid_period_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    // Test 5: invalid topic in signature
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &Pox4SignatureTopic::StackStx, // wrong topic
        1_u128,
        u128::MAX,
        1,
    );
    let invalid_topic_nonce = delegate_nonce;
    let invalid_topic_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    // Test using incorrect auth-id
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1_u128,
        u128::MAX,
        2, // wrong auth-id
    );
    let invalid_auth_id_nonce = delegate_nonce;
    let invalid_auth_id_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1, // different auth-id
    );

    // Test incorrect max-amount
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1_u128,
        u128::MAX,
        1,
    );
    let invalid_max_amount_nonce = delegate_nonce;
    let invalid_max_amount_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        u128::MAX - 1, // different max-amount
        1,
    );

    // Test amount > max-amount
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1_u128,
        min_ustx.saturating_sub(1), // amount > max-amount
        1,
    );
    let invalid_amount_nonce = delegate_nonce;
    let invalid_amount_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature),
        &signer_pk,
        min_ustx.saturating_sub(1), // amount > max-amount
        1,
    );

    // Test with valid signature
    delegate_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1_u128,
        u128::MAX,
        1,
    );
    let valid_nonce = delegate_nonce;
    let valid_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        Some(signature.clone()),
        &signer_pk,
        u128::MAX,
        1,
    );

    let latest_block = peer.tenure_with_txs(
        &[
            delegate_tx,
            delegate_stack_stx_tx,
            invalid_cycle_tx,
            invalid_pox_addr_tx,
            invalid_key_tx,
            invalid_period_tx,
            invalid_topic_tx,
            invalid_auth_id_tx,
            invalid_max_amount_tx,
            invalid_amount_tx,
            valid_tx,
        ],
        &mut coinbase_nonce,
    );

    let txs = get_last_block_sender_transactions(&observer, delegate_addr);

    let tx_result = |nonce: u64| -> Value { txs.get(nonce as usize).unwrap().result.clone() };

    let expected_error = Value::error(Value::Int(35)).unwrap();
    let amount_too_high_error = Value::error(Value::Int(38)).unwrap();

    tx_result(delegate_stack_stx_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
    assert_eq!(tx_result(invalid_cycle_nonce), expected_error);
    assert_eq!(tx_result(invalid_pox_addr_nonce), expected_error);
    assert_eq!(tx_result(invalid_key_nonce), expected_error);
    assert_eq!(tx_result(invalid_period_nonce), expected_error);
    assert_eq!(tx_result(invalid_topic_nonce), expected_error);
    assert_eq!(tx_result(invalid_auth_id_nonce), expected_error);
    assert_eq!(tx_result(invalid_max_amount_nonce), expected_error);
    assert_eq!(tx_result(invalid_amount_nonce), amount_too_high_error);
    tx_result(valid_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");

    // Ensure that the used signature cannot be re-used
    let result = verify_signer_key_sig(
        &signature,
        &signer_pk,
        &pox_addr,
        &mut peer,
        &latest_block,
        next_reward_cycle,
        1,
        &topic,
        min_ustx,
        u128::MAX,
        1,
    );
    let expected_error = Value::error(Value::Int(39)).unwrap();
    assert_eq!(result, expected_error);

    // Ensure the authorization is stored as used
    let entry = get_signer_key_authorization_used_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        next_reward_cycle.try_into().unwrap(),
        &topic,
        1,
        &signer_pk,
        u128::MAX,
        1,
    );
}

// Helper struct to hold information about stackers and signers
#[derive(Debug, Clone)]
struct StackerSignerInfo {
    private_key: StacksPrivateKey,
    public_key: StacksPublicKey,
    principal: PrincipalData,
    address: StacksAddress,
    pox_address: PoxAddress,
    nonce: u64,
}

impl StackerSignerInfo {
    fn new() -> Self {
        let private_key = StacksPrivateKey::new();
        let public_key = StacksPublicKey::from_private(&private_key);
        let address = key_to_stacks_addr(&private_key);
        let pox_address =
            PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, address.bytes.clone());
        let principal = PrincipalData::from(address.clone());
        let nonce = 0;
        Self {
            private_key,
            public_key,
            address,
            principal,
            pox_address,
            nonce,
        }
    }
}

/// Helper function to advance to a specific block height with the passed txs as the first in the block
/// Returns a tuple of the tip and the observed block that should contain the provided txs
fn advance_to_block_height(
    peer: &mut TestPeer,
    observer: &TestEventObserver,
    txs: &[StacksTransaction],
    peer_nonce: &mut usize,
    target_height: u64,
    test_signers: &mut Option<TestSigners>,
) -> (
    StacksBlockId,
    TestEventObserverBlock,
    Vec<StacksTransactionReceipt>,
) {
    let mut tx_block = None;
    let mut latest_block = None;
    let mut passed_txs = txs;
    while peer.get_burn_block_height() < target_height {
        info!(
            "Advancing to block height: {} from {} with {} txs",
            target_height,
            peer.get_burn_block_height(),
            passed_txs.len()
        );
        latest_block = Some(tenure_with_txs(peer, &passed_txs, peer_nonce, test_signers));
        passed_txs = &[];
        if tx_block.is_none() {
            tx_block = Some(observer.get_blocks().last().unwrap().clone());
        }
    }
    let latest_block = latest_block.expect("Failed to get tip");
    let tx_block = tx_block.expect("Failed to get tx block");
    let tx_block_receipts = if test_signers.is_some() {
        tx_block.receipts[1..].to_vec() // remove TenureChange
    } else {
        tx_block.receipts.clone()
    };
    (latest_block, tx_block, tx_block_receipts)
}

#[test]
/// Test for verifying that the stacker aggregation works as expected
///   with new signature parameters. In this test Alice is the service signer,
///   Bob is the pool operator, Carl & Dave are delegates for pool 1, Eve is a late
///   delegate for pool 1, Frank is a delegate for pool 2, & Grace is a delegate for pool 2.
fn stack_agg_increase() {
    // Alice service signer setup
    let alice = StackerSignerInfo::new();
    // Bob pool operator
    let mut bob = StackerSignerInfo::new();
    // Carl pool 1 delegate
    let mut carl = StackerSignerInfo::new();
    // Dave pool 1 delegate
    let mut dave = StackerSignerInfo::new();
    // Eve late 1 pool delegate
    let mut eve = StackerSignerInfo::new();
    // Frank pool 2 delegate
    let mut frank = StackerSignerInfo::new();
    // Grace pool 2 delegate
    let mut grace = StackerSignerInfo::new();

    let default_initial_balances = 1_000_000_000_000_000_000;
    let observer = TestEventObserver::new();
    let test_signers = TestSigners::new(vec![]);
    let mut initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
        (carl.principal.clone(), default_initial_balances),
        (dave.principal.clone(), default_initial_balances),
        (eve.principal.clone(), default_initial_balances),
        (frank.principal.clone(), default_initial_balances),
        (grace.principal.clone(), default_initial_balances),
    ];
    let aggregate_public_key = test_signers.aggregate_public_key.clone();
    let mut peer_config = TestPeerConfig::new(function_name!(), 0, 0);
    let private_key = peer_config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    peer_config.aggregate_public_key = Some(aggregate_public_key.clone());
    peer_config
        .stacker_dbs
        .push(boot_code_id(MINERS_NAME, false));
    peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(1000)); // Let us not activate nakamoto to make life easier
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];
    peer_config.initial_balances.append(&mut initial_balances);
    peer_config.burnchain.pox_constants.v2_unlock_height = 81;
    peer_config.burnchain.pox_constants.pox_3_activation_height = 101;
    peer_config.burnchain.pox_constants.v3_unlock_height = 102;
    peer_config.burnchain.pox_constants.pox_4_activation_height = 105;
    peer_config.test_signers = Some(test_signers.clone());
    peer_config.burnchain.pox_constants.reward_cycle_length = 20;
    peer_config.burnchain.pox_constants.prepare_length = 5;
    let epochs = peer_config.epochs.clone().unwrap();
    let epoch_3 = &epochs[StacksEpochId::Epoch30];

    let mut peer = TestPeer::new_with_observer(peer_config, Some(&observer));
    let mut peer_nonce = 0;
    // Set constants
    let reward_cycle_len = peer.config.burnchain.pox_constants.reward_cycle_length;
    let prepare_phase_len = peer.config.burnchain.pox_constants.prepare_length;

    // Advance into pox4
    let mut target_height = peer.config.burnchain.pox_constants.pox_4_activation_height;
    let mut latest_block = None;
    // Produce blocks until the first reward phase that everyone should be in
    while peer.get_burn_block_height() < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut peer_nonce));
    }
    let latest_block = latest_block.expect("Failed to get tip");
    // Current reward cycle: 5 (starts at burn block 101)
    let reward_cycle = get_current_reward_cycle(&peer, &peer.config.burnchain);
    let next_reward_cycle = reward_cycle.wrapping_add(1);
    // Current burn block height: 105
    let burn_block_height = peer.get_burn_block_height();
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;

    // Signatures
    // Initial Alice Signature For Bob Pool 1
    let lock_period = 1;
    let alice_signature_initial_one = make_signer_key_signature(
        &bob.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        lock_period,
        u128::MAX,
        1,
    );
    // Increase Error Bob Signature For Bob
    let bob_err_signature_increase = make_signer_key_signature(
        &bob.pox_address,
        &bob.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        lock_period,
        u128::MAX,
        1,
    );
    // Increase Alice Signature For Bob
    let alice_signature_increase = make_signer_key_signature(
        &bob.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationIncrease,
        lock_period,
        u128::MAX,
        1,
    );
    // Initial Alice Signature For Bob Pool 2
    let alice_signature_initial_two = make_signer_key_signature(
        &bob.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        lock_period,
        u128::MAX,
        2,
    );

    // Timely Delegate-STX Functions
    // Carl pool stacker timely delegating STX to Bob
    let carl_delegate_stx_to_bob_tx = make_pox_4_delegate_stx(
        &carl.private_key,
        carl.nonce,
        amount,
        bob.principal.clone(),
        None,
        Some(bob.pox_address.clone()),
    );
    carl.nonce += 1;

    // Dave pool stacker timely delegating STX to Bob
    let dave_delegate_stx_to_bob_tx = make_pox_4_delegate_stx(
        &dave.private_key,
        dave.nonce,
        amount,
        bob.principal.clone(),
        None,
        Some(bob.pox_address.clone()),
    );
    dave.nonce += 1;

    // Timely Delegate-Stack-STX Functions
    // Bob pool operator calling delegate-stack-stx on behalf of Carl
    let bob_delegate_stack_stx_for_carl_tx = make_pox_4_delegate_stack_stx(
        &bob.private_key,
        bob.nonce,
        carl.principal.clone(),
        amount,
        bob.pox_address.clone(),
        burn_block_height as u128,
        lock_period,
    );
    bob.nonce += 1;
    // Bob pool operator calling delegate-stack-stx on behalf of Dave
    let bob_delegate_stack_stx_for_dave_tx = make_pox_4_delegate_stack_stx(
        &bob.private_key,
        bob.nonce,
        dave.principal.clone(),
        amount,
        bob.pox_address.clone(),
        burn_block_height as u128,
        lock_period,
    );
    bob.nonce += 1;

    // Aggregate Commit
    let bobs_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &bob.private_key,
        bob.nonce,
        &bob.pox_address,
        next_reward_cycle,
        Some(alice_signature_initial_one),
        &alice.public_key,
        u128::MAX,
        1,
    );
    bob.nonce += 1;

    let txs = vec![
        carl_delegate_stx_to_bob_tx.clone(),
        dave_delegate_stx_to_bob_tx.clone(),
        bob_delegate_stack_stx_for_carl_tx.clone(),
        bob_delegate_stack_stx_for_dave_tx.clone(),
        bobs_aggregate_commit_index_tx.clone(),
    ];

    // Advance to next block in order to collect aggregate commit reward index
    target_height += 1;
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height.into(),
        &mut None,
    );

    // Get Bob's aggregate commit reward index
    let bob_aggregate_commit_reward_index_actual = &tx_block
        .receipts
        .get(5)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    let bob_aggregate_commit_reward_index_expected = Value::UInt(0);
    assert_eq!(
        bob_aggregate_commit_reward_index_actual,
        &bob_aggregate_commit_reward_index_expected
    );

    // Eve Late Functions
    // Eve pool stacker late delegating STX to Bob
    let eve_delegate_stx_to_bob_tx = make_pox_4_delegate_stx(
        &eve.private_key,
        eve.nonce,
        amount,
        bob.principal.clone(),
        None,
        Some(bob.pox_address.clone()),
    );
    eve.nonce += 1;
    // Bob pool operator calling delegate-stack-stx on behalf of Eve
    let bob_delegate_stack_stx_for_eve_tx = make_pox_4_delegate_stack_stx(
        &bob.private_key,
        bob.nonce,
        eve.principal.clone(),
        amount,
        bob.pox_address.clone(),
        burn_block_height as u128,
        lock_period,
    );
    bob.nonce += 1;
    // Bob's Error Aggregate Increase
    let bobs_err_aggregate_increase = make_pox_4_aggregation_increase(
        &bob.private_key,
        bob.nonce,
        &bob.pox_address,
        next_reward_cycle,
        bob_aggregate_commit_reward_index_actual
            .clone()
            .expect_u128()
            .unwrap(),
        Some(bob_err_signature_increase),
        &bob.public_key,
        u128::MAX,
        1,
    );
    bob.nonce += 1;
    // Bob's Aggregate Increase
    let bobs_aggregate_increase = make_pox_4_aggregation_increase(
        &bob.private_key,
        bob.nonce,
        &bob.pox_address,
        next_reward_cycle,
        bob_aggregate_commit_reward_index_actual
            .clone()
            .expect_u128()
            .unwrap(),
        Some(alice_signature_increase.clone()),
        &alice.public_key,
        u128::MAX,
        1,
    );
    bob.nonce += 1;
    // Frank pool stacker delegating STX to Bob
    let frank_delegate_stx_to_bob_tx = make_pox_4_delegate_stx(
        &frank.private_key,
        frank.nonce,
        amount,
        bob.principal.clone(),
        None,
        Some(bob.pox_address.clone()),
    );
    frank.nonce += 1;
    // Grace pool stacker delegating STX to Bob
    let grace_delegate_stx_to_bob_tx = make_pox_4_delegate_stx(
        &grace.private_key,
        grace.nonce,
        amount,
        bob.principal.clone(),
        None,
        Some(bob.pox_address.clone()),
    );
    grace.nonce += 1;
    // Bob pool operator calling delegate-stack-stx on behalf of Faith
    let bob_delegate_stack_stx_for_faith_tx = make_pox_4_delegate_stack_stx(
        &bob.private_key,
        bob.nonce,
        frank.principal.clone(),
        amount,
        bob.pox_address.clone(),
        burn_block_height as u128,
        lock_period,
    );
    bob.nonce += 1;
    // Bob pool operator calling delegate-stack-stx on behalf of Grace
    let bob_delegate_stack_stx_for_grace_tx = make_pox_4_delegate_stack_stx(
        &bob.private_key,
        bob.nonce,
        grace.principal.clone(),
        amount,
        bob.pox_address.clone(),
        burn_block_height as u128,
        lock_period,
    );
    bob.nonce += 1;
    // Aggregate Commit 2nd Pool
    let bobs_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &bob.private_key,
        bob.nonce,
        &bob.pox_address,
        next_reward_cycle,
        Some(alice_signature_initial_two),
        &alice.public_key,
        u128::MAX,
        2,
    );
    bob.nonce += 1;

    let txs = vec![
        eve_delegate_stx_to_bob_tx.clone(),
        bob_delegate_stack_stx_for_eve_tx.clone(),
        bobs_err_aggregate_increase.clone(),
        bobs_aggregate_increase.clone(),
        frank_delegate_stx_to_bob_tx.clone(),
        grace_delegate_stx_to_bob_tx.clone(),
        bob_delegate_stack_stx_for_faith_tx.clone(),
        bob_delegate_stack_stx_for_grace_tx.clone(),
        bobs_aggregate_commit_index_tx.clone(),
    ];

    // Advance to next block in order to attempt aggregate increase
    target_height += 1;
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height.into(),
        &mut None,
    );

    // Fetch the error aggregate increase result & check that the err is ERR_INVALID_SIGNER_KEY
    let bob_err_increase_result_actual = &tx_block
        .receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    let bob_err_increase_result_expected = Value::Int(32);
    assert_eq!(
        bob_err_increase_result_actual,
        &bob_err_increase_result_expected
    );

    let bob_aggregate_increase_tx = &tx_block.receipts.get(4).unwrap();

    // Fetch the aggregate increase result & check that value is true
    let bob_aggregate_increase_result = bob_aggregate_increase_tx
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_aggregate_increase_result, Value::Bool(true));

    let aggregation_increase_event = &bob_aggregate_increase_tx.events[0];

    let expected_result = Value::okay(Value::Tuple(
        TupleData::from_data(vec![
            (
                "stacker".into(),
                Value::Principal(PrincipalData::from(bob.address.clone())),
            ),
            ("total-locked".into(), Value::UInt(min_ustx * 2)),
        ])
        .unwrap(),
    ))
    .unwrap();

    let increase_op_data = HashMap::from([
        (
            "signer-sig",
            Value::some(Value::buff_from(alice_signature_increase).unwrap()).unwrap(),
        ),
        (
            "signer-key",
            Value::buff_from(alice.public_key.to_bytes_compressed()).unwrap(),
        ),
        ("max-amount", Value::UInt(u128::MAX)),
        ("auth-id", Value::UInt(1)),
    ]);

    let common_data = PoxPrintFields {
        op_name: "stack-aggregation-increase".to_string(),
        stacker: Value::Principal(PrincipalData::from(bob.address.clone())),
        balance: Value::UInt(1000000000000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };

    check_pox_print_event(&aggregation_increase_event, common_data, increase_op_data);

    // Check that Bob's second pool has an assigned reward index of 1
    let bob_aggregate_commit_reward_index = &tx_block
        .receipts
        .get(9)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_aggregate_commit_reward_index, &Value::UInt(1));
}

#[apply(nakamoto_cases)]
fn stack_increase_verify_signer_key(use_nakamoto: bool) {
    let lock_period = 1;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let stacker_addr = key_to_stacks_addr(&stacker_key);
    let signer_sk = &keys[1];
    let signer_pk = StacksPublicKey::from_private(signer_sk);
    let pox_addr = pox_addr_from(&signer_sk);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let topic = Pox4SignatureTopic::StackIncrease;

    // Setup: stack-stx
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let stack_nonce = stacker_nonce;
    let stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_pk,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid reward cycle
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle - 1, // invalid
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_cycle_nonce = stacker_nonce;
    let invalid_cycle_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid pox addr
    stacker_nonce += 1;
    let other_pox_addr = pox_addr_from(&Secp256k1PrivateKey::new());
    let signature = make_signer_key_signature(
        &other_pox_addr, // different than existing
        &signer_sk,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_pox_addr_nonce = stacker_nonce;
    let invalid_pox_addr_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid private key
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &stacker_key, // different than signer
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_key_nonce = stacker_nonce;
    let invalid_key_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid period
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &topic,
        lock_period + 1, // wrong
        u128::MAX,
        1,
    );
    let invalid_period_nonce = stacker_nonce;
    let invalid_period_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid topic
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend, // wrong topic
        lock_period,
        u128::MAX,
        1,
    );
    let invalid_topic_nonce = stacker_nonce;
    let invalid_topic_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid auth-id
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX,
        2, // wrong auth-id
    );
    let invalid_auth_id_nonce = stacker_nonce;
    let invalid_auth_id_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    // invalid max-amount
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &topic,
        lock_period,
        u128::MAX.saturating_sub(1),
        1,
    );
    let invalid_max_amount_nonce = stacker_nonce;
    let invalid_max_amount_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX, // different than signature
        1,
    );

    // invalid amount
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &topic,
        lock_period,
        min_ustx.saturating_sub(1),
        1,
    );
    let invalid_amount_nonce = stacker_nonce;
    let invalid_amount_tx = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        min_ustx.saturating_sub(1),
        1,
    );

    // Valid tx
    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        lock_period,
        u128::MAX,
        1,
    );
    let valid_nonce = stacker_nonce;
    let stack_increase = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    let latest_block = tenure_with_txs(
        &mut peer,
        &[
            stack_tx,
            invalid_cycle_tx,
            invalid_pox_addr_tx,
            invalid_key_tx,
            invalid_period_tx,
            invalid_topic_tx,
            invalid_auth_id_tx,
            invalid_max_amount_tx,
            invalid_amount_tx,
            stack_increase,
        ],
        &mut coinbase_nonce,
        &mut test_signers,
    );

    let txs = get_last_block_sender_transactions(&observer, stacker_addr);
    let tx_result = |nonce: u64| -> Value { txs.get(nonce as usize).unwrap().result.clone() };
    let signature_error = Value::error(Value::Int(35)).unwrap();

    // stack-stx should work
    tx_result(stack_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
    assert_eq!(tx_result(invalid_cycle_nonce), signature_error);
    assert_eq!(tx_result(invalid_pox_addr_nonce), signature_error);
    assert_eq!(tx_result(invalid_key_nonce), signature_error);
    assert_eq!(tx_result(invalid_period_nonce), signature_error);
    assert_eq!(tx_result(invalid_topic_nonce), signature_error);
    assert_eq!(tx_result(invalid_auth_id_nonce), signature_error);
    assert_eq!(tx_result(invalid_max_amount_nonce), signature_error);
    assert_eq!(
        tx_result(invalid_amount_nonce),
        Value::error(Value::Int(38)).unwrap()
    );

    // valid tx should succeed
    tx_result(valid_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
}

#[apply(nakamoto_cases)]
/// Verify that when calling `stack-increase`, the function
/// fails if the signer key for each cycle being updated is not the same
/// as the provided `signer-key` argument
fn stack_increase_different_signer_keys(use_nakamoto: bool) {
    let lock_period = 1;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let stacker_addr = key_to_stacks_addr(&stacker_key);
    let signer_sk = &keys[1];
    let signer_pk = StacksPublicKey::from_private(signer_sk);
    let pox_addr = pox_addr_from(&signer_sk);

    // Second key is used in `stack-extend`
    let second_signer_sk = &keys[2];
    let second_signer_pk = StacksPublicKey::from_private(second_signer_sk);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    // Setup: stack-stx
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let stack_nonce = stacker_nonce;
    let stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_pk,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &second_signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        lock_period,
        u128::MAX,
        1,
    );
    let extend_nonce = stacker_nonce;
    let extend_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        second_signer_pk.clone(),
        Some(signature.clone()),
        u128::MAX,
        1,
    );

    stacker_nonce += 1;
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        2, // 2 cycles total (1 from stack-stx, 1 from extend)
        u128::MAX,
        1,
    );
    let increase_nonce = stacker_nonce;
    let stack_increase = make_pox_4_stack_increase(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &signer_pk,
        Some(signature),
        u128::MAX,
        1,
    );

    let latest_block = tenure_with_txs(
        &mut peer,
        &[stack_tx, extend_tx, stack_increase],
        &mut coinbase_nonce,
        &mut test_signers,
    );

    let txs = get_last_block_sender_transactions(&observer, stacker_addr.clone());

    let tx_result = |nonce: u64| -> Value { txs.get(nonce as usize).unwrap().result.clone() };

    // stack-stx should work
    tx_result(stack_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
    // `stack-extend` should work
    tx_result(extend_nonce)
        .expect_result_ok()
        .expect("Expected ok result from tx");
    let increase_result = tx_result(increase_nonce);

    // Validate that the error is not due to the signature
    assert_ne!(
        tx_result(increase_nonce),
        Value::error(Value::Int(35)).unwrap()
    );
    assert_eq!(increase_result, Value::error(Value::Int(40)).unwrap())
}

pub fn assert_latest_was_burn(peer: &mut TestPeer) {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;

    let conn = peer.sortdb().conn();

    // check the *parent* burn block, because that's what we'll be
    //  checking with get_burn_pox_addr_info
    let mut burn_ops =
        SortitionDB::get_block_commits_by_block(conn, &tip.parent_sortition_id).unwrap();
    assert_eq!(burn_ops.len(), 1);
    let commit = burn_ops.pop().unwrap();
    assert!(commit.all_outputs_burn());
    assert!(commit.burn_fee > 0);

    let (addrs, payout) = get_burn_pox_addr_info(peer);
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;
    info!("Checking burn outputs at burn_height = {burn_height}");
    if peer.config.burnchain.is_in_prepare_phase(burn_height) {
        assert_eq!(addrs.len(), 1);
        assert_eq!(payout, 1000);
        assert!(addrs[0].is_burn());
    } else {
        assert_eq!(addrs.len(), 2);
        assert_eq!(payout, 500);
        assert!(addrs[0].is_burn());
        assert!(addrs[1].is_burn());
    }
}

fn assert_latest_was_pox(peer: &mut TestPeer) -> Vec<PoxAddress> {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;

    let conn = peer.sortdb().conn();

    // check the *parent* burn block, because that's what we'll be
    //  checking with get_burn_pox_addr_info
    let mut burn_ops =
        SortitionDB::get_block_commits_by_block(conn, &tip.parent_sortition_id).unwrap();
    assert_eq!(burn_ops.len(), 1);
    let commit = burn_ops.pop().unwrap();
    assert!(!commit.all_outputs_burn());
    let commit_addrs = commit.commit_outs;

    let (addrs, payout) = get_burn_pox_addr_info(peer);
    info!(
        "Checking pox outputs at burn_height = {burn_height}, commit_addrs = {commit_addrs:?}, fetch_addrs = {addrs:?}"
    );
    assert_eq!(addrs.len(), 2);
    assert_eq!(payout, 500);
    assert!(commit_addrs.contains(&addrs[0]));
    assert!(commit_addrs.contains(&addrs[1]));
    addrs
}

fn balances_from_keys(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    keys: &[Secp256k1PrivateKey],
) -> Vec<STXBalance> {
    keys.iter()
        .map(key_to_stacks_addr)
        .map(PrincipalData::from)
        .map(|principal| get_stx_account_at(peer, tip, &principal))
        .collect()
}

#[apply(nakamoto_cases)]
fn stack_stx_signer_key(use_nakamoto: bool) {
    let observer = TestEventObserver::new();
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let signer_key_val = Value::buff_from(signer_public_key.to_bytes_compressed()).unwrap();

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    // (define-public (stack-stx (amount-ustx uint)
    //                       (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
    //                       (start-burn-ht uint)
    //                       (lock-period uint)
    //                       (signer-key (buff 33)))
    let pox_addr = pox_addr_from(&stacker_key);
    let pox_addr_val = Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap());
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        2_u128,
        u128::MAX,
        1,
    );

    let txs = vec![make_pox_4_contract_call(
        stacker_key,
        stacker_nonce,
        "stack-stx",
        vec![
            Value::UInt(min_ustx),
            pox_addr_val.clone(),
            Value::UInt(block_height as u128),
            Value::UInt(2),
            Value::some(Value::buff_from(signature.clone()).unwrap()).unwrap(),
            signer_key_val.clone(),
            Value::UInt(u128::MAX),
            Value::UInt(1),
        ],
    )];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    let stacker_txs =
        get_last_block_sender_transactions(&observer, key_to_stacks_addr(&stacker_key));

    let stacking_tx = stacker_txs.get(0).unwrap();
    let events: Vec<&STXLockEventData> = stacking_tx
        .events
        .iter()
        .filter_map(|e| match e {
            StacksTransactionEvent::STXEvent(STXEventType::STXLockEvent(data)) => Some(data),
            _ => None,
        })
        .collect();

    assert_eq!(events.get(0).unwrap().locked_amount, min_ustx);

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| {
            entry.reward_address == PoxAddress::try_from_pox_tuple(false, &pox_addr_val).unwrap()
        })
        .expect("No reward entry found");
    assert_eq!(
        &reward_entry.signer.unwrap(),
        &signer_public_key.to_bytes_compressed().as_slice(),
    );
}

#[apply(nakamoto_cases)]
/// Test `stack-stx` using signer key authorization
fn stack_stx_signer_auth(use_nakamoto: bool) {
    let observer = TestEventObserver::new();
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let signer_nonce = 0;
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let signer_key_val = Value::buff_from(signer_public_key.to_bytes_compressed()).unwrap();

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let pox_addr = pox_addr_from(&stacker_key);
    let pox_addr_val = Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap());
    let lock_period = 6;

    let topic = Pox4SignatureTopic::StackStx;

    let failed_stack_nonce = stacker_nonce;
    let failed_stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        None,
        u128::MAX,
        1,
    );

    let enable_auth_nonce = signer_nonce;
    let enable_auth_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        true,
        signer_nonce,
        None,
        u128::MAX,
        1,
    );

    // Ensure that stack-stx succeeds with auth
    stacker_nonce += 1;
    let successful_stack_nonce = stacker_nonce;
    let valid_stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        None,
        u128::MAX,
        1,
    );

    let txs = vec![failed_stack_tx, enable_auth_tx, valid_stack_tx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    let stacker_txs =
        get_last_block_sender_transactions(&observer, key_to_stacks_addr(&stacker_key));

    let expected_error = Value::error(Value::Int(19)).unwrap();

    assert_eq!(stacker_txs.len(), (stacker_nonce + 1) as usize);
    let stacker_tx_result =
        |nonce: u64| -> Value { stacker_txs.get(nonce as usize).unwrap().result.clone() };

    // First stack-stx failed
    assert_eq!(stacker_tx_result(failed_stack_nonce), expected_error);

    let successful_stack_result = stacker_tx_result(successful_stack_nonce);
    // second stack-stx worked
    successful_stack_result
        .expect_result_ok()
        .expect("Expected ok result from stack-stx tx");

    let signer_txs = get_last_block_sender_transactions(&observer, key_to_stacks_addr(&signer_key));

    // enable auth worked
    let enable_tx_result = signer_txs
        .get(enable_auth_nonce as usize)
        .unwrap()
        .result
        .clone();
    assert_eq!(enable_tx_result, Value::okay_true());
}

#[apply(nakamoto_cases)]
/// Test `stack-aggregation-commit` using signer key authorization
fn stack_agg_commit_signer_auth(use_nakamoto: bool) {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let mut delegate_nonce = 0;
    let stacker_nonce = 0;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    let stacker_key = &keys[0];
    let stacker_addr = PrincipalData::from(key_to_stacks_addr(&stacker_key));

    let signer_sk = &keys[1];
    let signer_pk = StacksPublicKey::from_private(signer_sk);

    let delegate_key = &keys[2];
    let delegate_addr = key_to_stacks_addr(&delegate_key);

    let pox_addr = pox_addr_from(&delegate_key);

    let reward_cycle = burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap() as u128;
    let next_reward_cycle = reward_cycle + 1;

    // Setup: delegate-stx and delegate-stack-stx

    let delegate_tx = make_pox_4_delegate_stx(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        delegate_addr.clone().into(),
        None,
        None,
    );

    let delegate_stack_stx_nonce = delegate_nonce;
    let delegate_stack_stx_tx = make_pox_4_delegate_stack_stx(
        &delegate_key,
        delegate_nonce,
        stacker_addr,
        min_ustx,
        pox_addr.clone(),
        block_height.into(),
        lock_period,
    );

    let topic = Pox4SignatureTopic::AggregationCommit;

    // Stack agg fails without auth
    delegate_nonce += 1;
    let invalid_agg_nonce = delegate_nonce;
    let invalid_agg_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        None,
        &signer_pk,
        u128::MAX,
        1,
    );

    // Signer enables auth
    let enable_auth_nonce = 0;
    let enable_auth_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_sk,
        next_reward_cycle,
        &topic,
        1,
        true,
        enable_auth_nonce,
        None,
        u128::MAX,
        1,
    );

    // Stack agg works with auth
    delegate_nonce += 1;
    let valid_agg_nonce = delegate_nonce;
    let valid_agg_tx = make_pox_4_aggregation_commit_indexed(
        &delegate_key,
        delegate_nonce,
        &pox_addr,
        next_reward_cycle,
        None,
        &signer_pk,
        u128::MAX,
        1,
    );

    let txs = vec![
        delegate_tx,
        delegate_stack_stx_tx,
        invalid_agg_tx,
        enable_auth_tx,
        valid_agg_tx,
    ];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let delegate_txs = get_last_block_sender_transactions(&observer, delegate_addr);

    let tx_result =
        |nonce: u64| -> Value { delegate_txs.get(nonce as usize).unwrap().result.clone() };

    let expected_error = Value::error(Value::Int(19)).unwrap();
    assert_eq!(tx_result(invalid_agg_nonce), expected_error);
    let successful_agg_result = tx_result(valid_agg_nonce);
    successful_agg_result
        .expect_result_ok()
        .expect("Expected ok result from stack-agg-commit tx");
}

#[apply(nakamoto_cases)]
/// Test `stack-extend` using signer key authorization
/// instead of signatures
fn stack_extend_signer_auth(use_nakamoto: bool) {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let stacker_addr = key_to_stacks_addr(&stacker_key);
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let pox_addr = pox_addr_from(&signer_key);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let topic = Pox4SignatureTopic::StackExtend;

    // Setup: stack-stx
    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let stack_nonce = stacker_nonce;
    let stack_tx = make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_public_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Stack-extend should fail without auth
    stacker_nonce += 1;
    let invalid_extend_nonce = stacker_nonce;
    let invalid_cycle_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        lock_period,
        signer_public_key.clone(),
        None,
        u128::MAX,
        1,
    );

    // Enable authorization
    let enable_auth_nonce = 0;
    let enable_auth_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        reward_cycle,
        &topic,
        lock_period,
        true,
        enable_auth_nonce,
        None,
        u128::MAX,
        1,
    );

    // Stack-extend should work with auth
    stacker_nonce += 1;
    let valid_extend_nonce = stacker_nonce;
    let valid_tx = make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr,
        lock_period,
        signer_public_key.clone(),
        None,
        u128::MAX,
        1,
    );

    let txs = vec![stack_tx, invalid_cycle_tx, enable_auth_tx, valid_tx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let stacker_txs = get_last_block_sender_transactions(&observer, stacker_addr);

    let tx_result =
        |nonce: u64| -> Value { stacker_txs.get(nonce as usize).unwrap().result.clone() };

    let expected_error = Value::error(Value::Int(19)).unwrap();
    assert_eq!(tx_result(invalid_extend_nonce), expected_error);

    let valid_extend_tx_result = tx_result(valid_extend_nonce);
    valid_extend_tx_result
        .expect_result_ok()
        .expect("Expected ok result from stack-extend tx");
}

#[apply(nakamoto_cases)]
/// Test `set-signer-key-authorization` function
fn test_set_signer_key_auth(use_nakamoto: bool) {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, coinbase_nonce, mut test_signers) =
        prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut coinbase_nonce = coinbase_nonce;

    let alice_nonce = 0;
    let alice_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let alice_addr = key_to_stacks_addr(&alice_key);
    let mut signer_nonce = 0;
    let signer_key = &keys[1];
    let signer_public_key = StacksPublicKey::from_private(signer_key);
    let signer_addr = key_to_stacks_addr(&signer_key);
    let pox_addr = pox_addr_from(&signer_key);

    let current_reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    // Only the address associated with `signer-key` can enable auth for that key
    let invalid_enable_nonce = alice_nonce;
    let invalid_enable_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        1,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        true,
        invalid_enable_nonce,
        Some(&alice_key),
        u128::MAX,
        1,
    );

    // Test that period is at least u1
    let signer_invalid_period_nonce = signer_nonce;
    signer_nonce += 1;
    let invalid_tx_period: StacksTransaction = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        current_reward_cycle,
        &Pox4SignatureTopic::StackStx,
        0,
        false,
        signer_invalid_period_nonce,
        Some(&signer_key),
        u128::MAX,
        1,
    );

    let signer_invalid_cycle_nonce = signer_nonce;
    signer_nonce += 1;
    // Test that confirmed reward cycle is at least current reward cycle
    let invalid_tx_cycle: StacksTransaction = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        1,
        &Pox4SignatureTopic::StackStx,
        1,
        false,
        signer_invalid_cycle_nonce,
        Some(&signer_key),
        u128::MAX,
        1,
    );

    // Disable auth for `signer-key`
    let disable_auth_tx: StacksTransaction = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        current_reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        false,
        signer_nonce,
        None,
        u128::MAX,
        1,
    );

    let latest_block = tenure_with_txs(
        &mut peer,
        &[
            invalid_enable_tx,
            invalid_tx_period,
            invalid_tx_cycle,
            disable_auth_tx,
        ],
        &mut coinbase_nonce,
        &mut test_signers,
    );

    let alice_txs = get_last_block_sender_transactions(&observer, alice_addr);
    let invalid_enable_tx_result = alice_txs
        .get(invalid_enable_nonce as usize)
        .unwrap()
        .result
        .clone();
    let expected_error = Value::error(Value::Int(19)).unwrap();
    assert_eq!(invalid_enable_tx_result, expected_error);

    let signer_txs = get_last_block_sender_transactions(&observer, signer_addr);

    let invalid_tx_period_result = signer_txs
        .clone()
        .get(signer_invalid_period_nonce as usize)
        .unwrap()
        .result
        .clone();

    // Check for invalid lock period err
    assert_eq!(
        invalid_tx_period_result,
        Value::error(Value::Int(2)).unwrap()
    );

    let invalid_tx_cycle_result = signer_txs
        .clone()
        .get(signer_invalid_cycle_nonce as usize)
        .unwrap()
        .result
        .clone();

    // Check for invalid cycle err
    assert_eq!(
        invalid_tx_cycle_result,
        Value::error(Value::Int(37)).unwrap()
    );

    let signer_key_enabled = get_signer_key_authorization_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        current_reward_cycle.clone() as u64,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        &signer_public_key,
        u128::MAX,
        1,
    );

    assert_eq!(signer_key_enabled.unwrap(), false);

    // Next block, enable the key
    signer_nonce += 1;
    let enable_auth_nonce = signer_nonce;
    let enable_auth_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        current_reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        true,
        enable_auth_nonce,
        None,
        u128::MAX,
        1,
    );

    let latest_block = tenure_with_txs(
        &mut peer,
        &[enable_auth_tx],
        &mut coinbase_nonce,
        &mut test_signers,
    );

    let signer_key_enabled = get_signer_key_authorization_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        current_reward_cycle.clone() as u64,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        &signer_public_key,
        u128::MAX,
        1,
    );

    assert_eq!(signer_key_enabled.unwrap(), true);

    // Next block, re-disable the key authorization
    signer_nonce += 1;
    let disable_auth_nonce = signer_nonce;
    let disable_auth_tx = make_pox_4_set_signer_key_auth(
        &pox_addr,
        &signer_key,
        current_reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        false,
        disable_auth_nonce,
        None,
        u128::MAX,
        1,
    );

    let latest_block = tenure_with_txs(
        &mut peer,
        &[disable_auth_tx],
        &mut coinbase_nonce,
        &mut test_signers,
    );

    let signer_key_enabled = get_signer_key_authorization_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        current_reward_cycle.clone() as u64,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        &signer_public_key,
        u128::MAX,
        1,
    );

    assert_eq!(signer_key_enabled.unwrap(), false);
}

#[apply(nakamoto_cases)]
fn stack_extend_signer_key(use_nakamoto: bool) {
    let lock_period = 2;
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), None, use_nakamoto);

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block) * 2;

    let pox_addr = pox_addr_from(&stacker_key);
    let pox_addr_val = Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap());

    let signer_sk = Secp256k1PrivateKey::from_seed(&[0]);
    let signer_extend_sk = Secp256k1PrivateKey::from_seed(&[1]);

    let signer_key = Secp256k1PublicKey::from_private(&signer_sk);
    let signer_bytes = signer_key.to_bytes_compressed();

    let signer_extend_key = Secp256k1PublicKey::from_private(&signer_extend_sk);
    let signer_extend_bytes = signer_extend_key.to_bytes_compressed();
    let signer_extend_key_val = Value::buff_from(signer_extend_bytes.clone()).unwrap();

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );

    let txs = vec![make_pox_4_lockup(
        &stacker_key,
        stacker_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signer_key,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    )];

    stacker_nonce += 1;

    let mut latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_extend_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        1_u128,
        u128::MAX,
        1,
    );

    let update_txs = vec![make_pox_4_extend(
        &stacker_key,
        stacker_nonce,
        pox_addr.clone(),
        1,
        signer_extend_key.clone(),
        Some(signature),
        u128::MAX,
        1,
    )];

    latest_block = tenure_with_txs(
        &mut peer,
        &update_txs,
        &mut coinbase_nonce,
        &mut test_signers,
    );
    let new_stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .unwrap()
    .expect_tuple();

    let extend_reward_cycle = 2 + next_reward_cycle;
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let extend_cycle_ht = burnchain.reward_cycle_to_block_height(extend_reward_cycle);

    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(&reward_entry.signer.unwrap(), signer_bytes.as_slice(),);

    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, extend_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_extend_bytes.as_slice(),
    );
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_extend_bytes.as_slice(),
    );
}

#[apply(nakamoto_cases)]
fn delegate_stack_stx_signer_key(use_nakamoto: bool) {
    let lock_period = 2;
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), None, use_nakamoto);

    let stacker_nonce = 0;
    let stacker_key = &keys[0];
    let delegate_nonce = 0;
    let delegate_key = &keys[1];
    let delegate_principal = PrincipalData::from(key_to_stacks_addr(delegate_key));

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    // (define-public (delegate-stx (amount-ustx uint)
    //                          (delegate-to principal)
    //                          (until-burn-ht (optional uint))
    //                          (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) })))
    let pox_addr = pox_addr_from(&stacker_key);
    let pox_addr_val = Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap());
    let signer_sk = Secp256k1PrivateKey::from_seed(&[1, 1, 1]);
    let signer_key = Secp256k1PublicKey::from_private(&signer_sk);
    let signer_key_val = Value::buff_from(signer_key.to_bytes_compressed()).unwrap();
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle.into(),
        &Pox4SignatureTopic::AggregationCommit,
        1_u128,
        u128::MAX,
        1,
    );

    let txs = vec![
        make_pox_4_contract_call(
            stacker_key,
            stacker_nonce,
            "delegate-stx",
            vec![
                Value::UInt(min_ustx + 1),
                delegate_principal.clone().into(),
                Value::none(),
                Value::Optional(OptionalData {
                    data: Some(Box::new(pox_addr_val.clone())),
                }),
            ],
        ),
        make_pox_4_contract_call(
            delegate_key,
            delegate_nonce,
            "delegate-stack-stx",
            vec![
                PrincipalData::from(key_to_stacks_addr(stacker_key)).into(),
                Value::UInt(min_ustx + 1),
                pox_addr_val.clone(),
                Value::UInt(block_height as u128),
                Value::UInt(lock_period),
            ],
        ),
        make_pox_4_contract_call(
            delegate_key,
            delegate_nonce + 1,
            "stack-aggregation-commit",
            vec![
                pox_addr_val.clone(),
                Value::UInt(next_reward_cycle.into()),
                Value::some(Value::buff_from(signature).unwrap()).unwrap(),
                signer_key_val.clone(),
                Value::UInt(u128::MAX),
                Value::UInt(1),
            ],
        ),
    ];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let delegation_state = get_delegation_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No delegation state, delegate-stx failed")
    .expect_tuple();

    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, delegate-stack-stx failed")
    .expect_tuple();

    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_key.to_bytes_compressed().as_slice()
    );
}

// In this test case, Alice delegates to Bob.
//  Bob then stacks the delegated stx for one cycle with an
//  'old' signer key. The next cycle, Bob extends the delegation
//  & rotates to a 'new' signer key.
//
// This test asserts that the signing key in Alice's stacking state
//  is equal to Bob's 'new' signer key.
#[apply(nakamoto_cases)]
fn delegate_stack_stx_extend_signer_key(use_nakamoto: bool) {
    let lock_period: u128 = 2;
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), None, use_nakamoto);

    let alice_nonce = 0;
    let alice_stacker_key = &keys[0];
    let mut bob_nonce = 0;
    let bob_delegate_private_key = &keys[1];
    let bob_delegate_principal = PrincipalData::from(key_to_stacks_addr(bob_delegate_private_key));

    let signer_sk = Secp256k1PrivateKey::from_seed(&[0]);
    let signer_extend_sk = Secp256k1PrivateKey::from_seed(&[1]);

    let signer_key = Secp256k1PublicKey::from_private(&signer_sk);
    let signer_bytes = signer_key.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_bytes.clone()).unwrap();

    let signer_extend_key = Secp256k1PublicKey::from_private(&signer_extend_sk);
    let signer_extend_bytes = signer_extend_key.to_bytes_compressed();
    let signer_extend_key_val = Value::buff_from(signer_extend_bytes.clone()).unwrap();

    let min_ustx = 2 * get_stacking_minimum(&mut peer, &latest_block);

    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(bob_delegate_private_key).bytes,
    );

    let delegate_stx = make_pox_4_delegate_stx(
        alice_stacker_key,
        alice_nonce,
        min_ustx + 1,
        bob_delegate_principal.clone(),
        None,
        Some(pox_addr.clone()),
    );

    let alice_principal = PrincipalData::from(key_to_stacks_addr(alice_stacker_key));

    let delegate_stack_stx = make_pox_4_delegate_stack_stx(
        bob_delegate_private_key,
        bob_nonce,
        key_to_stacks_addr(alice_stacker_key).into(),
        min_ustx + 1,
        pox_addr.clone(),
        block_height as u128,
        lock_period,
    );

    // Initial txs arr includes initial delegate_stx & delegate_stack_stx
    // Both are pox_4 helpers found in mod.rs
    let txs = vec![delegate_stx, delegate_stack_stx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let delegation_state = get_delegation_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacker_key).into(),
    )
    .expect("No delegation state, delegate-stx failed")
    .expect_tuple();

    let delegation_state = get_delegation_state_pox_4(&mut peer, &latest_block, &alice_principal)
        .expect("No delegation state, delegate-stx failed")
        .expect_tuple();

    let stacking_state = get_stacking_state_pox_4(&mut peer, &latest_block, &alice_principal)
        .expect("No stacking state, bob called delegate-stack-stx that failed here")
        .expect_tuple();

    let reward_cycle = burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let next_reward_cycle = 1 + reward_cycle;

    let extend_cycle = 1 + next_reward_cycle;

    let partially_stacked_0 = get_partially_stacked_state_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        next_reward_cycle,
        &key_to_stacks_addr(bob_delegate_private_key),
    );

    let partially_stacked_1 = get_partially_stacked_state_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        next_reward_cycle,
        &key_to_stacks_addr(bob_delegate_private_key),
    );

    info!("Currently partially stacked = {partially_stacked_0:?} + {partially_stacked_1:?}");

    bob_nonce += 1;

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle.into(),
        &Pox4SignatureTopic::AggregationCommit,
        1_u128,
        u128::MAX,
        1,
    );

    let delegate_stack_extend = make_pox_4_delegate_stack_extend(
        bob_delegate_private_key,
        bob_nonce,
        key_to_stacks_addr(alice_stacker_key).into(),
        pox_addr.clone(),
        1,
    );

    let agg_tx_0 = make_pox_4_contract_call(
        bob_delegate_private_key,
        bob_nonce + 1,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(next_reward_cycle.into()),
            Value::some(Value::buff_from(signature).unwrap()).unwrap(),
            signer_key_val.clone(),
            Value::UInt(u128::MAX),
            Value::UInt(1),
        ],
    );

    let extend_signature = make_signer_key_signature(
        &pox_addr,
        &signer_extend_sk,
        extend_cycle.into(),
        &Pox4SignatureTopic::AggregationCommit,
        1_u128,
        u128::MAX,
        2,
    );

    let agg_tx_1 = make_pox_4_contract_call(
        bob_delegate_private_key,
        bob_nonce + 2,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(extend_cycle.into()),
            Value::some(Value::buff_from(extend_signature).unwrap()).unwrap(),
            signer_extend_key_val.clone(),
            Value::UInt(u128::MAX),
            Value::UInt(2),
        ],
    );

    // Next tx arr calls a delegate_stack_extend pox_4 helper found in mod.rs
    let txs = vec![delegate_stack_extend, agg_tx_0, agg_tx_1];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);
    let new_stacking_state = get_stacking_state_pox_4(&mut peer, &latest_block, &alice_principal)
        .unwrap()
        .expect_tuple();

    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let extend_cycle_ht = burnchain.reward_cycle_to_block_height(extend_cycle);

    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(&reward_entry.signer.unwrap(), signer_bytes.as_slice(),);

    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, extend_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_extend_bytes.as_slice(),
    );
}

// In this test case, Alice is a solo stacker-signer.
//  Alice stacks the stacking minimum for two cycles.
//  In the next cycle, Alice calls stack-increase to increase
//  her total-locked by a second stacking minimum.
//
// This test asserts that Alice's total-locked is equal to
//  twice the stacking minimum after calling stack-increase.
#[apply(nakamoto_cases)]
fn stack_increase(use_nakamoto: bool) {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let mut alice_nonce = 0;
    let alice_stacking_private_key = &keys[0];
    let alice_address = key_to_stacks_addr(alice_stacking_private_key);
    let signing_sk = StacksPrivateKey::from_seed(&[1]);
    let signing_pk = StacksPublicKey::from_private(&signing_sk);
    let signing_bytes = signing_pk.to_bytes_compressed();
    let alice_balance = get_balance(&mut peer, &alice_address.into());

    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(alice_stacking_private_key).bytes,
    );
    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);

    let reward_cycle = get_current_reward_cycle(&peer, &burnchain);
    let signature = make_signer_key_signature(
        &pox_addr,
        &signing_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );

    let stack_stx = make_pox_4_lockup(
        alice_stacking_private_key,
        alice_nonce,
        min_ustx,
        &pox_addr,
        lock_period,
        &signing_pk,
        block_height,
        Some(signature),
        u128::MAX,
        1,
    );

    // Initial tx arr includes a stack_stx pox_4 helper found in mod.rs
    let txs = vec![stack_stx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacking_private_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    alice_nonce += 1;

    let signature = make_signer_key_signature(
        &pox_addr,
        &signing_sk,
        reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        lock_period,
        u128::MAX,
        1,
    );

    let stack_increase = make_pox_4_stack_increase(
        alice_stacking_private_key,
        alice_nonce,
        min_ustx,
        &signing_pk,
        Some(signature.clone()),
        u128::MAX,
        1,
    );
    // Next tx arr includes a stack_increase pox_4 helper found in mod.rs
    let txs = vec![stack_increase];
    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);
    let stacker_transactions = get_last_block_sender_transactions(&observer, alice_address);

    let actual_result = stacker_transactions.first().cloned().unwrap().result;

    let increase_event = &stacker_transactions.first().cloned().unwrap().events[0];

    let expected_result = Value::okay(Value::Tuple(
        TupleData::from_data(vec![
            (
                "stacker".into(),
                Value::Principal(PrincipalData::from(alice_address.clone())),
            ),
            ("total-locked".into(), Value::UInt(min_ustx * 2)),
        ])
        .unwrap(),
    ))
    .unwrap();

    let increase_op_data = HashMap::from([
        (
            "signer-sig",
            Value::some(Value::buff_from(signature).unwrap()).unwrap(),
        ),
        (
            "signer-key",
            Value::buff_from(signing_pk.to_bytes_compressed()).unwrap(),
        ),
        ("max-amount", Value::UInt(u128::MAX)),
        ("auth-id", Value::UInt(1)),
    ]);

    let alice_expected_balance = alice_balance - min_ustx;

    // Compute the expected unlock height because the 3.0 and 2.5 cases
    // have different PoX constants
    let cycle_len = burnchain.pox_constants.reward_cycle_length as u128;
    let unlock_cycle = burnchain
        .pox_constants
        .block_height_to_reward_cycle(
            0,
            ((block_height as u128) + ((lock_period + 1) * cycle_len))
                .try_into()
                .unwrap(),
        )
        .unwrap();
    let expected_unlock_height =
        unlock_cycle * (burnchain.pox_constants.reward_cycle_length as u64);

    let common_data = PoxPrintFields {
        op_name: "stack-increase".to_string(),
        stacker: Value::Principal(PrincipalData::from(alice_address.clone())),
        balance: Value::UInt(alice_expected_balance),
        locked: Value::UInt(min_ustx),
        burnchain_unlock_height: Value::UInt(expected_unlock_height as u128),
    };

    check_pox_print_event(&increase_event, common_data, increase_op_data);

    // Testing stack_increase response is equal to expected response
    // Test is straightforward because 'stack-increase' in PoX-4 is the same as PoX-3
    assert_eq!(actual_result, expected_result);

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(&reward_entry.signer.unwrap(), &signing_bytes.as_slice());
}

// In this test case, Alice delegates twice the stacking minimum to Bob.
//  Bob stacks half of Alice's funds. In the next cycle,
//  Bob stacks Alice's remaining funds.
//
// This test asserts that Alice's total-locked is equal to
//  twice the stacking minimum after calling delegate-stack-increase.
#[apply(nakamoto_cases)]
fn delegate_stack_increase(use_nakamoto: bool) {
    let lock_period: u128 = 2;
    let observer = TestEventObserver::new();
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let alice_nonce = 0;
    let alice_key = &keys[0];
    let alice_address = PrincipalData::from(key_to_stacks_addr(alice_key));
    let mut bob_nonce = 0;
    let bob_delegate_key = &keys[1];
    let bob_delegate_address = PrincipalData::from(key_to_stacks_addr(bob_delegate_key));
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let signer_sk = StacksPrivateKey::from_seed(&[1, 3, 3, 7]);
    let signer_pk = StacksPublicKey::from_private(&signer_sk);
    let signer_pk_bytes = signer_pk.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_pk_bytes.clone()).unwrap();

    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(bob_delegate_key).bytes,
    );

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let delegate_stx = make_pox_4_delegate_stx(
        alice_key,
        alice_nonce,
        2 * min_ustx,
        bob_delegate_address.clone(),
        None,
        Some(pox_addr.clone()),
    );

    let alice_principal = PrincipalData::from(key_to_stacks_addr(alice_key));

    let delegate_stack_stx = make_pox_4_delegate_stack_stx(
        bob_delegate_key,
        bob_nonce,
        alice_principal,
        min_ustx,
        pox_addr.clone(),
        block_height as u128,
        lock_period,
    );

    // Initial tx arr includes a delegate_stx & delegate_stack_stx pox_4 helper found in mod.rs
    let txs = vec![delegate_stx, delegate_stack_stx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    bob_nonce += 1;

    let delegate_increase = make_pox_4_delegate_stack_increase(
        bob_delegate_key,
        bob_nonce,
        &alice_address,
        pox_addr.clone(),
        min_ustx,
    );

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle.into(),
        &Pox4SignatureTopic::AggregationCommit,
        1_u128,
        u128::MAX,
        1,
    );

    let agg_tx = make_pox_4_contract_call(
        bob_delegate_key,
        bob_nonce + 1,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(next_reward_cycle.into()),
            (Value::some(Value::buff_from(signature).unwrap()).unwrap()),
            signer_key_val.clone(),
            Value::UInt(u128::MAX),
            Value::UInt(1),
        ],
    );

    // Next tx arr includes a delegate_increase pox_4 helper found in mod.rs
    let txs = vec![delegate_increase, agg_tx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let delegate_transactions =
        get_last_block_sender_transactions(&observer, key_to_stacks_addr(bob_delegate_key));

    let actual_result = delegate_transactions.first().cloned().unwrap().result;

    let expected_result = Value::okay(Value::Tuple(
        TupleData::from_data(vec![
            ("stacker".into(), Value::Principal(alice_address.clone())),
            ("total-locked".into(), Value::UInt(min_ustx * 2)),
        ])
        .unwrap(),
    ))
    .unwrap();

    // Testing stack_increase response is equal to expected response
    // Test is straightforward because 'stack-increase' in PoX-4 is the same as PoX-3
    assert_eq!(actual_result, expected_result);

    // test that the reward set contains the increased amount and the expected key
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), {
        if use_nakamoto {
            2
        } else {
            1
        }
    });
    let reward_entry = reward_set
        .iter()
        .find(|entry| entry.reward_address == pox_addr)
        .expect("No reward entry found");
    assert_eq!(pox_addr, reward_entry.reward_address);
    assert_eq!(min_ustx * 2, reward_entry.amount_stacked);
    assert_eq!(&reward_entry.signer.unwrap(), signer_pk_bytes.as_slice());
}

pub fn pox_4_scenario_test_setup<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    initial_balances: Vec<(PrincipalData, u64)>,
    use_nakamoto: bool,
) -> (
    TestPeer<'a>,
    usize,
    u64,
    u128,
    u128,
    u128,
    TestPeerConfig,
    Option<TestSigners>,
) {
    if use_nakamoto {
        return pox_4_scenario_test_setup_nakamoto(test_name, observer, initial_balances);
    }
    // Setup code extracted from your original test
    let test_signers = TestSigners::new(vec![]);
    let aggregate_public_key = test_signers.aggregate_public_key.clone();
    let mut peer_config = TestPeerConfig::new(function_name!(), 0, 0);
    let private_key = peer_config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    peer_config.aggregate_public_key = Some(aggregate_public_key.clone());
    peer_config
        .stacker_dbs
        .push(boot_code_id(MINERS_NAME, false));
    peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(1000));
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];
    peer_config
        .initial_balances
        .append(&mut initial_balances.clone());
    peer_config.burnchain.pox_constants.v2_unlock_height = 81;
    peer_config.burnchain.pox_constants.pox_3_activation_height = 101;
    peer_config.burnchain.pox_constants.v3_unlock_height = 102;
    peer_config.burnchain.pox_constants.pox_4_activation_height = 105;
    peer_config.test_signers = Some(test_signers.clone());
    peer_config.burnchain.pox_constants.reward_cycle_length = 20;
    peer_config.burnchain.pox_constants.prepare_length = 5;

    let mut peer = TestPeer::new_with_observer(peer_config.clone(), Some(&observer));

    let mut peer_nonce = 0;

    let reward_cycle_len = peer.config.burnchain.pox_constants.reward_cycle_length;
    let prepare_phase_len = peer.config.burnchain.pox_constants.prepare_length;

    let target_height = peer.config.burnchain.pox_constants.pox_4_activation_height;
    let mut latest_block = None;

    while peer.get_burn_block_height() < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut peer_nonce));
        observer.get_blocks();
    }
    let latest_block = latest_block.expect("Failed to get tip");

    let reward_cycle = get_current_reward_cycle(&peer, &peer.config.burnchain);
    let next_reward_cycle = reward_cycle.wrapping_add(1);
    let burn_block_height = peer.get_burn_block_height();
    let current_block_height = peer.config.current_block;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    (
        peer,
        peer_nonce,
        burn_block_height,
        reward_cycle as u128,
        next_reward_cycle as u128,
        min_ustx as u128,
        peer_config.clone(),
        None,
    )
}

pub fn pox_4_scenario_test_setup_nakamoto<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    initial_balances: Vec<(PrincipalData, u64)>,
) -> (
    TestPeer<'a>,
    usize,
    u64,
    u128,
    u128,
    u128,
    TestPeerConfig,
    Option<TestSigners>,
) {
    let (epochs, pox_constants) = make_test_epochs_pox(true);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (peer, keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        test_name,
        Some(epochs.clone()),
        Some(observer),
    );

    let test_key = keys[3].clone();
    let test_keys = vec![test_key.clone()];
    let test_addr = key_to_stacks_addr(&test_key);
    let test_signers = TestSigners::new(vec![test_key.clone()]);
    let aggregate_public_key = test_signers.aggregate_public_key.clone();

    let private_key = StacksPrivateKey::from_seed(&[2]);
    let test_signers = TestSigners::new(test_keys.clone());
    let addrs: Vec<StacksAddress> = test_keys.iter().map(key_to_stacks_addr).collect();
    let initial_stacker_balance = initial_balances
        .get(0)
        .expect("Expected at least 1 initial balance")
        .1;
    let test_stackers = vec![TestStacker {
        signer_private_key: test_key.clone(),
        stacker_private_key: test_key.clone(),
        amount: initial_stacker_balance as u128,
        pox_addr: Some(pox_addr_from(&test_key)),
        max_amount: None,
    }];
    let mut peer_config = TestPeerConfig::default();
    peer_config.aggregate_public_key = Some(aggregate_public_key.clone());
    let mut pox_constants = peer_config.clone().burnchain.pox_constants;
    pox_constants.reward_cycle_length = 10;
    pox_constants.v2_unlock_height = 21;
    pox_constants.pox_3_activation_height = 26;
    pox_constants.v3_unlock_height = 27;
    pox_constants.pox_4_activation_height = 41;
    pox_constants.prepare_length = 5;
    let mut boot_plan = NakamotoBootPlan::new(test_name)
        .with_test_stackers(test_stackers)
        .with_test_signers(test_signers.clone())
        .with_private_key(private_key);
    boot_plan.add_default_balance = false;

    boot_plan.initial_balances = initial_balances;
    boot_plan.pox_constants = pox_constants.clone();
    burnchain.pox_constants = pox_constants.clone();
    peer_config.burnchain = burnchain.clone();
    peer_config.test_signers = Some(test_signers.clone());

    info!("---- Booting into Nakamoto Peer ----");
    let mut peer = boot_plan.boot_into_nakamoto_peer(vec![], Some(observer));
    let sort_db = peer.sortdb.as_ref().unwrap();
    let latest_block = sort_db
        .index_handle_at_tip()
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();
    let coinbase_nonce = 0;

    let burn_block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let reward_cycle = burnchain
        .block_height_to_reward_cycle(burn_block_height)
        .unwrap() as u128;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    (
        peer,
        coinbase_nonce,
        burn_block_height,
        reward_cycle as u128,
        reward_cycle.wrapping_add(1),
        min_ustx as u128,
        peer_config.clone(),
        Some(test_signers),
    )
}

#[apply(nakamoto_cases)]
// In this test two solo stacker-signers Alice & Bob sign & stack
//  for two reward cycles. Alice provides a signature, Bob uses
//  'set-signer-key-authorizations' to authorize. Two cycles later,
//  when no longer stacked, they both try replaying their auths.
fn test_scenario_one(use_nakamoto: bool) {
    // Alice solo stacker-signer setup
    let mut alice = StackerSignerInfo::new();
    // Bob solo stacker-signer setup
    let mut bob = StackerSignerInfo::new();
    let default_initial_balances: u64 = 1_000_000_000_000_000_000;
    let initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
    ];

    let observer = TestEventObserver::new();
    let (
        mut peer,
        mut peer_nonce,
        burn_block_height,
        reward_cycle,
        next_reward_cycle,
        min_ustx,
        peer_config,
        mut test_signers,
    ) = pox_4_scenario_test_setup(
        "test_scenario_one",
        &observer,
        initial_balances,
        use_nakamoto,
    );

    // Add alice and bob to test_signers
    if let Some(ref mut test_signers) = test_signers.as_mut() {
        test_signers
            .signer_keys
            .extend(vec![alice.private_key.clone(), bob.private_key.clone()]);
    }

    // Alice Signatures
    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;
    let lock_period = 1;
    let alice_signature = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let alice_signature_err = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        reward_cycle - 1,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        100,
        2,
    );

    // Bob Authorizations
    let bob_authorization_low = make_pox_4_set_signer_key_auth(
        &bob.pox_address,
        &bob.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        true,
        bob.nonce,
        Some(&bob.private_key),
        100,
        2,
    );
    bob.nonce += 1;
    let bob_authorization = make_pox_4_set_signer_key_auth(
        &bob.pox_address,
        &bob.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        true,
        bob.nonce,
        Some(&bob.private_key),
        u128::MAX,
        3,
    );
    bob.nonce += 1;

    // Alice stacks
    let alice_err_nonce = alice.nonce;
    let alice_stack_err = make_pox_4_lockup(
        &alice.private_key,
        alice_err_nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_err),
        100,
        1,
    );

    let alice_stack_nonce = alice_err_nonce + 1;
    let alice_stack = make_pox_4_lockup(
        &alice.private_key,
        alice_stack_nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature.clone()),
        u128::MAX,
        1,
    );
    alice.nonce = alice_stack_nonce + 1;

    // Bob stacks
    let bob_nonce_stack_err = bob.nonce;
    let bob_stack_err = make_pox_4_lockup(
        &bob.private_key,
        bob_nonce_stack_err,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        None,
        100,
        2,
    );
    let bob_nonce_stack = bob_nonce_stack_err + 1;
    let bob_stack = make_pox_4_lockup(
        &bob.private_key,
        bob_nonce_stack,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        None,
        u128::MAX,
        3,
    );
    bob.nonce = bob_nonce_stack + 1;

    let txs = vec![
        bob_authorization_low,
        bob_authorization,
        alice_stack_err,
        alice_stack,
        bob_stack_err,
        bob_stack,
    ];

    // Commit tx & advance to the reward set calculation height (2nd block of the prepare phase)
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer.config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Verify Alice stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &alice.principal)
            .expect("Failed to find alice initial stack-stx");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, alice.pox_address);

    // Verify Bob stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &bob.principal)
            .expect("Failed to find bob initial stack-stx");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, bob.pox_address);

    // 1. Check bob's low authorization transaction
    let bob_tx_result_low = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_tx_result_low, Value::Bool(true));

    // 2. Check bob's expected authorization transaction
    let bob_tx_result_ok = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_tx_result_ok, Value::Bool(true));

    // 3. Check alice's low stack transaction
    let alice_tx_result_err = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_tx_result_err, Value::Int(38));

    // Get alice's expected stack transaction
    let alice_tx_result_ok = receipts
        .get(4)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // 4.1 Check amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = alice_tx_result_ok
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // 4.2 Check signer key
    let signer_key_expected = Value::buff_from(alice.public_key.to_bytes_compressed()).unwrap();
    let signer_key_actual = alice_tx_result_ok
        .data_map
        .get("signer-key")
        .unwrap()
        .clone();
    assert_eq!(signer_key_expected, signer_key_actual);

    // 4.3 Check unlock height
    let unlock_height_expected = Value::UInt(
        peer.config
            .burnchain
            .reward_cycle_to_block_height(next_reward_cycle as u64 + lock_period as u64)
            .wrapping_sub(1) as u128,
    );
    let unlock_height_actual = alice_tx_result_ok
        .data_map
        .get("unlock-burn-height")
        .unwrap()
        .clone();
    assert_eq!(unlock_height_expected, unlock_height_actual);

    // 5. Check bob's error stack transaction
    let bob_tx_result_err = receipts
        .get(5)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(bob_tx_result_err, Value::Int(38));

    // Get bob's expected stack transaction
    let bob_tx_result_ok = receipts
        .get(6)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // 6.1 Check amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = bob_tx_result_ok
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // 6.2 Check signer key
    let signer_key_expected = Value::buff_from(bob.public_key.to_bytes_compressed()).unwrap();
    let signer_key_actual = bob_tx_result_ok.data_map.get("signer-key").unwrap().clone();
    assert_eq!(signer_key_expected, signer_key_actual);

    // 6.3 Check unlock height (end of cycle 7 - block 140)
    let unlock_height_expected = Value::UInt(
        peer.config
            .burnchain
            .reward_cycle_to_block_height((next_reward_cycle + lock_period) as u64)
            .wrapping_sub(1) as u128,
    );
    let unlock_height_actual = bob_tx_result_ok
        .data_map
        .get("unlock-burn-height")
        .unwrap()
        .clone();
    assert_eq!(unlock_height_expected, unlock_height_actual);

    // Now starting create vote txs
    // Fetch signer indices in reward cycle 6
    let alice_index = get_signer_index(
        &mut peer,
        latest_block,
        alice.address.clone(),
        next_reward_cycle,
    );
    let bob_index = get_signer_index(
        &mut peer,
        latest_block,
        bob.address.clone(),
        next_reward_cycle,
    );
    // Alice vote
    let alice_vote = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    alice.nonce += 1;
    // Bob vote
    let bob_vote = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    bob.nonce += 1;
    let mut txs = vec![alice_vote, bob_vote];

    // Also vote for aggregate key with default test signer if in Nakamoto:
    if let Some(test_signers) = test_signers.clone() {
        let tester_key = test_signers.signer_keys[0];
        let tester_addr = key_to_stacks_addr(&tester_key);
        let tester_index = get_signer_index(
            &mut peer,
            latest_block,
            tester_addr.clone(),
            next_reward_cycle,
        );
        let tester_vote = make_signers_vote_for_aggregate_public_key(
            &tester_key,
            1, // only tx is a stack-stx
            tester_index,
            peer_config.aggregate_public_key.unwrap(),
            1,
            next_reward_cycle,
        );
        txs.push(tester_vote);
    }

    let target_reward_cycle = next_reward_cycle + 1;
    // Commit vote txs & advance to the first burn block of reward cycle 8 (block 161)
    let mut target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(target_reward_cycle as u64);
    info!(
        "Submitting block with vote transactions and advancing to reward cycle {} at block {}",
        target_reward_cycle, target_height
    );
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    let approved_key = get_approved_aggregate_key(&mut peer, latest_block, next_reward_cycle)
        .expect("No approved key found");

    // Start replay transactions
    // Alice stacks with a replayed signature
    let alice_replay_nonce = alice.nonce;
    let alice_stack_replay = make_pox_4_lockup(
        &alice.private_key,
        alice_replay_nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        target_height,
        Some(alice_signature.clone()),
        u128::MAX,
        1,
    );
    // Bob stacks with a replayed authorization
    let bob_nonce_stack_replay = bob.nonce;
    let bob_stack_replay = make_pox_4_lockup(
        &bob.private_key,
        bob_nonce_stack_replay,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        target_height,
        None,
        u128::MAX,
        3,
    );
    let txs = vec![alice_stack_replay, bob_stack_replay];

    // Commit replay txs & advance to the second burn block of reward cycle 8 (block 162)
    target_height += 1;
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check Alice replay, expect (err 35) - ERR_INVALID_SIGNATURE_PUBKEY
    let alice_replay_result = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_replay_result, Value::Int(35));

    // Check Bob replay, expect (err 19) - ERR_SIGNER_AUTH_USED
    let bob_tx_result = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(bob_tx_result, Value::Int(19));
}

// In this test two solo service signers, Alice & Bob, provide auth
//  for Carl & Dave, solo stackers. Alice provides a signature for Carl,
//  Bob uses 'set-signer-key...' for Dave.
#[apply(nakamoto_cases)]
fn test_scenario_two(use_nakamoto: bool) {
    // Alice service signer setup
    let mut alice = StackerSignerInfo::new();
    // Bob service signer setup
    let mut bob = StackerSignerInfo::new();
    // Carl solo stacker setup
    let mut carl = StackerSignerInfo::new();
    // Dave solo stacker setup
    let mut dave = StackerSignerInfo::new();

    let default_initial_balances = 1_000_000_000_000_000_000;
    let initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
        (carl.principal.clone(), default_initial_balances),
        (dave.principal.clone(), default_initial_balances),
    ];
    let observer = TestEventObserver::new();
    let (
        mut peer,
        mut peer_nonce,
        burn_block_height,
        reward_cycle,
        next_reward_cycle,
        min_ustx,
        peer_config,
        mut test_signers,
    ) = pox_4_scenario_test_setup(
        "test_scenario_two",
        &observer,
        initial_balances,
        use_nakamoto,
    );

    // Add to test signers
    if let Some(ref mut test_signers) = test_signers.as_mut() {
        test_signers
            .signer_keys
            .extend(vec![alice.private_key.clone(), bob.private_key.clone()]);
    }

    // Alice Signature For Carl
    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;
    let lock_period = 1;
    let alice_signature_for_carl = make_signer_key_signature(
        &carl.pox_address,
        &alice.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    // Bob Authorization For Dave
    let bob_authorization_for_dave = make_pox_4_set_signer_key_auth(
        &dave.pox_address,
        &bob.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        true,
        bob.nonce,
        Some(&bob.private_key),
        u128::MAX,
        1,
    );
    bob.nonce += 1;

    // Carl Stacks w/ Alices Signature - Malformed (lock period)
    let carl_stack_err = make_pox_4_lockup(
        &carl.private_key,
        carl.nonce,
        amount,
        &carl.pox_address,
        lock_period + 1,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_for_carl.clone()),
        u128::MAX,
        1,
    );
    carl.nonce += 1;

    // Carl Stacks w/ Alices Signature
    let carl_stack = make_pox_4_lockup(
        &carl.private_key,
        carl.nonce,
        amount,
        &carl.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_for_carl.clone()),
        u128::MAX,
        1,
    );
    carl.nonce += 1;

    // Dave Stacks w/ Bobs Authorization - Malformed (pox)
    let dave_stack_err = make_pox_4_lockup(
        &dave.private_key,
        dave.nonce,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        None,
        u128::MAX,
        1,
    );
    dave.nonce += 1;

    // Dave Stacks w/ Bobs Authorization
    let dave_stack = make_pox_4_lockup(
        &dave.private_key,
        dave.nonce,
        amount,
        &dave.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        None,
        u128::MAX,
        1,
    );
    dave.nonce += 1;

    let txs = vec![
        bob_authorization_for_dave,
        carl_stack_err,
        carl_stack,
        dave_stack_err,
        dave_stack,
    ];

    // Commit tx & advance to the reward set calculation height (2nd block of the prepare phase for reward cycle 6)
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Verify Carl Stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &carl.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, carl.pox_address);

    // Verify Dave Stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &dave.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, dave.pox_address);

    // Check Carl's malformed signature stack transaction (err 35 - INVALID_SIGNATURE_PUBKEY)
    let carl_tx_result_err = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(carl_tx_result_err, Value::Int(35));

    // Check Carl's expected stack transaction
    let carl_tx_result_ok = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Carl amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = carl_tx_result_ok
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Carl signer key
    let signer_key_expected = Value::buff_from(alice.public_key.to_bytes_compressed()).unwrap();
    let signer_key_actual = carl_tx_result_ok
        .data_map
        .get("signer-key")
        .unwrap()
        .clone();
    assert_eq!(signer_key_expected, signer_key_actual);

    // Check Dave's malformed pox stack transaction (err 19 - INVALID_SIGNER_AUTH)
    let dave_tx_result_err = receipts
        .get(4)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(dave_tx_result_err, Value::Int(19));

    // Check Dave's expected stack transaction
    let dave_tx_result_ok = receipts
        .get(5)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Dave amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = dave_tx_result_ok
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Dave signer key
    let signer_key_expected = Value::buff_from(bob.public_key.to_bytes_compressed()).unwrap();
    let signer_key_actual = dave_tx_result_ok
        .data_map
        .get("signer-key")
        .unwrap()
        .clone();
    assert_eq!(signer_key_expected, signer_key_actual);

    // Now starting create vote txs
    // Fetch signer indices in reward cycle 6
    let alice_index = get_signer_index(
        &mut peer,
        latest_block,
        alice.address.clone(),
        next_reward_cycle,
    );
    let bob_index = get_signer_index(
        &mut peer,
        latest_block,
        bob.address.clone(),
        next_reward_cycle,
    );
    // Alice expected vote
    let alice_vote_expected = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    alice.nonce += 1;
    // Alice duplicate vote
    let alice_vote_duplicate = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    alice.nonce += 1;
    // Bob vote err (err 17 - INVALID_ROUND)
    let bob_vote_err = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        3,
        next_reward_cycle,
    );
    bob.nonce += 1;
    // Bob expected vote
    let bob_vote_expected = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.unwrap(),
        1,
        next_reward_cycle,
    );
    bob.nonce += 1;
    let txs = vec![
        alice_vote_expected,
        alice_vote_duplicate,
        bob_vote_err,
        bob_vote_expected,
    ];

    let target_reward_cycle = next_reward_cycle;
    // Commit vote txs & advance to the first burn block of reward cycle 8 (block 161)
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(target_reward_cycle as u64);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check Alice's expected vote
    let alice_expected_vote = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(alice_expected_vote, Value::Bool(true));

    // Check Alice's duplicate vote (err 15 - DUPLICATE_ROUND)
    let alice_duplicate_vote = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_duplicate_vote, Value::UInt(15));

    // Check Bob's round err vote (err 17 - INVALID_ROUND)
    let bob_round_err_vote = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(bob_round_err_vote, Value::UInt(17));

    // Check Bob's expected vote
    let bob_expected_vote = receipts
        .get(4)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_expected_vote, Value::Bool(true));
}

#[apply(nakamoto_cases)]
// In this scenario, two solo stacker-signers (Alice, Bob), one service signer (Carl),
//  one stacking pool operator (Dave), & three pool stackers (Eve, Frank, Grace).
fn test_scenario_three(use_nakamoto: bool) {
    // Alice stacker signer setup
    let mut alice = StackerSignerInfo::new();
    // Bob stacker signer setup
    let mut bob = StackerSignerInfo::new();
    // Carl service signer setup
    let carl = StackerSignerInfo::new();
    // David stacking pool operator setup
    let mut david = StackerSignerInfo::new();
    // Eve pool stacker setup
    let mut eve = StackerSignerInfo::new();
    // Frank pool stacker setup
    let mut frank = StackerSignerInfo::new();
    // Grace pool stacker setup
    let mut grace = StackerSignerInfo::new();

    let default_initial_balances = 1_000_000_000_000_000_000;
    let initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
        (carl.principal.clone(), default_initial_balances),
        (david.principal.clone(), default_initial_balances),
        (eve.principal.clone(), default_initial_balances),
        (frank.principal.clone(), default_initial_balances),
        (grace.principal.clone(), default_initial_balances),
    ];
    let observer = TestEventObserver::new();
    let (
        mut peer,
        mut peer_nonce,
        burn_block_height,
        reward_cycle,
        next_reward_cycle,
        min_ustx,
        peer_config,
        mut test_signers,
    ) = pox_4_scenario_test_setup(
        "test_scenario_three",
        &observer,
        initial_balances,
        use_nakamoto,
    );

    // Add to test signers
    if let Some(ref mut test_signers) = test_signers.as_mut() {
        test_signers.signer_keys.extend(vec![
            alice.private_key.clone(),
            bob.private_key.clone(),
            carl.private_key.clone(),
        ]);
    }

    let lock_period = 2;
    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;
    let alice_signature_for_alice_err = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        13,
        u128::MAX,
        1,
    );
    let alice_signature_for_alice_expected = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let bob_signature_for_bob_err = make_signer_key_signature(
        &bob.pox_address,
        &bob.private_key,
        reward_cycle - 1,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let bob_signature_for_bob_expected = make_signer_key_signature(
        &bob.pox_address,
        &bob.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    let carl_signature_for_david_err = make_signer_key_signature(
        &david.pox_address,
        &carl.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        1,
        u128::MAX,
        1,
    );
    let carl_signature_for_david = make_signer_key_signature(
        &david.pox_address,
        &carl.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        1,
    );
    // Alice solo stack, error
    let alice_stack_tx_err = make_pox_4_lockup(
        &alice.private_key,
        alice.nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_for_alice_err.clone()),
        u128::MAX,
        1,
    );
    alice.nonce += 1;
    // Alice solo stack
    let alice_stack_tx_expected = make_pox_4_lockup(
        &alice.private_key,
        alice.nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_for_alice_expected),
        u128::MAX,
        1,
    );
    alice.nonce += 1;
    // Bob solo stack, error
    let bob_stack_tx_err = make_pox_4_lockup(
        &bob.private_key,
        bob.nonce,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        Some(bob_signature_for_bob_err.clone()),
        u128::MAX,
        1,
    );
    bob.nonce += 1;
    // Bob solo stack
    let bob_stack_tx_expected = make_pox_4_lockup(
        &bob.private_key,
        bob.nonce,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        Some(bob_signature_for_bob_expected),
        u128::MAX,
        1,
    );
    bob.nonce += 1;
    // Eve pool stacker delegating STX to David
    let eve_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &eve.private_key,
        eve.nonce,
        amount,
        david.principal.clone(),
        Some(
            peer.config
                .burnchain
                .reward_cycle_to_block_height(next_reward_cycle as u64)
                .into(),
        ),
        Some(david.pox_address.clone()),
    );
    eve.nonce += 1;
    // Frank pool stacker delegating STX to David
    let frank_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &frank.private_key,
        frank.nonce,
        amount,
        david.principal.clone(),
        None,
        Some(david.pox_address.clone()),
    );
    frank.nonce += 1;
    // Grace pool stacker delegating STX to David
    let grace_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &grace.private_key,
        grace.nonce,
        amount,
        david.principal.clone(),
        None,
        Some(david.pox_address.clone()),
    );
    grace.nonce += 1;
    // Alice error delegating while stacked
    let alice_delegate_stx_to_david_err = make_pox_4_delegate_stx(
        &alice.private_key,
        alice.nonce,
        amount,
        david.principal.clone(),
        None,
        Some(david.pox_address.clone()),
    );
    // Collecting all the pool stackers
    let davids_stackers = &[
        (eve.clone(), lock_period),
        (frank.clone(), lock_period),
        (grace.clone(), lock_period),
        (alice.clone(), lock_period),
    ];
    let davids_delegate_stack_stx_txs: Vec<_> = davids_stackers
        .iter()
        .map(|(stacker, lock_period)| {
            let tx = make_pox_4_delegate_stack_stx(
                &david.private_key,
                david.nonce,
                stacker.principal.clone(),
                amount,
                david.pox_address.clone(),
                burn_block_height as u128,
                *lock_period,
            );
            david.nonce += 1;
            tx
        })
        .collect();
    // Aggregate commit david's pool stackers, error by committing for two cycles
    let davids_aggregate_commit_index_tx_err_cycles = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle.wrapping_add(1),
        Some(carl_signature_for_david.clone()),
        &carl.public_key,
        u128::MAX,
        1,
    );
    david.nonce += 1;
    // Aggregate commit david's pool stackers, error by committing for two cycles
    let davids_aggregate_commit_index_tx_err_signature = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle,
        Some(carl_signature_for_david_err.clone()),
        &carl.public_key,
        u128::MAX,
        1,
    );
    david.nonce += 1;
    // Aggregate commit david's pool stackers correctly
    let davids_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle,
        Some(carl_signature_for_david.clone()),
        &carl.public_key,
        u128::MAX,
        1,
    );
    david.nonce += 1;

    let mut txs = vec![
        alice_stack_tx_err,
        alice_stack_tx_expected,
        bob_stack_tx_err,
        bob_stack_tx_expected,
        eve_delegate_stx_to_david_tx,
        frank_delegate_stx_to_david_tx,
        grace_delegate_stx_to_david_tx,
        alice_delegate_stx_to_david_err,
    ];
    txs.extend(davids_delegate_stack_stx_txs);
    txs.extend(vec![
        davids_aggregate_commit_index_tx_err_cycles,
        davids_aggregate_commit_index_tx_err_signature,
        davids_aggregate_commit_index_tx,
    ]);

    // Commit txs in next block & advance to reward set calculation of the next reward cycle
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Start of test checks
    // 1. Check that Alice can't stack with an lock_period different than signature
    let alice_stack_tx_err = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_stack_tx_err, Value::Int(35));

    // 2. Check that Alice can solo stack-sign
    let alice_stack_tx_ok = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Alice amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = alice_stack_tx_ok
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Alice signer key
    let signer_key_expected = Value::buff_from(alice.public_key.to_bytes_compressed()).unwrap();
    let signer_key_actual = alice_stack_tx_ok
        .data_map
        .get("signer-key")
        .unwrap()
        .clone();
    assert_eq!(signer_key_expected, signer_key_actual);

    // 3. Check that Bob can't stack with a signature that points to a reward cycle in the past
    let bob_stack_tx_err = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(bob_stack_tx_err, Value::Int(35));

    // 4. Check that Bob can solo stack-sign
    let bob_stack_tx_ok = receipts
        .get(4)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Bob amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = bob_stack_tx_ok.data_map.get("lock-amount").unwrap().clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Bob signer key
    let signer_key_expected = Value::buff_from(bob.public_key.to_bytes_compressed());
    let signer_key_actual = bob_stack_tx_ok.data_map.get("signer-key").unwrap().clone();
    assert_eq!(signer_key_actual, signer_key_actual);

    // 5. Check that David can't delegate-stack-stx Eve if delegation expires during lock period
    let eve_delegate_stx_to_david_err = receipts
        .get(9)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(eve_delegate_stx_to_david_err, Value::Int(21));

    // 6. Check that Frank is correctly delegated to David
    let frank_delegate_stx_to_david_tx = receipts
        .get(10)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Frank amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = frank_delegate_stx_to_david_tx
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Frank stacker address
    let stacker_expected = Value::Principal(frank.address.clone().into());
    let stacker_actual = frank_delegate_stx_to_david_tx
        .data_map
        .get("stacker")
        .unwrap()
        .clone();
    assert_eq!(stacker_expected, stacker_actual);

    // 7. Check that Grace is correctly delegated to David
    let grace_delegate_stx_to_david_tx = receipts
        .get(11)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap()
        .expect_tuple()
        .unwrap();

    // Check Grace amount locked
    let amount_locked_expected = Value::UInt(amount);
    let amount_locked_actual = grace_delegate_stx_to_david_tx
        .data_map
        .get("lock-amount")
        .unwrap()
        .clone();
    assert_eq!(amount_locked_actual, amount_locked_expected);

    // Check Grace stacker address
    let stacker_expected = Value::Principal(grace.address.clone().into());
    let stacker_actual = grace_delegate_stx_to_david_tx
        .data_map
        .get("stacker")
        .unwrap()
        .clone();
    assert_eq!(stacker_expected, stacker_actual);

    // 8. Check that Alice can't delegate-stack if already stacking
    let alice_delegate_stx_to_david_err = receipts
        .get(12)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_delegate_stx_to_david_err, Value::Int(3));

    // 9. Check that David can't aggregate-commit-indexed if pointing to a reward cycle in the future
    let david_aggregate_commit_indexed_err = receipts
        .get(13)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(david_aggregate_commit_indexed_err, Value::Int(35));

    // 10. Check that David can aggregate-commit-indexed if using the incorrect signature topic
    let david_aggregate_commit_indexed_err = receipts
        .get(14)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(david_aggregate_commit_indexed_err, Value::Int(35));

    let david_index = if use_nakamoto { 3 } else { 2 };

    // 11. Check that David can aggregate-commit-indexed successfully, checking stacking index = 2
    let david_aggregate_commit_indexed_ok = receipts
        .get(15)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(david_aggregate_commit_indexed_ok, Value::UInt(david_index));
}

#[apply(nakamoto_cases)]
// In this test scenario two solo stacker-signers (Alice & Bob),
//  test out the updated stack-extend & stack-increase functions
//  across multiple cycles.
fn test_scenario_four(use_nakamoto: bool) {
    // Alice service signer setup
    let mut alice = StackerSignerInfo::new();
    // Bob service signer setup
    let mut bob = StackerSignerInfo::new();

    let default_initial_balances = 1_000_000_000_000_000_000;
    let initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
    ];
    let observer = TestEventObserver::new();
    let (
        mut peer,
        mut peer_nonce,
        burn_block_height,
        reward_cycle,
        next_reward_cycle,
        min_ustx,
        peer_config,
        mut test_signers,
    ) = pox_4_scenario_test_setup(
        "test_scenario_four",
        &observer,
        initial_balances,
        use_nakamoto,
    );

    // Add to test signers
    if let Some(ref mut test_signers) = test_signers.as_mut() {
        test_signers
            .signer_keys
            .extend(vec![alice.private_key.clone(), bob.private_key.clone()]);
    }

    // Initial Alice Signature
    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;
    let lock_period = 2;
    let alice_signature_initial = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    // Extend Alice Signature Err (meant for Bob)
    let alice_signature_extend_err = make_signer_key_signature(
        &bob.pox_address,
        &bob.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        lock_period,
        u128::MAX,
        1,
    );
    info!(
        "Generating stack-extend signature for cycle {}",
        next_reward_cycle
    );
    // Extend Alice Signature Expected
    let alice_signature_extend = make_signer_key_signature(
        &alice.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        lock_period,
        u128::MAX,
        1,
    );
    // Initial Bob Signature
    let bob_signature_initial = make_signer_key_signature(
        &bob.pox_address,
        &bob.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        lock_period,
        u128::MAX,
        1,
    );
    // Alice initial stack
    let alice_stack = make_pox_4_lockup(
        &alice.private_key,
        alice.nonce,
        amount,
        &alice.pox_address,
        lock_period,
        &alice.public_key,
        burn_block_height,
        Some(alice_signature_initial.clone()),
        u128::MAX,
        1,
    );
    alice.nonce += 1;
    // Bob initial stack
    let bob_stack = make_pox_4_lockup(
        &bob.private_key,
        bob.nonce,
        amount,
        &bob.pox_address,
        lock_period,
        &bob.public_key,
        burn_block_height,
        Some(bob_signature_initial.clone()),
        u128::MAX,
        1,
    );
    bob.nonce += 1;

    let txs = vec![alice_stack.clone(), bob_stack.clone()];

    // Commit tx & advance to the reward set calculation height (2nd block of the prepare phase for reward cycle 6)
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Verify Alice Stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &alice.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, alice.pox_address);

    // Verify Bob Stacked
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &bob.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, bob.pox_address);

    // Now starting create vote txs
    // Fetch signer indices in reward cycle 6
    let alice_index = get_signer_index(
        &mut peer,
        latest_block,
        alice.address.clone(),
        next_reward_cycle,
    );
    let bob_index = get_signer_index(
        &mut peer,
        latest_block,
        bob.address.clone(),
        next_reward_cycle,
    );
    // Alice err vote
    let alice_vote_err = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    alice.nonce += 1;
    // Alice expected vote
    let alice_vote_expected = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    alice.nonce += 1;
    // Bob expected vote
    let bob_vote_expected = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    bob.nonce += 1;
    let mut txs = vec![
        alice_vote_err.clone(),
        alice_vote_expected.clone(),
        bob_vote_expected.clone(),
    ];

    // Also vote for aggregate key with default test signer if in Nakamoto:
    if let Some(test_signers) = test_signers.clone() {
        let tester_key = test_signers.signer_keys[0];
        let tester_addr = key_to_stacks_addr(&tester_key);
        let tester_index = get_signer_index(
            &mut peer,
            latest_block,
            tester_addr.clone(),
            next_reward_cycle,
        );
        let tester_vote = make_signers_vote_for_aggregate_public_key(
            &tester_key,
            1, // only tx is a stack-stx
            tester_index,
            peer_config.aggregate_public_key.clone().unwrap(),
            1,
            next_reward_cycle,
        );
        txs.push(tester_vote);
    }

    // Commit vote txs & move to the prepare phase of reward cycle 7 (block 155)
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64 + 1)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check Alice's err vote (err 10 - INVALID_SIGNER_INDEX)
    let alice_err_vote = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_err_vote, Value::UInt(10));

    // Check Alice's expected vote
    let alice_expected_vote = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(alice_expected_vote, Value::Bool(true));

    // Check Bob's expected vote
    let bob_expected_vote = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    assert_eq!(bob_expected_vote, Value::Bool(true));

    let approved_key = get_approved_aggregate_key(&mut peer, latest_block, next_reward_cycle)
        .expect("No approved key found");
    assert_eq!(
        approved_key,
        peer_config.aggregate_public_key.clone().unwrap()
    );

    // Alice stack-extend err tx
    let alice_extend_err = make_pox_4_extend(
        &alice.private_key,
        alice.nonce,
        alice.pox_address.clone(),
        lock_period,
        bob.public_key.clone(),
        Some(alice_signature_extend_err.clone()),
        u128::MAX,
        1,
    );
    alice.nonce += 1;
    // Alice stack-extend tx
    let alice_extend = make_pox_4_extend(
        &alice.private_key,
        alice.nonce,
        alice.pox_address.clone(),
        lock_period,
        alice.public_key.clone(),
        Some(alice_signature_extend.clone()),
        u128::MAX,
        1,
    );
    alice.nonce += 1;
    // Now starting second round of vote txs
    // Fetch signer indices in reward cycle 7
    let alice_index = get_signer_index(&mut peer, latest_block, alice.address.clone(), 7);
    // Alice err vote
    let alice_vote_expected_err = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        7,
    );
    alice.nonce += 1;

    let txs = vec![
        alice_extend_err.clone(),
        alice_extend.clone(),
        alice_vote_expected_err.clone(),
    ];
    let target_height = target_height.wrapping_add(1);
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check Alice's err stack-extend tx (err 35 - INVALID_SIGNATURE_PUBKEY)
    let alice_err_extend = receipts
        .get(1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_err_extend, Value::Int(35));

    // Check Alice's stack-extend tx
    let alice_extend_receipt = receipts
        .get(2)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();

    // Check Alice's expected err vote (err 14 - DUPLICATE_AGGREGATE_PUBLIC_KEY)
    let alice_expected_vote_err = receipts
        .get(3)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
    assert_eq!(alice_expected_vote_err, Value::UInt(14));

    // Get approved key & assert that it wasn't sent (None)
    let approved_key = get_approved_aggregate_key(&mut peer, latest_block, 7);
    assert_eq!(approved_key, None);
}

// In this test case, Alice delegates twice the stacking minimum to Bob.
//  Bob stacks Alice's funds, and then immediately tries to stacks-aggregation-increase.
//  This should return a clarity user error.
#[apply(nakamoto_cases)]
fn delegate_stack_increase_err(use_nakamoto: bool) {
    let lock_period: u128 = 2;
    let observer = TestEventObserver::new();
    let (
        burnchain,
        mut peer,
        keys,
        latest_block,
        block_height,
        mut coinbase_nonce,
        mut test_signers,
    ) = prepare_pox4_test(function_name!(), Some(&observer), use_nakamoto);

    let alice_nonce = 0;
    let alice_key = &keys[0];
    let alice_address = PrincipalData::from(key_to_stacks_addr(alice_key));
    let mut bob_nonce = 0;
    let bob_delegate_key = &keys[1];
    let bob_delegate_address = PrincipalData::from(key_to_stacks_addr(bob_delegate_key));
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let signer_sk = StacksPrivateKey::from_seed(&[1, 3, 3, 7]);
    let signer_pk = StacksPublicKey::from_private(&signer_sk);
    let signer_pk_bytes = signer_pk.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_pk_bytes.clone()).unwrap();

    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(bob_delegate_key).bytes,
    );

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let delegate_stx = make_pox_4_delegate_stx(
        alice_key,
        alice_nonce,
        2 * min_ustx,
        bob_delegate_address.clone(),
        None,
        Some(pox_addr.clone()),
    );

    let alice_principal = PrincipalData::from(key_to_stacks_addr(alice_key));

    let delegate_stack_stx = make_pox_4_delegate_stack_stx(
        bob_delegate_key,
        bob_nonce,
        alice_principal,
        min_ustx * 2,
        pox_addr.clone(),
        block_height as u128,
        lock_period,
    );

    let txs = vec![delegate_stx, delegate_stack_stx];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    bob_nonce += 1;

    let signature = make_signer_key_signature(
        &pox_addr,
        &signer_sk,
        next_reward_cycle.into(),
        &Pox4SignatureTopic::AggregationIncrease,
        1_u128,
        u128::MAX,
        1,
    );

    let slot_idx = if use_nakamoto { 1 } else { 0 };

    // Bob's Aggregate Increase
    let bobs_aggregate_increase = make_pox_4_aggregation_increase(
        &bob_delegate_key,
        bob_nonce,
        &pox_addr,
        next_reward_cycle.into(),
        slot_idx,
        Some(signature),
        &signer_pk,
        u128::MAX,
        1,
    );

    let txs = vec![bobs_aggregate_increase];

    let latest_block = tenure_with_txs(&mut peer, &txs, &mut coinbase_nonce, &mut test_signers);

    let delegate_transactions =
        get_last_block_sender_transactions(&observer, key_to_stacks_addr(bob_delegate_key));

    let actual_result = delegate_transactions.first().cloned().unwrap().result;

    // Should be a DELEGATION NO REWARD SLOT error
    let expected_result = Value::error(Value::Int(28)).unwrap();

    assert_eq!(actual_result, expected_result);

    // test that the reward set is empty
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    if use_nakamoto {
        assert_eq!(reward_set.len(), 1);
    } else {
        assert!(reward_set.is_empty());
    }
}

pub fn get_stacking_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> Option<Value> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = Value::Tuple(
            TupleData::from_data(vec![("stacker".into(), account.clone().into())]).unwrap(),
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "stacking-state",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
    })
}

pub fn make_signer_key_authorization_lookup_key(
    pox_addr: &PoxAddress,
    reward_cycle: u64,
    topic: &Pox4SignatureTopic,
    period: u128,
    signer_key: &StacksPublicKey,
    max_amount: u128,
    auth_id: u128,
) -> Value {
    TupleData::from_data(vec![
        (
            "pox-addr".into(),
            pox_addr.as_clarity_tuple().unwrap().into(),
        ),
        ("reward-cycle".into(), Value::UInt(reward_cycle.into())),
        (
            "topic".into(),
            Value::string_ascii_from_bytes(topic.get_name_str().into()).unwrap(),
        ),
        ("period".into(), Value::UInt(period)),
        (
            "signer-key".into(),
            Value::buff_from(signer_key.to_bytes_compressed()).unwrap(),
        ),
        ("max-amount".into(), Value::UInt(max_amount)),
        ("auth-id".into(), Value::UInt(auth_id)),
    ])
    .unwrap()
    .into()
}

pub fn get_signer_key_authorization_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    pox_addr: &PoxAddress,
    reward_cycle: u64,
    topic: &Pox4SignatureTopic,
    period: u128,
    signer_key: &StacksPublicKey,
    max_amount: u128,
    auth_id: u128,
) -> Option<bool> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = make_signer_key_authorization_lookup_key(
            &pox_addr,
            reward_cycle,
            &topic,
            period,
            &signer_key,
            max_amount,
            auth_id,
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "signer-key-authorizations",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
        .map(|v| v.expect_bool().unwrap())
    })
}

/// Lookup in the `used-signer-key-authorizations` map
/// for a specific signer key authorization. If no entry is
/// found, `false` is returned.
pub fn get_signer_key_authorization_used_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    pox_addr: &PoxAddress,
    reward_cycle: u64,
    topic: &Pox4SignatureTopic,
    period: u128,
    signer_key: &StacksPublicKey,
    max_amount: u128,
    auth_id: u128,
) -> bool {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = make_signer_key_authorization_lookup_key(
            &pox_addr,
            reward_cycle,
            &topic,
            period,
            &signer_key,
            max_amount,
            auth_id,
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "used-signer-key-authorizations",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
        .map(|v| v.expect_bool().unwrap())
    })
    .unwrap_or(false)
}

pub fn get_partially_stacked_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    pox_addr: &PoxAddress,
    reward_cycle: u64,
    sender: &StacksAddress,
) -> Option<u128> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = TupleData::from_data(vec![
            (
                "pox-addr".into(),
                pox_addr.as_clarity_tuple().unwrap().into(),
            ),
            ("reward-cycle".into(), Value::UInt(reward_cycle.into())),
            ("sender".into(), PrincipalData::from(sender.clone()).into()),
        ])
        .unwrap()
        .into();
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "partial-stacked-by-cycle",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
        .map(|v| {
            v.expect_tuple()
                .unwrap()
                .get_owned("stacked-amount")
                .unwrap()
                .expect_u128()
                .unwrap()
        })
    })
}

pub fn get_delegation_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> Option<Value> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = Value::Tuple(
            TupleData::from_data(vec![("stacker".into(), account.clone().into())]).unwrap(),
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "delegation-state",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
    })
}

pub fn get_stacking_minimum(peer: &mut TestPeer, latest_block: &StacksBlockId) -> u128 {
    with_sortdb(peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &latest_block)
    })
    .unwrap()
}

pub fn prepare_pox4_test<'a>(
    test_name: &str,
    observer: Option<&'a TestEventObserver>,
    use_nakamoto: bool,
) -> (
    Burnchain,
    TestPeer<'a>,
    Vec<StacksPrivateKey>,
    StacksBlockId,
    u64,
    usize,
    Option<TestSigners>,
) {
    let (epochs, pox_constants) = make_test_epochs_pox(use_nakamoto);

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, test_name, Some(epochs.clone()), observer);

    if use_nakamoto {
        let test_key = keys[3].clone();
        let test_keys = vec![test_key.clone()];

        let private_key = StacksPrivateKey::from_seed(&[2]);
        let test_signers = TestSigners::new(test_keys.clone());
        let test_stackers = test_keys
            .iter()
            .map(|key| TestStacker {
                signer_private_key: key.clone(),
                stacker_private_key: key.clone(),
                amount: 1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr: Some(pox_addr_from(&key)),
                max_amount: None,
            })
            .collect::<Vec<_>>();
        let mut pox_constants = TestPeerConfig::default().burnchain.pox_constants;
        pox_constants.reward_cycle_length = 10;
        pox_constants.v2_unlock_height = 21;
        pox_constants.pox_3_activation_height = 26;
        pox_constants.v3_unlock_height = 27;
        pox_constants.pox_4_activation_height = 41;
        pox_constants.prepare_length = 5;
        let mut boot_plan = NakamotoBootPlan::new(test_name)
            .with_test_stackers(test_stackers)
            .with_test_signers(test_signers.clone())
            .with_private_key(private_key);
        boot_plan.add_default_balance = false;
        let addrs: Vec<StacksAddress> = keys.iter().map(key_to_stacks_addr).collect();

        let balances: Vec<(PrincipalData, u64)> = addrs
            .clone()
            .into_iter()
            .map(|addr| (addr.into(), (1024 * POX_THRESHOLD_STEPS_USTX) as u64))
            .collect();
        boot_plan.initial_balances = balances;
        boot_plan.pox_constants = pox_constants.clone();
        burnchain.pox_constants = pox_constants.clone();

        info!("---- Booting into Nakamoto Peer ----");
        let peer = boot_plan.boot_into_nakamoto_peer(vec![], observer);
        let sort_db = peer.sortdb.as_ref().unwrap();
        let latest_block = sort_db
            .index_handle_at_tip()
            .get_nakamoto_tip_block_id()
            .unwrap()
            .unwrap();
        let coinbase_nonce = 0;

        let block_height = get_tip(peer.sortdb.as_ref()).block_height;

        info!("Block height: {}", block_height);

        (
            burnchain,
            peer,
            keys,
            latest_block,
            block_height,
            coinbase_nonce,
            Some(test_signers),
        )
    } else {
        // Advance into pox4
        let target_height = burnchain.pox_constants.pox_4_activation_height;
        let mut coinbase_nonce = 0;
        let mut latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // if we reach epoch 2.1, perform the check
            if get_tip(peer.sortdb.as_ref()).block_height
                > epochs[StacksEpochId::Epoch21].start_height
            {
                assert_latest_was_burn(&mut peer);
            }
        }
        let block_height = get_tip(peer.sortdb.as_ref()).block_height;
        (
            burnchain,
            peer,
            keys,
            latest_block,
            block_height,
            coinbase_nonce,
            None,
        )
    }
}

pub fn tenure_with_txs(
    peer: &mut TestPeer,
    txs: &[StacksTransaction],
    coinbase_nonce: &mut usize,
    test_signers: &mut Option<TestSigners>,
) -> StacksBlockId {
    if let Some(test_signers) = test_signers {
        let (burn_ops, mut tenure_change, miner_key) =
            peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

        tenure_change.tenure_consensus_hash = consensus_hash.clone();
        tenure_change.burn_view_consensus_hash = consensus_hash.clone();

        let tenure_change_tx = peer
            .miner
            .make_nakamoto_tenure_change(tenure_change.clone());
        let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

        let blocks_and_sizes = peer.make_nakamoto_tenure(
            tenure_change_tx,
            coinbase_tx,
            test_signers,
            |_miner, _chainstate, _sort_dbconn, _blocks| {
                info!("Building nakamoto block. Blocks len {}", _blocks.len());
                if _blocks.is_empty() {
                    txs.to_vec()
                } else {
                    vec![]
                }
            },
        );
        let blocks: Vec<_> = blocks_and_sizes
            .into_iter()
            .map(|(block, _, _)| block)
            .collect();

        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let latest_block = sort_db
            .index_handle_at_tip()
            .get_nakamoto_tip_block_id()
            .unwrap()
            .unwrap();
        latest_block
    } else {
        peer.tenure_with_txs(txs, coinbase_nonce)
    }
}

pub fn get_last_block_sender_transactions(
    observer: &TestEventObserver,
    address: StacksAddress,
) -> Vec<StacksTransactionReceipt> {
    observer
        .get_blocks()
        .last()
        .unwrap()
        .clone()
        .receipts
        .into_iter()
        .filter(|receipt| {
            if let TransactionOrigin::Stacks(ref transaction) = receipt.transaction {
                return transaction.auth.origin().address_testnet() == address;
            }
            false
        })
        .collect::<Vec<_>>()
}

/// In this test case, two Stackers, Alice and Bob stack in PoX 4. Alice stacks enough
///  to qualify for slots, but Bob does not. In PoX-2 and PoX-3, this would result
///  in an auto unlock, but PoX-4 it should not.
#[test]
fn missed_slots_no_unlock() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, mut pox_constants) = make_test_epochs_pox(false);
    pox_constants.pox_4_activation_height =
        u32::try_from(epochs[StacksEpochId::Epoch25].start_height).unwrap() + 1;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants = None;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);

    let mut coinbase_nonce = 0;

    let first_v4_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_4_activation_height as u64)
        .unwrap()
        + 1;

    // produce blocks until epoch 2.5
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[StacksEpochId::Epoch25].start_height
    {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // perform lockups so we can test that pox-4 does not exhibit unlock-on-miss behavior
    let tip = get_tip(peer.sortdb.as_ref());

    let alice_lockup =
        make_simple_pox_4_lock(&alice, &mut peer, 1024 * POX_THRESHOLD_STEPS_USTX, 6);

    let bob_lockup = make_simple_pox_4_lock(&bob, &mut peer, 1 * POX_THRESHOLD_STEPS_USTX, 6);

    let txs = [alice_lockup, bob_lockup];
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice and bob
    //  for the pox-4 cycles
    for cycle_number in first_v4_cycle..first_v4_cycle + 6 {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(
            reward_set_entries.len(),
            2,
            "Reward set should contain two entries in cycle {cycle_number}"
        );
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            bob_address.bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            alice_address.bytes.0.to_vec()
        );
    }

    // we'll produce blocks until the next reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(first_v4_cycle) + 1;
    let auto_unlock_coinbase = height_target - 1 - EMPTY_SORTITIONS;

    // but first, check that bob has locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &bob_address.to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward sets for all cycles contain entries for alice and bob still!
    for cycle_number in first_v4_cycle..(first_v4_cycle + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            bob_address.bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            alice_address.bytes.0.to_vec()
        );
    }

    let expected_unlock_height = burnchain.reward_cycle_to_block_height(first_v4_cycle + 6) - 1;
    // now check that bob has an unlock height of `height_target`
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &bob_address.to_account_principal(),
    );
    assert_eq!(bob_bal.unlock_height(), expected_unlock_height);
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    let alice_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &alice_address.to_account_principal(),
    );
    assert_eq!(alice_bal.unlock_height(), expected_unlock_height);
    assert_eq!(alice_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX * 1024);

    // check that the total reward cycle amounts have not decremented
    for cycle_number in first_v4_cycle..(first_v4_cycle + 6) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            1025 * POX_THRESHOLD_STEPS_USTX
        );
    }

    // check that bob's stacking-state is gone and alice's stacking-state is correct
    let bob_state = get_stacking_state_pox(
        &mut peer,
        &latest_block,
        &bob_address.to_account_principal(),
        PoxVersions::Pox4.get_name_str(),
    )
    .expect("Bob should have stacking-state entry")
    .expect_tuple()
    .unwrap();
    let reward_indexes_str = bob_state.get("reward-set-indexes").unwrap().to_string();
    assert_eq!(reward_indexes_str, "(u1 u1 u1 u1 u1 u1)");

    let alice_state = get_stacking_state_pox(
        &mut peer,
        &latest_block,
        &alice_address.to_account_principal(),
        PoxVersions::Pox4.get_name_str(),
    )
    .expect("Alice should have stacking-state entry")
    .expect_tuple()
    .unwrap();
    let reward_indexes_str = alice_state.get("reward-set-indexes").unwrap().to_string();
    assert_eq!(reward_indexes_str, "(u0 u0 u0 u0 u0 u0)");

    // check that bob is still locked at next block
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &bob_address.to_account_principal(),
    );
    assert_eq!(bob_bal.unlock_height(), expected_unlock_height);
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    // now let's check some tx receipts

    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut coinbase_txs = vec![];
    let mut reward_cycles_in_2_5 = 0u64;

    for b in blocks.into_iter() {
        if let Some(ref reward_set_data) = b.reward_set_data {
            let signers_set = reward_set_data.reward_set.signers.as_ref().unwrap();
            assert_eq!(signers_set.len(), 1);
            assert_eq!(
                StacksPublicKey::from_private(&alice).to_bytes_compressed(),
                signers_set[0].signing_key.to_vec()
            );
            let rewarded_addrs = HashSet::<_>::from_iter(
                reward_set_data
                    .reward_set
                    .rewarded_addresses
                    .iter()
                    .map(|a| a.to_burnchain_repr()),
            );
            assert_eq!(rewarded_addrs.len(), 1);
            assert_eq!(
                reward_set_data.reward_set.rewarded_addresses[0].bytes(),
                alice_address.bytes.0.to_vec(),
            );
            reward_cycles_in_2_5 += 1;
            eprintln!("{:?}", b.reward_set_data)
        }

        for (i, r) in b.receipts.into_iter().enumerate() {
            if i == 0 {
                coinbase_txs.push(r);
                continue;
            }
            match r.transaction {
                TransactionOrigin::Stacks(ref t) => {
                    let addr = t.auth.origin().address_testnet();
                    if addr == alice_address {
                        alice_txs.insert(t.auth.get_origin_nonce(), r);
                    } else if addr == bob_address {
                        bob_txs.insert(t.auth.get_origin_nonce(), r);
                    }
                }
                _ => {}
            }
        }
    }

    assert_eq!(alice_txs.len(), 1);
    assert_eq!(bob_txs.len(), 1);
    // only mined one 2.5 reward cycle, but make sure it was picked up in the events loop above
    assert_eq!(reward_cycles_in_2_5, 1);

    //  all should have committedd okay
    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    // Check that the event produced by "handle-unlock" has a well-formed print event
    // and that this event is included as part of the coinbase tx
    for unlock_coinbase_index in [auto_unlock_coinbase] {
        // expect the unlock to occur 1 block after the handle-unlock method was invoked.
        let expected_unlock_height = unlock_coinbase_index + EMPTY_SORTITIONS + 1;
        let expected_cycle = pox_constants
            .block_height_to_reward_cycle(0, expected_unlock_height)
            .unwrap();
        assert!(
            coinbase_txs[unlock_coinbase_index as usize].events.is_empty(),
            "handle-unlock events are coinbase events and there should be no handle-unlock invocation in this test"
        );
    }
}

/// In this test case, we lockup enough to get participation to be non-zero, but not enough to qualify for a reward slot.
#[test]
fn no_lockups_2_5() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, mut pox_constants) = make_test_epochs_pox(false);
    pox_constants.pox_4_activation_height =
        u32::try_from(epochs[StacksEpochId::Epoch25].start_height).unwrap() + 1;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants = None;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);

    let mut coinbase_nonce = 0;

    let first_v4_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_4_activation_height as u64)
        .unwrap()
        + 1;

    // produce blocks until epoch 2.5
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[StacksEpochId::Epoch25].start_height
    {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_simple_pox_4_lock(&bob, &mut peer, 1 * POX_THRESHOLD_STEPS_USTX, 6);

    let txs = [bob_lockup];
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // check that the "raw" reward set will contain an entry for bob
    for cycle_number in first_v4_cycle..first_v4_cycle + 6 {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(
            reward_set_entries.len(),
            1,
            "Reward set should contain one entry in cycle {cycle_number}"
        );
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            bob_address.bytes.0.to_vec()
        );
    }

    // we'll produce blocks until the next reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(first_v4_cycle + 1) + 1;
    let auto_unlock_coinbase = height_target - 1 - EMPTY_SORTITIONS;

    // but first, check that bob has locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &bob_address.to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let blocks = observer.get_blocks();
    for b in blocks.into_iter() {
        if let Some(ref reward_set_data) = b.reward_set_data {
            assert_eq!(reward_set_data.reward_set.signers, Some(vec![]));
            assert!(reward_set_data.reward_set.rewarded_addresses.is_empty());
            eprintln!("{:?}", b.reward_set_data)
        }
    }
}

// In this scenario, two service signers (Alice, Bob), one stacker-signer (Carl), two stacking pool operators (Dave, Eve), & six pool stackers (Frank, Grace, Heidi, Ivan, Judy, Mallory).

// First Nakamoto Reward Cycle
// First Nakamoto Tenure

// 1. Franks stacks for 1 reward cycle, Grace stacks for 2 reward cycles & so on…Mallory stacks for 6 reward cycles: (so 6 wallets stacking n, n+1, n+2… cycles)
// 2. Dave asks Alice for 3 signatures
// 3. Eve asks Bob for 3 set-authorizations
// 4. Ivan - Mallory ask Bob to set-approval-authorization
// 5. Carl stx-stacks & self-signs for 3 reward cycle
// 6. In Carl's second reward cycle, he calls stx-extend for 3 more reward cycles
// 7. In Carl's third reward cycle, he calls stx-increase and should fail as he is straddling 2 keys
#[apply(nakamoto_cases)]
fn test_scenario_five(use_nakamoto: bool) {
    // Alice service signer setup
    let mut alice = StackerSignerInfo::new();
    // Bob service signer setup
    let mut bob = StackerSignerInfo::new();
    // Carl solo stacker and signer setup
    let mut carl = StackerSignerInfo::new();
    // David stacking pool operator (delegating signing to Alice) Setup
    let mut david = StackerSignerInfo::new();
    // Eve stacking pool operator (delegating signing to Bob) Setup
    let mut eve = StackerSignerInfo::new();
    // Frank pool stacker delegating STX to David
    let mut frank = StackerSignerInfo::new();
    // Grace pool stacker delegating STX to David
    let mut grace = StackerSignerInfo::new();
    // Heidi pool stacker delegating STX to David
    let mut heidi = StackerSignerInfo::new();
    // Ivan pool stacker delegating STX to Eve
    let mut ivan = StackerSignerInfo::new();
    // Jude pool stacker delegating STX to Eve
    let mut jude = StackerSignerInfo::new();
    // Mallory pool stacker delegating STX to Eve
    let mut mallory = StackerSignerInfo::new();

    let default_initial_balances = 1_000_000_000_000_000_000;
    let initial_balances = vec![
        (alice.principal.clone(), default_initial_balances),
        (bob.principal.clone(), default_initial_balances),
        (carl.principal.clone(), default_initial_balances),
        (david.principal.clone(), default_initial_balances),
        (eve.principal.clone(), default_initial_balances),
        (frank.principal.clone(), default_initial_balances),
        (grace.principal.clone(), default_initial_balances),
        (heidi.principal.clone(), default_initial_balances),
        (ivan.principal.clone(), default_initial_balances),
        (jude.principal.clone(), default_initial_balances),
        (mallory.principal.clone(), default_initial_balances),
    ];
    let observer = TestEventObserver::new();
    let (
        mut peer,
        mut peer_nonce,
        burn_block_height,
        reward_cycle,
        next_reward_cycle,
        min_ustx,
        mut peer_config,
        mut test_signers,
    ) = pox_4_scenario_test_setup(
        "test_scenario_five",
        &observer,
        initial_balances,
        use_nakamoto,
    );

    // Add to test signers
    if let Some(ref mut test_signers) = test_signers.as_mut() {
        test_signers.signer_keys.extend(vec![
            alice.private_key.clone(),
            bob.private_key.clone(),
            carl.private_key.clone(),
            david.private_key.clone(),
            eve.private_key.clone(),
        ]);
    }

    // Lock periods for each stacker
    let carl_lock_period = 3;
    let frank_lock_period = 1;
    let grace_lock_period = 2;
    let heidi_lock_period = 3;
    let ivan_lock_period = 4;
    let jude_lock_period = 5;
    let mallory_lock_period = 6;

    let carl_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(carl_lock_period) as u64)
        as u128;
    let frank_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(frank_lock_period) as u64)
        as u128;
    let grace_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(grace_lock_period) as u64)
        as u128;
    let heidi_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(heidi_lock_period) as u64)
        as u128;
    let ivan_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(ivan_lock_period) as u64)
        as u128;
    let jude_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(jude_lock_period) as u64)
        as u128;
    let mallory_end_burn_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle.wrapping_add(mallory_lock_period) as u64)
        as u128;

    // The pool operators should delegate their signing power for as long as their longest stacker
    let david_lock_period = heidi_lock_period;
    let eve_lock_period = mallory_lock_period;

    let amount = (default_initial_balances / 2).wrapping_sub(1000) as u128;
    let carl_signature_for_carl = make_signer_key_signature(
        &carl.pox_address,
        &carl.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackStx,
        carl_lock_period,
        u128::MAX,
        1,
    );
    let carl_stack_tx = make_pox_4_lockup(
        &carl.private_key,
        carl.nonce,
        amount,
        &carl.pox_address,
        carl_lock_period,
        &carl.public_key,
        burn_block_height,
        Some(carl_signature_for_carl),
        u128::MAX,
        1,
    );
    carl.nonce += 1;

    // Frank pool stacker delegating STX to David
    let frank_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &frank.private_key,
        frank.nonce,
        amount,
        david.principal.clone(),
        Some(frank_end_burn_height),
        Some(david.pox_address.clone()),
    );
    frank.nonce += 1;

    // Grace pool stacker delegating STX to David
    let grace_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &grace.private_key,
        grace.nonce,
        amount,
        david.principal.clone(),
        Some(grace_end_burn_height),
        Some(david.pox_address.clone()),
    );
    grace.nonce += 1;

    // Heidi pool stacker delegating STX to David
    let heidi_delegate_stx_to_david_tx = make_pox_4_delegate_stx(
        &heidi.private_key,
        heidi.nonce,
        amount,
        david.principal.clone(),
        Some(heidi_end_burn_height),
        Some(david.pox_address.clone()),
    );
    heidi.nonce += 1;

    // Ivan pool stacker delegating STX to Eve
    let ivan_delegate_stx_to_eve_tx = make_pox_4_delegate_stx(
        &ivan.private_key,
        ivan.nonce,
        amount,
        eve.principal.clone(),
        Some(ivan_end_burn_height),
        Some(eve.pox_address.clone()),
    );
    ivan.nonce += 1;

    // Jude pool stacker delegating STX to Eve
    let jude_delegate_stx_to_eve_tx = make_pox_4_delegate_stx(
        &jude.private_key,
        jude.nonce,
        amount,
        eve.principal.clone(),
        Some(jude_end_burn_height),
        Some(eve.pox_address.clone()),
    );
    jude.nonce += 1;

    // Mallory pool stacker delegating STX to Eve
    let mallory_delegate_stx_to_eve_tx = make_pox_4_delegate_stx(
        &mallory.private_key,
        mallory.nonce,
        amount,
        eve.principal.clone(),
        Some(mallory_end_burn_height),
        Some(eve.pox_address.clone()),
    );
    mallory.nonce += 1;

    let davids_stackers = &[
        (frank.clone(), frank_lock_period),
        (grace.clone(), grace_lock_period),
        (heidi.clone(), heidi_lock_period),
    ];
    let eves_stackers = &[
        (ivan.clone(), ivan_lock_period),
        (jude.clone(), jude_lock_period),
        (mallory.clone(), mallory_lock_period),
    ];

    // David calls 'delegate-stack-stx' for each of his stackers
    let davids_delegate_stack_stx_txs: Vec<_> = davids_stackers
        .iter()
        .map(|(stacker, lock_period)| {
            let tx = make_pox_4_delegate_stack_stx(
                &david.private_key,
                david.nonce,
                stacker.principal.clone(),
                amount,
                david.pox_address.clone(),
                burn_block_height as u128,
                *lock_period,
            );
            david.nonce += 1;
            tx
        })
        .collect();

    // Eve calls 'delegate-stack-stx' for each of her stackers
    let eves_delegate_stack_stx_txs: Vec<_> = eves_stackers
        .iter()
        .map(|(stacker, lock_period)| {
            let tx = make_pox_4_delegate_stack_stx(
                &eve.private_key,
                eve.nonce,
                stacker.principal.clone(),
                amount,
                eve.pox_address.clone(),
                burn_block_height as u128,
                *lock_period, // Must be called every reward cycle, therefore only ever lasts for 1 lock period
            );
            eve.nonce += 1;
            tx
        })
        .collect();

    // Alice's authorization for David to aggregate commit
    let alice_authorization_for_david = make_signer_key_signature(
        &david.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        1,
    );

    // David aggregate commits
    let davids_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle,
        Some(alice_authorization_for_david),
        &alice.public_key,
        u128::MAX,
        1,
    );
    david.nonce += 1;

    // Bob's authorization for Eve to aggregate commit
    let bob_authorization_for_eve = make_signer_key_signature(
        &eve.pox_address,
        &bob.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        1,
    );

    // Eve aggregate commits
    let eves_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &eve.private_key,
        eve.nonce,
        &eve.pox_address,
        next_reward_cycle,
        Some(bob_authorization_for_eve),
        &bob.public_key,
        u128::MAX,
        1,
    );
    eve.nonce += 1;

    let mut txs = vec![
        frank_delegate_stx_to_david_tx,
        grace_delegate_stx_to_david_tx,
        heidi_delegate_stx_to_david_tx,
        ivan_delegate_stx_to_eve_tx,
        jude_delegate_stx_to_eve_tx,
        mallory_delegate_stx_to_eve_tx,
        carl_stack_tx,
    ];
    txs.extend(davids_delegate_stack_stx_txs);
    txs.extend(eves_delegate_stack_stx_txs);
    txs.extend(vec![
        davids_aggregate_commit_index_tx,
        eves_aggregate_commit_index_tx,
    ]);

    // Advance to reward set calculation of the next reward cycle
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    info!(
        "Scenario five: submitting stacking txs.";
        "target_height" => target_height,
        "next_reward_cycle" => next_reward_cycle,
        "prepare_length" => peer_config.burnchain.pox_constants.prepare_length,
    );
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check that all of David's stackers have been added to the reward set
    for (stacker, stacker_lock_period) in davids_stackers {
        let (pox_address, first_reward_cycle, lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal).expect("Failed to find stacker");
        assert_eq!(first_reward_cycle, next_reward_cycle);
        assert_eq!(pox_address, david.pox_address);
        assert_eq!(lock_period, *stacker_lock_period);
    }

    // Check that all of Eve's stackers have been added to the reward set
    for (stacker, stacker_lock_period) in eves_stackers {
        let (pox_address, first_reward_cycle, lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal).expect("Failed to find stacker");
        assert_eq!(first_reward_cycle, next_reward_cycle);
        assert_eq!(pox_address, eve.pox_address);
        assert_eq!(lock_period, *stacker_lock_period);
    }
    // Check that Carl's stacker has been added to the reward set
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &carl.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, next_reward_cycle);
    assert_eq!(pox_address, carl.pox_address);
    assert_eq!(lock_period, carl_lock_period);

    // Verify stacker transactions
    let mut observed_txs = HashSet::new();
    for tx_receipt in tx_block.receipts {
        if let TransactionOrigin::Stacks(ref tx) = tx_receipt.transaction {
            observed_txs.insert(tx.txid());
        }
    }

    for tx in &txs {
        let txid = tx.txid();
        if !observed_txs.contains(&txid) {
            panic!("Failed to find stacking transaction ({txid}) in observed transactions")
        }
    }

    let cycle_id = next_reward_cycle;
    // Create vote txs for each signer
    let alice_index = get_signer_index(&mut peer, latest_block, alice.address.clone(), cycle_id);
    let bob_index = get_signer_index(&mut peer, latest_block, bob.address.clone(), cycle_id);
    let carl_index = get_signer_index(&mut peer, latest_block, carl.address.clone(), cycle_id);
    let alice_vote = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let bob_vote = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let carl_vote = make_signers_vote_for_aggregate_public_key(
        &carl.private_key,
        carl.nonce,
        carl_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let vote_txs = vec![alice_vote, bob_vote, carl_vote];
    alice.nonce += 1;
    bob.nonce += 1;
    carl.nonce += 1;
    // Mine vote txs & advance to the reward set calculation of the next reward cycle
    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64);
    info!(
        "Scenario five: submitting votes. Target height: {}",
        target_height
    );
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &vote_txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    let mut observed_txs = HashSet::new();
    for tx_receipt in tx_block.receipts {
        if let TransactionOrigin::Stacks(ref tx) = tx_receipt.transaction {
            observed_txs.insert(tx.txid());
        }
    }

    for tx in &vote_txs {
        let txid = tx.txid();
        if !observed_txs.contains(&txid) {
            panic!("Failed to find vote transaction ({txid}) in observed transactions")
        }
    }
    let approved_key = get_approved_aggregate_key(&mut peer, latest_block, next_reward_cycle)
        .expect("No approved key found");
    assert_eq!(approved_key, peer_config.aggregate_public_key.unwrap());

    // Stack for following reward cycle again and then advance to epoch 3.0 activation boundary
    let reward_cycle = peer.get_reward_cycle() as u128;
    let next_reward_cycle = reward_cycle.wrapping_add(1);
    let carl_lock_period = carl_lock_period.wrapping_add(3); // Carl's total lock period is now 5
    let carl_signature_for_carl = make_signer_key_signature(
        &carl.pox_address,
        &carl.private_key,
        reward_cycle,
        &Pox4SignatureTopic::StackExtend,
        3,
        u128::MAX,
        2,
    );
    // Carl extends his lock period by 3 cycles
    let carl_extend_tx = make_pox_4_extend(
        &carl.private_key,
        carl.nonce,
        carl.pox_address.clone(),
        3,
        carl.public_key,
        Some(carl_signature_for_carl),
        u128::MAX,
        2,
    );
    carl.nonce += 1;
    let alice_authorization_for_david = make_signer_key_signature(
        &david.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        2,
    );
    // David commits his aggregate for the next reward cycle
    let davids_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle,
        Some(alice_authorization_for_david),
        &alice.public_key,
        u128::MAX,
        2,
    );
    david.nonce += 1;

    let bob_authorization_for_eve = make_signer_key_signature(
        &eve.pox_address,
        &bob.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        2,
    );
    // Eve commits her aggregate for the next reward cycle
    let eves_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &eve.private_key,
        eve.nonce,
        &eve.pox_address,
        next_reward_cycle,
        Some(bob_authorization_for_eve),
        &bob.public_key,
        u128::MAX,
        2,
    );
    eve.nonce += 1;

    let txs = vec![
        carl_extend_tx,
        davids_aggregate_commit_index_tx,
        eves_aggregate_commit_index_tx,
    ];

    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    info!(
        "Scenario five: submitting extend and aggregate commit txs. Target height: {}",
        target_height
    );
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    // Check that all of David's stackers are stacked
    for (idx, (stacker, stacker_lock_period)) in davids_stackers.iter().enumerate() {
        let (pox_address, first_reward_cycle, lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal)
                .expect(format!("Failed to find stacker {}", idx).as_str());
        assert_eq!(first_reward_cycle, reward_cycle);
        assert_eq!(pox_address, david.pox_address);
        assert_eq!(lock_period, *stacker_lock_period);
    }
    // Check that all of Eve's stackers are stacked
    for (idx, (stacker, stacker_lock_period)) in eves_stackers.iter().enumerate() {
        let (pox_address, first_reward_cycle, lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal)
                .expect(format!("Failed to find stacker {}", idx).as_str());
        assert_eq!(first_reward_cycle, reward_cycle);
        assert_eq!(pox_address, eve.pox_address);
        assert_eq!(lock_period, *stacker_lock_period);
    }
    let (pox_address, first_reward_cycle, lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &carl.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, reward_cycle);
    assert_eq!(pox_address, carl.pox_address);
    assert_eq!(lock_period, carl_lock_period);

    // Verify stacker transactions
    let mut observed_txs = HashSet::new();
    for tx_receipt in tx_block.receipts {
        if let TransactionOrigin::Stacks(ref tx) = tx_receipt.transaction {
            observed_txs.insert(tx.txid());
        }
    }

    for tx in &txs {
        let txid = tx.txid();
        if !observed_txs.contains(&txid) {
            panic!("Failed to find stacking transaction ({txid}) in observed transactions")
        }
    }

    let cycle_id = next_reward_cycle;
    // Generate next cycle aggregate public key
    peer_config.aggregate_public_key = Some(
        peer_config
            .test_signers
            .unwrap()
            .generate_aggregate_key(cycle_id as u64),
    );
    // create vote txs
    let alice_index = get_signer_index(&mut peer, latest_block, alice.address.clone(), cycle_id);
    let bob_index = get_signer_index(&mut peer, latest_block, bob.address.clone(), cycle_id);
    let carl_index = get_signer_index(&mut peer, latest_block, carl.address.clone(), cycle_id);
    let alice_vote = make_signers_vote_for_aggregate_public_key(
        &alice.private_key,
        alice.nonce,
        alice_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let bob_vote = make_signers_vote_for_aggregate_public_key(
        &bob.private_key,
        bob.nonce,
        bob_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let carl_vote = make_signers_vote_for_aggregate_public_key(
        &carl.private_key,
        carl.nonce,
        carl_index,
        peer_config.aggregate_public_key.clone().unwrap(),
        1,
        next_reward_cycle,
    );
    let vote_txs = vec![alice_vote, bob_vote, carl_vote];
    alice.nonce += 1;
    bob.nonce += 1;
    carl.nonce += 1;

    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64);
    // Submit vote transactions
    info!(
        "Scenario five: submitting votes. Target height: {}",
        target_height
    );
    let (latest_block, tx_block, _receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &vote_txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    let mut observed_txs = HashSet::new();
    for tx_receipt in tx_block.receipts {
        if let TransactionOrigin::Stacks(ref tx) = tx_receipt.transaction {
            observed_txs.insert(tx.txid());
        }
    }

    for tx in &vote_txs {
        let txid = tx.txid();
        if !observed_txs.contains(&txid) {
            panic!("Failed to find vote transaction ({txid}) in observed transactions")
        }
    }
    let approved_key = get_approved_aggregate_key(&mut peer, latest_block, next_reward_cycle)
        .expect("No approved key found");
    assert_eq!(approved_key, peer_config.aggregate_public_key.unwrap());

    // Let us start stacking for the following reward cycle
    let current_reward_cycle = peer.get_reward_cycle() as u128;
    let next_reward_cycle = current_reward_cycle.wrapping_add(1);

    let alice_authorization_for_david = make_signer_key_signature(
        &david.pox_address,
        &alice.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        3,
    );

    let davids_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &david.private_key,
        david.nonce,
        &david.pox_address,
        next_reward_cycle,
        Some(alice_authorization_for_david),
        &alice.public_key,
        u128::MAX,
        3,
    );
    david.nonce += 1;

    let bob_authorization_for_eve = make_signer_key_signature(
        &eve.pox_address,
        &bob.private_key,
        next_reward_cycle,
        &Pox4SignatureTopic::AggregationCommit,
        1,
        u128::MAX,
        3,
    );

    let eves_aggregate_commit_index_tx = make_pox_4_aggregation_commit_indexed(
        &eve.private_key,
        eve.nonce,
        &eve.pox_address,
        next_reward_cycle,
        Some(bob_authorization_for_eve),
        &bob.public_key,
        u128::MAX,
        3,
    );
    eve.nonce += 1;

    // Carl attempts a stx-increase using Alice's key instead of his own
    // Should fail as he already has delegated his signing power to himself
    let alice_signature_for_carl = make_signer_key_signature(
        &carl.pox_address,
        &alice.private_key,
        current_reward_cycle,
        &Pox4SignatureTopic::StackIncrease,
        carl_lock_period,
        u128::MAX,
        4,
    );

    let carl_increase_tx = make_pox_4_stack_increase(
        &carl.private_key,
        carl.nonce,
        amount,
        &alice.public_key,
        Some(alice_signature_for_carl),
        u128::MAX,
        4,
    );
    carl.nonce += 1;

    let txs = vec![
        carl_increase_tx,
        davids_aggregate_commit_index_tx,
        eves_aggregate_commit_index_tx,
    ];

    let target_height = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(next_reward_cycle as u64)
        .saturating_sub(peer_config.burnchain.pox_constants.prepare_length as u64)
        .wrapping_add(2);
    // This assertion just makes testing logic a bit easier
    let davids_stackers = &[
        (grace.clone(), grace_lock_period),
        (heidi.clone(), heidi_lock_period),
    ];

    info!("Scenario five: submitting increase and aggregate-commit txs");
    let (latest_block, tx_block, receipts) = advance_to_block_height(
        &mut peer,
        &observer,
        &txs,
        &mut peer_nonce,
        target_height,
        &mut test_signers,
    );

    for (stacker, _) in davids_stackers {
        let (pox_address, first_reward_cycle, _lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal).expect("Failed to find stacker");
        assert_eq!(first_reward_cycle, reward_cycle);
        assert_eq!(pox_address, david.pox_address);
    }
    // Frank should no longer be considered a stacker as his lock period has expired
    assert!(get_stacker_info_pox_4(&mut peer, &frank.principal).is_none());

    for (stacker, _) in eves_stackers {
        let (pox_address, first_reward_cycle, _lock_period, _indices) =
            get_stacker_info_pox_4(&mut peer, &stacker.principal).expect("Failed to find stacker");
        assert_eq!(first_reward_cycle, reward_cycle);
        assert_eq!(pox_address, eve.pox_address);
    }

    let (pox_address, first_reward_cycle, _lock_period, _indices) =
        get_stacker_info_pox_4(&mut peer, &carl.principal).expect("Failed to find stacker");
    assert_eq!(first_reward_cycle, reward_cycle);
    assert_eq!(pox_address, carl.pox_address);

    // Assert that carl's error is err(40)
    let carl_increase_err = receipts[1].clone().result;
    assert_eq!(carl_increase_err, Value::error(Value::Int(40)).unwrap());
}
