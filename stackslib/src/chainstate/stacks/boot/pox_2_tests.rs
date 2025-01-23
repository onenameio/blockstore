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
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::tests::{execute, is_committed, is_err_code, symbols_from_values};
use clarity::vm::types::Value::Response;
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    StacksAddressExtensions, StandardPrincipalData, TupleData, TupleTypeSignature, TypeSignature,
    Value, NONE,
};
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::Address;
use stacks_common::util::hash::{hex_bytes, to_hex, Sha256Sum, Sha512Trunc256Sum};

use super::test::*;
use super::RawRewardSetEntry;
use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::{
    BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET, POX_2_NAME,
    POX_3_NAME,
};
use crate::chainstate::stacks::db::{
    MinerPaymentSchedule, StacksChainState, StacksDBConn, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::TransactionOrigin;
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::tests::make_coinbase;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::{ClarityBlockConnection, Error as ClarityError};
use crate::clarity_vm::database::marf::{MarfedKV, WritableMarfStore};
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{DBConn, FromRow};

const USTX_PER_HOLDER: u128 = 1_000_000;

/// Return the BlockSnapshot for the latest sortition in the provided
///  SortitionDB option-reference. Panics on any errors.
fn get_tip(sortdb: Option<&SortitionDB>) -> BlockSnapshot {
    SortitionDB::get_canonical_burn_chain_tip(&sortdb.unwrap().conn()).unwrap()
}

/// Get the reward set entries if evaluated at the given StacksBlock
pub fn get_reward_set_entries_at(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    at_burn_ht: u64,
) -> Vec<RawRewardSetEntry> {
    let burnchain = peer.config.burnchain.clone();
    with_sortdb(peer, |ref mut c, ref sortdb| {
        get_reward_set_entries_at_block(c, &burnchain, sortdb, tip, at_burn_ht).unwrap()
    })
}

/// Get the reward set entries if evaluated at the given StacksBlock
///  in order of index in the reward-cycle-address-list map
pub fn get_reward_set_entries_index_order_at(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    at_burn_ht: u64,
) -> Vec<RawRewardSetEntry> {
    let burnchain = peer.config.burnchain.clone();
    with_sortdb(peer, |ref mut c, ref sortdb| {
        c.get_reward_addresses(&burnchain, sortdb, at_burn_ht, tip)
            .unwrap()
    })
}

/// Get the canonicalized STXBalance for `account` at the given chaintip
pub fn get_stx_account_at(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> STXBalance {
    with_clarity_db_ro(peer, tip, |db| {
        db.get_stx_balance_snapshot(account)
            .unwrap()
            .canonical_balance_repr()
            .unwrap()
    })
}

/// get the stacking-state entry for an account at the chaintip
pub fn get_stacking_state_pox(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
    pox_contract: &str,
) -> Option<Value> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = Value::Tuple(
            TupleData::from_data(vec![("stacker".into(), account.clone().into())]).unwrap(),
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(pox_contract, false),
            "stacking-state",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
    })
}

/// Get the pox-2 stacking-state entry for `account` at the given chaintip
pub fn get_stacking_state_pox_2(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> Option<Value> {
    get_stacking_state_pox(peer, tip, account, boot::POX_2_NAME)
}

/// Perform `check_stacker_link_invariants` on cycles [first_cycle_number, max_cycle_number]
pub fn check_all_stacker_link_invariants(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    first_cycle_number: u64,
    max_cycle_number: u64,
) {
    // if PoX-2 hasn't published yet, just return.
    let epoch = with_clarity_db_ro(peer, tip, |db| db.get_clarity_epoch_version()).unwrap();
    if epoch < StacksEpochId::Epoch21 {
        eprintln!("Skipping invariant checks when PoX-2 has not published yet");
        return;
    } else {
        eprintln!("Invariants being checked");
    }

    info!("Invoked check all"; "tip" => %tip, "first" => first_cycle_number, "last" => max_cycle_number);
    for cycle in first_cycle_number..(max_cycle_number + 1) {
        // check if it makes sense to test invariants yet.
        // For cycles where PoX-3 is active, check if Epoch24 has activated first.
        let active_pox_contract = peer
            .config
            .burnchain
            .pox_constants
            .active_pox_contract(peer.config.burnchain.reward_cycle_to_block_height(cycle));
        if active_pox_contract == POX_3_NAME && epoch < StacksEpochId::Epoch24 {
            info!(
                "Skipping check on a PoX-3 reward cycle because Epoch24 has not started yet";
                "cycle" => cycle,
                "epoch" => %epoch,
                "active_pox_contract" => %active_pox_contract,
            );
            continue;
        }

        check_stacker_link_invariants(peer, tip, cycle);
    }
}

pub fn generate_pox_clarity_value(str_hash: &str) -> Value {
    let byte_vec = hex_bytes(str_hash).unwrap();
    let pox_addr_tuple = TupleData::from_data(vec![
        ("hashbytes".into(), Value::buff_from(byte_vec).unwrap()),
        ("version".into(), Value::buff_from_byte(0)),
    ])
    .unwrap();

    Value::Tuple(pox_addr_tuple)
}

pub struct PoxPrintFields {
    pub op_name: String,
    pub stacker: Value,
    pub balance: Value,
    pub locked: Value,
    pub burnchain_unlock_height: Value,
}

// This function takes in a StacksTransactionEvent for a print statement from a pox function that modifies
// a stacker's state. It verifies that the values in the print statement are as expected.
pub fn check_pox_print_event(
    event: &StacksTransactionEvent,
    common_data: PoxPrintFields,
    op_data: HashMap<&str, Value>,
) {
    if let StacksTransactionEvent::SmartContractEvent(data) = event {
        test_debug!(
            "Decode event, expecting for {}: {:?}",
            common_data.op_name,
            data
        );
        assert_eq!(data.key.1, "print");
        let outer_tuple = data
            .value
            .clone()
            .expect_result()
            .unwrap()
            .unwrap()
            .expect_tuple()
            .unwrap();
        test_debug!(
            "Check name: {:?} =?= {:?}",
            &outer_tuple
                .data_map
                .get("name")
                .unwrap()
                .clone()
                .expect_ascii()
                .unwrap(),
            common_data.op_name
        );
        assert_eq!(
            outer_tuple
                .data_map
                .get("name")
                .unwrap()
                .clone()
                .expect_ascii()
                .unwrap(),
            common_data.op_name
        );
        assert_eq!(
            outer_tuple.data_map.get("stacker"),
            Some(&common_data.stacker)
        );
        assert_eq!(
            outer_tuple.data_map.get("balance"),
            Some(&common_data.balance)
        );
        assert_eq!(
            outer_tuple.data_map.get("locked"),
            Some(&common_data.locked)
        );
        assert_eq!(
            outer_tuple.data_map.get("burnchain-unlock-height"),
            Some(&common_data.burnchain_unlock_height)
        );

        let args = outer_tuple
            .data_map
            .get("data")
            .expect("The event tuple should have a field named `data`");
        let inner_tuple = args.clone().expect_tuple().unwrap();

        test_debug!("Check for ops {:?}", &op_data);
        test_debug!("Inner tuple is {:?}", &inner_tuple);
        let mut missing = vec![];
        let mut wrong = vec![];
        for (inner_key, inner_val) in op_data {
            match inner_tuple.data_map.get(inner_key) {
                Some(v) => {
                    if v != &inner_val {
                        wrong.push((inner_key.to_string(), v.to_string(), inner_val.to_string()));
                    }
                }
                None => {
                    missing.push(inner_key.to_string());
                }
            }
            // assert_eq!(inner_tuple.data_map.get(inner_key), Some(&inner_val));
        }
        if !missing.is_empty() || !wrong.is_empty() {
            eprintln!("missing:\n{missing:#?}");
            eprintln!("wrong:\n{wrong:#?}");
            assert!(false);
        }
    } else {
        error!("unexpected event type: {event:?}");
        panic!("Unexpected transaction event type.")
    }
}

pub struct StackingStateCheckData {
    pub pox_addr: PoxAddress,
    /// this is a map from reward cycle number to the value in reward-set-indexes
    pub cycle_indexes: HashMap<u128, u128>,
    pub first_cycle: u128,
    pub lock_period: u128,
}

/// Check the stacking-state invariants of `stacker`
/// Mostly that all `stacking-state.reward-set-indexes` match the index of their reward cycle entries
pub fn check_stacking_state_invariants(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    stacker: &PrincipalData,
    expect_indexes: bool,
    active_pox_contract: &str,
) -> StackingStateCheckData {
    let account_state = with_clarity_db_ro(peer, tip, |db| {
        db.get_stx_balance_snapshot(stacker)
            .unwrap()
            .canonical_balance_repr()
            .unwrap()
    });

    let tip_burn_height = StacksChainState::get_stacks_block_header_info_by_index_block_hash(
        peer.chainstate().db(),
        tip,
    )
    .unwrap()
    .unwrap()
    .burn_header_height;

    let stacking_state_entry = get_stacking_state_pox(peer, tip, stacker, active_pox_contract)
        .expect(&format!(
            "Invariant violated: reward-cycle entry has stacker field set, but not present in stacker-state (pox_contract = {})",
            active_pox_contract,
        ))
        .expect_tuple().unwrap();
    let first_cycle = stacking_state_entry
        .get("first-reward-cycle")
        .unwrap()
        .clone()
        .expect_u128()
        .unwrap();
    let lock_period = stacking_state_entry
        .get("lock-period")
        .unwrap()
        .clone()
        .expect_u128()
        .unwrap();
    let pox_addr = stacking_state_entry.get("pox-addr").unwrap();
    let pox_addr = PoxAddress::try_from_pox_tuple(false, pox_addr).unwrap();

    let reward_indexes: Vec<u128> = stacking_state_entry
        .get_owned("reward-set-indexes")
        .unwrap()
        .expect_list()
        .unwrap()
        .into_iter()
        .map(|x| x.expect_u128().unwrap())
        .collect();

    let stacking_state_unlock_ht = peer
        .config
        .burnchain
        .reward_cycle_to_block_height((first_cycle + lock_period) as u64);

    assert_eq!(
        account_state.unlock_height() + 1,
        stacking_state_unlock_ht,
        "Invariant violated: stacking-state and account state have different unlock heights. Tip height = {}, PoX Contract: {}",
        tip_burn_height,
        active_pox_contract,
    );

    let mut cycle_indexes = HashMap::new();

    if !reward_indexes.is_empty() || expect_indexes {
        assert_eq!(
            reward_indexes.len() as u128,
            lock_period,
            "Invariant violated: lock-period should be equal to the reward indexes length"
        );

        for i in 0..lock_period {
            let cycle_checked = first_cycle + i;
            let reward_index = reward_indexes[i as usize];

            let entry_key = Value::from(
                TupleData::from_data(vec![
                    ("reward-cycle".into(), Value::UInt(cycle_checked)),
                    ("index".into(), Value::UInt(reward_index)),
                ])
                .unwrap(),
            );
            let entry_value = with_clarity_db_ro(peer, tip, |db| {
                let epoch = db.get_clarity_epoch_version().unwrap();
                db.fetch_entry_unknown_descriptor(
                    &boot_code_id(active_pox_contract, false),
                    "reward-cycle-pox-address-list",
                    &entry_key,
                    &epoch,
                )
                    .unwrap()
                    .expect_optional().unwrap()
                    .expect("Invariant violated: stacking-state.reward-set-indexes pointed at a non-existent entry")
                    .expect_tuple().unwrap()
            });

            let entry_stacker = entry_value.get("stacker")
                .unwrap()
                .clone()
                .expect_optional().unwrap()
                .expect("Invariant violated: stacking-state.reward-set-indexes pointed at an entry without a stacker set")
                .expect_principal().unwrap();

            assert_eq!(
                &entry_stacker, stacker,
                "Invariant violated: reward-set-index points to different stacker's entry"
            );

            let entry_pox_addr = entry_value.get_owned("pox-addr").unwrap();
            let entry_pox_addr = PoxAddress::try_from_pox_tuple(false, &entry_pox_addr).unwrap();

            assert_eq!(
                &entry_pox_addr, &pox_addr,
                "Invariant violated: linked reward set entry has a different PoX address"
            );

            cycle_indexes.insert(cycle_checked, reward_index);
        }
    }

    StackingStateCheckData {
        cycle_indexes,
        pox_addr,
        first_cycle,
        lock_period,
    }
}

/// Check that:
///  (1) `reward-cycle-pox-address-list.stacker` points to a real `stacking-state`
///  (2) `stacking-state.reward-set-indexes` matches the index of that `reward-cycle-pox-address-list`
///  (3) all `stacking-state.reward-set-indexes` match the index of their reward cycle entries
///  (4) `reward-cycle-total-stacked` is equal to the sum of all entries
///  (5) `stacking-state.pox-addr` matches `reward-cycle-pox-address-list.pox-addr`
pub fn check_stacker_link_invariants(peer: &mut TestPeer, tip: &StacksBlockId, cycle_number: u64) {
    let current_burn_height = StacksChainState::get_stacks_block_header_info_by_index_block_hash(
        peer.chainstate().db(),
        tip,
    )
    .unwrap()
    .unwrap()
    .burn_header_height;
    let tip_cycle = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(current_burn_height.into())
        .unwrap();
    let cycle_start = peer
        .config
        .burnchain
        .reward_cycle_to_block_height(cycle_number);

    let tip_epoch = SortitionDB::get_stacks_epoch(peer.sortdb().conn(), current_burn_height as u64)
        .unwrap()
        .unwrap();

    let cycle_start_epoch = SortitionDB::get_stacks_epoch(peer.sortdb().conn(), cycle_start)
        .unwrap()
        .unwrap();

    let active_pox_contract = peer.config.burnchain.pox_constants.active_pox_contract(
        peer.config
            .burnchain
            .reward_cycle_to_block_height(cycle_number),
    );

    if cycle_start_epoch.epoch_id == StacksEpochId::Epoch22
        || cycle_start_epoch.epoch_id == StacksEpochId::Epoch23
    {
        info!(
            "Skipping reward set validation checks on reward cycles that start in Epoch 2.2 or Epoch 2.3";
            "cycle" => cycle_number,
        );
        return;
    }

    if cycle_start_epoch.epoch_id == StacksEpochId::Epoch24 && active_pox_contract != POX_3_NAME {
        info!(
            "Skipping validation of reward set that started in Epoch24, but its cycle starts before pox-3 activation";
            "cycle" => cycle_number,
            "cycle_start" => cycle_start,
            "pox_3_activation" => peer.config.burnchain.pox_constants.pox_3_activation_height,
            "pox_4_activation" => peer.config.burnchain.pox_constants.pox_4_activation_height,
            "epoch_2_4_start" => cycle_start_epoch.start_height,
        );
        return;
    }

    let reward_set_entries = get_reward_set_entries_index_order_at(peer, tip, cycle_start);
    let mut checked_total = 0;
    for (actual_index, entry) in reward_set_entries.iter().enumerate() {
        debug!(
            "Cycle {}: Check {:?} (stacked={}, stacker={}, tip_epoch={})",
            cycle_number,
            &entry.reward_address,
            entry.amount_stacked,
            &entry
                .stacker
                .as_ref()
                .map(|s| format!("{}", &s))
                .unwrap_or("(none)".to_string()),
            &tip_epoch.epoch_id,
        );
        checked_total += entry.amount_stacked;
        if let Some(stacker) = &entry.stacker {
            if tip_cycle > cycle_number {
                // if the checked cycle is before the tip's cycle,
                // the reward-set-entrie's stacker links are no longer necessarily valid
                // (because the reward cycles for those entries has passed)
                // so we continue here to skip the stacker reference checks
                continue;
            }

            if tip_epoch.epoch_id == StacksEpochId::Epoch22
                || tip_epoch.epoch_id == StacksEpochId::Epoch23
            {
                // if the current tip is epoch-2.2 or epoch-2.3, the stacker invariant checks
                // no longer make sense: the stacker has unlocked, even though a reward cycle
                // is still active (i.e., the last active cycle from epoch-2.1).
                continue;
            }

            if tip_epoch.epoch_id >= StacksEpochId::Epoch24
                && current_burn_height
                    <= peer.config.burnchain.pox_constants.pox_3_activation_height
            {
                // if the tip is epoch-2.4, and pox-3 isn't the active pox contract yet,
                //  the invariant checks will not make sense for the same reasons as above
                continue;
            }

            if tip_epoch.epoch_id >= StacksEpochId::Epoch25
                && current_burn_height
                    <= peer.config.burnchain.pox_constants.pox_4_activation_height
            {
                // if the tip is epoch-2.5, and pox-5 isn't the active pox contract yet,
                //  the invariant checks will not make sense for the same reasons as above
                continue;
            }

            let StackingStateCheckData {
                pox_addr,
                cycle_indexes,
                ..
            } = check_stacking_state_invariants(peer, tip, stacker, true, active_pox_contract);

            assert_eq!(&entry.reward_address, &pox_addr, "Invariant violated: reward-cycle entry has a different PoX addr than in stacker-state");
            assert_eq!(
                cycle_indexes.get(&(cycle_number as u128)).cloned().unwrap(),
                actual_index as u128,
                "Invariant violated: stacking-state.reward-set-indexes entry at cycle_number must point to this stacker's entry"
            );
        }
    }
    let expected_total = get_reward_cycle_total(peer, tip, cycle_number);
    assert_eq!(
        checked_total,
        expected_total,
        "Invariant violated at cycle {cycle_number}: total reward cycle amount does not equal sum of reward set"
    );
}

/// Get the `cycle_number`'s total stacked amount at the given chaintip
pub fn get_reward_cycle_total(peer: &mut TestPeer, tip: &StacksBlockId, cycle_number: u64) -> u128 {
    let active_pox_contract = peer.config.burnchain.pox_constants.active_pox_contract(
        peer.config
            .burnchain
            .reward_cycle_to_block_height(cycle_number),
    );

    with_clarity_db_ro(peer, tip, |db| {
        let total_stacked_key = TupleData::from_data(vec![(
            "reward-cycle".into(),
            Value::UInt(cycle_number.into()),
        )])
        .unwrap()
        .into();
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(active_pox_contract, false),
            "reward-cycle-total-stacked",
            &total_stacked_key,
            &epoch,
        )
        .map(|v| {
            v.expect_optional()
                .unwrap()
                .map(|v| {
                    v.expect_tuple()
                        .unwrap()
                        .get_owned("total-ustx")
                        .expect("Malformed tuple returned by PoX contract")
                        .expect_u128()
                        .unwrap()
                })
                // if no entry yet, return 0
                .unwrap_or(0)
        })
        // if the map doesn't exist yet, return 0
        .unwrap_or(0)
    })
}

/// Get the `partial-stacked-by-cycle` entry at a given chain tip
pub fn get_partial_stacked(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    pox_addr: &Value,
    cycle_number: u64,
    sender: &PrincipalData,
    pox_contract: &str,
) -> u128 {
    with_clarity_db_ro(peer, tip, |db| {
        let key = TupleData::from_data(vec![
            ("pox-addr".into(), pox_addr.clone()),
            ("reward-cycle".into(), Value::UInt(cycle_number.into())),
            ("sender".into(), Value::from(sender.clone())),
        ])
        .unwrap()
        .into();
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(pox_contract, false),
            "partial-stacked-by-cycle",
            &key,
            &epoch,
        )
        .map(|v| {
            v.expect_optional()
                .unwrap()
                .expect("Expected fetch_entry to return a value")
        })
        .unwrap()
        .expect_tuple()
        .unwrap()
        .get_owned("stacked-amount")
        .expect("Malformed tuple returned by PoX contract")
        .expect_u128()
        .unwrap()
    })
}

/// Allows you to do something read-only with the ClarityDB at the given chaintip
pub fn with_clarity_db_ro<F, R>(peer: &mut TestPeer, tip: &StacksBlockId, todo: F) -> R
where
    F: FnOnce(&mut ClarityDatabase) -> R,
{
    with_sortdb(peer, |ref mut c, ref sortdb| {
        let headers_db = HeadersDBConn(StacksDBConn::new(&c.state_index, ()));
        let burn_db = sortdb.index_handle_at_tip();
        let mut read_only_clar = c
            .clarity_state
            .read_only_connection(tip, &headers_db, &burn_db);
        read_only_clar.with_clarity_db_readonly(todo)
    })
}

/// In this test case, two Stackers, Alice and Bob stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition.
///
/// Alice: stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        After the early unlock, Alice re-stacks in PoX v2
///        Alice tries to stack again via PoX v1, which is allowed by the contract,
///        but forbidden by the VM (because PoX has transitioned to v2)
/// Bob:   stacks via PoX v2 for 6 cycles. He attempted to stack via PoX v1 as well,
///        but is forbidden because he has already placed an account lock via PoX v2.
///
#[test]
fn test_simple_pox_lockup_transition_pox_2() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_simple_pox_lockup_transition_pox_2",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;

    let mut coinbase_nonce = 0;

    // these checks are very repetitive
    let reward_cycle_checks = |tip_index_block| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) =
            with_sortdb(&mut peer, |ref mut c, ref sortdb| {
                (
                    c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                    get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block)
                        .unwrap(),
                    c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                        .unwrap(),
                )
            });

        eprintln!(
            "\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal-stacked: {}\n",
            cur_reward_cycle, min_ustx, &reward_addrs, total_stacked
        );

        if cur_reward_cycle < EXPECTED_ALICE_FIRST_REWARD_CYCLE {
            // no reward addresses yet
            assert_eq!(reward_addrs.len(), 0);
        } else if cur_reward_cycle < EXPECTED_FIRST_V2_CYCLE as u128 {
            // After the start of Alice's first cycle, but before the first V2 cycle,
            //  Alice is the only Stacker, so check that.
            let (amount_ustx, pox_addr, lock_period, first_reward_cycle) =
                get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
            eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);

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
            assert_eq!(reward_addrs[0].1, 1024 * POX_THRESHOLD_STEPS_USTX);
        } else {
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
            assert_eq!(reward_addrs[0].1, 512 * POX_THRESHOLD_STEPS_USTX);

            assert_eq!(
                (reward_addrs[1].0).version(),
                AddressHashMode::SerializeP2PKH as u8
            );
            assert_eq!(
                (reward_addrs[1].0).hash160(),
                key_to_stacks_addr(&alice).bytes
            );
            assert_eq!(reward_addrs[1].1, 512 * POX_THRESHOLD_STEPS_USTX);
        }
    };

    // our "tenure counter" is now at 0
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 0 + EMPTY_SORTITIONS as u64);

    // first tenure is empty
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(
        alice_account.stx_balance.amount_unlocked(),
        1024 * POX_THRESHOLD_STEPS_USTX
    );
    assert_eq!(alice_account.stx_balance.amount_locked(), 0);
    assert_eq!(alice_account.stx_balance.unlock_height(), 0);

    // next tenure include Alice's lockup
    let tip = get_tip(peer.sortdb.as_ref());
    let alice_lockup = make_pox_lockup(
        &alice,
        0,
        1024 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        4,
        tip.block_height,
    );

    // our "tenure counter" is now at 1
    assert_eq!(tip.block_height, 1 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_first_reward_cycle, EXPECTED_ALICE_FIRST_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until immediately before the epoch switch (7 more blocks to block height 35)

    for _i in 0..7 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
    }

    // Have Charlie try to use the PoX2 contract. This transaction
    //  should be accepted (checked via the tx receipt). Also, importantly,
    //  the cost tracker should assign costs to Charlie's transaction.
    //  This is also checked by the transaction receipt.
    let tip = get_tip(peer.sortdb.as_ref());

    // our "tenure counter" is now at 9
    assert_eq!(tip.block_height, 9 + EMPTY_SORTITIONS as u64);

    let test = make_pox_2_contract_call(
        &charlie,
        0,
        "delegate-stx",
        vec![
            Value::UInt(1_000_000),
            PrincipalData::from(key_to_stacks_addr(&charlie)).into(),
            Value::none(),
            Value::none(),
        ],
    );
    peer.tenure_with_txs(&[test], &mut coinbase_nonce);

    // alice is still locked, balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10, and 11
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip.block_height,
    );

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let block_id = peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    // alice is still locked, balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // Now, Bob tries to lock in PoX v1 too, but it shouldn't work!
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_lockup(
        &bob,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
        4,
        tip.block_height,
    );

    // our "tenure counter" is now at 11
    assert_eq!(tip.block_height, 11 + EMPTY_SORTITIONS as u64);
    let block_id = peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    // our "tenure counter" is now at 12
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 12 + EMPTY_SORTITIONS as u64);
    // One more empty tenure to reach the unlock height
    let block_id = peer.tenure_with_txs(&[], &mut coinbase_nonce);

    // Auto unlock height is reached, Alice balance should be unlocked
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    // At this point, the auto unlock height for v1 accounts should be reached.
    //  let Alice stack in PoX v2
    let tip = get_tip(peer.sortdb.as_ref());

    // our "tenure counter" is now at 13
    assert_eq!(tip.block_height, 13 + EMPTY_SORTITIONS as u64);

    let alice_lockup = make_pox_2_lockup(
        &alice,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        12,
        tip.block_height,
    );
    peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // Alice locked half her balance in PoX 2
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now, let's roll the chain forward until Alice *would* have unlocked in v1 anyways.
    //  that's block height 31, so play 27 empty blocks

    for _i in 0..17 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always include this half lockup
        assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let tip = get_tip(peer.sortdb.as_ref());

    // our "tenure counter" is now at 31
    assert_eq!(tip.block_height, 31 + EMPTY_SORTITIONS as u64);

    let alice_lockup = make_pox_lockup(
        &alice,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );
    let block_id = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut charlie_txs = HashMap::new();

    eprintln!("Alice addr: {}", alice_address);
    eprintln!("Bob addr: {}", bob_address);

    let mut tested_charlie = false;

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                eprintln!("TX addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == key_to_stacks_addr(&charlie) {
                    assert!(
                        r.execution_cost != ExecutionCost::ZERO,
                        "Execution cost is not zero!"
                    );
                    charlie_txs.insert(t.auth.get_origin_nonce(), r);

                    tested_charlie = true;
                }
            }
        }
    }

    assert!(tested_charlie, "Charlie TX must be tested");
    // Alice should have three accepted transactions:
    //  TX0 -> Alice's initial lockup in PoX 1
    //  TX1 -> Alice's PoX 2 lockup
    //  TX2 -> Alice's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    assert_eq!(alice_txs.len(), 3, "Alice should have 3 confirmed txs");
    // Bob should have two accepted transactions:
    //  TX0 -> Bob's initial lockup in PoX 2
    //  TX1 -> Bob's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    assert_eq!(bob_txs.len(), 2, "Bob should have 2 confirmed txs");
    // Charlie should have one accepted transactions:
    //  TX0 -> Charlie's delegation in PoX 2. This tx just checks that the
    //         initialization code tracks costs in txs that occur after the
    //         initialization code (which uses a free tracker).
    assert_eq!(charlie_txs.len(), 1, "Charlie should have 1 confirmed txs");

    //  TX0 -> Alice's initial lockup in PoX 1
    assert!(
        match alice_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx0 should have committed okay"
    );

    //  TX1 -> Alice's PoX 2 lockup
    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx1 should have committed okay"
    );

    //  TX2 -> Alice's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    assert_eq!(
        alice_txs.get(&2).unwrap().result,
        Value::err_none(),
        "Alice tx2 should have resulted in a runtime error"
    );

    //  TX0 -> Bob's initial lockup in PoX 2
    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    //  TX1 -> Bob's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    assert_eq!(
        bob_txs.get(&1).unwrap().result,
        Value::err_none(),
        "Bob tx1 should have resulted in a runtime error"
    );

    //  TX0 -> Charlie's delegation in PoX 2. This tx just checks that the
    //         initialization code tracks costs in txs that occur after the
    //         initialization code (which uses a free tracker).
    assert!(
        match charlie_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Charlie tx0 should have committed okay"
    );
}

#[test]
fn test_simple_pox_2_auto_unlock_ab() {
    test_simple_pox_2_auto_unlock(true)
}

#[test]
fn test_simple_pox_2_auto_unlock_ba() {
    test_simple_pox_2_auto_unlock(false)
}

/// In this test case, two Stackers, Alice and Bob stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition.
///
/// Alice: stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        After the early unlock, Alice re-stacks in PoX v2
///        Alice tries to stack again via PoX v1, which is allowed by the contract,
///        but forbidden by the VM (because PoX has transitioned to v2)
/// Bob:   stacks via PoX v2 for 6 cycles. He attempted to stack via PoX v1 as well,
///        but is forbidden because he has already placed an account lock via PoX v2.
///
/// Note: this test is symmetric over the order of alice and bob's stacking calls.
///       when alice goes first, the auto-unlock code doesn't need to perform a "move"
///       when bob goes first, the auto-unlock code does need to perform a "move"
fn test_simple_pox_2_auto_unlock(alice_first: bool) {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.pox_participation_threshold_pct = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &format!("test_simple_pox_2_auto_unlock_{}", alice_first),
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();

    let mut coinbase_nonce = 0;

    // produce blocks until the epoch switch
    for _i in 0..10 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10, and 11
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let alice_lockup = make_pox_2_lockup(
        &alice,
        0,
        1024 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        1 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip.block_height,
    );

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let txs = if alice_first {
        [alice_lockup, bob_lockup]
    } else {
        [bob_lockup, alice_lockup]
    };
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice and bob
    //  at the cycle start
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&bob).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // we'll produce blocks until the next reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE) + 1;

    // but first, check that bob has locked tokens at (height_target + 1)
    let (bob_bal, _) = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    )
    .canonical_repr_at_block(
        height_target + 1,
        burnchain.pox_constants.v1_unlock_height,
        burnchain.pox_constants.v2_unlock_height,
        burnchain.pox_constants.v3_unlock_height,
    )
    .unwrap();
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward sets for all cycles just contains entries for alice
    //  at the cycle start
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // now check that bob has no locked tokens at (height_target + 1)
    let (bob_bal, _) = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    )
    .canonical_repr_at_block(
        height_target + 1,
        burnchain.pox_constants.v1_unlock_height,
        burnchain.pox_constants.v2_unlock_height,
        burnchain.pox_constants.v3_unlock_height,
    )
    .unwrap();
    assert_eq!(bob_bal.amount_locked(), 0);

    // but bob's still locked at (height_target): the unlock is accelerated to the "next" burn block
    let (bob_bal, _) = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    )
    .canonical_repr_at_block(
        height_target + 1,
        burnchain.pox_constants.v1_unlock_height,
        burnchain.pox_constants.v2_unlock_height,
        burnchain.pox_constants.v3_unlock_height,
    )
    .unwrap();
    assert_eq!(bob_bal.amount_locked(), 0);

    // check that the total reward cycle amounts have decremented correctly
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            1024 * POX_THRESHOLD_STEPS_USTX
        );
    }

    // check that bob's stacking-state is gone and alice's stacking-state is correct
    assert!(
        get_stacking_state_pox_2(
            &mut peer,
            &latest_block,
            &key_to_stacks_addr(&bob).to_account_principal()
        )
        .is_none(),
        "Bob should not have a stacking-state entry"
    );

    let alice_state = get_stacking_state_pox_2(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&alice).to_account_principal(),
    )
    .expect("Alice should have stacking-state entry")
    .expect_tuple()
    .unwrap();
    let reward_indexes_str = format!("{}", alice_state.get("reward-set-indexes").unwrap());
    assert_eq!(reward_indexes_str, "(u0 u0 u0 u0 u0 u0)");

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let charlie_address = key_to_stacks_addr(&charlie);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut charlie_txs = HashMap::new();
    // let mut network_protocol_txs = vec![];
    let mut coinbase_txs = vec![];

    eprintln!("Alice addr: {}", alice_address);
    eprintln!("Bob addr: {}", bob_address);

    for b in blocks.into_iter() {
        for (i, r) in b.receipts.into_iter().enumerate() {
            if i == 0 {
                coinbase_txs.push(r);
                continue;
            }
            match r.transaction {
                TransactionOrigin::Stacks(ref t) => {
                    let addr = t.auth.origin().address_testnet();
                    eprintln!("TX addr: {}", addr);
                    if addr == alice_address {
                        alice_txs.insert(t.auth.get_origin_nonce(), r);
                    } else if addr == bob_address {
                        bob_txs.insert(t.auth.get_origin_nonce(), r);
                    } else if addr == charlie_address {
                        assert!(
                            r.execution_cost != ExecutionCost::ZERO,
                            "Execution cost is not zero!"
                        );
                        charlie_txs.insert(t.auth.get_origin_nonce(), r);
                    }
                }
                _ => {}
            }
        }
    }

    assert_eq!(alice_txs.len(), 1);
    assert_eq!(charlie_txs.len(), 0);

    assert_eq!(bob_txs.len(), 1);

    //  TX0 -> Bob's initial lockup in PoX 2
    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    assert_eq!(coinbase_txs.len(), 17);

    // Check that the event produced by "handle-unlock" has a well-formed print event
    // and that this event is included as part of the coinbase tx
    let auto_unlock_tx = coinbase_txs[16].events[0].clone();
    let pox_addr_val = generate_pox_clarity_value("60c59ab11f7063ef44c16d3dc856f76bbb915eba");
    let auto_unlock_op_data = HashMap::from([
        ("first-cycle-locked", Value::UInt(8)),
        ("first-unlocked-cycle", Value::UInt(8)),
        ("pox-addr", pox_addr_val),
    ]);
    let common_data = PoxPrintFields {
        op_name: "handle-unlock".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(10230000000000),
        locked: Value::UInt(10000000000),
        burnchain_unlock_height: Value::UInt(42),
    };
    check_pox_print_event(&auto_unlock_tx, common_data, auto_unlock_op_data);
}

/// In this test case, Alice delegates to Bob.
///  Bob stacks Alice's funds via PoX v2 for 6 cycles. In the third cycle,
///  Bob increases Alice's stacking amount.
///
#[test]
fn delegate_stack_increase() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.pox_participation_threshold_pct = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {first_v2_cycle}");

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "pox_2_delegate_stack_increase",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, bob_address.bytes.clone());
    let mut alice_nonce = 0;
    let mut bob_nonce = 0;

    let alice_delegation_amount = 1023 * POX_THRESHOLD_STEPS_USTX;
    let alice_first_lock_amount = 512 * POX_THRESHOLD_STEPS_USTX;

    let mut coinbase_nonce = 0;

    // produce blocks until the epoch switch
    for _i in 0..10 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit delegation tx
    let success_alice_delegation = alice_nonce;
    let alice_delegation_1 = make_pox_2_contract_call(
        &alice,
        alice_nonce,
        "delegate-stx",
        vec![
            Value::UInt(alice_delegation_amount),
            bob_principal.clone().into(),
            Value::none(),
            Value::none(),
        ],
    );

    alice_nonce += 1;

    let delegate_stack_tx = make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-stx",
        vec![
            alice_principal.clone().into(),
            Value::UInt(alice_first_lock_amount),
            bob_pox_addr.clone(),
            Value::UInt(tip.block_height as u128),
            Value::UInt(6),
        ],
    );

    bob_nonce += 1;

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let mut latest_block = peer.tenure_with_txs(
        &[alice_delegation_1, delegate_stack_tx],
        &mut coinbase_nonce,
    );

    // check that the partial stacking state contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // we'll produce blocks until the 3rd reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 3) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);

    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);

    // check that the partial stacking state contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let mut txs_to_submit = vec![];

    let fail_direct_increase_delegation = alice_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &alice,
        alice_nonce,
        "stack-increase",
        vec![Value::UInt(1)],
    ));
    alice_nonce += 1;

    let fail_delegate_too_much_locked = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount + 1),
        ],
    ));
    bob_nonce += 1;

    let fail_invalid_amount = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(0),
        ],
    ));
    bob_nonce += 1;

    let fail_insufficient_funds = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_bal.amount_unlocked() + 1),
        ],
    ));
    bob_nonce += 1;

    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount),
        ],
    ));
    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        alice_delegation_amount
    );

    // check that the partial stacking state contains entries for bob and they've incremented correctly
    for cycle_number in (EXPECTED_FIRST_V2_CYCLE)..(EXPECTED_FIRST_V2_CYCLE + 4) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, alice_first_lock_amount);
    }

    for cycle_number in (EXPECTED_FIRST_V2_CYCLE + 4)..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, alice_delegation_amount,);
    }

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
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

    assert_eq!(alice_txs.len() as u64, 2);
    assert_eq!(bob_txs.len() as u64, 5);

    // transaction should fail because Alice cannot increase her own stacking amount while delegating
    assert_eq!(
        &alice_txs[&fail_direct_increase_delegation]
            .result
            .to_string(),
        "(err 20)"
    );

    // transaction should fail because Alice did not delegate enough funds to Bob
    assert_eq!(
        &bob_txs[&fail_delegate_too_much_locked].result.to_string(),
        "(err 22)"
    );

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &bob_txs[&fail_insufficient_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(
        &bob_txs[&fail_invalid_amount].result.to_string(),
        "(err 18)"
    );

    let delegate_stx_tx = &alice_txs
        .get(&success_alice_delegation)
        .unwrap()
        .clone()
        .events[0];
    let delegate_stx_op_data = HashMap::from([
        ("pox-addr", Value::none()),
        ("amount-ustx", Value::UInt(10230000000000)),
        ("unlock-burn-height", Value::none()),
        (
            "delegate-to",
            Value::Principal(
                StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                    .unwrap()
                    .to_account_principal(),
            ),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stx".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(delegate_stx_tx, common_data, delegate_stx_op_data);

    // Check that the call to `delegate-stack-increase` has a well-formed print event.
    let delegate_stack_increase_tx = &bob_txs.get(&4).unwrap().clone().events[0];
    let pox_addr_val = generate_pox_clarity_value("60c59ab11f7063ef44c16d3dc856f76bbb915eba");
    let delegate_op_data = HashMap::from([
        ("pox-addr", pox_addr_val),
        ("increase-by", Value::UInt(5110000000000)),
        ("total-locked", Value::UInt(10230000000000)),
        (
            "delegator",
            Value::Principal(
                StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                    .unwrap()
                    .to_account_principal(),
            ),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-increase".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(5120000000000),
        locked: Value::UInt(5120000000000),
        burnchain_unlock_height: Value::UInt(70),
    };
    check_pox_print_event(delegate_stack_increase_tx, common_data, delegate_op_data);
}

/// In this test case, Alice stacks and interacts with the
///  PoX v2 contract after the epoch transition.
///
/// Alice: stacks via PoX v2 for 6 cycles. In the third cycle, Alice invokes
/// `stack-increase`
///
#[test]
fn stack_increase() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.pox_participation_threshold_pct = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_simple_pox_2_increase",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let mut alice_nonce = 0;

    let mut coinbase_nonce = 0;

    let first_lockup_amt = 512 * POX_THRESHOLD_STEPS_USTX;
    let total_balance = 1024 * POX_THRESHOLD_STEPS_USTX;
    let increase_amt = total_balance - first_lockup_amt;

    // produce blocks until the epoch switch
    for _i in 0..10 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit an increase: this should fail, because Alice is not yet locked
    let fail_no_lock_tx = alice_nonce;
    let alice_increase = make_pox_2_increase(&alice, alice_nonce, increase_amt);
    alice_nonce += 1;

    let alice_lockup = make_pox_2_lockup(
        &alice,
        alice_nonce,
        first_lockup_amt,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );
    alice_nonce += 1;

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let mut latest_block =
        peer.tenure_with_txs(&[alice_increase, alice_lockup], &mut coinbase_nonce);

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        first_lockup_amt,
    );

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal)
            .get_total_balance()
            .unwrap(),
        total_balance,
    );

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    // we'll produce blocks until the 3rd reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 3) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward sets for all cycles contains entries for alice
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    let mut txs_to_submit = vec![];
    let fail_bad_amount = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, 0));
    alice_nonce += 1;

    // this stack-increase tx should work
    let success_increase = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, increase_amt));
    alice_nonce += 1;

    // increase by an amount we don't have!
    let fail_not_enough_funds = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, 1));
    alice_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        first_lockup_amt + increase_amt,
    );

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal)
            .get_total_balance()
            .unwrap(),
        total_balance,
    );

    // check that the total reward cycle amounts have incremented correctly
    for cycle_number in (EXPECTED_FIRST_V2_CYCLE)..(EXPECTED_FIRST_V2_CYCLE + 4) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    for cycle_number in (EXPECTED_FIRST_V2_CYCLE + 4)..(EXPECTED_FIRST_V2_CYCLE + 6) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt + increase_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[0].amount_stacked,
            first_lockup_amt + increase_amt,
        );
    }

    // now let's check some tx receipts
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

    assert_eq!(alice_txs.len() as u64, alice_nonce);

    // transaction should fail because lock isn't applied
    assert_eq!(&alice_txs[&fail_no_lock_tx].result.to_string(), "(err 27)");

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &alice_txs[&fail_not_enough_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(&alice_txs[&fail_bad_amount].result.to_string(), "(err 18)");

    // Check that the call to `stack-increase` has a well-formed print event.
    let stack_increase_tx = &alice_txs.get(&success_increase).unwrap().clone().events[0];
    let pox_addr_val = generate_pox_clarity_value("ae1593226f85e49a7eaff5b633ff687695438cc9");
    let stack_op_data = HashMap::from([
        ("increase-by", Value::UInt(5120000000000)),
        ("total-locked", Value::UInt(10240000000000)),
        ("pox-addr", pox_addr_val),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-increase".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(5120000000000),
        locked: Value::UInt(5120000000000),
        burnchain_unlock_height: Value::UInt(70),
    };
    check_pox_print_event(stack_increase_tx, common_data, stack_op_data);
}

#[test]
fn test_lock_period_invariant_extend_transition() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HT = 25;
    let EXPECTED_FIRST_V2_CYCLE = 11;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    eprintln!("First v2 cycle = {}", first_v2_cycle);
    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_lp_invariant_extend_trans",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;
    let mut coinbase_nonce = 0;

    let INITIAL_BALANCE = 1024 * POX_THRESHOLD_STEPS_USTX;
    let ALICE_LOCKUP = 1024 * POX_THRESHOLD_STEPS_USTX;

    // our "tenure counter" is now at 0
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 0 + EMPTY_SORTITIONS as u64);

    // first tenure is empty
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, INITIAL_BALANCE);

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

    // our "tenure counter" is now at 1
    assert_eq!(tip.block_height, 1 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_first_reward_cycle, EXPECTED_ALICE_FIRST_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until alice's first reward cycle
    for _i in 0..4 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // produce blocks until immediately after the epoch switch (4 more blocks to block height 36)
    for _i in 0..4 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

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

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);
}

/// In this test case, two Stackers, Alice and Bob stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition. This test
///  covers the two different ways a Stacker can validly extend via `stack-extend` --
///  extending from a V1 lockup and extending from a V2 lockup.
///
/// Alice: stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        Before the early unlock, Alice invokes `stack-extend` in PoX v2
///        Alice tries to stack again via PoX v1, which is allowed by the contract,
///        but forbidden by the VM (because PoX has transitioned to v2)
/// Bob:   stacks via PoX v2 for 3 cycles.
///        Bob extends 1 cycles
#[test]
fn test_pox_extend_transition_pox_2() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    eprintln!("First v2 cycle = {}", first_v2_cycle);
    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_pox_extend_transition_pox_2",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();

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

    // our "tenure counter" is now at 0
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 0 + EMPTY_SORTITIONS as u64);

    // first tenure is empty
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, INITIAL_BALANCE);

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

    // our "tenure counter" is now at 1
    assert_eq!(tip.block_height, 1 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_first_reward_cycle, EXPECTED_ALICE_FIRST_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until alice's first reward cycle
    for _i in 0..4 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // produce blocks until immediately after the epoch switch (8 more blocks to block height 36)
    for _i in 0..4 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
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

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);

    alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);

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

    let tip_index_block = peer.tenure_with_txs(&[bob_extend], &mut coinbase_nonce);

    alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);

    // produce blocks until "tenure counter" is 15 -- this is where
    //  the v2 reward cycles start
    for _i in 0..3 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    // our "tenure counter" is now at 15
    assert_eq!(tip.block_height, 15 + EMPTY_SORTITIONS as u64);

    // produce blocks until "tenure counter" is 32 -- this is where
    //  alice *would have been* unlocked under v1 rules
    for _i in 0..17 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        v2_rewards_checks(tip_index_block, &mut peer);
    }

    // our "tenure counter" is now at 32
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 32 + EMPTY_SORTITIONS as u64);

    // Alice would have unlocked under v1 rules, so try to stack again via PoX 1 and expect a runtime error
    // in the tx
    let alice_lockup = make_pox_lockup(
        &alice,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    v2_rewards_checks(tip_index_block, &mut peer);

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    eprintln!("Alice addr: {}", alice_address);
    eprintln!("Bob addr: {}", bob_address);

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                eprintln!("TX addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len(), 3, "Alice should have 3 confirmed txs");
    assert_eq!(bob_txs.len(), 2, "Bob should have 2 confirmed txs");

    assert!(
        match alice_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx0 should have committed okay"
    );

    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx1 should have committed okay"
    );

    assert_eq!(
        alice_txs.get(&2).unwrap().result,
        Value::err_none(),
        "Alice tx2 should have resulted in a runtime error (was the attempt to lock again in Pox 1)"
    );

    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    assert!(
        match bob_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx1 should have committed okay"
    );

    // Check that the call to `stack-stx` has a well-formed print event.
    let stack_tx = &bob_txs.get(&0).unwrap().clone().events[0];
    let pox_addr_val = generate_pox_clarity_value("60c59ab11f7063ef44c16d3dc856f76bbb915eba");
    let stack_op_data = HashMap::from([
        ("lock-amount", Value::UInt(5_120_000_000_000)),
        ("unlock-burn-height", Value::UInt(55)),
        ("start-burn-height", Value::UInt(35)),
        ("pox-addr", pox_addr_val.clone()),
        ("lock-period", Value::UInt(3)),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(stack_tx, common_data, stack_op_data);

    // Check that the call to `stack-extend` has a well-formed print event.
    let stack_extend_tx = &bob_txs.get(&1).unwrap().clone().events[0];
    let stack_ext_op_data = HashMap::from([
        ("extend-count", Value::UInt(1)),
        ("pox-addr", pox_addr_val),
        ("unlock-burn-height", Value::UInt(60)),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-extend".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(5120000000000),
        locked: Value::UInt(5120000000000),
        burnchain_unlock_height: Value::UInt(55),
    };
    check_pox_print_event(stack_extend_tx, common_data, stack_ext_op_data);
}

/// In this test case, two Stackers, Alice and Bob delegate stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition. This test
///  covers the two different ways a Stacker can be validly extended via `delegate-stack-extend` --
///  extending from a V1 lockup and extending from a V2 lockup.
///
/// Alice: delegate-stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        Before the early unlock, Alice invokes:
///           `delegate-stx` in PoX v2
///           `delegate-stack-stx` in PoX v2
///        Alice tries to stack again via PoX v1, which is allowed by the contract,
///        but forbidden by the VM (because PoX has transitioned to v2)
/// Bob:   delegate-stacks via PoX v2 for 3 cycles.
///        Bob extends 1 cycles
#[test]
fn test_delegate_extend_transition_pox_2() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    eprintln!("First v2 cycle = {}", first_v2_cycle);
    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_delegate_extend_transition_pox_2",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let charlie_address = key_to_stacks_addr(&charlie);

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;
    let mut coinbase_nonce = 0;

    let INITIAL_BALANCE = 1024 * POX_THRESHOLD_STEPS_USTX;
    let LOCKUP_AMT = 1024 * POX_THRESHOLD_STEPS_USTX;

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
        // one reward address, and it's Charlies's
        // either way, there's a single reward address
        assert_eq!(reward_addrs.len(), 1);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(&(reward_addrs[0].0).hash160(), &charlie_address.bytes);
        // 1 lockup was done between alice's first cycle and the start of v2 cycles
        assert_eq!(reward_addrs[0].1, 1 * LOCKUP_AMT);
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
        // v2 reward cycles have begun, so reward addrs should be read from PoX2 which is just Charlie, but 2048*threshold
        assert_eq!(reward_addrs.len(), 1);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(&(reward_addrs[0].0).hash160(), &charlie_address.bytes);
        // 2 lockups were performed in v2 cycles
        assert_eq!(reward_addrs[0].1, 2 * LOCKUP_AMT);
    };

    // our "tenure counter" is now at 0
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 0 + EMPTY_SORTITIONS as u64);

    // first tenure is empty
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, INITIAL_BALANCE);

    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_account.stx_balance.amount_unlocked(), INITIAL_BALANCE,);
    assert_eq!(alice_account.stx_balance.amount_locked(), 0);
    assert_eq!(alice_account.stx_balance.unlock_height(), 0);

    // next tenure include Alice's lockup
    let tip = get_tip(peer.sortdb.as_ref());
    let delegate_tx = make_pox_contract_call(
        &alice,
        0,
        "delegate-stx",
        vec![
            Value::UInt(LOCKUP_AMT),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::none(),
        ],
    );

    let delegate_stack_tx = make_pox_contract_call(
        &charlie,
        0,
        "delegate-stack-stx",
        vec![
            PrincipalData::from(alice_address.clone()).into(),
            Value::UInt(LOCKUP_AMT),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(tip.block_height as u128),
            Value::UInt(4),
        ],
    );

    // aggregate commit to each cycle delegate-stack-stx locked for (cycles 6, 7, 8, 9)
    let agg_commit_tx_1 = make_pox_contract_call(
        &charlie,
        1,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(EXPECTED_ALICE_FIRST_REWARD_CYCLE),
        ],
    );

    let agg_commit_tx_2 = make_pox_contract_call(
        &charlie,
        2,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(EXPECTED_ALICE_FIRST_REWARD_CYCLE + 1),
        ],
    );

    let agg_commit_tx_3 = make_pox_contract_call(
        &charlie,
        3,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(EXPECTED_ALICE_FIRST_REWARD_CYCLE + 2),
        ],
    );

    let agg_commit_tx_4 = make_pox_contract_call(
        &charlie,
        4,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(EXPECTED_ALICE_FIRST_REWARD_CYCLE + 3),
        ],
    );

    // our "tenure counter" is now at 1
    assert_eq!(tip.block_height, 1 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(
        &[
            delegate_tx,
            delegate_stack_tx,
            agg_commit_tx_1,
            agg_commit_tx_2,
            agg_commit_tx_3,
            agg_commit_tx_4,
        ],
        &mut coinbase_nonce,
    );

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_first_reward_cycle, EXPECTED_ALICE_FIRST_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until alice's first reward cycle
    for _i in 0..4 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // produce blocks until immediately after the epoch switch (8 more blocks to block height 36)
    for _i in 0..4 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_delegate_tx = make_pox_2_contract_call(
        &bob,
        0,
        "delegate-stx",
        vec![
            Value::UInt(2048 * POX_THRESHOLD_STEPS_USTX),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::none(),
        ],
    );

    let alice_delegate_tx = make_pox_2_contract_call(
        &alice,
        1,
        "delegate-stx",
        vec![
            Value::UInt(2048 * POX_THRESHOLD_STEPS_USTX),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::none(),
        ],
    );

    let delegate_stack_tx = make_pox_2_contract_call(
        &charlie,
        5,
        "delegate-stack-stx",
        vec![
            PrincipalData::from(bob_address.clone()).into(),
            Value::UInt(LOCKUP_AMT),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(tip.block_height as u128),
            Value::UInt(3),
        ],
    );

    // Alice _will_ auto-unlock: she can be delegate-stack-extend'ed in PoX v2
    let delegate_extend_tx = make_pox_2_contract_call(
        &charlie,
        6,
        "delegate-stack-extend",
        vec![
            PrincipalData::from(alice_address.clone()).into(),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(6),
        ],
    );

    // Charlie agg commits the first 3 cycles, but wait until delegate-extended bob to
    //   agg commit the 4th cycle
    // aggregate commit to each cycle delegate-stack-stx locked for (cycles 6, 7, 8, 9)
    let agg_commit_tx_1 = make_pox_2_contract_call(
        &charlie,
        7,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(first_v2_cycle as u128),
        ],
    );

    let agg_commit_tx_2 = make_pox_2_contract_call(
        &charlie,
        8,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(first_v2_cycle as u128 + 1),
        ],
    );

    let agg_commit_tx_3 = make_pox_2_contract_call(
        &charlie,
        9,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(first_v2_cycle as u128 + 2),
        ],
    );

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(
        &[
            bob_delegate_tx,
            alice_delegate_tx,
            delegate_stack_tx,
            delegate_extend_tx,
            agg_commit_tx_1,
            agg_commit_tx_2,
            agg_commit_tx_3,
        ],
        &mut coinbase_nonce,
    );
    alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
    let alice_principal = alice_address.clone().into();
    let bob_principal = bob_address.clone().into();
    let StackingStateCheckData {
        first_cycle: alice_first_cycle,
        lock_period: alice_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &alice_principal,
        false,
        POX_2_NAME,
    );
    let StackingStateCheckData {
        first_cycle: bob_first_cycle,
        lock_period: bob_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &bob_principal,
        false,
        POX_2_NAME,
    );

    assert_eq!(
        alice_first_cycle as u64, first_v2_cycle,
        "Alice's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(alice_lock_period, 6);
    assert_eq!(
        bob_first_cycle as u64, first_v2_cycle,
        "Bob's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(bob_lock_period, 3);

    // Extend bob's lockup via `delegate-stack-extend` for 1 more cycle
    let delegate_extend_tx = make_pox_2_contract_call(
        &charlie,
        10,
        "delegate-stack-extend",
        vec![
            PrincipalData::from(bob_address.clone()).into(),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(1),
        ],
    );

    let agg_commit_tx = make_pox_2_contract_call(
        &charlie,
        11,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(first_v2_cycle as u128 + 3),
        ],
    );

    let tip_index_block =
        peer.tenure_with_txs(&[delegate_extend_tx, agg_commit_tx], &mut coinbase_nonce);
    alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
    let StackingStateCheckData {
        first_cycle: alice_first_cycle,
        lock_period: alice_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &alice_principal,
        false,
        POX_2_NAME,
    );
    let StackingStateCheckData {
        first_cycle: bob_first_cycle,
        lock_period: bob_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &bob_principal,
        false,
        POX_2_NAME,
    );

    assert_eq!(
        alice_first_cycle as u64, first_v2_cycle,
        "Alice's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(alice_lock_period, 6);
    assert_eq!(
        bob_first_cycle as u64, first_v2_cycle,
        "Bob's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(bob_lock_period, 4);

    // produce blocks until "tenure counter" is 15 -- this is where
    //  the v2 reward cycles start
    for _i in 0..3 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(tip_index_block, &mut peer);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    // our "tenure counter" is now at 15
    assert_eq!(tip.block_height, 15 + EMPTY_SORTITIONS as u64);

    // Extend bob's lockup via `delegate-stack-extend` for 1 more cycle
    //  so that we can check the first-reward-cycle is correctly updated
    let delegate_extend_tx = make_pox_2_contract_call(
        &charlie,
        12,
        "delegate-stack-extend",
        vec![
            PrincipalData::from(bob_address.clone()).into(),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(1),
        ],
    );

    let tip_index_block = peer.tenure_with_txs(&[delegate_extend_tx], &mut coinbase_nonce);
    v2_rewards_checks(tip_index_block, &mut peer);
    let StackingStateCheckData {
        first_cycle: alice_first_cycle,
        lock_period: alice_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &alice_principal,
        false,
        POX_2_NAME,
    );
    let StackingStateCheckData {
        first_cycle: bob_first_cycle,
        lock_period: bob_lock_period,
        ..
    } = check_stacking_state_invariants(
        &mut peer,
        &tip_index_block,
        &bob_principal,
        false,
        POX_2_NAME,
    );

    assert_eq!(
        alice_first_cycle as u64, first_v2_cycle,
        "Alice's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(alice_lock_period, 6);
    assert_eq!(
        bob_first_cycle as u64, first_v2_cycle,
        "Bob's first cycle in PoX-2 stacking state is the next cycle, which is 8"
    );
    assert_eq!(bob_lock_period, 5);

    // produce blocks until "tenure counter" is 32 -- this is where
    //  alice *would have been* unlocked under v1 rules
    for _i in 0..16 {
        let tip_index_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        v2_rewards_checks(tip_index_block, &mut peer);
    }

    // our "tenure counter" is now at 32
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 32 + EMPTY_SORTITIONS as u64);

    // Alice would have unlocked under v1 rules, so try to stack again via PoX 1 and expect a runtime error
    // in the tx
    let alice_lockup = make_pox_lockup(
        &alice,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);
    v2_rewards_checks(tip_index_block, &mut peer);

    // now let's check some tx receipts
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut charlie_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                eprintln!("TX addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == charlie_address {
                    charlie_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len(), 3, "Alice should have 3 confirmed txs");
    assert_eq!(bob_txs.len(), 1, "Bob should have 1 confirmed tx");
    assert_eq!(
        charlie_txs.len(),
        13,
        "Charlie should have 13 confirmed txs"
    );

    assert!(
        match alice_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx0 should have committed okay"
    );

    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx1 should have committed okay"
    );

    assert_eq!(
        alice_txs.get(&2).unwrap().result,
        Value::err_none(),
        "Alice tx2 should have resulted in a runtime error (was the attempt to lock again in Pox 1)"
    );

    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    // Check that the call to `delegate-stack-stx` has a well-formed print event.
    let delegate_stack_tx = &charlie_txs.get(&5).unwrap().clone().events[0];
    let pox_addr_val = generate_pox_clarity_value("12d93ae7b61e5b7d905c85828d4320e7c221f433");
    let delegate_op_data = HashMap::from([
        ("lock-amount", Value::UInt(10240000000000)),
        ("unlock-burn-height", Value::UInt(55)),
        ("start-burn-height", Value::UInt(35)),
        ("pox-addr", pox_addr_val.clone()),
        ("lock-period", Value::UInt(3)),
        (
            "delegator",
            Value::Principal(
                StacksAddress::from_string("ST9DJEQ7PRF5PZCGBJ2R53A343KW48FM6DJS5VNY")
                    .unwrap()
                    .to_account_principal(),
            ),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-stx".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(delegate_stack_tx, common_data, delegate_op_data);

    // Check that the call to `delegate-stack-extend` has a well-formed print event.
    let delegate_stack_extend_tx = &charlie_txs.get(&6).unwrap().clone().events[0];
    let delegate_ext_op_data = HashMap::from([
        ("pox-addr", pox_addr_val.clone()),
        ("unlock-burn-height", Value::UInt(70)),
        ("extend-count", Value::UInt(6)),
        (
            "delegator",
            Value::Principal(
                StacksAddress::from_string("ST9DJEQ7PRF5PZCGBJ2R53A343KW48FM6DJS5VNY")
                    .unwrap()
                    .to_account_principal(),
            ),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "delegate-stack-extend".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(0),
        locked: Value::UInt(10240000000000),
        burnchain_unlock_height: Value::UInt(37),
    };
    check_pox_print_event(delegate_stack_extend_tx, common_data, delegate_ext_op_data);

    // Check that the call to `stack-aggregation-commit` has a well-formed print event.
    let stack_agg_commit_tx = &charlie_txs.get(&8).unwrap().clone().events[0];
    let stack_agg_commit_op_data = HashMap::from([
        ("pox-addr", pox_addr_val),
        ("reward-cycle", Value::UInt(9)),
        ("amount-ustx", Value::UInt(20480000000000)),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-aggregation-commit".to_string(),
        stacker: Value::Principal(
            StacksAddress::from_string("ST9DJEQ7PRF5PZCGBJ2R53A343KW48FM6DJS5VNY")
                .unwrap()
                .to_account_principal(),
        ),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(stack_agg_commit_tx, common_data, stack_agg_commit_op_data);

    for (_nonce, tx) in charlie_txs.iter() {
        assert!(
            match tx.result {
                Value::Response(ref r) => r.committed,
                _ => false,
            },
            "All of Charlie's transactions should have committed okay"
        );
    }
}

#[test]
fn test_pox_2_getters() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;
    let LOCKUP_AMT = 1024 * POX_THRESHOLD_STEPS_USTX;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    eprintln!("First v2 cycle = {}", first_v2_cycle);
    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test-pox-2-getters",
        Some(epochs.clone()),
        None,
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let mut coinbase_nonce = 0;
    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();
    let danielle = keys.pop().unwrap();

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let charlie_address = key_to_stacks_addr(&charlie);

    for _i in 0..20 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    let cur_reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    // alice locks in v2
    let alice_lockup = make_pox_2_lockup(
        &alice,
        0,
        LOCKUP_AMT,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        4,
        tip.block_height,
    );

    // bob deleates to charlie
    let bob_delegate_tx = make_pox_2_contract_call(
        &bob,
        0,
        "delegate-stx",
        vec![
            Value::UInt(LOCKUP_AMT),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::none(),
        ],
    );

    // charlie calls delegate-stack-stx for bob
    let charlie_delegate_stack_tx = make_pox_2_contract_call(
        &charlie,
        0,
        "delegate-stack-stx",
        vec![
            PrincipalData::from(bob_address.clone()).into(),
            Value::UInt(LOCKUP_AMT),
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(tip.block_height as u128),
            Value::UInt(4),
        ],
    );

    let agg_commit_tx_1 = make_pox_2_contract_call(
        &charlie,
        1,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(cur_reward_cycle as u128),
        ],
    );

    let agg_commit_tx_2 = make_pox_2_contract_call(
        &charlie,
        2,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(cur_reward_cycle as u128 + 1),
        ],
    );

    let agg_commit_tx_3 = make_pox_2_contract_call(
        &charlie,
        3,
        "stack-aggregation-commit",
        vec![
            make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                charlie_address.bytes.clone(),
            ),
            Value::UInt(cur_reward_cycle as u128 + 2),
        ],
    );

    let reject_pox = make_pox_2_contract_call(&danielle, 0, "reject-pox", vec![]);

    peer.tenure_with_txs(
        &[
            alice_lockup,
            bob_delegate_tx,
            charlie_delegate_stack_tx,
            agg_commit_tx_1,
            agg_commit_tx_2,
            agg_commit_tx_3,
            reject_pox,
        ],
        &mut coinbase_nonce,
    );

    let result = eval_at_tip(&mut peer, "pox-2", &format!("
    {{
        ;; should be none
        get-delegation-info-alice: (get-delegation-info '{}),
        ;; should be (some $charlie_address)
        get-delegation-info-bob: (get-delegation-info '{}),
        ;; should be none
        get-allowance-contract-callers: (get-allowance-contract-callers '{} '{}),
        ;; should be 1
        get-num-reward-set-pox-addresses-current: (get-num-reward-set-pox-addresses u{}),
        ;; should be 0
        get-num-reward-set-pox-addresses-future: (get-num-reward-set-pox-addresses u1000),
        ;; should be 0
        get-partial-stacked-by-cycle-bob-0: (get-partial-stacked-by-cycle {{ version: 0x00, hashbytes: 0x{} }} u{} '{}),
        get-partial-stacked-by-cycle-bob-1: (get-partial-stacked-by-cycle {{ version: 0x00, hashbytes: 0x{} }} u{} '{}),
        get-partial-stacked-by-cycle-bob-2: (get-partial-stacked-by-cycle {{ version: 0x00, hashbytes: 0x{} }} u{} '{}),
        ;; should be LOCKUP_AMT
        get-partial-stacked-by-cycle-bob-3: (get-partial-stacked-by-cycle {{ version: 0x00, hashbytes: 0x{} }} u{} '{}),
        ;; should be 0
        get-total-pox-rejection-now: (get-total-pox-rejection u{}),
        ;; should be LOCKUP_AMT
        get-total-pox-rejection-next: (get-total-pox-rejection u{}),
        ;; should be 0
        get-total-pox-rejection-future: (get-total-pox-rejection u{})
    }}", &alice_address,
        &bob_address,
        &bob_address, &format!("{}.hello-world", &charlie_address), cur_reward_cycle + 1,
        &charlie_address.bytes, cur_reward_cycle + 0, &charlie_address,
        &charlie_address.bytes, cur_reward_cycle + 1, &charlie_address,
        &charlie_address.bytes, cur_reward_cycle + 2, &charlie_address,
        &charlie_address.bytes, cur_reward_cycle + 3, &charlie_address,
        cur_reward_cycle,
        cur_reward_cycle + 1,
        cur_reward_cycle + 2,
    ));

    eprintln!("{}", &result);
    let data = result.expect_tuple().unwrap().data_map;

    let alice_delegation_info = data
        .get("get-delegation-info-alice")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap();
    assert!(alice_delegation_info.is_none());

    let bob_delegation_info = data
        .get("get-delegation-info-bob")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap()
        .unwrap()
        .expect_tuple()
        .unwrap()
        .data_map;
    let bob_delegation_addr = bob_delegation_info
        .get("delegated-to")
        .cloned()
        .unwrap()
        .expect_principal()
        .unwrap();
    let bob_delegation_amt = bob_delegation_info
        .get("amount-ustx")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    let bob_pox_addr_opt = bob_delegation_info
        .get("pox-addr")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap();
    assert_eq!(bob_delegation_addr, charlie_address.to_account_principal());
    assert_eq!(bob_delegation_amt, LOCKUP_AMT);
    assert!(bob_pox_addr_opt.is_none());

    let allowance = data
        .get("get-allowance-contract-callers")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap();
    assert!(allowance.is_none());

    let current_num_reward_addrs = data
        .get("get-num-reward-set-pox-addresses-current")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(current_num_reward_addrs, 2);

    let future_num_reward_addrs = data
        .get("get-num-reward-set-pox-addresses-future")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(future_num_reward_addrs, 0);

    for i in 0..3 {
        let key =
            ClarityName::try_from(format!("get-partial-stacked-by-cycle-bob-{}", &i)).unwrap();
        let partial_stacked = data.get(&key).cloned().unwrap().expect_optional().unwrap();
        assert!(partial_stacked.is_none());
    }
    let partial_stacked = data
        .get("get-partial-stacked-by-cycle-bob-3")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap()
        .unwrap()
        .expect_tuple()
        .unwrap()
        .data_map
        .get("stacked-amount")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(partial_stacked, LOCKUP_AMT);

    let rejected = data
        .get("get-total-pox-rejection-now")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(rejected, 0);

    let rejected = data
        .get("get-total-pox-rejection-next")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(rejected, LOCKUP_AMT);

    let rejected = data
        .get("get-total-pox-rejection-future")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    assert_eq!(rejected, 0);
}

#[test]
fn test_get_pox_addrs() {
    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 4; // 4 reward slots
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = 4;

    assert_eq!(burnchain.pox_constants.reward_slots(), 4);

    let epochs = StacksEpoch::all(1, 2, 3);

    let (mut peer, keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test-get-pox-addrs",
        Some(epochs.clone()),
        None,
    );
    let num_blocks = 20;

    let mut lockup_reward_cycle = 0;
    let mut prepared = false;
    let mut rewarded = false;
    let mut paid_out = HashSet::new();
    let mut all_reward_addrs = vec![];

    for tenure_id in 0..num_blocks {
        let microblock_privkey = StacksPrivateKey::new();
        let microblock_pubkeyhash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
        let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap() as u128;

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![coinbase_tx];

                if tenure_id == 1 {
                    // all peers lock at the same time
                    for (key, hash_mode) in keys.iter().zip(
                        [
                            AddressHashMode::SerializeP2PKH,
                            AddressHashMode::SerializeP2SH,
                            AddressHashMode::SerializeP2WPKH,
                            AddressHashMode::SerializeP2WSH,
                        ]
                        .iter(),
                    ) {
                        let lockup = make_pox_2_lockup(
                            key,
                            0,
                            1024 * POX_THRESHOLD_STEPS_USTX,
                            PoxAddress::from_legacy(*hash_mode, key_to_stacks_addr(key).bytes),
                            2,
                            tip.block_height,
                        );
                        block_txs.push(lockup);
                    }
                }

                let block_builder = StacksBlockBuilder::make_block_builder(
                    &burnchain,
                    false,
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    microblock_pubkeyhash,
                )
                .unwrap();
                let (anchored_block, _size, _cost) =
                    StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        block_txs,
                    )
                    .unwrap();
                (anchored_block, vec![])
            },
        );

        let (burn_height, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if burnchain.is_in_prepare_phase(burn_height)
            || burn_height >= burnchain.reward_cycle_to_block_height(lockup_reward_cycle + 2)
        {
            // make sure we burn!
            for op in burn_ops.iter() {
                if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = &op {
                    eprintln!("prepare phase || no PoX {}: {:?}", burn_height, opdata);
                    assert!(opdata.all_outputs_burn());
                    assert!(opdata.burn_fee > 0);

                    if tenure_id > 1 && cur_reward_cycle > lockup_reward_cycle.into() {
                        prepared = true;
                    }
                }
            }
        } else {
            // no burns -- 100% commitment
            for op in burn_ops.iter() {
                if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = &op {
                    eprintln!("reward phase {}: {:?}", burn_height, opdata);
                    if tenure_id > 1 && cur_reward_cycle == (lockup_reward_cycle + 1).into() {
                        assert!(!opdata.all_outputs_burn());
                        rewarded = true;
                    } else {
                        // lockup hasn't happened yet
                        assert!(opdata.all_outputs_burn());
                    }

                    assert!(opdata.burn_fee > 0);
                }
            }
        }

        let total_liquid_ustx = get_liquid_ustx(&mut peer);
        let tip_index_block = StacksBlockId::new(&consensus_hash, &stacks_block.block_hash());

        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;

        if tenure_id <= 1 {
            // record the first reward cycle when tokens get stacked
            lockup_reward_cycle = 1 + burnchain
                .block_height_to_reward_cycle(tip_burn_block_height)
                .unwrap();
            eprintln!(
                "\nlockup reward cycle: {}\ncur reward cycle: {}\n",
                lockup_reward_cycle, cur_reward_cycle
            );
        }
        if tenure_id > 1 {
            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                chainstate.get_stacking_minimum(sortdb, &tip_index_block)
            })
            .unwrap();
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
            })
            .unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                chainstate.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
            })
            .unwrap();

            // all keys locked up STX no matter what if we're in the lock period
            if burn_height < burnchain.reward_cycle_to_block_height(lockup_reward_cycle + 2) {
                for key in keys.iter() {
                    let balance = get_balance(&mut peer, &key_to_stacks_addr(key).into());
                    assert_eq!(balance, 0);
                }
            } else {
                for key in keys.iter() {
                    let balance = get_balance(&mut peer, &key_to_stacks_addr(key).into());
                    assert!(balance > 0);
                }
                assert_eq!(reward_addrs.len(), 0);
            }

            eprintln!("\ntenure: {}\nreward cycle: {}\nlockup_reward_cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, lockup_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

            if cur_reward_cycle == lockup_reward_cycle.into() {
                assert_eq!(reward_addrs.len(), 4);
                all_reward_addrs = reward_addrs;
            }

            // let's see who got paid
            let addrs_and_payout = with_sortdb(&mut peer, |ref mut chainstate, ref mut sortdb| {
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
                                            &format!(
                                                "(get-burn-block-info? pox-addrs u{})",
                                                &(burn_height - 1)
                                            ),
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
            .expect("FATAL: expected list")
            .expect_tuple()
            .unwrap();

            eprintln!(
                "At block height {}: {:?}",
                burn_height - 1,
                &addrs_and_payout
            );

            let addrs = addrs_and_payout
                .get("addrs")
                .unwrap()
                .to_owned()
                .expect_list()
                .unwrap();

            let payout = addrs_and_payout
                .get("payout")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();

            // there's always some burnchain tokens spent.
            assert!(payout > 0);

            if burnchain.is_in_prepare_phase(burn_height - 1) {
                assert_eq!(payout, 1000);
                assert_eq!(addrs.len(), 1);
                let pox_addr = PoxAddress::try_from_pox_tuple(false, &addrs[0]).unwrap();
                assert!(pox_addr.is_burn());
            } else {
                assert_eq!(payout, 500);
                assert_eq!(addrs.len(), 2);
                for addr in addrs.into_iter() {
                    let pox_addr = PoxAddress::try_from_pox_tuple(false, &addr).unwrap();
                    if !pox_addr.is_burn() {
                        paid_out.insert(pox_addr);
                    }
                }
            }
        }
    }
    assert!(prepared);
    assert!(rewarded);

    assert_eq!(paid_out.len(), 4);
    for (rw_addr, _) in all_reward_addrs.into_iter() {
        assert!(paid_out.contains(&rw_addr));
    }
}

#[test]
fn test_stack_with_segwit() {
    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 4; // 4 reward slots
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = 4;

    assert_eq!(burnchain.pox_constants.reward_slots(), 4);

    let epochs = StacksEpoch::all(1, 2, 3);

    let (mut peer, all_keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test-stack-with-segwit",
        Some(epochs.clone()),
        None,
    );
    let num_blocks = 20;

    let segwit_keys: Vec<_> = all_keys.into_iter().take(4).collect();

    let mut lockup_reward_cycle = 0;
    let mut prepared = false;
    let mut rewarded = false;
    let mut paid_out = HashSet::new();
    let mut all_reward_addrs = vec![];

    for tenure_id in 0..num_blocks {
        let microblock_privkey = StacksPrivateKey::new();
        let microblock_pubkeyhash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
        let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
            .unwrap();

        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap() as u128;

        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(
            |ref mut miner,
             ref mut sortdb,
             ref mut chainstate,
             vrf_proof,
             ref parent_opt,
             ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![coinbase_tx];

                if tenure_id == 1 {
                    let segwit_p2wpkh_lockup = make_pox_2_lockup(
                        &segwit_keys[0],
                        0,
                        1024 * POX_THRESHOLD_STEPS_USTX,
                        PoxAddress::Addr20(false, PoxAddressType20::P2WPKH, [0x01; 20]),
                        2,
                        tip.block_height,
                    );
                    block_txs.push(segwit_p2wpkh_lockup);

                    let segwit_p2wsh_lockup = make_pox_2_lockup(
                        &segwit_keys[1],
                        0,
                        1024 * POX_THRESHOLD_STEPS_USTX,
                        PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [0x02; 32]),
                        2,
                        tip.block_height,
                    );
                    block_txs.push(segwit_p2wsh_lockup);

                    let segwit_p2tr_lockup = make_pox_2_lockup(
                        &segwit_keys[2],
                        0,
                        1024 * POX_THRESHOLD_STEPS_USTX,
                        PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0x03; 32]),
                        2,
                        tip.block_height,
                    );
                    block_txs.push(segwit_p2tr_lockup);

                    let lockup = make_pox_2_lockup(
                        &segwit_keys[3],
                        0,
                        1024 * POX_THRESHOLD_STEPS_USTX,
                        PoxAddress::from_legacy(
                            AddressHashMode::SerializeP2PKH,
                            Hash160([0x04; 20]),
                        ),
                        2,
                        tip.block_height,
                    );
                    block_txs.push(lockup);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(
                    &burnchain,
                    false,
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    microblock_pubkeyhash,
                )
                .unwrap();
                let (anchored_block, _size, _cost) =
                    StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        block_txs,
                    )
                    .unwrap();
                (anchored_block, vec![])
            },
        );

        let (burn_height, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

        if burnchain.is_in_prepare_phase(burn_height)
            || burn_height >= burnchain.reward_cycle_to_block_height(lockup_reward_cycle + 2)
        {
            // make sure we burn!
            for op in burn_ops.iter() {
                if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = &op {
                    eprintln!("prepare phase || no PoX {}: {:?}", burn_height, opdata);
                    assert!(opdata.all_outputs_burn());
                    assert!(opdata.burn_fee > 0);

                    if tenure_id > 1 && cur_reward_cycle > lockup_reward_cycle.into() {
                        prepared = true;
                    }
                }
            }
        } else {
            // no burns -- 100% commitment
            for op in burn_ops.iter() {
                if let BlockstackOperationType::LeaderBlockCommit(ref opdata) = &op {
                    eprintln!("reward phase {}: {:?}", burn_height, opdata);
                    if tenure_id > 1 && cur_reward_cycle == (lockup_reward_cycle + 1).into() {
                        assert!(!opdata.all_outputs_burn());
                        rewarded = true;
                    } else {
                        // lockup hasn't happened yet
                        assert!(opdata.all_outputs_burn());
                    }

                    assert!(opdata.burn_fee > 0);
                }
            }
        }

        let total_liquid_ustx = get_liquid_ustx(&mut peer);
        let tip_index_block = StacksBlockId::new(&consensus_hash, &stacks_block.block_hash());

        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;

        if tenure_id <= 1 {
            // record the first reward cycle when tokens get stacked
            lockup_reward_cycle = 1 + burnchain
                .block_height_to_reward_cycle(tip_burn_block_height)
                .unwrap();
            eprintln!(
                "\nlockup reward cycle: {}\ncur reward cycle: {}\n",
                lockup_reward_cycle, cur_reward_cycle
            );
        }
        if tenure_id > 1 {
            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                chainstate.get_stacking_minimum(sortdb, &tip_index_block)
            })
            .unwrap();
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
            })
            .unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
                chainstate.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
            })
            .unwrap();

            // all keys locked up STX no matter what if we're in the lock period
            if burn_height < burnchain.reward_cycle_to_block_height(lockup_reward_cycle + 2) {
                for key in segwit_keys.iter() {
                    let balance = get_balance(&mut peer, &key_to_stacks_addr(key).into());
                    assert_eq!(balance, 0);
                }
            } else {
                for key in segwit_keys.iter() {
                    let balance = get_balance(&mut peer, &key_to_stacks_addr(key).into());
                    assert!(balance > 0);
                }
                assert_eq!(reward_addrs.len(), 0);
            }

            eprintln!("\ntenure: {}\nreward cycle: {}\nlockup_reward_cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, lockup_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

            if cur_reward_cycle == lockup_reward_cycle.into() {
                assert_eq!(reward_addrs.len(), 4);
                all_reward_addrs = reward_addrs;
            }

            // let's see who got paid
            let addrs_and_payout = with_sortdb(&mut peer, |ref mut chainstate, ref mut sortdb| {
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
                                            &format!(
                                                "(get-burn-block-info? pox-addrs u{})",
                                                &(burn_height - 1)
                                            ),
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
            .expect("FATAL: expected list")
            .expect_tuple()
            .unwrap();

            eprintln!(
                "At block height {}: {:?}",
                burn_height - 1,
                &addrs_and_payout
            );

            let addrs = addrs_and_payout
                .get("addrs")
                .unwrap()
                .to_owned()
                .expect_list()
                .unwrap();

            let payout = addrs_and_payout
                .get("payout")
                .unwrap()
                .to_owned()
                .expect_u128()
                .unwrap();

            // there's always some burnchain tokens spent.
            assert!(payout > 0);

            if burnchain.is_in_prepare_phase(burn_height - 1) {
                assert_eq!(payout, 1000);
                assert_eq!(addrs.len(), 1);
                let pox_addr = PoxAddress::try_from_pox_tuple(false, &addrs[0]).unwrap();
                assert!(pox_addr.is_burn());
            } else {
                assert_eq!(payout, 500);
                assert_eq!(addrs.len(), 2);
                for addr in addrs.into_iter() {
                    let pox_addr = PoxAddress::try_from_pox_tuple(false, &addr).unwrap();
                    if !pox_addr.is_burn() {
                        paid_out.insert(pox_addr);
                    }
                }
            }
        }
    }
    assert!(prepared);
    assert!(rewarded);

    assert_eq!(paid_out.len(), 4);
    let mut expected_addrs = vec![
        PoxAddress::Addr20(false, PoxAddressType20::P2WPKH, [0x01; 20]),
        PoxAddress::Addr32(false, PoxAddressType32::P2WSH, [0x02; 32]),
        PoxAddress::Addr32(false, PoxAddressType32::P2TR, [0x03; 32]),
        PoxAddress::Standard(
            StacksAddress {
                version: 26,
                bytes: Hash160([0x04; 20]),
            },
            Some(AddressHashMode::SerializeP2PKH),
        ),
    ];

    for (rw_addr, _) in all_reward_addrs.into_iter() {
        assert!(paid_out.contains(&rw_addr));
        assert!(expected_addrs.contains(&rw_addr));
        expected_addrs.retain(|addr| *addr != rw_addr);
    }
    assert_eq!(expected_addrs.len(), 0);
}

/// Verify that delegate-stx validates the PoX addr, if given
#[test]
fn test_pox_2_delegate_stx_addr_validation() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;
    let LOCKUP_AMT = 1024 * POX_THRESHOLD_STEPS_USTX;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    eprintln!("First v2 cycle = {}", first_v2_cycle);
    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test-pox-2-delegate-stx-addr",
        Some(epochs.clone()),
        None,
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let mut coinbase_nonce = 0;
    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();
    let danielle = keys.pop().unwrap();

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let charlie_address = key_to_stacks_addr(&charlie);

    for _i in 0..20 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    let cur_reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    // alice delegates to charlie in v2 to a valid address
    let alice_delegation = make_pox_2_contract_call(
        &alice,
        0,
        "delegate-stx",
        vec![
            Value::UInt(LOCKUP_AMT),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::some(make_pox_addr(
                AddressHashMode::SerializeP2PKH,
                alice_address.bytes.clone(),
            ))
            .unwrap(),
        ],
    );

    let bob_bad_pox_addr = Value::Tuple(
        TupleData::from_data(vec![
            (
                ClarityName::try_from("version".to_owned()).unwrap(),
                Value::buff_from_byte(0xff),
            ),
            (
                ClarityName::try_from("hashbytes".to_owned()).unwrap(),
                Value::Sequence(SequenceData::Buffer(BuffData {
                    data: bob_address.bytes.as_bytes().to_vec(),
                })),
            ),
        ])
        .unwrap(),
    );

    // bob delegates to charlie in v2 with an invalid address
    let bob_delegation = make_pox_2_contract_call(
        &bob,
        0,
        "delegate-stx",
        vec![
            Value::UInt(LOCKUP_AMT),
            PrincipalData::from(charlie_address.clone()).into(),
            Value::none(),
            Value::some(bob_bad_pox_addr).unwrap(),
        ],
    );

    peer.tenure_with_txs(&[alice_delegation, bob_delegation], &mut coinbase_nonce);

    let result = eval_at_tip(
        &mut peer,
        "pox-2",
        &format!(
            "
    {{
        ;; should be (some $charlie_address)
        get-delegation-info-alice: (get-delegation-info '{}),
        ;; should be none
        get-delegation-info-bob: (get-delegation-info '{}),
    }}",
            &alice_address, &bob_address,
        ),
    );

    eprintln!("{}", &result);
    let data = result.expect_tuple().unwrap().data_map;

    // bob had an invalid PoX address
    let bob_delegation_info = data
        .get("get-delegation-info-bob")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap();
    assert!(bob_delegation_info.is_none());

    // alice was valid
    let alice_delegation_info = data
        .get("get-delegation-info-alice")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap()
        .unwrap()
        .expect_tuple()
        .unwrap()
        .data_map;
    let alice_delegation_addr = alice_delegation_info
        .get("delegated-to")
        .cloned()
        .unwrap()
        .expect_principal()
        .unwrap();
    let alice_delegation_amt = alice_delegation_info
        .get("amount-ustx")
        .cloned()
        .unwrap()
        .expect_u128()
        .unwrap();
    let alice_pox_addr_opt = alice_delegation_info
        .get("pox-addr")
        .cloned()
        .unwrap()
        .expect_optional()
        .unwrap();
    assert_eq!(
        alice_delegation_addr,
        charlie_address.to_account_principal()
    );
    assert_eq!(alice_delegation_amt, LOCKUP_AMT);
    assert!(alice_pox_addr_opt.is_some());

    let alice_pox_addr = alice_pox_addr_opt.unwrap();

    assert_eq!(
        alice_pox_addr,
        make_pox_addr(AddressHashMode::SerializeP2PKH, alice_address.bytes.clone(),)
    );
}

/// In this test case, Alice delegates to Bob.
///  Bob stacks Alice's funds via PoX v2 for 6 cycles. In the third cycle,
///  Bob increases Alice's stacking amount by less than the stacking min.
///  Bob is able to increase the pool's aggregate amount anyway.
///
#[test]
fn stack_aggregation_increase() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.pox_participation_threshold_pct = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "pox_2_stack_aggregation_increase",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, bob_address.bytes.clone());
    let charlie = keys.pop().unwrap();
    let charlie_address = key_to_stacks_addr(&charlie);
    let charlie_pox_addr = make_pox_addr(
        AddressHashMode::SerializeP2PKH,
        charlie_address.bytes.clone(),
    );
    let dan = keys.pop().unwrap();
    let dan_address = key_to_stacks_addr(&dan);
    let dan_principal = PrincipalData::from(dan_address.clone());
    let dan_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, dan_address.bytes.clone());
    let alice_nonce = 0;
    let mut bob_nonce = 0;
    let mut charlie_nonce = 0;
    let mut dan_nonce = 0;

    let alice_first_lock_amount = 512 * POX_THRESHOLD_STEPS_USTX;
    let alice_delegation_amount = alice_first_lock_amount + 1;
    let dan_delegation_amount = alice_first_lock_amount + 1;
    let dan_stack_amount = 511 * POX_THRESHOLD_STEPS_USTX;

    let mut coinbase_nonce = 0;

    // produce blocks until the epoch switch
    for _i in 0..10 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit delegation tx for alice
    let alice_delegation_1 = make_pox_2_contract_call(
        &alice,
        alice_nonce,
        "delegate-stx",
        vec![
            Value::UInt(alice_delegation_amount),
            bob_principal.clone().into(),
            Value::none(),
            Value::none(),
        ],
    );

    // bob locks some of alice's tokens
    let delegate_stack_tx_bob = make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-stx",
        vec![
            alice_principal.clone().into(),
            Value::UInt(alice_first_lock_amount),
            bob_pox_addr.clone(),
            Value::UInt(tip.block_height as u128),
            Value::UInt(6),
        ],
    );
    bob_nonce += 1;

    // dan stacks some tokens
    let stack_tx_dan = make_pox_2_lockup(
        &dan,
        dan_nonce,
        dan_stack_amount,
        PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, dan_address.bytes.clone()),
        12,
        tip.block_height,
    );
    dan_nonce += 1;

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    let mut latest_block = peer.tenure_with_txs(
        &[alice_delegation_1, delegate_stack_tx_bob, stack_tx_dan],
        &mut coinbase_nonce,
    );

    // check that the partial stacking state contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // we'll produce blocks until the 3rd reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 3) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);

    let dan_bal = get_stx_account_at(&mut peer, &latest_block, &dan_principal);
    assert_eq!(dan_bal.amount_locked(), dan_stack_amount);

    // check that the partial stacking state still contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    let cur_reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    let mut txs_to_submit = vec![];

    // bob locks in alice's tokens to a PoX address,
    // which clears the partially-stacked state
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-commit-indexed",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 1) as u128),
        ],
    ));
    let bob_stack_aggregation_commit_indexed = bob_nonce;
    bob_nonce += 1;

    // bob tries to lock tokens in a reward cycle that's already committed (should fail with
    // ERR_STACKING_NO_SUCH_PRINCIPAL)
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 1) as u128),
            Value::UInt(0),
        ],
    ));
    let bob_err_stacking_no_such_principal = bob_nonce;
    bob_nonce += 1;

    // bob locks up 1 more of alice's tokens
    // takes effect in the _next_ reward cycle
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(1),
        ],
    ));
    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);
    let tip = get_tip(peer.sortdb.as_ref());
    let cur_reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    // locked up more tokens
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        alice_delegation_amount,
    );

    // only 1 uSTX to lock in this next cycle for Alice
    let partial_stacked = get_partial_stacked(
        &mut peer,
        &latest_block,
        &bob_pox_addr,
        cur_reward_cycle + 1,
        &bob_principal,
        POX_2_NAME,
    );
    assert_eq!(partial_stacked, 1);

    for cycle_number in (cur_reward_cycle + 2)..(EXPECTED_FIRST_V2_CYCLE + 6) {
        // alice has 512 * POX_THRESHOLD_STEPS_USTX partially-stacked STX in all cycles after
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, alice_delegation_amount);
    }

    let mut txs_to_submit = vec![];

    // charlie tries to lock alice's additional tokens to his own PoX address (should fail with
    // ERR_STACKING_NO_SUCH_PRINCIPAL)
    txs_to_submit.push(make_pox_2_contract_call(
        &charlie,
        charlie_nonce,
        "stack-aggregation-increase",
        vec![
            charlie_pox_addr.clone(),
            Value::UInt(cur_reward_cycle as u128),
            Value::UInt(0),
        ],
    ));
    let charlie_err_stacking_no_principal = charlie_nonce;
    charlie_nonce += 1;

    // charlie tries to lock alice's additional tokens to bob's PoX address (should fail with
    // ERR_STACKING_NO_SUCH_PRINCIPAL)
    txs_to_submit.push(make_pox_2_contract_call(
        &charlie,
        charlie_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt(cur_reward_cycle as u128),
            Value::UInt(0),
        ],
    ));
    let charlie_err_stacking_no_principal_2 = charlie_nonce;
    charlie_nonce += 1;

    // bob tries to retcon a reward cycle lockup (should fail with ERR_STACKING_INVALID_LOCK_PERIOD)
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt(cur_reward_cycle as u128),
            Value::UInt(0),
        ],
    ));
    let bob_err_stacking_invalid_lock_period = bob_nonce;
    bob_nonce += 1;

    // bob tries to lock tokens in a reward cycle that has no tokens stacked in it yet (should
    // fail with ERR_DELEGATION_NO_REWARD_CYCLE)
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 13) as u128),
            Value::UInt(0),
        ],
    ));
    let bob_err_delegation_no_reward_cycle = bob_nonce;
    bob_nonce += 1;

    // bob tries to lock tokens to a non-existant PoX reward address (should fail with
    // ERR_DELEGATION_NO_REWARD_SLOT)
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 1) as u128),
            Value::UInt(2),
        ],
    ));
    let bob_err_delegation_no_reward_slot = bob_nonce;
    bob_nonce += 1;

    // bob tries to lock tokens to the wrong PoX address (should fail with ERR_DELEGATION_WRONG_REWARD_SLOT).
    // slot 0 belongs to dan.
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 1) as u128),
            Value::UInt(0),
        ],
    ));
    let bob_err_delegation_wrong_reward_slot = bob_nonce;
    bob_nonce += 1;

    // bob locks tokens for Alice (bob's previous stack-aggregation-commit put his PoX address in
    // slot 1 for this reward cycle)
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "stack-aggregation-increase",
        vec![
            bob_pox_addr.clone(),
            Value::UInt((cur_reward_cycle + 1) as u128),
            Value::UInt(1),
        ],
    ));
    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        alice_delegation_amount
    );

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut charlie_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == charlie_address {
                    charlie_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len(), 1);
    assert_eq!(bob_txs.len(), 9);
    assert_eq!(charlie_txs.len(), 2);

    // bob's stack-aggregation-commit-indexed succeeded and returned the right index
    assert_eq!(
        &bob_txs[&bob_stack_aggregation_commit_indexed]
            .result
            .to_string(),
        "(ok u1)"
    );

    // check bob's errors
    assert_eq!(
        &bob_txs[&bob_err_stacking_no_such_principal]
            .result
            .to_string(),
        "(err 4)"
    );
    assert_eq!(
        &bob_txs[&bob_err_stacking_invalid_lock_period]
            .result
            .to_string(),
        "(err 2)"
    );
    assert_eq!(
        &bob_txs[&bob_err_delegation_no_reward_cycle]
            .result
            .to_string(),
        "(err 4)"
    );
    assert_eq!(
        &bob_txs[&bob_err_delegation_no_reward_slot]
            .result
            .to_string(),
        "(err 28)"
    );
    assert_eq!(
        &bob_txs[&bob_err_delegation_wrong_reward_slot]
            .result
            .to_string(),
        "(err 29)"
    );

    // check charlie's errors
    assert_eq!(
        &charlie_txs[&charlie_err_stacking_no_principal]
            .result
            .to_string(),
        "(err 4)"
    );
    assert_eq!(
        &charlie_txs[&charlie_err_stacking_no_principal_2]
            .result
            .to_string(),
        "(err 4)"
    );
}

#[test]
fn stack_in_both_pox1_and_pox2() {
    // this is the number of blocks after the first sortition any V1
    // PoX locks will automatically unlock at.
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.pox_participation_threshold_pct = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, 0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "stack_in_both_pox1_and_pox2",
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_pox_addr =
        make_pox_addr(AddressHashMode::SerializeP2PKH, alice_address.bytes.clone());

    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, bob_address.bytes.clone());

    let mut alice_nonce = 0;
    let mut bob_nonce = 0;

    let alice_first_lock_amount = 512 * POX_THRESHOLD_STEPS_USTX;
    let bob_first_lock_amount = 512 * POX_THRESHOLD_STEPS_USTX;

    let mut coinbase_nonce = 0;

    // produce blocks until the epoch switch
    for _i in 0..10 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // our "tenure counter" is now at 10
    assert_eq!(tip.block_height, 10 + EMPTY_SORTITIONS as u64);

    // alice stacks some of her STX in pox1
    let alice_stx_1 = make_pox_lockup(
        &alice,
        alice_nonce,
        alice_first_lock_amount,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );
    alice_nonce += 1;

    // alice stacks some of her STX in pox2
    let alice_stx_2 = make_pox_2_lockup(
        &alice,
        alice_nonce,
        alice_first_lock_amount,
        PoxAddress::try_from_pox_tuple(false, &alice_pox_addr).unwrap(),
        12,
        tip.block_height,
    );
    alice_nonce += 1;

    // bob stacks some of his STX in pox2
    let bob_stx_2 = make_pox_2_lockup(
        &bob,
        bob_nonce,
        bob_first_lock_amount,
        PoxAddress::try_from_pox_tuple(false, &bob_pox_addr).unwrap(),
        12,
        tip.block_height,
    );
    bob_nonce += 1;

    // bob stacks some of her STX in pox1
    let bob_stx_1 = make_pox_lockup(
        &bob,
        bob_nonce,
        bob_first_lock_amount,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
        12,
        tip.block_height,
    );
    bob_nonce += 1;

    // mine it
    peer.tenure_with_txs(
        &[alice_stx_1, alice_stx_2, bob_stx_2, bob_stx_1],
        &mut coinbase_nonce,
    );

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

    // alice's and bob's second transactions both failed with runtime errors
    alice_txs
        .get(&0)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    alice_txs
        .get(&1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();

    bob_txs
        .get(&0)
        .unwrap()
        .result
        .clone()
        .expect_result_ok()
        .unwrap();
    bob_txs
        .get(&1)
        .unwrap()
        .result
        .clone()
        .expect_result_err()
        .unwrap();
}
