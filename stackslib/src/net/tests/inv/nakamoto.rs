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

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::thread::JoinHandle;

use clarity::vm::types::PrincipalData;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::{read_next, StacksMessageCodec};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpoch;
use stacks_common::util::hash::Hash160;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::nakamoto::coordinator::tests::{
    simple_nakamoto_coordinator_10_extended_tenures_10_sortitions,
    simple_nakamoto_coordinator_10_tenures_10_sortitions,
    simple_nakamoto_coordinator_2_tenures_3_sortitions,
};
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::StacksEpochExtension;
use crate::net::inv::nakamoto::{InvGenerator, NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::comms::NeighborComms;
use crate::net::test::{to_addr, TestEventObserver, TestPeer};
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};
use crate::net::{
    Error as NetError, GetNakamotoInvData, HandshakeData, NakamotoInvData, NeighborAddress,
    PeerNetworkComms, StacksMessage, StacksMessageType,
};
use crate::stacks_common::types::Address;
use crate::util_lib::db::Error as DBError;

/// Handshake with and get the reward cycle inventories for a range of reward cycles
pub fn peer_get_nakamoto_invs<'a>(
    mut peer: TestPeer<'a>,
    reward_cycles: &[u64],
) -> (TestPeer<'a>, Vec<StacksMessageType>) {
    let privk = StacksPrivateKey::new();
    let mut convo = peer.make_client_convo();
    let client_peer = peer.make_client_local_peer(privk.clone());
    let peer_addr = peer.p2p_socketaddr();
    let chain_view = peer.network.get_chain_view().clone();

    let mut get_nakamoto_invs = vec![];
    for reward_cycle in reward_cycles {
        let consensus_hash = {
            let sortdb = peer.sortdb();
            let reward_cycle_start_height = sortdb
                .pox_constants
                .reward_cycle_to_block_height(sortdb.first_block_height, *reward_cycle);
            let ih = sortdb.index_handle_at_tip();
            let Some(rc_start_sn) = ih
                .get_block_snapshot_by_height(reward_cycle_start_height)
                .unwrap()
            else {
                continue;
            };
            rc_start_sn.consensus_hash
        };

        let get_nakamoto_inv =
            StacksMessageType::GetNakamotoInv(GetNakamotoInvData { consensus_hash });
        let signed_get_nakamoto_inv = convo
            .sign_message(&chain_view, &privk, get_nakamoto_inv)
            .unwrap();
        get_nakamoto_invs.push(signed_get_nakamoto_inv);
    }

    let (shutdown_send, shutdown_recv) = sync_channel(1);
    let join_handle = thread::spawn(move || {
        let mut tcp_socket = TcpStream::connect(peer_addr).unwrap();

        // first, handshake
        let handshake_data =
            StacksMessageType::Handshake(HandshakeData::from_local_peer(&client_peer));
        let signed_handshake_data = convo
            .sign_message(&chain_view, &privk, handshake_data)
            .unwrap();
        signed_handshake_data
            .consensus_serialize(&mut tcp_socket)
            .unwrap();

        // read back handshake-accept
        let msg: StacksMessage = read_next(&mut tcp_socket).unwrap();
        match msg.payload {
            StacksMessageType::HandshakeAccept(..)
            | StacksMessageType::StackerDBHandshakeAccept(..) => {}
            x => {
                error!("Peer returned {:?}", &x);
                panic!();
            }
        }

        let mut replies = vec![];
        for get_nakamoto_inv in get_nakamoto_invs {
            // send getnakamotoinv
            get_nakamoto_inv
                .consensus_serialize(&mut tcp_socket)
                .unwrap();

            loop {
                // read back the message
                let msg: StacksMessage = read_next(&mut tcp_socket).unwrap();
                let is_inv_reply = if let StacksMessageType::NakamotoInv(..) = &msg.payload {
                    true
                } else {
                    false
                };
                if is_inv_reply {
                    replies.push(msg.payload);
                    break;
                } else {
                    debug!("Got spurious meessage {:?}", &msg);
                }
            }
        }

        shutdown_send.send(true).unwrap();
        replies
    });

    loop {
        peer.step_with_ibd(false).unwrap();
        if let Ok(..) = shutdown_recv.try_recv() {
            break;
        }
    }

    let replies = join_handle.join().unwrap();

    (peer, replies)
}

#[test]
fn test_nakamoto_inv_10_tenures_10_sortitions() {
    let peer = simple_nakamoto_coordinator_10_tenures_10_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 10);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();
    let stacks_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bh = peer.network.stacks_tip.block_hash.clone();

    let mut inv_generator = InvGenerator::new();
    let mut inv_generator_no_cache = InvGenerator::new_no_cache();

    // processed 10 tenures
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 46);

    // check the reward cycles
    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();

        let bitvec_no_cache = inv_generator_no_cache
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();

        assert_eq!(bitvec, bitvec_no_cache);

        debug!(
            "At reward cycle {}: {:?}, mesasge = {:?}",
            rc, &bitvec, &inv
        );

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // first Nakamoto tenure starts at block 37
            assert_eq!(bitvec, vec![false, false, true, true, true]);
        } else if rc == 8 {
            // full reward cycle of nakamoto
            assert_eq!(bitvec, vec![true, true, true, true, true]);
        } else if rc == 9 {
            // we stopped at height 46
            assert_eq!(bitvec, vec![true, true]);
        } else if rc >= 10 {
            // haven't processed this high yet
            assert_eq!(bitvec.len(), 0);
        }

        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
    }
}

#[test]
fn test_nakamoto_inv_2_tenures_3_sortitions() {
    let peer = simple_nakamoto_coordinator_2_tenures_3_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 8);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();
    let stacks_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bh = peer.network.stacks_tip.block_hash.clone();

    let mut inv_generator = InvGenerator::new();
    let mut inv_generator_no_cache = InvGenerator::new_no_cache();

    // processed 3 sortitions
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 39);

    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();

        let bitvec_no_cache = inv_generator_no_cache
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();
        assert_eq!(bitvec, bitvec_no_cache);

        debug!(
            "At reward cycle {}: {:?}, mesasge = {:?}",
            rc, &bitvec, &inv
        );

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // nakamoto starts at height 37, but we skipeed the sortition at 38
            assert_eq!(bitvec, vec![false, false, true, false, true]);
        } else {
            assert_eq!(bitvec.len(), 0);
        }
        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
    }
}

#[test]
fn test_nakamoto_inv_10_extended_tenures_10_sortitions() {
    let peer = simple_nakamoto_coordinator_10_extended_tenures_10_sortitions();

    // sanity check -- nakamoto begins at height 37
    assert_eq!(
        peer.config.epochs,
        Some(StacksEpoch::unit_test_3_0_only(37))
    );

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(reward_cycle_invs.len(), 10);

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();
    let stacks_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let stacks_tip_bh = peer.network.stacks_tip.block_hash.clone();

    let mut inv_generator = InvGenerator::new();
    let mut inv_generator_no_cache = InvGenerator::new_no_cache();

    // processed 10 tenures
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 46);

    for (rc, inv) in reward_cycle_invs.into_iter().enumerate() {
        let bitvec = inv_generator
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();
        let bitvec_no_cache = inv_generator_no_cache
            .make_tenure_bitvector(
                &tip,
                sort_db,
                chainstate,
                &stacks_tip_ch,
                &stacks_tip_bh,
                rc as u64,
            )
            .unwrap();
        assert_eq!(bitvec, bitvec_no_cache);

        debug!("At reward cycle {}: {:?}", rc, &bitvec);

        if rc <= 6 {
            // prior to start of nakamoto
            assert_eq!(bitvec, vec![false, false, false, false, false]);
        } else if rc == 7 {
            // first Nakamoto tenure starts at block 37
            assert_eq!(bitvec, vec![false, false, true, true, true]);
        } else if rc == 8 {
            // full reward cycle of nakamoto
            assert_eq!(bitvec, vec![true, true, true, true, true]);
        } else if rc == 9 {
            // we stopped at height 46
            assert_eq!(bitvec, vec![true, true]);
        } else if rc >= 10 {
            // haven't processed this high yet
            assert_eq!(bitvec.len(), 0);
        }
        let StacksMessageType::NakamotoInv(inv) = inv else {
            panic!("Did not receive an inv for reward cycle {}", rc);
        };
        assert_eq!(
            NakamotoInvData::try_from(&bitvec).unwrap().tenures,
            inv.tenures
        );
        assert_eq!(bitvec.len() as u16, inv.tenures.len());
    }
}

/// NOTE: The second return value does _not_ need `<'a>`, since `observer` is never installed into
/// the peers here.  However, it appears unavoidable to the borrow-checker.
pub fn make_nakamoto_peers_from_invs<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    rc_len: u32,
    prepare_len: u32,
    bitvecs: Vec<Vec<bool>>,
    num_peers: usize,
) -> (TestPeer<'a>, Vec<TestPeer<'a>>) {
    make_nakamoto_peers_from_invs_ext(test_name, observer, bitvecs, |boot_plan| {
        boot_plan
            .with_pox_constants(rc_len, prepare_len)
            .with_extra_peers(num_peers)
            .with_initial_balances(vec![])
    })
}

/// NOTE: The second return value does _not_ need `<'a>`, since `observer` is never installed into
/// the peers here.  However, it appears unavoidable to the borrow-checker.
pub fn make_nakamoto_peers_from_invs_and_balances<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    rc_len: u32,
    prepare_len: u32,
    bitvecs: Vec<Vec<bool>>,
    num_peers: usize,
    initial_balances: Vec<(PrincipalData, u64)>,
) -> (TestPeer<'a>, Vec<TestPeer<'a>>) {
    make_nakamoto_peers_from_invs_ext(test_name, observer, bitvecs, |boot_plan| {
        boot_plan
            .with_pox_constants(rc_len, prepare_len)
            .with_extra_peers(num_peers)
            .with_initial_balances(initial_balances)
    })
}

/// Make peers from inventories and balances
/// NOTE: The second return value does _not_ need `<'a>`, since `observer` is never installed into
/// the peers here.  However, it appears unavoidable to the borrow-checker.
pub fn make_nakamoto_peers_from_invs_ext<'a, F>(
    test_name: &str,
    observer: &'a TestEventObserver,
    bitvecs: Vec<Vec<bool>>,
    boot_config: F,
) -> (TestPeer<'a>, Vec<TestPeer<'a>>)
where
    F: FnOnce(NakamotoBootPlan) -> NakamotoBootPlan,
{
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut initial_balances = vec![(addr.to_account_principal(), 1_000_000)];

    let mut sender_nonce = 0;

    let mut next_stx_transfer = || {
        let mut stx_transfer = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&private_key).unwrap(),
            TransactionPayload::TokenTransfer(
                recipient_addr.clone().to_account_principal(),
                1,
                TokenTransferMemo([0x00; 34]),
            ),
        );
        stx_transfer.chain_id = 0x80000000;
        stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;
        stx_transfer.set_tx_fee(1);
        stx_transfer.auth.set_origin_nonce(sender_nonce);
        sender_nonce += 1;

        let mut tx_signer = StacksTransactionSigner::new(&stx_transfer);
        tx_signer.sign_origin(&private_key).unwrap();
        let stx_transfer_signed = tx_signer.get_tx().unwrap();

        stx_transfer_signed
    };

    let mut boot_tenures = vec![];
    for bitvec in bitvecs.iter() {
        for has_tenure in bitvec {
            if *has_tenure {
                boot_tenures.push(NakamotoBootTenure::Sortition(vec![
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                ]));
            } else {
                boot_tenures.push(NakamotoBootTenure::NoSortition(vec![
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                    NakamotoBootStep::Block(vec![next_stx_transfer()]),
                    NakamotoBootStep::TenureExtend(vec![next_stx_transfer()]),
                ]));
            }
        }
    }

    // make malleablized blocks
    let (test_signers, test_stackers) = TestStacker::multi_signing_set(&[
        0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
    ]);

    let mut plan = boot_config(
        NakamotoBootPlan::new(test_name)
            .with_private_key(private_key)
            .with_test_signers(test_signers)
            .with_test_stackers(test_stackers),
    );
    plan.initial_balances.append(&mut initial_balances);

    let (peer, other_peers) = plan.boot_into_nakamoto_peers(boot_tenures, Some(observer));
    (peer, other_peers)
}

pub fn make_nakamoto_peer_from_invs<'a>(
    test_name: &str,
    observer: &'a TestEventObserver,
    rc_len: u32,
    prepare_len: u32,
    bitvecs: Vec<Vec<bool>>,
) -> TestPeer<'a> {
    make_nakamoto_peers_from_invs(test_name, observer, rc_len, prepare_len, bitvecs, 0).0
}

fn check_inv_messages(
    bitvecs: Vec<Vec<bool>>,
    rc_len: u32,
    nakamoto_start_burn_height: u64,
    messages: Vec<StacksMessageType>,
) {
    for (msg_idx, msg) in messages.into_iter().enumerate() {
        let StacksMessageType::NakamotoInv(inv) = msg else {
            panic!("Did not receive an inv for reward cycle {}", msg_idx);
        };
        for bit in 0..(inv.tenures.len() as usize) {
            let burn_block_height = (msg_idx as u64) * u64::from(rc_len) + (bit as u64);
            let msg_bit = inv.tenures.get(bit as u16).unwrap_or(false);
            if burn_block_height < nakamoto_start_burn_height {
                // inv doesn't cover epoch 2
                assert!(
                    !msg_bit,
                    "Bit {} in message {} is set but is before nakamoto-start height {} ({})",
                    bit, msg_idx, nakamoto_start_burn_height, burn_block_height
                );
                continue;
            }

            let inv_offset: u64 = burn_block_height - nakamoto_start_burn_height;
            let bitvec_idx = (inv_offset / u64::from(rc_len)) as usize;
            let expected_bit = if bitvec_idx >= bitvecs.len() {
                false
            } else {
                bitvecs[bitvec_idx][(inv_offset % u64::from(rc_len)) as usize]
            };
            assert_eq!(msg_bit, expected_bit, "Bit {} in message {} is {}, but expected {}. burn_block_height = {}, inv_offset = {}, bitvec_idx = {}, nakamoto_start_burn_height = {}",
                       bit, msg_idx, msg_bit, expected_bit, burn_block_height, inv_offset, bitvec_idx, nakamoto_start_burn_height);
        }
    }
}

fn check_inv_state(
    bitvecs: Vec<Vec<bool>>,
    rc_len: u32,
    nakamoto_start_burn_height: u64,
    inv_state: &NakamotoTenureInv,
) {
    for (i, (tenure_rc, tenure_inv)) in inv_state.tenures_inv.iter().enumerate() {
        for bit in 0..(rc_len as usize) {
            let msg_bit = if bit / 8 >= tenure_inv.len().into() {
                // only allowed at the end
                debug!(
                    "bit = {}, tenure_rc = {}, tenure_inv = {:?}",
                    bit, tenure_rc, &tenure_inv
                );
                assert_eq!(i, inv_state.tenures_inv.len() - 1);
                false
            } else {
                tenure_inv.get(bit.try_into().unwrap()).unwrap_or(false)
            };

            let burn_block_height = *tenure_rc * u64::from(rc_len) + (bit as u64);
            if burn_block_height < nakamoto_start_burn_height {
                // inv doesn't cover epoch 2
                assert!(
                    !msg_bit,
                    "Bit {} in tenure {} is set but is before nakamoto-start height {} ({})",
                    bit, tenure_rc, nakamoto_start_burn_height, burn_block_height
                );
                continue;
            }

            let inv_offset: u64 = burn_block_height - nakamoto_start_burn_height;
            let bitvec_idx = (inv_offset / u64::from(rc_len)) as usize;
            let expected_bit = if bitvec_idx >= bitvecs.len() {
                false
            } else {
                bitvecs[bitvec_idx][(inv_offset % u64::from(rc_len)) as usize]
            };
            assert_eq!(msg_bit, expected_bit, "Bit {} in tenure {} is {}, but expected {}. burn_block_height = {}, inv_offset = {}, bitvec_idx = {}, nakamoto_start_burn_height = {}",
                       bit, tenure_rc, msg_bit, expected_bit, burn_block_height, inv_offset, bitvec_idx, nakamoto_start_burn_height);
        }
    }
}

#[test]
fn test_nakamoto_invs_full() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 10);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_alternating() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        vec![
            true, false, true, false, true, false, true, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 10);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_sparse() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, true, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, true, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, true, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, true, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, true, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 12);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_invs_different_anchor_blocks() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        vec![true, true, true, true, true, true, false, true, true, true],
        vec![true, true, true, true, true, false, false, true, true, true],
        vec![
            true, true, true, true, false, false, false, true, true, true,
        ],
        vec![
            true, true, true, false, false, false, false, true, true, true,
        ],
        vec![
            true, true, false, false, false, false, false, true, true, true,
        ],
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        vec![
            false, false, false, false, false, false, false, true, true, true,
        ],
    ];

    let peer = make_nakamoto_peer_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone());
    let (peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    eprintln!("{:#?}", &reward_cycle_invs);
    assert_eq!(reward_cycle_invs.len(), 12);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);
}

#[test]
fn test_nakamoto_tenure_inv() {
    let na = NeighborAddress {
        addrbytes: PeerAddress([
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]),
        port: 65535,
        public_key_hash: Hash160([0x11; 20]),
    };
    let mut nakamoto_inv = NakamotoTenureInv::new(100, 100, 0, na);
    assert!(!nakamoto_inv.has_ith_tenure(0));
    assert!(!nakamoto_inv.has_ith_tenure(99));
    assert!(!nakamoto_inv.has_ith_tenure(100));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 0);

    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 1);
    assert!(learned);

    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.tenures, 1);
    assert!(!learned);

    debug!("nakamoto_inv = {:?}", &nakamoto_inv);
    for i in 0..200 {
        assert!(!nakamoto_inv.has_ith_tenure(i));
    }
    for i in 200..300 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }
    assert!(!nakamoto_inv.has_ith_tenure(199));
    assert!(nakamoto_inv.has_ith_tenure(200));
    assert!(!nakamoto_inv.has_ith_tenure(300));
    assert!(!nakamoto_inv.has_ith_tenure(301));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 1);

    let mut partial_tenure_bools = vec![];
    for i in 0..100 {
        partial_tenure_bools.push(i % 2 == 0);
    }

    // has_ith_tenure() works (non-triial case)
    let partial_tenure = NakamotoInvData::try_from(&partial_tenure_bools).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(partial_tenure.clone().tenures, 2);
    assert!(learned);

    for i in 300..400 {
        assert_eq!(nakamoto_inv.has_ith_tenure(i), i % 2 == 0);
    }
    assert!(!nakamoto_inv.has_ith_tenure(199));
    assert!(nakamoto_inv.has_ith_tenure(299));
    assert!(nakamoto_inv.has_ith_tenure(300));
    assert!(nakamoto_inv.has_ith_tenure(398));
    assert!(!nakamoto_inv.has_ith_tenure(399));
    assert!(!nakamoto_inv.has_ith_tenure(400));
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 2);

    // supports sparse updates
    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.tenures, 4);
    assert!(learned);

    for i in 400..500 {
        assert!(!nakamoto_inv.has_ith_tenure(i));
    }
    for i in 500..600 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    // can overwrite tenures
    let full_tenure = NakamotoInvData::try_from(&[true; 100]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 2);
    assert!(learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 2);
    assert!(!learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 4);

    for i in 300..400 {
        assert!(nakamoto_inv.has_ith_tenure(i));
    }

    // partial data
    let partial_tenure = NakamotoInvData::try_from(&[true; 50]).unwrap();
    let learned = nakamoto_inv.merge_tenure_inv(full_tenure.clone().tenures, 5);
    assert!(learned);
    assert_eq!(nakamoto_inv.highest_reward_cycle(), 5);

    // state machine advances when we say so
    assert_eq!(nakamoto_inv.reward_cycle(), 0);
    assert!(nakamoto_inv.is_online());
    nakamoto_inv.set_online(false);
    assert!(!nakamoto_inv.is_online());

    nakamoto_inv.next_reward_cycle();
    assert_eq!(nakamoto_inv.reward_cycle(), 1);

    nakamoto_inv.try_reset_comms(0, 0, 0);
    assert_eq!(nakamoto_inv.reward_cycle(), 0);
    assert!(nakamoto_inv.is_online());
}

#[test]
fn test_nakamoto_inv_sync_state_machine() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // alternating rc
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    // boot two peers, and cannibalize the second one for its network and sortdb so we can use them
    // to directly drive a state machine.
    let (mut peer, mut other_peers) =
        make_nakamoto_peers_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone(), 1);
    let mut other_peer = other_peers.pop().unwrap();

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let tip = {
        let sort_db = peer.sortdb.as_mut().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    let total_rcs = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap()
        + 1;

    // run peer and other_peer until they connect
    loop {
        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        let event_ids = peer.network.iter_peer_event_ids();
        let other_event_ids = other_peer.network.iter_peer_event_ids();

        if !(event_ids.count() == 0) && !(other_event_ids.count() == 0) {
            break;
        }
    }

    debug!("Peers are connected");
    let peer_addr = NeighborAddress::from_neighbor(&peer.to_neighbor());

    let (sx, rx) = sync_channel(1);
    let mut inv_machine = NakamotoInvStateMachine::new(PeerNetworkComms::new());

    // ::scope is necessary because Rust is forced to think that `other_peers` has the same lifetime
    // as `observer`, which prohibits running a bare thread in which `other_peers` outlives
    // `observer`
    std::thread::scope(|s| {
        s.spawn(|| {
            let sortdb = other_peer.sortdb.take().unwrap();
            inv_machine
                .process_getnakamotoinv_begins(&mut other_peer.network, &sortdb, false)
                .unwrap();
            other_peer.sortdb = Some(sortdb);

            let mut last_learned_rc = 0;
            loop {
                let _ = other_peer.step_with_ibd(false);
                let ev_ids = other_peer.network.iter_peer_event_ids();
                if ev_ids.count() == 0 {
                    // disconnected
                    panic!("Disconnected");
                }

                let (num_msgs, learned) = inv_machine
                    .process_getnakamotoinv_finishes(&mut other_peer.network)
                    .unwrap();

                for (_, inv) in inv_machine.inventories.iter() {
                    debug!(
                        "inv is at rc {}, last learned rc is {}, total rcs = {}",
                        inv.reward_cycle(),
                        last_learned_rc,
                        total_rcs
                    );
                    last_learned_rc = last_learned_rc.max(inv.reward_cycle());
                }

                if last_learned_rc >= total_rcs {
                    break;
                }

                let sortdb = other_peer.sortdb.take().unwrap();
                inv_machine
                    .process_getnakamotoinv_begins(&mut other_peer.network, &sortdb, false)
                    .unwrap();
                other_peer.sortdb = Some(sortdb);
            }

            sx.send(true).unwrap();
        });

        loop {
            let _ = peer.step_with_ibd(false);
            if rx.try_recv().is_ok() {
                break;
            }
        }
    });

    // inv_machine learned everything
    for (_, inv) in inv_machine.inventories.iter() {
        debug!("Check inv state: {:?}", inv);
        check_inv_state(bitvecs.clone(), 10, nakamoto_start, inv);
    }
}

#[test]
fn test_nakamoto_inv_sync_across_epoch_change() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // alternating rc
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    // boot two peers, and cannibalize the second one for its network and sortdb so we can use them
    // to directly drive a state machine.
    let (mut peer, mut other_peers) =
        make_nakamoto_peers_from_invs(function_name!(), &observer, 10, 3, bitvecs.clone(), 1);
    let mut other_peer = other_peers.pop().unwrap();

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let tip = {
        let sort_db = peer.sortdb.as_mut().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    let total_rcs = peer
        .config
        .burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    // run peer and other_peer until they connect
    loop {
        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        let event_ids = peer.network.iter_peer_event_ids();
        let other_event_ids = other_peer.network.iter_peer_event_ids();

        if !(event_ids.count() == 0) && !(other_event_ids.count() == 0) {
            break;
        }
    }

    debug!("Peers are connected");

    // force peers to sync their epoch 2.x inventories
    let old_burn_chain_tip = peer.network.burnchain_tip.block_height;
    let num_epoch2_blocks = nakamoto_start - 26; // TestPeer starts making blocks at sortition 26

    // check epoch 2.x state machine
    let mut round = 0;
    let mut inv_1_count = 0;
    let mut inv_2_count = 0;
    let mut highest_rc_1 = 0;
    let mut highest_rc_2 = 0;

    let burn_tip_start = peer.network.get_current_epoch().start_height;

    while inv_1_count < num_epoch2_blocks
        || inv_2_count < num_epoch2_blocks
        || highest_rc_1 < total_rcs
        || highest_rc_2 < total_rcs
    {
        // trick the work loop into thinking that the current chain view is this
        peer.network.connection_opts.force_nakamoto_epoch_transition = true;
        other_peer
            .network
            .connection_opts
            .force_nakamoto_epoch_transition = true;

        let _ = peer.step_with_ibd(false);
        let _ = other_peer.step_with_ibd(false);

        inv_1_count = peer
            .network
            .inv_state
            .as_ref()
            .map(|inv| inv.get_inv_num_blocks(&other_peer.to_neighbor().addr))
            .unwrap_or(0);
        inv_2_count = other_peer
            .network
            .inv_state
            .as_ref()
            .map(|inv| inv.get_inv_num_blocks(&peer.to_neighbor().addr))
            .unwrap_or(0);

        highest_rc_1 = peer
            .network
            .inv_state_nakamoto
            .as_ref()
            .map(|inv| inv.highest_reward_cycle())
            .unwrap_or(0);
        highest_rc_2 = other_peer
            .network
            .inv_state_nakamoto
            .as_ref()
            .map(|inv| inv.highest_reward_cycle())
            .unwrap_or(0);

        // nothing should break
        match peer.network.inv_state {
            Some(ref inv) => {
                assert_eq!(inv.get_broken_peers().len(), 0);
                assert_eq!(inv.get_dead_peers().len(), 0);
                assert_eq!(inv.get_diverged_peers().len(), 0);
            }
            None => {}
        }

        match other_peer.network.inv_state {
            Some(ref inv) => {
                assert_eq!(inv.get_broken_peers().len(), 0);
                assert_eq!(inv.get_dead_peers().len(), 0);
                assert_eq!(inv.get_diverged_peers().len(), 0);
            }
            None => {}
        }

        round += 1;

        info!(
            "Epoch 2.x state machine: Peer 1: {}, Peer 2: {} (total {})",
            inv_1_count, inv_2_count, num_epoch2_blocks
        );
        info!(
            "Nakamoto state machine: Peer 1: {}, Peer 2: {} (total {})",
            highest_rc_1, highest_rc_2, total_rcs
        );
    }
}

#[test]
fn test_nakamoto_make_tenure_inv_in_forks() {
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];

    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let (mut peer, _) = make_nakamoto_peers_from_invs_and_balances(
        function_name!(),
        &observer,
        10,
        3,
        bitvecs.clone(),
        0,
        initial_balances,
    );
    peer.refresh_burnchain_view();
    peer.mine_malleablized_blocks = false;

    let mut invgen = InvGenerator::new().with_tip_ancestor_search_depth(5);
    let mut invgen_no_cache = InvGenerator::new_no_cache().with_tip_ancestor_search_depth(5);

    //
    // ---------------------- basic operations ----------------------
    //

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let first_burn_block_height = sortdb.first_block_height;

    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let tip_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(first_burn_block_height, sort_tip.block_height)
        .unwrap();

    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let naka_tip = peer.network.stacks_tip.block_id();
    let first_naka_tip = naka_tip.clone();
    let first_sort_tip = sort_tip.clone();
    let first_naka_tip_ch = naka_tip_ch.clone();
    let first_naka_tip_bh = naka_tip_bh.clone();

    // find the first block in this tenure
    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();
    let naka_tenure_start_header = NakamotoChainState::get_nakamoto_tenure_start_block_header(
        &mut chainstate.index_conn(),
        &naka_tip,
        &naka_tip_header.consensus_hash,
    )
    .unwrap()
    .unwrap();
    let (naka_tenure_start_block, _) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(&naka_tenure_start_header.index_block_hash())
        .unwrap()
        .unwrap();

    assert_eq!(invgen.cache_misses(), 0);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, vec![true, true]);
    assert_eq!(invgen.cache_misses(), 3);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, vec![true, true]);
    assert_eq!(invgen.cache_misses(), 3);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(
        bits,
        vec![false, false, true, true, true, true, true, true, true, true]
    );
    assert_eq!(invgen.cache_misses(), 13);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(
        bits,
        vec![false, false, true, true, true, true, true, true, true, true]
    );
    assert_eq!(invgen.cache_misses(), 13);

    //
    // ---------------------- the inv generator can keep up with new blocks ----------------------
    //

    let mut expected_bits = vec![true, true];
    let mut expected_cache_misses = 13;
    let mut naka_tip_block = None;

    for i in 0..3 {
        let (naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
        debug!(
            "test: produced {}: {:?}",
            &naka_block.block_id(),
            &naka_block
        );

        peer.refresh_burnchain_view();
        let naka_tip = peer.network.stacks_tip.block_id();
        let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
        let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let tip_rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(first_burn_block_height, sort_tip.block_height)
            .unwrap();

        let bits = invgen
            .make_tenure_bitvector(
                &sort_tip,
                &sortdb,
                &chainstate,
                &naka_tip_ch,
                &naka_tip_bh,
                tip_rc,
            )
            .unwrap();
        debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
        debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

        expected_bits.push(true);
        expected_cache_misses += 2;

        assert_eq!(bits, expected_bits);
        assert_eq!(invgen.cache_misses(), expected_cache_misses);

        naka_tip_block = Some(naka_block);
    }

    let naka_tip_block = naka_tip_block.unwrap();

    peer.refresh_burnchain_view();
    let naka_tip = peer.network.stacks_tip.block_id();
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();

    //
    // ---------------------- the inv generator can track multiple forks at once ----------------------
    //

    peer.mine_nakamoto_on(vec![naka_tenure_start_block.clone()]);
    let (fork_naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    debug!(
        "test: produced fork {}: {:?}",
        &fork_naka_block.block_id(),
        &fork_naka_block
    );

    peer.refresh_burnchain_view();
    let new_naka_tip = peer.network.stacks_tip.block_id();
    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let tip_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(first_burn_block_height, sort_tip.block_height)
        .unwrap();

    // this will not have reorged
    assert_eq!(naka_tip, new_naka_tip);

    // load inv off of the canonical tip.
    // It should show a missed sortition.
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!(
        "test: Bits in fork on {} at rc {}: {:?}",
        &naka_tip, tip_rc, &bits
    );
    debug!(
        "test: invgen.cache_misses() in fork = {}",
        invgen.cache_misses()
    );

    assert_eq!(bits, [true, true, true, true, true, false]);
    assert_eq!(invgen.cache_misses(), 20);

    // load inv off of the non-canonical tip.
    // it should show the last 3 canonical tenures as missing, and this forked block as present
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &fork_naka_block.header.consensus_hash,
            &fork_naka_block.header.block_hash(),
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &fork_naka_block.header.consensus_hash,
            &fork_naka_block.header.block_hash(),
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!(
        "test: Bits in fork on {} at rc {}: {:?}",
        &fork_naka_block.block_id(),
        tip_rc,
        &bits
    );
    debug!(
        "test: invgen.cache_misses() in fork = {}",
        invgen.cache_misses()
    );

    assert_eq!(bits, [true, true, false, false, false, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 24);

    // add more to the fork
    peer.mine_nakamoto_on(vec![fork_naka_block.clone()]);

    let (fork_naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    debug!(
        "test: produced fork {}: {:?}",
        &fork_naka_block.block_id(),
        &fork_naka_block
    );

    peer.refresh_burnchain_view();
    let new_naka_tip = peer.network.stacks_tip.block_id();
    let new_naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let new_naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let tip_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(first_burn_block_height, sort_tip.block_height)
        .unwrap();

    // this will not have reorged (yet)
    assert_eq!(naka_tip, new_naka_tip);

    // load inv off of the canonical tip.
    // It should show two missed sortitions, for each fork.
    // only one additional cache miss
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!(
        "test: Bits in fork on {} at rc {}: {:?}",
        &naka_tip, tip_rc, &bits
    );
    debug!(
        "test: invgen.cache_misses() in fork = {}",
        invgen.cache_misses()
    );

    assert_eq!(bits, [true, true, true, true, true, false, false]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 25);

    // load inv off of the non-canonical tip again.
    // it should show the last 3 last canonical tenures as missing, and this forked block as
    // present. Two additional cache misses should manifest, since we invalidate the common
    // parent's tenure data.
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &fork_naka_block.header.consensus_hash,
            &fork_naka_block.header.block_hash(),
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &fork_naka_block.header.consensus_hash,
            &fork_naka_block.header.block_hash(),
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!(
        "test: Bits in fork on {} at rc {}: {:?}",
        &fork_naka_block.block_id(),
        tip_rc,
        &bits
    );
    debug!(
        "test: invgen.cache_misses() in fork = {}",
        invgen.cache_misses()
    );

    // only one more cache miss
    assert_eq!(bits, [true, true, false, false, false, true, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 27);

    // load inv off of the canonical tip again.
    // It should show two missed sortitions.
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    debug!(
        "test: Bits in fork on {} at rc {}: {:?}",
        &naka_tip, tip_rc, &bits
    );
    debug!(
        "test: invgen.cache_misses() in fork = {}",
        invgen.cache_misses()
    );

    // no new cache misses
    assert_eq!(bits, [true, true, true, true, true, false, false]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 27);

    //
    // ---------------------- the inv generator will search only a maximum depth before giving up ----------------------
    //

    // advance the canonical chain by 3 more blocks, so the delta between `first_naka_tip` and
    // `naka_tip` is now 6 blocks
    peer.mine_nakamoto_on(vec![naka_tip_block.clone()]);
    for i in 0..3 {
        let (naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
        debug!(
            "test: produced {}: {:?}",
            &naka_block.block_id(),
            &naka_block
        );

        peer.refresh_burnchain_view();
        peer.mine_nakamoto_on(vec![naka_block.clone()]);
    }
    let naka_tip = peer.network.stacks_tip.block_id();
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    // new inv generator with a search depth of 3
    let mut invgen = InvGenerator::new().with_tip_ancestor_search_depth(3);

    // load an old tip on the canonical chain
    let bits = invgen
        .make_tenure_bitvector(
            &first_sort_tip,
            &sortdb,
            &chainstate,
            &first_naka_tip_ch,
            &first_naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &first_sort_tip,
            &sortdb,
            &chainstate,
            &first_naka_tip_ch,
            &first_naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    assert_eq!(bits, [true, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 3);

    // load a descendant that is 6 blocks higher
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    assert_eq!(
        bits,
        [true, true, true, true, true, false, false, true, true, true]
    );

    // all 10 tenures were loaded, because we had to search more than 5 blocks back
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 12);

    // new inv generator with a search depth of 10
    let mut invgen = InvGenerator::new().with_tip_ancestor_search_depth(10);

    // load an old tip on the canonical chain
    let bits = invgen
        .make_tenure_bitvector(
            &first_sort_tip,
            &sortdb,
            &chainstate,
            &first_naka_tip_ch,
            &first_naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &first_sort_tip,
            &sortdb,
            &chainstate,
            &first_naka_tip_ch,
            &first_naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    assert_eq!(bits, [true, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 3);

    // load a descendant that is 6 blocks higher
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    assert_eq!(bits, bits_no_cache);

    assert_eq!(
        bits,
        [true, true, true, true, true, false, false, true, true, true]
    );

    // reused old canonical tip information, but still had an additional cache miss from the parent
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 10);
}

#[test]
fn test_nakamoto_make_tenure_inv_in_many_reward_cycles() {
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];

    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // alternating rc
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let (mut peer, _) = make_nakamoto_peers_from_invs_and_balances(
        function_name!(),
        &observer,
        10,
        3,
        bitvecs.clone(),
        0,
        initial_balances,
    );
    peer.refresh_burnchain_view();
    peer.mine_malleablized_blocks = false;

    let mut invgen = InvGenerator::new().with_tip_ancestor_search_depth(5);
    let mut invgen_no_cache = InvGenerator::new_no_cache().with_tip_ancestor_search_depth(5);

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let first_burn_block_height = sortdb.first_block_height;

    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let tip_rc = sortdb
        .pox_constants
        .block_height_to_reward_cycle(first_burn_block_height, sort_tip.block_height)
        .unwrap();

    let naka_tip = peer.network.stacks_tip.block_id();
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let first_naka_tip = naka_tip.clone();
    let first_sort_tip = sort_tip.clone();

    // find the first block in this tenure
    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();
    let naka_tenure_start_header = NakamotoChainState::get_nakamoto_tenure_start_block_header(
        &mut chainstate.index_conn(),
        &naka_tip,
        &naka_tip_header.consensus_hash,
    )
    .unwrap()
    .unwrap();
    let (naka_tenure_start_block, _) = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_block(&naka_tenure_start_header.index_block_hash())
        .unwrap()
        .unwrap();

    assert_eq!(invgen.cache_misses(), 0);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(bits, [true, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 3);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 1, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, true, true, true, true, true, true, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 13);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 2,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 2,
        )
        .unwrap();

    debug!("test: Bits at rc {}: {:?}", tip_rc - 2, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, false, false, false, false, false, false, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 17);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 3,
        )
        .unwrap();

    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 3,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 3, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, false, true, false, true, false, true, false, true]
    );
    assert_eq!(invgen.cache_misses(), 23);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 4,
        )
        .unwrap();

    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 4,
        )
        .unwrap();

    debug!("test: Bits at rc {}: {:?}", tip_rc - 4, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, true, false, false, false, false, false, false, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 27);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 5,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 5,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 5, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [false, false, true, true, true, true, true, true, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    // load them all again.  cache misses should remain the same.
    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(bits, [true, true]);
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 1,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 1, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, true, true, true, true, true, true, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 2,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 2,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 2, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, false, false, false, false, false, false, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 3,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 3,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 3, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, false, true, false, true, false, true, false, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 4,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 4,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 4, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [true, true, true, false, false, false, false, false, false, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);

    let bits = invgen
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 5,
        )
        .unwrap();
    let bits_no_cache = invgen_no_cache
        .make_tenure_bitvector(
            &sort_tip,
            &sortdb,
            &chainstate,
            &naka_tip_ch,
            &naka_tip_bh,
            tip_rc - 5,
        )
        .unwrap();
    debug!("test: Bits at rc {}: {:?}", tip_rc - 5, &bits);
    debug!("test: invgen.cache_misses() = {}", invgen.cache_misses());

    assert_eq!(bits, bits_no_cache);
    assert_eq!(
        bits,
        [false, false, true, true, true, true, true, true, true, true]
    );
    debug!("cache misses = {}", invgen.cache_misses());
    assert_eq!(invgen.cache_misses(), 37);
}

#[test]
fn test_nakamoto_make_tenure_inv_from_old_tips() {
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];

    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        // item 0 is sortition 42
        vec![true, true, true, true, true, true, true, true, true, true],
        // sparse rc
        // item 0 is sortition 52
        vec![
            true, false, false, false, false, false, false, true, true, true,
        ],
        // alternating rc
        // item 0 is sortition 62
        vec![
            false, true, false, true, false, true, false, true, true, true,
        ],
        // sparse rc
        // item 0 is sortition 72
        vec![
            false, false, false, false, false, false, true, true, true, true,
        ],
        // full rc
        // item 0 is sortition 82
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    // compute the rc-aligned bitvecs.
    // bitvecs[i][0] starts at reward cycle index 2.
    // aligned_bitvecs[i][0] starts at reward cycle index 0.
    let mut aligned_bitvecs = vec![vec![false, false]];
    let mut i = 2;
    loop {
        let bitvec_idx = (i - 2) / 10;
        let bitvec_bit = (i - 2) % 10;
        if bitvec_idx >= bitvecs.len() {
            if let Some(ref mut last_bitvec) = aligned_bitvecs.last_mut() {
                // last aligned bitvec has all `false`s
                while last_bitvec.len() < 10 {
                    last_bitvec.push(false);
                }
            }
            break;
        }

        let aligned_bitvec_idx = i / 10;
        let aligned_bitvec_bit = i % 10;
        if aligned_bitvec_bit == 0 {
            aligned_bitvecs.push(vec![]);
        }

        let bit = bitvecs[bitvec_idx][bitvec_bit];
        aligned_bitvecs[aligned_bitvec_idx].push(bit);

        i += 1;
    }

    assert_eq!(
        aligned_bitvecs[0],
        vec![false, false, true, true, true, true, true, true, true, true]
    );
    assert_eq!(
        aligned_bitvecs[1],
        vec![true, true, true, false, false, false, false, false, false, true]
    );
    assert_eq!(
        aligned_bitvecs[2],
        vec![true, true, false, true, false, true, false, true, false, true]
    );
    assert_eq!(
        aligned_bitvecs[3],
        vec![true, true, false, false, false, false, false, false, true, true]
    );
    assert_eq!(
        aligned_bitvecs[4],
        vec![true, true, true, true, true, true, true, true, true, true]
    );
    assert_eq!(
        aligned_bitvecs[5],
        vec![true, true, false, false, false, false, false, false, false, false]
    );

    let (mut peer, _) = make_nakamoto_peers_from_invs_and_balances(
        function_name!(),
        &observer,
        10,
        3,
        bitvecs.clone(),
        0,
        initial_balances,
    );
    peer.refresh_burnchain_view();
    peer.mine_malleablized_blocks = false;

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();
    let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    let mut invgen = InvGenerator::new().with_tip_ancestor_search_depth(5);
    let mut invgen_no_cache = InvGenerator::new_no_cache().with_tip_ancestor_search_depth(5);

    //
    // ---------------------- querying each tip will report the successive inv bits ----------------------
    //
    let naka_tip = peer.network.stacks_tip.block_id();
    let mut ancestor_tips = vec![];
    let mut cursor = naka_tip.clone();
    loop {
        ancestor_tips.push(cursor.clone());
        let Some(parent) =
            NakamotoChainState::get_nakamoto_parent_block_id(chainstate.db(), &cursor).unwrap()
        else {
            break;
        };
        cursor = parent;
    }
    // last item is an epoch2 block, which we don't care about
    ancestor_tips.pop();
    ancestor_tips.reverse();

    for tip in ancestor_tips.into_iter() {
        debug!("load tip {}", &tip);
        let hdr = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &tip)
            .unwrap()
            .unwrap();
        let tip_ch = hdr.consensus_hash;
        let tip_bh = hdr.anchored_header.block_hash();
        let sn = SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &tip_ch)
            .unwrap()
            .unwrap();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, sn.block_height)
            .unwrap();
        let rc_start_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, rc)
            - 1;
        let bits = invgen
            .make_tenure_bitvector(&sort_tip, &sortdb, &chainstate, &tip_ch, &tip_bh, rc)
            .unwrap();

        let bits_no_cache = invgen_no_cache
            .make_tenure_bitvector(&sort_tip, &sortdb, &chainstate, &tip_ch, &tip_bh, rc)
            .unwrap();

        debug!("tip {}: consensus_hash={}, burn_height={}, reward_cycle={}, bits={:?}, bits_no_cache={:?}", &tip, &tip_ch, sn.block_height, rc, &bits, &bits_no_cache);
        assert_eq!(bits, bits_no_cache);

        // nakamoto starts at burn height 42, and has a reward cycle length of 10, so compute the range of bitvecs we need
        assert_eq!(sortdb.pox_constants.reward_cycle_length, 10);
        assert!(rc >= 4);

        let mut expected_bits = aligned_bitvecs[(rc - 4) as usize].clone();
        let from_bits = expected_bits.clone();

        for i in (sn.block_height + 1 - rc_start_height)..10 {
            expected_bits[i as usize] = false;
        }

        let bit_len = bits.len();
        debug!(
            "tip {}: from_bits={:?}, expected_bits={:?}, inv_bits={:?}, rc={}, block_height={}",
            &tip, &from_bits, &expected_bits, &bits, rc, sn.block_height
        );

        assert_eq!(bits, expected_bits[0..bit_len]);
    }
}

#[test]
fn test_nakamoto_invs_shadow_blocks() {
    let observer = TestEventObserver::new();
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];
    let mut bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let (mut peer, _) = make_nakamoto_peers_from_invs_and_balances(
        function_name!(),
        &observer,
        10,
        3,
        bitvecs.clone(),
        0,
        initial_balances,
    );
    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let mut expected_ids = vec![];

    // construct and add shadow blocks to this peer's chainstate
    peer.refresh_burnchain_view();
    let shadow_block = peer.make_shadow_tenure(None);
    expected_ids.push(shadow_block.block_id());
    peer.mine_nakamoto_on(vec![shadow_block]);

    peer.refresh_burnchain_view();
    let (naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    expected_ids.push(naka_block.block_id());
    peer.mine_nakamoto_on(vec![naka_block]);

    peer.refresh_burnchain_view();
    let shadow_block = peer.make_shadow_tenure(None);
    expected_ids.push(shadow_block.block_id());
    peer.mine_nakamoto_on(vec![shadow_block]);

    peer.refresh_burnchain_view();
    let (naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    expected_ids.push(naka_block.block_id());
    peer.mine_nakamoto_on(vec![naka_block]);

    peer.refresh_burnchain_view();
    let shadow_block = peer.make_shadow_tenure(None);
    expected_ids.push(shadow_block.block_id());
    peer.mine_nakamoto_on(vec![shadow_block]);

    peer.refresh_burnchain_view();
    let (naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    expected_ids.push(naka_block.block_id());
    peer.mine_nakamoto_on(vec![naka_block]);

    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    // the inv should show `true` for each shadow tenure
    bitvecs.push(vec![true, true, true, true, true, true]);
    check_inv_messages(bitvecs, 10, nakamoto_start, reward_cycle_invs);

    // shadow blocks are part of the history
    peer.refresh_burnchain_view();
    let tip = peer.network.stacks_tip.block_id();

    let mut stored_block_ids = vec![];
    let mut cursor = tip;
    for _ in 0..expected_ids.len() {
        let block = peer
            .chainstate()
            .nakamoto_blocks_db()
            .get_nakamoto_block(&cursor)
            .unwrap()
            .unwrap()
            .0;
        stored_block_ids.push(block.block_id());
        cursor = block.header.parent_block_id;
    }

    stored_block_ids.reverse();
    assert_eq!(stored_block_ids, expected_ids);
}
