// Copyright (C) 2024 Stacks Open Internet Foundation
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
use std::collections::HashMap;

use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::ast::ASTRules;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ClarityVersion, MAX_CALL_STACK_DEPTH};
use rand::Rng;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, StacksWorkScore, TrieHash};
use stacks_common::types::Address;
use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::tests::TestMiner;
use crate::chainstate::stacks::db::blocks::{MINIMUM_TX_FEE, MINIMUM_TX_FEE_RATE_PER_BYTE};
use crate::chainstate::stacks::miner::{BlockBuilderSettings, StacksMicroblockBuilder};
use crate::chainstate::stacks::test::codec_all_transactions;
use crate::chainstate::stacks::tests::{
    make_coinbase, make_coinbase_with_nonce, make_smart_contract_with_version,
    make_user_stacks_transfer,
};
use crate::chainstate::stacks::{Error as ChainstateError, *};
use crate::clarity_vm::clarity::ClarityConnection;
use crate::core::*;
use crate::net::api::getinfo::RPCPeerInfoData;
use crate::net::asn::*;
use crate::net::chat::*;
use crate::net::codec::*;
use crate::net::db::PeerDB;
use crate::net::download::*;
use crate::net::http::{HttpRequestContents, HttpRequestPreamble};
use crate::net::httpcore::StacksHttpMessage;
use crate::net::inv::inv2x::*;
use crate::net::p2p::*;
use crate::net::relay::*;
use crate::net::test::*;
use crate::net::tests::download::epoch2x::run_get_blocks_and_microblocks;
use crate::net::{Error as net_error, *};
use crate::util_lib::test::*;

#[test]
fn test_sample_neighbors() {
    let neighbors: Vec<_> = (0..10)
        .map(|i| {
            let nk = NeighborKey {
                peer_version: 12345,
                network_id: 0x80000000,
                addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
                port: i,
            };
            nk
        })
        .collect();

    let neighbors_set: HashSet<_> = neighbors.clone().into_iter().collect();

    let empty_distribution: HashMap<NeighborKey, usize> = HashMap::new();

    assert_eq!(
        RelayerStats::sample_neighbors(empty_distribution.clone(), 0).len(),
        0
    );
    assert_eq!(
        RelayerStats::sample_neighbors(empty_distribution.clone(), 1).len(),
        0
    );
    assert_eq!(
        RelayerStats::sample_neighbors(empty_distribution.clone(), 5).len(),
        0
    );
    assert_eq!(
        RelayerStats::sample_neighbors(empty_distribution.clone(), 10).len(),
        0
    );

    let flat_distribution: HashMap<_, _> = neighbors.iter().map(|nk| (nk.clone(), 1)).collect();

    assert_eq!(
        RelayerStats::sample_neighbors(flat_distribution.clone(), 0).len(),
        0
    );
    assert_eq!(
        RelayerStats::sample_neighbors(flat_distribution.clone(), 1).len(),
        1
    );

    let flat_full_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(flat_distribution.clone(), 10)
            .into_iter()
            .collect();

    assert_eq!(flat_full_sample_set, neighbors_set);

    let flat_partial_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(flat_distribution.clone(), 5)
            .into_iter()
            .collect();

    assert_eq!(flat_partial_sample_set.len(), 5);

    let flat_unit_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(flat_distribution.clone(), 1)
            .into_iter()
            .collect();

    assert_eq!(flat_unit_sample_set.len(), 1);

    let biased_distribution: HashMap<_, _> = neighbors
        .iter()
        .enumerate()
        .map(|(i, nk)| (nk.clone(), if i == 0 { 10 } else { 1 }))
        .collect();

    assert_eq!(
        RelayerStats::sample_neighbors(biased_distribution.clone(), 0).len(),
        0
    );
    assert_eq!(
        RelayerStats::sample_neighbors(biased_distribution.clone(), 1).len(),
        1
    );

    let flat_full_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(biased_distribution.clone(), 10)
            .into_iter()
            .collect();

    assert_eq!(flat_full_sample_set, neighbors_set);

    let flat_partial_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(biased_distribution.clone(), 5)
            .into_iter()
            .collect();

    assert_eq!(flat_partial_sample_set.len(), 5);

    let flat_unit_sample_set: HashSet<_> =
        RelayerStats::sample_neighbors(biased_distribution.clone(), 1)
            .into_iter()
            .collect();

    assert_eq!(flat_unit_sample_set.len(), 1);
}

#[test]
fn test_relayer_stats_add_relyed_messages() {
    let mut relay_stats = RelayerStats::new();

    let all_transactions = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    assert!(all_transactions.len() > MAX_RECENT_MESSAGES);

    eprintln!("Test with {} transactions", all_transactions.len());

    let nk = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
        port: 54321,
    };

    // never overflow recent messages for a neighbor
    for (i, tx) in all_transactions.iter().enumerate() {
        relay_stats.add_relayed_message(nk.clone(), tx);

        assert_eq!(relay_stats.recent_messages.len(), 1);
        assert!(relay_stats.recent_messages.get(&nk).unwrap().len() <= MAX_RECENT_MESSAGES);

        assert_eq!(relay_stats.recent_updates.len(), 1);
    }

    assert_eq!(
        relay_stats.recent_messages.get(&nk).unwrap().len(),
        MAX_RECENT_MESSAGES
    );

    for i in (all_transactions.len() - MAX_RECENT_MESSAGES)..MAX_RECENT_MESSAGES {
        let digest = all_transactions[i].get_digest();
        let mut found = false;
        for (_, hash) in relay_stats.recent_messages.get(&nk).unwrap().iter() {
            found = found || (*hash == digest);
        }
        if !found {
            assert!(false);
        }
    }

    // never overflow number of neighbors tracked
    for i in 0..(MAX_RELAYER_STATS + 1) {
        let mut new_nk = nk.clone();
        new_nk.peer_version += i as u32;

        relay_stats.add_relayed_message(new_nk, &all_transactions[0]);

        assert!(relay_stats.recent_updates.len() <= i + 1);
        assert!(relay_stats.recent_updates.len() <= MAX_RELAYER_STATS);
    }
}

#[test]
fn test_relayer_merge_stats() {
    let mut relayer_stats = RelayerStats::new();

    let na = NeighborAddress {
        addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
        port: 54321,
        public_key_hash: Hash160([0u8; 20]),
    };

    let relay_stats = RelayStats {
        num_messages: 1,
        num_bytes: 1,
        last_seen: 1,
    };

    let mut rs = HashMap::new();
    rs.insert(na.clone(), relay_stats.clone());

    relayer_stats.merge_relay_stats(rs);
    assert_eq!(relayer_stats.relay_stats.len(), 1);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_messages, 1);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_bytes, 1);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().last_seen, 1);
    assert_eq!(relayer_stats.relay_updates.len(), 1);

    let now = get_epoch_time_secs() + 60;

    let relay_stats_2 = RelayStats {
        num_messages: 2,
        num_bytes: 2,
        last_seen: now,
    };

    let mut rs = HashMap::new();
    rs.insert(na.clone(), relay_stats_2.clone());

    relayer_stats.merge_relay_stats(rs);
    assert_eq!(relayer_stats.relay_stats.len(), 1);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_messages, 3);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_bytes, 3);
    assert!(
        relayer_stats.relay_stats.get(&na).unwrap().last_seen < now
            && relayer_stats.relay_stats.get(&na).unwrap().last_seen >= get_epoch_time_secs()
    );
    assert_eq!(relayer_stats.relay_updates.len(), 1);

    let relay_stats_3 = RelayStats {
        num_messages: 3,
        num_bytes: 3,
        last_seen: 0,
    };

    let mut rs = HashMap::new();
    rs.insert(na.clone(), relay_stats_3.clone());

    relayer_stats.merge_relay_stats(rs);
    assert_eq!(relayer_stats.relay_stats.len(), 1);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_messages, 3);
    assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_bytes, 3);
    assert!(
        relayer_stats.relay_stats.get(&na).unwrap().last_seen < now
            && relayer_stats.relay_stats.get(&na).unwrap().last_seen >= get_epoch_time_secs()
    );
    assert_eq!(relayer_stats.relay_updates.len(), 1);

    for i in 0..(MAX_RELAYER_STATS + 1) {
        let na = NeighborAddress {
            addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
            port: 14321 + (i as u16),
            public_key_hash: Hash160([0u8; 20]),
        };

        let now = get_epoch_time_secs() + (i as u64) + 1;

        let relay_stats = RelayStats {
            num_messages: 1,
            num_bytes: 1,
            last_seen: now,
        };

        let mut rs = HashMap::new();
        rs.insert(na.clone(), relay_stats.clone());

        relayer_stats.merge_relay_stats(rs);
        assert!(relayer_stats.relay_stats.len() <= MAX_RELAYER_STATS);
        assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_messages, 1);
        assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().num_bytes, 1);
        assert_eq!(relayer_stats.relay_stats.get(&na).unwrap().last_seen, now);
    }
}

#[test]
fn test_relay_inbound_peer_rankings() {
    let mut relay_stats = RelayerStats::new();

    let all_transactions = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    assert!(all_transactions.len() > MAX_RECENT_MESSAGES);

    let nk_1 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
        port: 54321,
    };

    let nk_2 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
        port: 54322,
    };

    let nk_3 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
        port: 54323,
    };

    let dups = relay_stats.count_relay_dups(&all_transactions[0]);
    assert_eq!(dups.len(), 0);

    relay_stats.add_relayed_message(nk_1.clone(), &all_transactions[0]);
    relay_stats.add_relayed_message(nk_1.clone(), &all_transactions[0]);
    relay_stats.add_relayed_message(nk_1.clone(), &all_transactions[0]);

    let dups = relay_stats.count_relay_dups(&all_transactions[0]);
    assert_eq!(dups.len(), 1);
    assert_eq!(*dups.get(&nk_1).unwrap(), 3);

    relay_stats.add_relayed_message(nk_2.clone(), &all_transactions[0]);
    relay_stats.add_relayed_message(nk_2.clone(), &all_transactions[0]);
    relay_stats.add_relayed_message(nk_2.clone(), &all_transactions[0]);
    relay_stats.add_relayed_message(nk_2.clone(), &all_transactions[0]);

    let dups = relay_stats.count_relay_dups(&all_transactions[0]);
    assert_eq!(dups.len(), 2);
    assert_eq!(*dups.get(&nk_1).unwrap(), 3);
    assert_eq!(*dups.get(&nk_2).unwrap(), 4);

    // total dups == 7
    let dist = relay_stats.get_inbound_relay_rankings(
        &[nk_1.clone(), nk_2.clone(), nk_3.clone()],
        &all_transactions[0],
        0,
    );
    assert_eq!(*dist.get(&nk_1).unwrap(), 7 - 3 + 1);
    assert_eq!(*dist.get(&nk_2).unwrap(), 7 - 4 + 1);
    assert_eq!(*dist.get(&nk_3).unwrap(), 7 + 1);

    // high warmup period
    let dist = relay_stats.get_inbound_relay_rankings(
        &[nk_1.clone(), nk_2.clone(), nk_3.clone()],
        &all_transactions[0],
        100,
    );
    assert_eq!(*dist.get(&nk_1).unwrap(), 100 + 1);
    assert_eq!(*dist.get(&nk_2).unwrap(), 100 + 1);
    assert_eq!(*dist.get(&nk_3).unwrap(), 100 + 1);
}

#[test]
fn test_relay_outbound_peer_rankings() {
    let relay_stats = RelayerStats::new();

    let asn1 = ASEntry4 {
        prefix: 0x10000000,
        mask: 8,
        asn: 1,
        org: 1,
    };

    let asn2 = ASEntry4 {
        prefix: 0x20000000,
        mask: 8,
        asn: 2,
        org: 2,
    };

    let nk_1 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x10, 0x11, 0x12, 0x13,
        ]),
        port: 54321,
    };

    let nk_2 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x20, 0x21, 0x22, 0x23,
        ]),
        port: 54322,
    };

    let nk_3 = NeighborKey {
        peer_version: 12345,
        network_id: 0x80000000,
        addrbytes: PeerAddress([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x20, 0x21, 0x22, 0x24,
        ]),
        port: 54323,
    };

    let n1 = Neighbor {
        addr: nk_1.clone(),
        public_key: Secp256k1PublicKey::from_hex(
            "0260569384baa726f877d47045931e5310383f18d0b243a9b6c095cee6ef19abd6",
        )
        .unwrap(),
        expire_block: 4302,
        last_contact_time: 0,
        allowed: 0,
        denied: 0,
        asn: 1,
        org: 1,
        in_degree: 0,
        out_degree: 0,
    };

    let n2 = Neighbor {
        addr: nk_2.clone(),
        public_key: Secp256k1PublicKey::from_hex(
            "02465f9ff58dfa8e844fec86fa5fc3fd59c75ea807e20d469b0a9f885d2891fbd4",
        )
        .unwrap(),
        expire_block: 4302,
        last_contact_time: 0,
        allowed: 0,
        denied: 0,
        asn: 2,
        org: 2,
        in_degree: 0,
        out_degree: 0,
    };

    let n3 = Neighbor {
        addr: nk_3.clone(),
        public_key: Secp256k1PublicKey::from_hex(
            "032d8a1ea2282c1514fdc1a6f21019561569d02a225cf7c14b4f803b0393cef031",
        )
        .unwrap(),
        expire_block: 4302,
        last_contact_time: 0,
        allowed: 0,
        denied: 0,
        asn: 2,
        org: 2,
        in_degree: 0,
        out_degree: 0,
    };

    let peerdb = PeerDB::connect_memory(
        0x80000000,
        0,
        4032,
        UrlString::try_from("http://foo.com").unwrap(),
        &[asn1, asn2],
        &[n1.clone(), n2.clone(), n3.clone()],
    )
    .unwrap();

    let asn_count =
        RelayerStats::count_ASNs(peerdb.conn(), &[nk_1.clone(), nk_2.clone(), nk_3.clone()])
            .unwrap();
    assert_eq!(asn_count.len(), 3);
    assert_eq!(*asn_count.get(&nk_1).unwrap(), 1);
    assert_eq!(*asn_count.get(&nk_2).unwrap(), 2);
    assert_eq!(*asn_count.get(&nk_3).unwrap(), 2);

    let ranking = relay_stats
        .get_outbound_relay_rankings(&peerdb, &[nk_1.clone(), nk_2.clone(), nk_3.clone()])
        .unwrap();
    assert_eq!(ranking.len(), 3);
    assert_eq!(*ranking.get(&nk_1).unwrap(), 5 - 1 + 1);
    assert_eq!(*ranking.get(&nk_2).unwrap(), 5 - 2 + 1);
    assert_eq!(*ranking.get(&nk_3).unwrap(), 5 - 2 + 1);

    let ranking = relay_stats
        .get_outbound_relay_rankings(&peerdb, &[nk_2.clone(), nk_3.clone()])
        .unwrap();
    assert_eq!(ranking.len(), 2);
    assert_eq!(*ranking.get(&nk_2).unwrap(), 4 - 2 + 1);
    assert_eq!(*ranking.get(&nk_3).unwrap(), 4 - 2 + 1);
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_3_peers_push_available() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_3_peers_push_available",
            4200,
            3,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 3);

                // peer 0 produces the blocks
                peer_configs[0].connection_opts.disable_chat_neighbors = true;

                // peer 1 downloads the blocks from peer 0, and sends
                // BlocksAvailable and MicroblocksAvailable messages to
                // peer 2.
                peer_configs[1].connection_opts.disable_chat_neighbors = true;

                // peer 2 learns about the blocks and microblocks from peer 1's
                // BlocksAvaiable and MicroblocksAvailable messages, but
                // not from inv syncs.
                peer_configs[2].connection_opts.disable_chat_neighbors = true;
                peer_configs[2].connection_opts.disable_inv_sync = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;
                peer_configs[2].connection_opts.disable_natpunch = true;

                // do not push blocks and microblocks; only announce them
                peer_configs[0].connection_opts.disable_block_push = true;
                peer_configs[1].connection_opts.disable_block_push = true;
                peer_configs[2].connection_opts.disable_block_push = true;

                peer_configs[0].connection_opts.disable_microblock_push = true;
                peer_configs[1].connection_opts.disable_microblock_push = true;
                peer_configs[2].connection_opts.disable_microblock_push = true;

                // generous timeouts
                peer_configs[0].connection_opts.connect_timeout = 180;
                peer_configs[1].connection_opts.connect_timeout = 180;
                peer_configs[2].connection_opts.connect_timeout = 180;
                peer_configs[0].connection_opts.timeout = 180;
                peer_configs[1].connection_opts.timeout = 180;
                peer_configs[2].connection_opts.timeout = 180;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();
                let peer_2 = peer_configs[2].to_neighbor();

                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
                peer_configs[2].add_neighbor(&peer_1);
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    // only produce blocks for a single reward
                    // cycle, since pushing block/microblock
                    // announcements in reward cycles the remote
                    // peer doesn't know about won't work.
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }

                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }

                assert_eq!(block_data.len(), 5);

                block_data
            },
            |ref mut peers| {
                // make sure peer 2's inv has an entry for peer 1, even
                // though it's not doing an inv sync. This is required for the downloader to
                // work, and for (Micro)BlocksAvailable messages to be accepted
                let peer_1_nk = peers[1].to_neighbor().addr;
                let peer_2_nk = peers[2].to_neighbor().addr;
                let bc = peers[1].config.burnchain.clone();
                match peers[2].network.inv_state {
                    Some(ref mut inv_state) => {
                        if inv_state.get_stats(&peer_1_nk).is_none() {
                            test_debug!("initialize inv statistics for peer 1 in peer 2");
                            inv_state.add_peer(peer_1_nk.clone(), true);
                            if let Some(ref mut stats) = inv_state.get_stats_mut(&peer_1_nk) {
                                stats.scans = 1;
                                stats.inv.merge_pox_inv(&bc, 0, 6, vec![0xff], false);
                                stats.inv.merge_blocks_inv(
                                    0,
                                    30,
                                    vec![0, 0, 0, 0, 0],
                                    vec![0, 0, 0, 0, 0],
                                    false,
                                );
                            } else {
                                panic!("Unable to instantiate inv stats for {:?}", &peer_1_nk);
                            }
                        } else {
                            test_debug!("peer 2 has inv state for peer 1");
                        }
                    }
                    None => {
                        test_debug!("No inv state for peer 1");
                    }
                }

                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                let peer_1_nk = peers[1].to_neighbor().addr;
                match peers[2].network.inv_state {
                    Some(ref mut inv_state) => {
                        if inv_state.get_stats(&peer_1_nk).is_none() {
                            test_debug!("initialize inv statistics for peer 1 in peer 2");
                            inv_state.add_peer(peer_1_nk.clone(), true);

                            inv_state
                                .get_stats_mut(&peer_1_nk)
                                .unwrap()
                                .inv
                                .num_reward_cycles = this_reward_cycle;
                            inv_state.get_stats_mut(&peer_1_nk).unwrap().inv.pox_inv = vec![0x3f];
                        } else {
                            test_debug!("peer 2 has inv state for peer 1");
                        }
                    }
                    None => {
                        test_debug!("No inv state for peer 2");
                    }
                }

                // peer 2 should never see a BlocksInv
                // message.  That would imply it asked for an inv
                for (_, convo) in peers[2].network.peers.iter() {
                    assert_eq!(
                        convo
                            .stats
                            .get_message_recv_count(StacksMessageID::BlocksInv),
                        0
                    );
                }
            },
            |ref peer| {
                // check peer health
                // TODO
                true
            },
            |_| true,
        );
    })
}

fn is_peer_connected(peer: &TestPeer, dest: &NeighborKey) -> bool {
    let event_id = match peer.network.events.get(dest) {
        Some(evid) => *evid,
        None => {
            return false;
        }
    };

    match peer.network.peers.get(&event_id) {
        Some(convo) => {
            return convo.is_authenticated();
        }
        None => {
            return false;
        }
    }
}

fn push_message(
    peer: &mut TestPeer,
    dest: &NeighborKey,
    relay_hints: Vec<RelayData>,
    msg: StacksMessageType,
) -> bool {
    let event_id = match peer.network.events.get(dest) {
        Some(evid) => *evid,
        None => {
            panic!("Unreachable peer: {:?}", dest);
        }
    };

    let relay_msg = match peer.network.peers.get_mut(&event_id) {
        Some(convo) => convo
            .sign_relay_message(
                &peer.network.local_peer,
                &peer.network.chain_view,
                relay_hints,
                msg,
            )
            .unwrap(),
        None => {
            panic!("No such event ID {} from neighbor {}", event_id, dest);
        }
    };

    match peer.network.relay_signed_message(dest, relay_msg.clone()) {
        Ok(_) => {
            return true;
        }
        Err(net_error::OutboxOverflow) => {
            test_debug!(
                "{:?} outbox overflow; try again later",
                &peer.to_neighbor().addr
            );
            return false;
        }
        Err(net_error::SendError(msg)) => {
            warn!(
                "Failed to send to {:?}: SendError({})",
                &peer.to_neighbor().addr,
                msg
            );
            return false;
        }
        Err(e) => {
            test_debug!(
                "{:?} encountered fatal error when forwarding: {:?}",
                &peer.to_neighbor().addr,
                &e
            );
            assert!(false);
            unreachable!();
        }
    }
}

fn http_rpc(peer_http: u16, request: StacksHttpRequest) -> Result<StacksHttpResponse, net_error> {
    use std::net::TcpStream;

    let mut sock = TcpStream::connect(
        &format!("127.0.0.1:{}", peer_http)
            .parse::<SocketAddr>()
            .unwrap(),
    )
    .unwrap();

    let request_bytes = request.try_serialize().unwrap();
    match sock.write_all(&request_bytes) {
        Ok(_) => {}
        Err(e) => {
            test_debug!("Client failed to write: {:?}", &e);
            return Err(net_error::WriteError(e));
        }
    }

    let mut resp = vec![];
    match sock.read_to_end(&mut resp) {
        Ok(_) => {
            if resp.is_empty() {
                test_debug!("Client did not receive any data");
                return Err(net_error::PermanentlyDrained);
            }
        }
        Err(e) => {
            test_debug!("Client failed to read: {:?}", &e);
            return Err(net_error::ReadError(e));
        }
    }

    test_debug!("Client received {} bytes", resp.len());
    let response = StacksHttp::parse_response(
        &request.preamble().verb,
        &request.preamble().path_and_query_str,
        &resp,
    )
    .unwrap();
    match response {
        StacksHttpMessage::Response(x) => Ok(x),
        _ => {
            panic!("Did not receive a Response");
        }
    }
}

pub fn broadcast_message(
    broadcaster: &mut TestPeer,
    relay_hints: Vec<RelayData>,
    msg: StacksMessageType,
) -> bool {
    let request = NetworkRequest::Broadcast(relay_hints, msg);
    match broadcaster.network.dispatch_request(request) {
        Ok(_) => true,
        Err(e) => {
            error!("Failed to broadcast: {:?}", &e);
            false
        }
    }
}

fn push_block(
    peer: &mut TestPeer,
    dest: &NeighborKey,
    relay_hints: Vec<RelayData>,
    consensus_hash: ConsensusHash,
    block: StacksBlock,
) -> bool {
    test_debug!(
        "{:?}: Push block {}/{} to {:?}",
        peer.to_neighbor().addr,
        &consensus_hash,
        block.block_hash(),
        dest
    );

    let sn = SortitionDB::get_block_snapshot_consensus(
        peer.sortdb.as_ref().unwrap().conn(),
        &consensus_hash,
    )
    .unwrap()
    .unwrap();
    let consensus_hash = sn.consensus_hash;

    let msg = StacksMessageType::Blocks(BlocksData {
        blocks: vec![BlocksDatum(consensus_hash, block)],
    });
    push_message(peer, dest, relay_hints, msg)
}

fn broadcast_block(
    peer: &mut TestPeer,
    relay_hints: Vec<RelayData>,
    consensus_hash: ConsensusHash,
    block: StacksBlock,
) -> bool {
    test_debug!(
        "{:?}: Broadcast block {}/{}",
        peer.to_neighbor().addr,
        &consensus_hash,
        block.block_hash(),
    );

    let sn = SortitionDB::get_block_snapshot_consensus(
        peer.sortdb.as_ref().unwrap().conn(),
        &consensus_hash,
    )
    .unwrap()
    .unwrap();
    let consensus_hash = sn.consensus_hash;

    let msg = StacksMessageType::Blocks(BlocksData {
        blocks: vec![BlocksDatum(consensus_hash, block)],
    });
    broadcast_message(peer, relay_hints, msg)
}

fn push_microblocks(
    peer: &mut TestPeer,
    dest: &NeighborKey,
    relay_hints: Vec<RelayData>,
    consensus_hash: ConsensusHash,
    block_hash: BlockHeaderHash,
    microblocks: Vec<StacksMicroblock>,
) -> bool {
    test_debug!(
        "{:?}: Push {} microblocksblock {}/{} to {:?}",
        peer.to_neighbor().addr,
        microblocks.len(),
        &consensus_hash,
        &block_hash,
        dest
    );
    let msg = StacksMessageType::Microblocks(MicroblocksData {
        index_anchor_block: StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_hash),
        microblocks,
    });
    push_message(peer, dest, relay_hints, msg)
}

fn broadcast_microblocks(
    peer: &mut TestPeer,
    relay_hints: Vec<RelayData>,
    consensus_hash: ConsensusHash,
    block_hash: BlockHeaderHash,
    microblocks: Vec<StacksMicroblock>,
) -> bool {
    test_debug!(
        "{:?}: broadcast {} microblocksblock {}/{}",
        peer.to_neighbor().addr,
        microblocks.len(),
        &consensus_hash,
        &block_hash,
    );
    let msg = StacksMessageType::Microblocks(MicroblocksData {
        index_anchor_block: StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_hash),
        microblocks,
    });
    broadcast_message(peer, relay_hints, msg)
}

fn push_transaction(
    peer: &mut TestPeer,
    dest: &NeighborKey,
    relay_hints: Vec<RelayData>,
    tx: StacksTransaction,
) -> bool {
    test_debug!(
        "{:?}: Push tx {} to {:?}",
        peer.to_neighbor().addr,
        tx.txid(),
        dest
    );
    let msg = StacksMessageType::Transaction(tx);
    push_message(peer, dest, relay_hints, msg)
}

fn broadcast_transaction(
    peer: &mut TestPeer,
    relay_hints: Vec<RelayData>,
    tx: StacksTransaction,
) -> bool {
    test_debug!("{:?}: broadcast tx {}", peer.to_neighbor().addr, tx.txid(),);
    let msg = StacksMessageType::Transaction(tx);
    broadcast_message(peer, relay_hints, msg)
}

fn http_get_info(http_port: u16) -> RPCPeerInfoData {
    let mut request = HttpRequestPreamble::new_for_peer(
        PeerHost::from_host_port("127.0.0.1".to_string(), http_port),
        "GET".to_string(),
        "/v2/info".to_string(),
    );
    request.keep_alive = false;
    let getinfo = StacksHttpRequest::new(request, HttpRequestContents::new());
    let response = http_rpc(http_port, getinfo).unwrap();
    let peer_info = response.decode_peer_info().unwrap();
    peer_info
}

fn http_post_block(http_port: u16, consensus_hash: &ConsensusHash, block: &StacksBlock) -> bool {
    test_debug!(
        "upload block {}/{} to localhost:{}",
        consensus_hash,
        block.block_hash(),
        http_port
    );
    let mut request = HttpRequestPreamble::new_for_peer(
        PeerHost::from_host_port("127.0.0.1".to_string(), http_port),
        "POST".to_string(),
        "/v2/blocks".to_string(),
    );
    request.keep_alive = false;
    let post_block =
        StacksHttpRequest::new(request, HttpRequestContents::new().payload_stacks(block));

    let response = http_rpc(http_port, post_block).unwrap();
    let accepted = response.decode_stacks_block_accepted().unwrap();
    accepted.accepted
}

fn http_post_microblock(
    http_port: u16,
    consensus_hash: &ConsensusHash,
    block_hash: &BlockHeaderHash,
    mblock: &StacksMicroblock,
) -> bool {
    test_debug!(
        "upload microblock {}/{}-{} to localhost:{}",
        consensus_hash,
        block_hash,
        mblock.block_hash(),
        http_port
    );
    let mut request = HttpRequestPreamble::new_for_peer(
        PeerHost::from_host_port("127.0.0.1".to_string(), http_port),
        "POST".to_string(),
        "/v2/microblocks".to_string(),
    );
    request.keep_alive = false;
    let tip = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
    let post_microblock = StacksHttpRequest::new(
        request,
        HttpRequestContents::new()
            .payload_stacks(mblock)
            .for_specific_tip(tip),
    );

    let response = http_rpc(http_port, post_microblock).unwrap();
    let payload = response.get_http_payload_ok().unwrap();
    let bhh: BlockHeaderHash = serde_json::from_value(payload.try_into().unwrap()).unwrap();
    return true;
}

fn test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks(
    outbound_test: bool,
    disable_push: bool,
) {
    with_timeout(600, move || {
        let original_blocks_and_microblocks = RefCell::new(vec![]);
        let blocks_and_microblocks = RefCell::new(vec![]);
        let idx = RefCell::new(0);
        let sent_blocks = RefCell::new(false);
        let sent_microblocks = RefCell::new(false);

        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks",
            4210,
            2,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 2);

                // peer 0 produces the blocks and pushes them to peer 1
                // peer 1 receives the blocks and microblocks.  It
                // doesn't download them, nor does it try to get invs
                peer_configs[0].connection_opts.disable_block_advertisement = true;

                peer_configs[1].connection_opts.disable_inv_sync = true;
                peer_configs[1].connection_opts.disable_block_download = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;

                // force usage of blocksavailable/microblocksavailable?
                if disable_push {
                    peer_configs[0].connection_opts.disable_block_push = true;
                    peer_configs[0].connection_opts.disable_microblock_push = true;
                    peer_configs[1].connection_opts.disable_block_push = true;
                    peer_configs[1].connection_opts.disable_microblock_push = true;
                }

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();

                peer_configs[0].add_neighbor(&peer_1);

                if outbound_test {
                    // neighbor relationship is symmetric -- peer 1 has an outbound connection
                    // to peer 0.
                    peer_configs[1].add_neighbor(&peer_0);
                }
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }
                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                let saved_copy: Vec<(ConsensusHash, StacksBlock, Vec<StacksMicroblock>)> =
                    block_data
                        .clone()
                        .drain(..)
                        .map(|(ch, blk_opt, mblocks_opt)| {
                            (ch, blk_opt.unwrap(), mblocks_opt.unwrap())
                        })
                        .collect();
                *blocks_and_microblocks.borrow_mut() = saved_copy.clone();
                *original_blocks_and_microblocks.borrow_mut() = saved_copy;
                block_data
            },
            |ref mut peers| {
                if !disable_push {
                    for peer in peers.iter_mut() {
                        // force peers to keep trying to process buffered data
                        peer.network.burnchain_tip.burn_header_hash =
                            BurnchainHeaderHash([0u8; 32]);
                    }
                }

                // make sure peer 1's inv has an entry for peer 0, even
                // though it's not doing an inv sync.  This is required for the downloader to
                // work
                let peer_0_nk = peers[0].to_neighbor().addr;
                let peer_1_nk = peers[1].to_neighbor().addr;
                match peers[1].network.inv_state {
                    Some(ref mut inv_state) => {
                        if inv_state.get_stats(&peer_0_nk).is_none() {
                            test_debug!("initialize inv statistics for peer 0 in peer 1");
                            inv_state.add_peer(peer_0_nk.clone(), true);
                        } else {
                            test_debug!("peer 1 has inv state for peer 0");
                        }
                    }
                    None => {
                        test_debug!("No inv state for peer 1");
                    }
                }

                if is_peer_connected(&peers[0], &peer_1_nk) {
                    // randomly push a block and/or microblocks to peer 1.
                    let mut block_data = blocks_and_microblocks.borrow_mut();
                    let original_block_data = original_blocks_and_microblocks.borrow();
                    let mut next_idx = idx.borrow_mut();
                    let data_to_push = {
                        if block_data.is_empty() {
                            // start over (can happen if a message gets
                            // dropped due to a timeout)
                            test_debug!("Reset block transmission (possible timeout)");
                            *block_data = (*original_block_data).clone();
                            *next_idx = thread_rng().gen::<usize>() % block_data.len();
                            let (consensus_hash, block, microblocks) =
                                block_data[*next_idx].clone();
                            Some((consensus_hash, block, microblocks))
                        } else {
                            let (consensus_hash, block, microblocks) =
                                block_data[*next_idx].clone();
                            Some((consensus_hash, block, microblocks))
                        }
                    };

                    if let Some((consensus_hash, block, microblocks)) = data_to_push {
                        test_debug!(
                            "Push block {}/{} and microblocks",
                            &consensus_hash,
                            block.block_hash()
                        );

                        let block_hash = block.block_hash();
                        let mut sent_blocks = sent_blocks.borrow_mut();
                        let mut sent_microblocks = sent_microblocks.borrow_mut();

                        let pushed_block = if !*sent_blocks {
                            push_block(
                                &mut peers[0],
                                &peer_1_nk,
                                vec![],
                                consensus_hash.clone(),
                                block,
                            )
                        } else {
                            true
                        };

                        *sent_blocks = pushed_block;

                        if pushed_block {
                            let pushed_microblock = if !*sent_microblocks {
                                push_microblocks(
                                    &mut peers[0],
                                    &peer_1_nk,
                                    vec![],
                                    consensus_hash,
                                    block_hash,
                                    microblocks,
                                )
                            } else {
                                true
                            };

                            *sent_microblocks = pushed_microblock;

                            if pushed_block && pushed_microblock {
                                block_data.remove(*next_idx);
                                if !block_data.is_empty() {
                                    *next_idx = thread_rng().gen::<usize>() % block_data.len();
                                }
                                *sent_blocks = false;
                                *sent_microblocks = false;
                            }
                        }
                        test_debug!("{} blocks/microblocks remaining", block_data.len());
                    }
                }

                // peer 0 should never see a GetBlocksInv message.
                // peer 1 should never see a BlocksInv message
                for (_, convo) in peers[0].network.peers.iter() {
                    assert_eq!(
                        convo
                            .stats
                            .get_message_recv_count(StacksMessageID::GetBlocksInv),
                        0
                    );
                }
                for (_, convo) in peers[1].network.peers.iter() {
                    assert_eq!(
                        convo
                            .stats
                            .get_message_recv_count(StacksMessageID::BlocksInv),
                        0
                    );
                }
            },
            |ref peer| {
                // check peer health
                // nothing should break
                // TODO
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks_outbound() {
    // simulates node 0 pushing blocks to node 1, but node 0 is publicly routable.
    // nodes rely on blocksavailable/microblocksavailable to discover blocks
    test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks(true, true)
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks_inbound() {
    // simulates node 0 pushing blocks to node 1, where node 0 is behind a NAT
    // nodes rely on blocksavailable/microblocksavailable to discover blocks
    test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks(false, true)
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks_outbound_direct() {
    // simulates node 0 pushing blocks to node 1, but node 0 is publicly routable.
    // nodes may push blocks and microblocks directly to each other
    test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks(true, false)
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks_inbound_direct() {
    // simulates node 0 pushing blocks to node 1, where node 0 is behind a NAT
    // nodes may push blocks and microblocks directly to each other
    test_get_blocks_and_microblocks_2_peers_push_blocks_and_microblocks(false, false)
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_upload_blocks_http() {
    with_timeout(600, || {
        let (port_sx, port_rx) = std::sync::mpsc::sync_channel(1);
        let (block_sx, block_rx) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || loop {
            eprintln!("Get port");
            let remote_port: u16 = port_rx.recv().unwrap();
            eprintln!("Got port {}", remote_port);

            eprintln!("Send getinfo");
            let peer_info = http_get_info(remote_port);
            eprintln!("Got getinfo! {:?}", &peer_info);
            let idx = peer_info.stacks_tip_height as usize;

            eprintln!("Get blocks and microblocks");
            let blocks_and_microblocks: Vec<(
                ConsensusHash,
                Option<StacksBlock>,
                Option<Vec<StacksMicroblock>>,
            )> = block_rx.recv().unwrap();
            eprintln!("Got blocks and microblocks!");

            if idx >= blocks_and_microblocks.len() {
                eprintln!("Out of blocks to send!");
                return;
            }

            eprintln!(
                "Upload block {}",
                &blocks_and_microblocks[idx].1.as_ref().unwrap().block_hash()
            );
            http_post_block(
                remote_port,
                &blocks_and_microblocks[idx].0,
                blocks_and_microblocks[idx].1.as_ref().unwrap(),
            );
            for mblock in blocks_and_microblocks[idx].2.as_ref().unwrap().iter() {
                eprintln!("Upload microblock {}", mblock.block_hash());
                http_post_microblock(
                    remote_port,
                    &blocks_and_microblocks[idx].0,
                    &blocks_and_microblocks[idx].1.as_ref().unwrap().block_hash(),
                    mblock,
                );
            }
        });

        let original_blocks_and_microblocks = RefCell::new(vec![]);
        let port_sx_cell = RefCell::new(port_sx);
        let block_sx_cell = RefCell::new(block_sx);

        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_upload_blocks_http",
            4250,
            2,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 2);

                // peer 0 produces the blocks
                peer_configs[0].connection_opts.disable_chat_neighbors = true;

                // peer 0 sends them to peer 1
                peer_configs[1].connection_opts.disable_chat_neighbors = true;
                peer_configs[1].connection_opts.disable_inv_sync = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;

                // generous timeouts
                peer_configs[0].connection_opts.timeout = 180;
                peer_configs[1].connection_opts.timeout = 180;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    // only produce blocks for a single reward
                    // cycle, since pushing block/microblock
                    // announcements in reward cycles the remote
                    // peer doesn't know about won't work.
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }

                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }

                assert_eq!(block_data.len(), 5);

                *original_blocks_and_microblocks.borrow_mut() = block_data.clone();

                block_data
            },
            |ref mut peers| {
                let blocks_and_microblocks = original_blocks_and_microblocks.borrow().clone();
                let remote_port = peers[1].config.http_port;

                let port_sx = port_sx_cell.borrow_mut();
                let block_sx = block_sx_cell.borrow_mut();

                let _ = (*port_sx).try_send(remote_port);
                let _ = (*block_sx).try_send(blocks_and_microblocks);
            },
            |ref peer| {
                // check peer health
                // TODO
                true
            },
            |_| true,
        );
    })
}

fn make_test_smart_contract_transaction(
    peer: &mut TestPeer,
    name: &str,
    consensus_hash: &ConsensusHash,
    block_hash: &BlockHeaderHash,
) -> StacksTransaction {
    // make a smart contract
    let contract = "
    (define-data-var bar int 0)
    (define-public (get-bar) (ok (var-get bar)))
    (define-public (set-bar (x int) (y int))
      (begin (var-set bar (/ x y)) (ok (var-get bar))))";

    let cost_limits = peer.config.connection_opts.read_only_call_limit.clone();

    let tx_contract = peer
        .with_mining_state(
            |ref mut sortdb, ref mut miner, ref mut spending_account, ref mut stacks_node| {
                let mut tx_contract = StacksTransaction::new(
                    TransactionVersion::Testnet,
                    spending_account.as_transaction_auth().unwrap(),
                    TransactionPayload::new_smart_contract(
                        &name.to_string(),
                        &contract.to_string(),
                        None,
                    )
                    .unwrap(),
                );

                let chain_tip =
                    StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
                let iconn = sortdb
                    .index_handle_at_block(&stacks_node.chainstate, &chain_tip)
                    .unwrap();
                let cur_nonce = stacks_node
                    .chainstate
                    .with_read_only_clarity_tx(&iconn, &chain_tip, |clarity_tx| {
                        clarity_tx.with_clarity_db_readonly(|clarity_db| {
                            clarity_db
                                .get_account_nonce(
                                    &spending_account.origin_address().unwrap().into(),
                                )
                                .unwrap()
                        })
                    })
                    .unwrap();

                test_debug!(
                    "Nonce of {:?} is {} at {}/{}",
                    &spending_account.origin_address().unwrap(),
                    cur_nonce,
                    consensus_hash,
                    block_hash
                );

                // spending_account.set_nonce(cur_nonce + 1);

                tx_contract.chain_id = 0x80000000;
                tx_contract.auth.set_origin_nonce(cur_nonce);
                tx_contract.set_tx_fee(MINIMUM_TX_FEE_RATE_PER_BYTE * 500);

                let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
                spending_account.sign_as_origin(&mut tx_signer);

                let tx_contract_signed = tx_signer.get_tx().unwrap();

                test_debug!(
                    "make transaction {:?} off of {:?}/{:?}: {:?}",
                    &tx_contract_signed.txid(),
                    consensus_hash,
                    block_hash,
                    &tx_contract_signed
                );

                Ok(tx_contract_signed)
            },
        )
        .unwrap();

    tx_contract
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_push_transactions() {
    with_timeout(600, || {
        let blocks_and_microblocks = RefCell::new(vec![]);
        let blocks_idx = RefCell::new(0);
        let sent_txs = RefCell::new(vec![]);
        let done = RefCell::new(false);

        let peers = run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_2_peers_push_transactions",
            4220,
            2,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 2);

                // peer 0 generates blocks and microblocks, and pushes
                // them to peer 1.  Peer 0 also generates transactions
                // and pushes them to peer 1.
                peer_configs[0].connection_opts.disable_block_advertisement = true;

                // let peer 0 drive this test, as before, by controlling
                // when peer 1 sees blocks.
                peer_configs[1].connection_opts.disable_inv_sync = true;
                peer_configs[1].connection_opts.disable_block_download = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                peer_configs[0].connection_opts.outbox_maxlen = 100;
                peer_configs[1].connection_opts.inbox_maxlen = 100;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;

                let initial_balances = vec![
                    (
                        PrincipalData::from(
                            peer_configs[0].spending_account.origin_address().unwrap(),
                        ),
                        1000000,
                    ),
                    (
                        PrincipalData::from(
                            peer_configs[1].spending_account.origin_address().unwrap(),
                        ),
                        1000000,
                    ),
                ];

                peer_configs[0].initial_balances = initial_balances.clone();
                peer_configs[1].initial_balances = initial_balances.clone();

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();

                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for b in 0..num_blocks {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }
                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                        if b == 0 {
                            // prime with first block
                            peers[i].process_stacks_epoch_at_tip(&stacks_block, &[]);
                        }
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                *blocks_and_microblocks.borrow_mut() = block_data
                    .clone()
                    .drain(..)
                    .map(|(ch, blk_opt, mblocks_opt)| (ch, blk_opt.unwrap(), mblocks_opt.unwrap()))
                    .collect();
                block_data
            },
            |ref mut peers| {
                let peer_0_nk = peers[0].to_neighbor().addr;
                let peer_1_nk = peers[1].to_neighbor().addr;

                // peers must be connected to each other
                let mut peer_0_to_1 = false;
                let mut peer_1_to_0 = false;
                for (nk, event_id) in peers[0].network.events.iter() {
                    match peers[0].network.peers.get(event_id) {
                        Some(convo) => {
                            if *nk == peer_1_nk {
                                peer_0_to_1 = true;
                            }
                        }
                        None => {}
                    }
                }
                for (nk, event_id) in peers[1].network.events.iter() {
                    match peers[1].network.peers.get(event_id) {
                        Some(convo) => {
                            if *nk == peer_0_nk {
                                peer_1_to_0 = true;
                            }
                        }
                        None => {}
                    }
                }

                if !peer_0_to_1 || !peer_1_to_0 {
                    test_debug!(
                        "Peers not bi-directionally connected: 0->1 = {}, 1->0 = {}",
                        peer_0_to_1,
                        peer_1_to_0
                    );
                    return;
                }

                // make sure peer 2's inv has an entry for peer 1, even
                // though it's not doing an inv sync.
                match peers[1].network.inv_state {
                    Some(ref mut inv_state) => {
                        if inv_state.get_stats(&peer_0_nk).is_none() {
                            test_debug!("initialize inv statistics for peer 0 in peer 1");
                            inv_state.add_peer(peer_0_nk, true);
                        } else {
                            test_debug!("peer 1 has inv state for peer 0");
                        }
                    }
                    None => {
                        test_debug!("No inv state for peer 1");
                    }
                }

                let done_flag = *done.borrow();
                if is_peer_connected(&peers[0], &peer_1_nk) {
                    // only submit the next transaction if the previous
                    // one is accepted
                    let has_last_transaction = {
                        let expected_txs: std::cell::Ref<'_, Vec<StacksTransaction>> =
                            sent_txs.borrow();
                        if let Some(tx) = (*expected_txs).last() {
                            let txid = tx.txid();
                            if !peers[1].mempool.as_ref().unwrap().has_tx(&txid) {
                                debug!("Peer 1 still waiting for transaction {}", &txid);
                                push_transaction(&mut peers[0], &peer_1_nk, vec![], (*tx).clone());
                                false
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    };

                    if has_last_transaction {
                        // push blocks and microblocks in order, and push a
                        // transaction that can only be validated once the
                        // block and microblocks are processed.
                        let (
                            (
                                block_consensus_hash,
                                block,
                                microblocks_consensus_hash,
                                microblocks_block_hash,
                                microblocks,
                            ),
                            idx,
                        ) = {
                            let block_data = blocks_and_microblocks.borrow();
                            let mut idx = blocks_idx.borrow_mut();

                            let microblocks = block_data[*idx].2.clone();
                            let microblocks_consensus_hash = block_data[*idx].0.clone();
                            let microblocks_block_hash = block_data[*idx].1.block_hash();

                            *idx += 1;
                            if *idx >= block_data.len() {
                                *idx = 1;
                            }

                            let block = block_data[*idx].1.clone();
                            let block_consensus_hash = block_data[*idx].0.clone();
                            (
                                (
                                    block_consensus_hash,
                                    block,
                                    microblocks_consensus_hash,
                                    microblocks_block_hash,
                                    microblocks,
                                ),
                                *idx,
                            )
                        };

                        if !done_flag {
                            test_debug!(
                                "Push microblocks built by {}/{} (idx={})",
                                &microblocks_consensus_hash,
                                &microblocks_block_hash,
                                idx
                            );

                            let block_hash = block.block_hash();
                            push_microblocks(
                                &mut peers[0],
                                &peer_1_nk,
                                vec![],
                                microblocks_consensus_hash,
                                microblocks_block_hash,
                                microblocks,
                            );

                            test_debug!(
                                "Push block {}/{} and microblocks (idx = {})",
                                &block_consensus_hash,
                                block.block_hash(),
                                idx
                            );
                            push_block(
                                &mut peers[0],
                                &peer_1_nk,
                                vec![],
                                block_consensus_hash.clone(),
                                block,
                            );

                            // create a transaction against the resulting
                            // (anchored) chain tip
                            let tx = make_test_smart_contract_transaction(
                                &mut peers[0],
                                &format!("test-contract-{}", &block_hash.to_hex()[0..10]),
                                &block_consensus_hash,
                                &block_hash,
                            );

                            // push or post
                            push_transaction(&mut peers[0], &peer_1_nk, vec![], tx.clone());

                            let mut expected_txs = sent_txs.borrow_mut();
                            expected_txs.push(tx);
                        } else {
                            test_debug!("Done pushing data");
                        }
                    }
                }

                // peer 0 should never see a GetBlocksInv message.
                // peer 1 should never see a BlocksInv message
                for (_, convo) in peers[0].network.peers.iter() {
                    assert_eq!(
                        convo
                            .stats
                            .get_message_recv_count(StacksMessageID::GetBlocksInv),
                        0
                    );
                }
                for (_, convo) in peers[1].network.peers.iter() {
                    assert_eq!(
                        convo
                            .stats
                            .get_message_recv_count(StacksMessageID::BlocksInv),
                        0
                    );
                }
            },
            |ref peer| {
                // check peer health
                // nothing should break
                // TODO
                true
            },
            |ref mut peers| {
                // all blocks downloaded.  only stop if peer 1 has
                // all the transactions
                let mut done_flag = done.borrow_mut();
                *done_flag = true;

                let txs =
                    MemPoolDB::get_all_txs(peers[1].mempool.as_ref().unwrap().conn()).unwrap();
                test_debug!("Peer 1 has {} txs", txs.len());
                txs.len() == sent_txs.borrow().len()
            },
        );

        // peer 1 should have all the transactions
        let blocks_and_microblocks = blocks_and_microblocks.into_inner();

        let txs = MemPoolDB::get_all_txs(peers[1].mempool.as_ref().unwrap().conn()).unwrap();
        let expected_txs = sent_txs.into_inner();
        for tx in txs.iter() {
            let mut found = false;
            for expected_tx in expected_txs.iter() {
                if tx.tx.txid() == expected_tx.txid() {
                    found = true;
                    break;
                }
            }
            if !found {
                panic!("Transaction not found: {:?}", &tx.tx);
            }
        }

        // peer 1 should have 1 tx per chain tip
        for ((consensus_hash, block, _), sent_tx) in
            blocks_and_microblocks.iter().zip(expected_txs.iter())
        {
            let block_hash = block.block_hash();
            let tx_infos = MemPoolDB::get_txs_after(
                peers[1].mempool.as_ref().unwrap().conn(),
                consensus_hash,
                &block_hash,
                0,
                1000,
            )
            .unwrap();
            test_debug!(
                "Check {}/{} (height {}): expect {}",
                &consensus_hash,
                &block_hash,
                block.header.total_work.work,
                &sent_tx.txid()
            );
            assert_eq!(tx_infos.len(), 1);
            assert_eq!(tx_infos[0].tx.txid(), sent_tx.txid());
        }
    })
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_peers_broadcast() {
    with_timeout(600, || {
        let blocks_and_microblocks = RefCell::new(vec![]);
        let blocks_idx = RefCell::new(0);
        let sent_txs = RefCell::new(vec![]);
        let done = RefCell::new(false);
        let num_peers = 3;
        let privk = StacksPrivateKey::new();

        let peers = run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_peers_broadcast",
            4230,
            num_peers,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), num_peers);

                // peer 0 generates blocks and microblocks, and pushes
                // them to peers 1..n.  Peer 0 also generates transactions
                // and broadcasts them to the network.

                peer_configs[0].connection_opts.disable_inv_sync = true;
                peer_configs[0].connection_opts.disable_inv_chat = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state.
                for i in 0..peer_configs.len() {
                    peer_configs[i].connection_opts.disable_natpunch = true;
                    peer_configs[i].connection_opts.disable_network_prune = true;
                    peer_configs[i].connection_opts.timeout = 600;
                    peer_configs[i].connection_opts.connect_timeout = 600;

                    // do one walk
                    peer_configs[i].connection_opts.num_initial_walks = 0;
                    peer_configs[i].connection_opts.walk_retry_count = 0;
                    peer_configs[i].connection_opts.walk_interval = 600;

                    // don't throttle downloads
                    peer_configs[i].connection_opts.download_interval = 0;
                    peer_configs[i].connection_opts.inv_sync_interval = 0;

                    let max_inflight = peer_configs[i].connection_opts.max_inflight_blocks;
                    peer_configs[i].connection_opts.max_clients_per_host =
                        ((num_peers + 1) as u64) * max_inflight;
                    peer_configs[i].connection_opts.soft_max_clients_per_host =
                        ((num_peers + 1) as u64) * max_inflight;
                    peer_configs[i].connection_opts.num_neighbors = (num_peers + 1) as u64;
                    peer_configs[i].connection_opts.soft_num_neighbors = (num_peers + 1) as u64;
                }

                let initial_balances = vec![(
                    PrincipalData::from(peer_configs[0].spending_account.origin_address().unwrap()),
                    1000000,
                )];

                for i in 0..peer_configs.len() {
                    peer_configs[i].initial_balances = initial_balances.clone();
                }

                // connectivity
                let peer_0 = peer_configs[0].to_neighbor();
                for i in 1..peer_configs.len() {
                    peer_configs[i].add_neighbor(&peer_0);
                    let peer_i = peer_configs[i].to_neighbor();
                    peer_configs[0].add_neighbor(&peer_i);
                }
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }
                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();

                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                *blocks_and_microblocks.borrow_mut() = block_data
                    .clone()
                    .drain(..)
                    .map(|(ch, blk_opt, mblocks_opt)| (ch, blk_opt.unwrap(), mblocks_opt.unwrap()))
                    .collect();
                block_data
            },
            |ref mut peers| {
                for peer in peers.iter_mut() {
                    // force peers to keep trying to process buffered data
                    peer.network.burnchain_tip.burn_header_hash = BurnchainHeaderHash([0u8; 32]);
                }

                let done_flag = *done.borrow();

                let mut connectivity_0_to_n = HashSet::new();
                let mut connectivity_n_to_0 = HashSet::new();

                let peer_0_nk = peers[0].to_neighbor().addr;

                for (nk, event_id) in peers[0].network.events.iter() {
                    if let Some(convo) = peers[0].network.peers.get(event_id) {
                        if convo.is_authenticated() {
                            connectivity_0_to_n.insert(nk.clone());
                        }
                    }
                }
                for i in 1..peers.len() {
                    for (nk, event_id) in peers[i].network.events.iter() {
                        if *nk != peer_0_nk {
                            continue;
                        }

                        if let Some(convo) = peers[i].network.peers.get(event_id) {
                            if convo.is_authenticated() {
                                if let Some(inv_state) = &peers[i].network.inv_state {
                                    if let Some(inv_stats) = inv_state.block_stats.get(&peer_0_nk) {
                                        if inv_stats.inv.num_reward_cycles >= 5 {
                                            connectivity_n_to_0.insert(peers[i].to_neighbor().addr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if connectivity_0_to_n.len() < peers.len() - 1
                    || connectivity_n_to_0.len() < peers.len() - 1
                {
                    test_debug!(
                        "Network not connected: 0 --> N = {}, N --> 0 = {}",
                        connectivity_0_to_n.len(),
                        connectivity_n_to_0.len()
                    );
                    return;
                }

                let ((tip_consensus_hash, tip_block, _), idx) = {
                    let block_data = blocks_and_microblocks.borrow();
                    let idx: usize = *blocks_idx.borrow();
                    (block_data[idx.saturating_sub(1)].clone(), idx)
                };

                if idx > 0 {
                    let mut caught_up = true;
                    for i in 1..peers.len() {
                        peers[i]
                            .with_db_state(|sortdb, chainstate, relayer, mempool| {
                                let (canonical_consensus_hash, canonical_block_hash) =
                                    SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn())
                                        .unwrap();

                                if canonical_consensus_hash != tip_consensus_hash
                                    || canonical_block_hash != tip_block.block_hash()
                                {
                                    debug!(
                                        "Peer {} is not caught up yet (at {}/{}, need {}/{})",
                                        i + 1,
                                        &canonical_consensus_hash,
                                        &canonical_block_hash,
                                        &tip_consensus_hash,
                                        &tip_block.block_hash()
                                    );
                                    caught_up = false;
                                }
                                Ok(())
                            })
                            .unwrap();
                    }
                    if !caught_up {
                        return;
                    }
                }

                // caught up!
                // find next block
                let ((consensus_hash, block, microblocks), idx) = {
                    let block_data = blocks_and_microblocks.borrow();
                    let mut idx = blocks_idx.borrow_mut();
                    if *idx >= block_data.len() {
                        test_debug!("Out of blocks and microblocks to push");
                        return;
                    }

                    let ret = block_data[*idx].clone();
                    *idx += 1;
                    (ret, *idx)
                };

                if !done_flag {
                    test_debug!(
                        "Broadcast block {}/{} and microblocks (idx = {})",
                        &consensus_hash,
                        block.block_hash(),
                        idx
                    );

                    let block_hash = block.block_hash();

                    // create a transaction against the current
                    // (anchored) chain tip
                    let tx = make_test_smart_contract_transaction(
                        &mut peers[0],
                        &format!("test-contract-{}", &block_hash.to_hex()[0..10]),
                        &tip_consensus_hash,
                        &tip_block.block_hash(),
                    );

                    let mut expected_txs = sent_txs.borrow_mut();
                    expected_txs.push(tx.clone());

                    test_debug!(
                        "Broadcast {}/{} and its microblocks",
                        &consensus_hash,
                        &block.block_hash()
                    );
                    // next block
                    broadcast_block(&mut peers[0], vec![], consensus_hash.clone(), block);
                    broadcast_microblocks(
                        &mut peers[0],
                        vec![],
                        consensus_hash,
                        block_hash,
                        microblocks,
                    );

                    // NOTE: first transaction will be dropped since the other nodes haven't
                    // processed the first-ever Stacks block when their relayer code gets
                    // around to considering it.
                    broadcast_transaction(&mut peers[0], vec![], tx);
                } else {
                    test_debug!("Done pushing data");
                }
            },
            |ref peer| {
                // check peer health -- no message errors
                // (i.e. no relay cycles)
                for (_, convo) in peer.network.peers.iter() {
                    assert_eq!(convo.stats.msgs_err, 0);
                }
                true
            },
            |ref mut peers| {
                // all blocks downloaded.  only stop if peer 1 has
                // all the transactions
                let mut done_flag = done.borrow_mut();
                *done_flag = true;

                let mut ret = true;
                for i in 1..peers.len() {
                    let txs =
                        MemPoolDB::get_all_txs(peers[1].mempool.as_ref().unwrap().conn()).unwrap();
                    test_debug!("Peer {} has {} txs", i + 1, txs.len());
                    ret = ret && txs.len() == sent_txs.borrow().len() - 1;
                }
                ret
            },
        );

        // peers 1..n should have all the transactions
        let blocks_and_microblocks = blocks_and_microblocks.into_inner();
        let expected_txs = sent_txs.into_inner();

        for i in 1..peers.len() {
            let txs = MemPoolDB::get_all_txs(peers[i].mempool.as_ref().unwrap().conn()).unwrap();
            for tx in txs.iter() {
                let mut found = false;
                for expected_tx in expected_txs.iter() {
                    if tx.tx.txid() == expected_tx.txid() {
                        found = true;
                        break;
                    }
                }
                if !found {
                    panic!("Transaction not found: {:?}", &tx.tx);
                }
            }

            // peers 1..n should have 1 tx per chain tip (except for the first block)
            for ((consensus_hash, block, _), sent_tx) in
                blocks_and_microblocks.iter().zip(expected_txs[1..].iter())
            {
                let block_hash = block.block_hash();
                let tx_infos = MemPoolDB::get_txs_after(
                    peers[i].mempool.as_ref().unwrap().conn(),
                    consensus_hash,
                    &block_hash,
                    0,
                    1000,
                )
                .unwrap();
                assert_eq!(tx_infos.len(), 1);
                assert_eq!(tx_infos[0].tx.txid(), sent_tx.txid());
            }
        }
    })
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_antientropy() {
    with_timeout(600, move || {
        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_2_peers_antientropy",
            4240,
            2,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 2);

                // peer 0 mines blocks, but does not advertize them nor announce them as
                // available via its inventory.  It only uses its anti-entropy protocol to
                // discover that peer 1 doesn't have them, and sends them to peer 1 that way.
                peer_configs[0].connection_opts.disable_block_advertisement = true;
                peer_configs[0].connection_opts.disable_block_download = true;

                peer_configs[1].connection_opts.disable_block_download = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;

                // permit anti-entropy protocol even if nat'ed
                peer_configs[0].connection_opts.antientropy_public = true;
                peer_configs[1].connection_opts.antientropy_public = true;
                peer_configs[0].connection_opts.antientropy_retry = 1;
                peer_configs[1].connection_opts.antientropy_retry = 1;

                // make peer 0 go slowly
                peer_configs[0].connection_opts.max_block_push = 2;
                peer_configs[0].connection_opts.max_microblock_push = 2;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();

                // peer 0 is inbound to peer 1
                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    if peers[0]
                        .config
                        .burnchain
                        .block_height_to_reward_cycle(tip.block_height)
                        .unwrap()
                        != this_reward_cycle
                    {
                        continue;
                    }
                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    for i in 1..peers.len() {
                        peers[i].next_burnchain_block_raw(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }

                // cap with an empty sortition, so the antientropy protocol picks up all stacks
                // blocks
                let (_, burn_header_hash, consensus_hash) = peers[0].next_burnchain_block(vec![]);
                for i in 1..peers.len() {
                    peers[i].next_burnchain_block_raw(vec![]);
                }
                let sn = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                block_data.push((sn.consensus_hash.clone(), None, None));

                block_data
            },
            |ref mut peers| {
                for peer in peers.iter_mut() {
                    // force peers to keep trying to process buffered data
                    peer.network.burnchain_tip.burn_header_hash = BurnchainHeaderHash([0u8; 32]);
                }

                let tip_opt = peers[1]
                    .with_db_state(|sortdb, chainstate, _, _| {
                        let tip_opt =
                            NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
                                .unwrap();
                        Ok(tip_opt)
                    })
                    .unwrap();
            },
            |ref peer| {
                // check peer health
                // nothing should break
                // TODO
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
fn test_get_blocks_and_microblocks_2_peers_buffered_messages() {
    with_timeout(600, move || {
        let sortitions = RefCell::new(vec![]);
        let blocks_and_microblocks = RefCell::new(vec![]);
        let idx = RefCell::new(0usize);
        let pushed_idx = RefCell::new(0usize);
        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_2_peers_buffered_messages",
            4242,
            2,
            |ref mut peer_configs| {
                // build initial network topology.
                assert_eq!(peer_configs.len(), 2);

                // peer 0 mines blocks, but it does not present its inventory.
                peer_configs[0].connection_opts.disable_inv_chat = true;
                peer_configs[0].connection_opts.disable_block_download = true;

                peer_configs[1].connection_opts.disable_block_download = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                // disable nat punches -- disconnect/reconnect
                // clears inv state
                peer_configs[0].connection_opts.disable_natpunch = true;
                peer_configs[1].connection_opts.disable_natpunch = true;

                // peer 0 ignores peer 1's handshakes
                peer_configs[0].connection_opts.disable_inbound_handshakes = true;

                // disable anti-entropy
                peer_configs[0].connection_opts.max_block_push = 0;
                peer_configs[0].connection_opts.max_microblock_push = 0;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();

                // peer 0 is inbound to peer 1
                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
            },
            |num_blocks, ref mut peers| {
                let tip = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[0].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                let this_reward_cycle = peers[0]
                    .config
                    .burnchain
                    .block_height_to_reward_cycle(tip.block_height)
                    .unwrap();

                // build up block data to replicate
                let mut block_data = vec![];
                for block_num in 0..num_blocks {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    let (mut burn_ops, stacks_block, microblocks) = peers[0].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[0].next_burnchain_block(burn_ops.clone());
                    peers[0].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    if block_num == 0 {
                        for i in 1..peers.len() {
                            peers[i].next_burnchain_block_raw(burn_ops.clone());
                            peers[i].process_stacks_epoch_at_tip(&stacks_block, &microblocks);
                        }
                    } else {
                        let mut all_sortitions = sortitions.borrow_mut();
                        all_sortitions.push(burn_ops.clone());
                    }

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[0].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                *blocks_and_microblocks.borrow_mut() = block_data.clone()[1..]
                    .to_vec()
                    .drain(..)
                    .map(|(ch, blk_opt, mblocks_opt)| (ch, blk_opt.unwrap(), mblocks_opt.unwrap()))
                    .collect();
                block_data
            },
            |ref mut peers| {
                for peer in peers.iter_mut() {
                    // force peers to keep trying to process buffered data
                    peer.network.burnchain_tip.burn_header_hash = BurnchainHeaderHash([0u8; 32]);
                }

                let mut i = idx.borrow_mut();
                let mut pushed_i = pushed_idx.borrow_mut();
                let all_sortitions = sortitions.borrow();
                let all_blocks_and_microblocks = blocks_and_microblocks.borrow();
                let peer_0_nk = peers[0].to_neighbor().addr;
                let peer_1_nk = peers[1].to_neighbor().addr;

                let tip_opt = peers[1]
                    .with_db_state(|sortdb, chainstate, _, _| {
                        let tip_opt =
                            NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
                                .unwrap();
                        Ok(tip_opt)
                    })
                    .unwrap();

                if !is_peer_connected(&peers[0], &peer_1_nk) {
                    debug!("Peer 0 not connected to peer 1");
                    return;
                }

                if let Some(tip) = tip_opt {
                    debug!(
                        "Push at {}, need {}",
                        tip.anchored_header.height()
                            - peers[1].config.burnchain.first_block_height
                            - 1,
                        *pushed_i
                    );
                    if tip.anchored_header.height()
                        - peers[1].config.burnchain.first_block_height
                        - 1
                        == *pushed_i as u64
                    {
                        // next block
                        push_block(
                            &mut peers[0],
                            &peer_1_nk,
                            vec![],
                            (*all_blocks_and_microblocks)[*pushed_i].0.clone(),
                            (*all_blocks_and_microblocks)[*pushed_i].1.clone(),
                        );
                        push_microblocks(
                            &mut peers[0],
                            &peer_1_nk,
                            vec![],
                            (*all_blocks_and_microblocks)[*pushed_i].0.clone(),
                            (*all_blocks_and_microblocks)[*pushed_i].1.block_hash(),
                            (*all_blocks_and_microblocks)[*pushed_i].2.clone(),
                        );
                        *pushed_i += 1;
                    }
                    debug!(
                        "Sortition at {}, need {}",
                        tip.anchored_header.height()
                            - peers[1].config.burnchain.first_block_height
                            - 1,
                        *i
                    );
                    if tip.anchored_header.height()
                        - peers[1].config.burnchain.first_block_height
                        - 1
                        == *i as u64
                    {
                        let event_id = {
                            let mut ret = 0;
                            for (nk, event_id) in peers[1].network.events.iter() {
                                ret = *event_id;
                                break;
                            }
                            if ret == 0 {
                                return;
                            }
                            ret
                        };
                        let mut update_sortition = false;
                        for ((event_id, _neighbor_key), pending) in
                            peers[1].network.pending_messages.iter()
                        {
                            debug!("Pending at {} is ({}, {})", *i, event_id, pending.len());
                            if !pending.is_empty() {
                                update_sortition = true;
                            }
                        }
                        if update_sortition {
                            debug!("Advance sortition!");
                            peers[1].next_burnchain_block_raw((*all_sortitions)[*i].clone());
                            *i += 1;
                        }
                    }
                }
            },
            |ref peer| {
                // check peer health
                // nothing should break
                // TODO
                true
            },
            |_| true,
        );
    })
}

pub fn make_contract_tx(
    sender: &StacksPrivateKey,
    cur_nonce: u64,
    tx_fee: u64,
    name: &str,
    contract: &str,
) -> StacksTransaction {
    let sender_spending_condition =
        TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");

    let spending_auth = TransactionAuth::Standard(sender_spending_condition);

    let mut tx_contract = StacksTransaction::new(
        TransactionVersion::Testnet,
        spending_auth.clone(),
        TransactionPayload::new_smart_contract(&name.to_string(), &contract.to_string(), None)
            .unwrap(),
    );

    tx_contract.chain_id = 0x80000000;
    tx_contract.auth.set_origin_nonce(cur_nonce);
    tx_contract.set_tx_fee(tx_fee);

    let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
    tx_signer.sign_origin(sender).unwrap();

    let tx_contract_signed = tx_signer.get_tx().unwrap();
    tx_contract_signed
}

#[test]
fn test_static_problematic_tests() {
    let spender_sk_1 = StacksPrivateKey::new();
    let spender_sk_2 = StacksPrivateKey::new();
    let spender_sk_3 = StacksPrivateKey::new();

    let edge_repeat_factor = AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) - 1;
    let tx_edge_body_start = "{ a : ".repeat(edge_repeat_factor as usize);
    let tx_edge_body_end = "} ".repeat(edge_repeat_factor as usize);
    let tx_edge_body = format!("{}u1 {}", tx_edge_body_start, tx_edge_body_end);

    let tx_edge = make_contract_tx(
        &spender_sk_1,
        0,
        (tx_edge_body.len() * 100) as u64,
        "test-edge",
        &tx_edge_body,
    );

    // something just over the limit of the expression depth
    let exceeds_repeat_factor = edge_repeat_factor + 1;
    let tx_exceeds_body_start = "{ a : ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body_end = "} ".repeat(exceeds_repeat_factor as usize);
    let tx_exceeds_body = format!("{}u1 {}", tx_exceeds_body_start, tx_exceeds_body_end);

    let tx_exceeds = make_contract_tx(
        &spender_sk_2,
        0,
        (tx_exceeds_body.len() * 100) as u64,
        "test-exceeds",
        &tx_exceeds_body,
    );

    // something stupidly high over the expression depth
    let high_repeat_factor = 128 * 1024;
    let tx_high_body_start = "{ a : ".repeat(high_repeat_factor as usize);
    let tx_high_body_end = "} ".repeat(high_repeat_factor as usize);
    let tx_high_body = format!("{}u1 {}", tx_high_body_start, tx_high_body_end);

    let tx_high = make_contract_tx(
        &spender_sk_3,
        0,
        (tx_high_body.len() * 100) as u64,
        "test-high",
        &tx_high_body,
    );
    assert!(Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_edge,
        ASTRules::Typical
    )
    .is_ok());
    assert!(Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_exceeds,
        ASTRules::Typical
    )
    .is_ok());
    assert!(Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_high,
        ASTRules::Typical
    )
    .is_ok());

    assert!(Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_edge,
        ASTRules::Typical
    )
    .is_ok());
    assert!(!Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_exceeds,
        ASTRules::PrecheckSize
    )
    .is_ok());
    assert!(!Relayer::static_check_problematic_relayed_tx(
        false,
        StacksEpochId::Epoch2_05,
        &tx_high,
        ASTRules::PrecheckSize
    )
    .is_ok());
}

#[test]
fn process_new_blocks_rejects_problematic_asts() {
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

    let initial_balances = vec![(addr.to_account_principal(), 100000000000)];

    let mut peer_config = TestPeerConfig::new(function_name!(), 32019, 32020);
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

    // activate new AST rules right away
    let mut peer = TestPeer::new(peer_config);
    let mut sortdb = peer.sortdb.take().unwrap();
    {
        let mut tx = sortdb
            .tx_begin()
            .expect("FATAL: failed to begin tx on sortition DB");
        SortitionDB::override_ast_rule_height(&mut tx, ASTRules::PrecheckSize, 1)
            .expect("FATAL: failed to override AST PrecheckSize rule height");
        tx.commit()
            .expect("FATAL: failed to commit sortition DB transaction");
    }
    peer.sortdb = Some(sortdb);

    let chainstate_path = peer.chainstate_path.clone();

    let first_stacks_block_height = {
        let sn = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn())
            .unwrap();
        sn.block_height
    };

    let recipient_addr_str = "ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV";
    let recipient = StacksAddress::from_string(recipient_addr_str).unwrap();

    let high_repeat_factor = 128 * 1024;
    let tx_high_body_start = "{ a : ".repeat(high_repeat_factor as usize);
    let tx_high_body_end = "} ".repeat(high_repeat_factor as usize);
    let tx_high_body = format!("{}u1 {}", tx_high_body_start, tx_high_body_end);

    let bad_tx = make_contract_tx(
        &privk,
        0,
        (tx_high_body.len() * 100) as u64,
        "test-high",
        &tx_high_body,
    );
    let bad_txid = bad_tx.txid();
    let bad_tx_len = {
        let mut bytes = vec![];
        bad_tx.consensus_serialize(&mut bytes).unwrap();
        bytes.len() as u64
    };

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let mblock_privk = StacksPrivateKey::new();

    // make one tenure with a valid block, but problematic microblocks
    let (burn_ops, block, microblocks) = peer.make_tenure(
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

            let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                &burnchain,
                &parent_tip,
                vrf_proof.clone(),
                tip.total_burn,
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privk)),
            )
            .unwrap();

            let block = StacksBlockBuilder::make_anchored_block_from_txs(
                block_builder,
                chainstate,
                &sortdb.index_handle(&tip.sortition_id),
                vec![coinbase_tx.clone()],
            )
            .unwrap()
            .0;

            (block, vec![])
        },
    );

    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    peer.process_stacks_epoch(&block, &consensus_hash, &[]);

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let (burn_ops, bad_block, mut microblocks) = peer.make_tenure(
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
            let coinbase_tx = make_coinbase(miner, 0);

            let mblock_privk = miner.next_microblock_privkey();
            let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                &burnchain,
                &parent_tip,
                vrf_proof.clone(),
                tip.total_burn,
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privk)),
            )
            .unwrap();

            // this tx would be problematic without our checks
            if let Err(ChainstateError::ProblematicTransaction(txid)) =
                StacksBlockBuilder::make_anchored_block_from_txs(
                    block_builder,
                    chainstate,
                    &sortdb.index_handle(&tip.sortition_id),
                    vec![coinbase_tx.clone(), bad_tx.clone()],
                )
            {
                assert_eq!(txid, bad_txid);
            } else {
                panic!("Did not get Error::ProblematicTransaction");
            }

            // make a bad block anyway
            // don't worry about the state root
            let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                &burnchain,
                &parent_tip,
                vrf_proof.clone(),
                tip.total_burn,
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&mblock_privk)),
            )
            .unwrap();
            let bad_block = StacksBlockBuilder::make_anchored_block_from_txs(
                block_builder,
                chainstate,
                &sortdb.index_handle(&tip.sortition_id),
                vec![coinbase_tx.clone()],
            )
            .unwrap();

            let mut bad_block = bad_block.0;
            bad_block.txs.push(bad_tx.clone());

            let txid_vecs: Vec<_> = bad_block
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            bad_block.header.tx_merkle_root = merkle_tree.root();

            chainstate
                .reload_unconfirmed_state(
                    &sortdb.index_handle(&tip.sortition_id),
                    parent_index_hash.clone(),
                )
                .unwrap();

            // make a bad microblock
            let iconn = &sortdb.index_handle(&tip.sortition_id);
            let mut microblock_builder = StacksMicroblockBuilder::new(
                parent_header_hash.clone(),
                parent_consensus_hash.clone(),
                chainstate,
                iconn,
                BlockBuilderSettings::max_value(),
            )
            .unwrap();

            // miner should fail with just the bad tx, since it's problematic
            let mblock_err = microblock_builder
                .mine_next_microblock_from_txs(vec![(bad_tx.clone(), bad_tx_len)], &mblock_privk)
                .unwrap_err();
            if let ChainstateError::NoTransactionsToMine = mblock_err {
            } else {
                panic!("Did not get NoTransactionsToMine");
            }

            let token_transfer =
                make_user_stacks_transfer(&privk, 0, 200, &recipient.to_account_principal(), 123);
            let tt_len = {
                let mut bytes = vec![];
                token_transfer.consensus_serialize(&mut bytes).unwrap();
                bytes.len() as u64
            };

            let mut bad_mblock = microblock_builder
                .mine_next_microblock_from_txs(
                    vec![(token_transfer, tt_len), (bad_tx.clone(), bad_tx_len)],
                    &mblock_privk,
                )
                .unwrap();

            // miner shouldn't include the bad tx, since it's problematic
            assert_eq!(bad_mblock.txs.len(), 1);
            bad_mblock.txs.push(bad_tx.clone());

            // force it in anyway
            let txid_vecs: Vec<_> = bad_mblock
                .txs
                .iter()
                .map(|tx| tx.txid().as_bytes().to_vec())
                .collect();

            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs);
            bad_mblock.header.tx_merkle_root = merkle_tree.root();
            bad_mblock.sign(&mblock_privk).unwrap();

            (bad_block, vec![bad_mblock])
        },
    );

    let bad_mblock = microblocks.pop().unwrap();
    let (_, _, new_consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    peer.process_stacks_epoch(&bad_block, &new_consensus_hash, &[]);

    // stuff them all into each possible field of NetworkResult
    // p2p messages
    let nk = NeighborKey {
        peer_version: 1,
        network_id: 2,
        addrbytes: PeerAddress([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]),
        port: 19,
    };
    let preamble = Preamble {
        peer_version: 1,
        network_id: 2,
        seq: 3,
        burn_block_height: 4,
        burn_block_hash: BurnchainHeaderHash([5u8; 32]),
        burn_stable_block_height: 6,
        burn_stable_block_hash: BurnchainHeaderHash([7u8; 32]),
        additional_data: 8,
        signature: MessageSignature([9u8; 65]),
        payload_len: 10,
    };
    let bad_msgs = vec![
        StacksMessage {
            preamble: preamble.clone(),
            relayers: vec![],
            payload: StacksMessageType::Blocks(BlocksData {
                blocks: vec![BlocksDatum(new_consensus_hash.clone(), bad_block.clone())],
            }),
        },
        StacksMessage {
            preamble: preamble.clone(),
            relayers: vec![],
            payload: StacksMessageType::Microblocks(MicroblocksData {
                index_anchor_block: StacksBlockId::new(
                    &new_consensus_hash,
                    &bad_block.block_hash(),
                ),
                microblocks: vec![bad_mblock.clone()],
            }),
        },
        StacksMessage {
            preamble: preamble.clone(),
            relayers: vec![],
            payload: StacksMessageType::Transaction(bad_tx.clone()),
        },
    ];
    let mut unsolicited = HashMap::new();
    unsolicited.insert((1, nk.clone()), bad_msgs.clone());

    let mut network_result = NetworkResult::new(
        peer.network.stacks_tip.block_id(),
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        ConsensusHash([0x01; 20]),
        HashMap::new(),
    );
    network_result.consume_unsolicited(unsolicited);

    assert!(network_result.has_blocks());
    assert!(network_result.has_microblocks());
    assert!(network_result.has_transactions());

    network_result.consume_http_uploads(
        bad_msgs
            .into_iter()
            .map(|msg| msg.payload)
            .collect::<Vec<_>>(),
    );

    assert!(network_result.has_blocks());
    assert!(network_result.has_microblocks());
    assert!(network_result.has_transactions());

    assert_eq!(network_result.uploaded_transactions.len(), 1);
    assert_eq!(network_result.uploaded_blocks.len(), 1);
    assert_eq!(network_result.uploaded_microblocks.len(), 1);
    assert_eq!(network_result.pushed_transactions.len(), 1);
    assert_eq!(network_result.pushed_blocks.len(), 1);
    assert_eq!(network_result.pushed_microblocks.len(), 1);

    network_result
        .blocks
        .push((new_consensus_hash.clone(), bad_block.clone(), 123));
    network_result.confirmed_microblocks.push((
        new_consensus_hash.clone(),
        vec![bad_mblock.clone()],
        234,
    ));

    let mut sortdb = peer.sortdb.take().unwrap();
    let (processed_blocks, processed_mblocks, relay_mblocks, bad_neighbors) =
        Relayer::process_new_blocks(
            &mut network_result,
            &mut sortdb,
            &mut peer.stacks_node.as_mut().unwrap().chainstate,
            None,
        )
        .unwrap();

    // despite this data showing up in all aspects of the network result, none of it actually
    // gets relayed
    assert_eq!(processed_blocks.len(), 0);
    assert_eq!(processed_mblocks.len(), 0);
    assert_eq!(relay_mblocks.len(), 0);
    assert_eq!(bad_neighbors.len(), 0);

    let txs_relayed = Relayer::process_transactions(
        &mut network_result,
        &sortdb,
        &mut peer.stacks_node.as_mut().unwrap().chainstate,
        &mut peer.mempool.as_mut().unwrap(),
        None,
    )
    .unwrap();
    assert_eq!(txs_relayed.len(), 0);
}

#[test]
fn test_block_pay_to_contract_gated_at_v210() {
    let mut peer_config = TestPeerConfig::new(function_name!(), 4246, 4247);
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
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: 28, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 28,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
    ]);
    peer_config.epochs = Some(epochs);
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let mut make_tenure =
        |miner: &mut TestMiner,
         sortdb: &mut SortitionDB,
         chainstate: &mut StacksChainState,
         vrfproof: VRFProof,
         parent_opt: Option<&StacksBlock>,
         microblock_parent_opt: Option<&StacksMicroblockHeader>| {
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            let stacks_tip_opt =
                NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb).unwrap();
            let parent_tip = match stacks_tip_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(header_tip) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &header_tip.anchored_header.block_hash(),
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

            let coinbase_tx = make_coinbase_with_nonce(
                miner,
                parent_tip.stacks_block_height as usize,
                0,
                Some(PrincipalData::Contract(
                    QualifiedContractIdentifier::parse("ST000000000000000000002AMW42H.bns")
                        .unwrap(),
                )),
            );

            let mut mblock_pubkey_hash_bytes = [0u8; 20];
            mblock_pubkey_hash_bytes.copy_from_slice(&coinbase_tx.txid()[0..20]);

            let builder = StacksBlockBuilder::make_block_builder(
                &burnchain,
                chainstate.mainnet,
                &parent_tip,
                vrfproof,
                tip.total_burn,
                Hash160(mblock_pubkey_hash_bytes),
            )
            .unwrap();

            let anchored_block = StacksBlockBuilder::make_anchored_block_from_txs(
                builder,
                chainstate,
                &sortdb.index_handle(&tip.sortition_id),
                vec![coinbase_tx],
            )
            .unwrap();

            (anchored_block.0, vec![])
        };

    // tenures 26 and 27 should fail, since the block is a pay-to-contract block
    // Pay-to-contract should only be supported if the block is in epoch 2.1, which
    // activates at tenure 27.
    for i in 0..2 {
        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

        let sortdb = peer.sortdb.take().unwrap();
        let mut node = peer.stacks_node.take().unwrap();
        match Relayer::process_new_anchored_block(
            &sortdb.index_conn(),
            &mut node.chainstate,
            &consensus_hash,
            &stacks_block,
            123,
        ) {
            Ok(x) => {
                panic!("Stored pay-to-contract stacks block before epoch 2.1");
            }
            Err(chainstate_error::InvalidStacksBlock(_)) => {}
            Err(e) => {
                panic!("Got unexpected error {:?}", &e);
            }
        };
        peer.sortdb = Some(sortdb);
        peer.stacks_node = Some(node);
    }

    // *now* it should succeed, since tenure 28 was in epoch 2.1
    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);

    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

    let sortdb = peer.sortdb.take().unwrap();
    let mut node = peer.stacks_node.take().unwrap();
    match Relayer::process_new_anchored_block(
        &sortdb.index_conn(),
        &mut node.chainstate,
        &consensus_hash,
        &stacks_block,
        123,
    ) {
        Ok(x) => {
            assert_eq!(
                x,
                BlockAcceptResponse::Accepted,
                "Failed to process valid pay-to-contract block"
            );
        }
        Err(e) => {
            panic!("Got unexpected error {:?}", &e);
        }
    };
    peer.sortdb = Some(sortdb);
    peer.stacks_node = Some(node);
}

#[test]
fn test_block_versioned_smart_contract_gated_at_v210() {
    let mut peer_config = TestPeerConfig::new(function_name!(), 4248, 4249);

    let initial_balances = vec![(
        PrincipalData::from(peer_config.spending_account.origin_address().unwrap()),
        1000000,
    )];

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
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: 28, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 28,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
    ]);

    peer_config.epochs = Some(epochs);
    peer_config.initial_balances = initial_balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);

    let mut make_tenure =
        |miner: &mut TestMiner,
         sortdb: &mut SortitionDB,
         chainstate: &mut StacksChainState,
         vrfproof: VRFProof,
         parent_opt: Option<&StacksBlock>,
         microblock_parent_opt: Option<&StacksMicroblockHeader>| {
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            let stacks_tip_opt =
                NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb).unwrap();
            let parent_tip = match stacks_tip_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(header_tip) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &header_tip.anchored_header.block_hash(),
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

            let coinbase_tx =
                make_coinbase_with_nonce(miner, parent_tip.stacks_block_height as usize, 0, None);

            let versioned_contract = make_smart_contract_with_version(
                miner,
                1,
                tip.block_height.try_into().unwrap(),
                0,
                Some(ClarityVersion::Clarity1),
                Some(1000),
            );

            let mut mblock_pubkey_hash_bytes = [0u8; 20];
            mblock_pubkey_hash_bytes.copy_from_slice(&coinbase_tx.txid()[0..20]);

            let builder = StacksBlockBuilder::make_block_builder(
                &burnchain,
                chainstate.mainnet,
                &parent_tip,
                vrfproof,
                tip.total_burn,
                Hash160(mblock_pubkey_hash_bytes),
            )
            .unwrap();

            let anchored_block = StacksBlockBuilder::make_anchored_block_from_txs(
                builder,
                chainstate,
                &sortdb.index_handle(&tip.sortition_id),
                vec![coinbase_tx, versioned_contract],
            )
            .unwrap();

            eprintln!("{:?}", &anchored_block.0);
            (anchored_block.0, vec![])
        };

    // tenures 26 and 27 should fail, since the block contains a versioned smart contract.
    // Versioned smart contracts should only be supported if the block is in epoch 2.1, which
    // activates at tenure 27.
    for i in 0..2 {
        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

        let sortdb = peer.sortdb.take().unwrap();
        let mut node = peer.stacks_node.take().unwrap();
        match Relayer::process_new_anchored_block(
            &sortdb.index_conn(),
            &mut node.chainstate,
            &consensus_hash,
            &stacks_block,
            123,
        ) {
            Ok(x) => {
                eprintln!("{:?}", &stacks_block);
                panic!("Stored pay-to-contract stacks block before epoch 2.1");
            }
            Err(chainstate_error::InvalidStacksBlock(_)) => {}
            Err(e) => {
                panic!("Got unexpected error {:?}", &e);
            }
        };
        peer.sortdb = Some(sortdb);
        peer.stacks_node = Some(node);
    }

    // *now* it should succeed, since tenure 28 was in epoch 2.1
    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);

    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

    let sortdb = peer.sortdb.take().unwrap();
    let mut node = peer.stacks_node.take().unwrap();
    match Relayer::process_new_anchored_block(
        &sortdb.index_conn(),
        &mut node.chainstate,
        &consensus_hash,
        &stacks_block,
        123,
    ) {
        Ok(x) => {
            assert_eq!(
                x,
                BlockAcceptResponse::Accepted,
                "Failed to process valid versioned smart contract block"
            );
        }
        Err(e) => {
            panic!("Got unexpected error {:?}", &e);
        }
    };
    peer.sortdb = Some(sortdb);
    peer.stacks_node = Some(node);
}

#[test]
fn test_block_versioned_smart_contract_mempool_rejection_until_v210() {
    let mut peer_config = TestPeerConfig::new(function_name!(), 4250, 4251);

    let initial_balances = vec![(
        PrincipalData::from(peer_config.spending_account.origin_address().unwrap()),
        1000000,
    )];

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
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: 28, // NOTE: the first 25 burnchain blocks have no sortition
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 28,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
    ]);

    peer_config.epochs = Some(epochs);
    peer_config.initial_balances = initial_balances;
    let burnchain = peer_config.burnchain.clone();

    let mut peer = TestPeer::new(peer_config);
    let versioned_contract_opt: RefCell<Option<StacksTransaction>> = RefCell::new(None);
    let nonce: RefCell<u64> = RefCell::new(0);

    let mut make_tenure =
        |miner: &mut TestMiner,
         sortdb: &mut SortitionDB,
         chainstate: &mut StacksChainState,
         vrfproof: VRFProof,
         parent_opt: Option<&StacksBlock>,
         microblock_parent_opt: Option<&StacksMicroblockHeader>| {
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            let stacks_tip_opt =
                NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb).unwrap();
            let parent_tip = match stacks_tip_opt {
                None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                Some(header_tip) => {
                    let ic = sortdb.index_conn();
                    let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &header_tip.anchored_header.block_hash(),
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

            let next_nonce = *nonce.borrow();
            let coinbase_tx = make_coinbase_with_nonce(
                miner,
                parent_tip.stacks_block_height as usize,
                next_nonce,
                None,
            );

            let versioned_contract = make_smart_contract_with_version(
                miner,
                next_nonce + 1,
                tip.block_height.try_into().unwrap(),
                0,
                Some(ClarityVersion::Clarity1),
                Some(1000),
            );

            *versioned_contract_opt.borrow_mut() = Some(versioned_contract);
            *nonce.borrow_mut() = next_nonce + 1;

            let mut mblock_pubkey_hash_bytes = [0u8; 20];
            mblock_pubkey_hash_bytes.copy_from_slice(&coinbase_tx.txid()[0..20]);

            let builder = StacksBlockBuilder::make_block_builder(
                &burnchain,
                chainstate.mainnet,
                &parent_tip,
                vrfproof,
                tip.total_burn,
                Hash160(mblock_pubkey_hash_bytes),
            )
            .unwrap();

            let anchored_block = StacksBlockBuilder::make_anchored_block_from_txs(
                builder,
                chainstate,
                &sortdb.index_handle(&tip.sortition_id),
                vec![coinbase_tx],
            )
            .unwrap();

            eprintln!("{:?}", &anchored_block.0);
            (anchored_block.0, vec![])
        };

    for i in 0..2 {
        let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

        let sortdb = peer.sortdb.take().unwrap();
        let mut node = peer.stacks_node.take().unwrap();

        // the empty block should be accepted
        match Relayer::process_new_anchored_block(
            &sortdb.index_conn(),
            &mut node.chainstate,
            &consensus_hash,
            &stacks_block,
            123,
        ) {
            Ok(x) => {
                assert_eq!(
                    x,
                    BlockAcceptResponse::Accepted,
                    "Did not accept valid block"
                );
            }
            Err(e) => {
                panic!("Got unexpected error {:?}", &e);
            }
        };

        // process it
        peer.coord.handle_new_stacks_block().unwrap();

        // the mempool would reject a versioned contract transaction, since we're not yet at
        // tenure 28
        let versioned_contract = (*versioned_contract_opt.borrow()).clone().unwrap();
        let versioned_contract_len = versioned_contract.serialize_to_vec().len();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        match node.chainstate.will_admit_mempool_tx(
            &sortdb.index_handle(&tip.sortition_id),
            &consensus_hash,
            &stacks_block.block_hash(),
            &versioned_contract,
            versioned_contract_len as u64,
        ) {
            Err(MemPoolRejection::Other(msg)) => {
                assert!(msg.find("not supported in this epoch").is_some());
            }
            Err(e) => {
                panic!("will_admit_mempool_tx {:?}", &e);
            }
            Ok(_) => {
                panic!("will_admit_mempool_tx succeeded");
            }
        };

        peer.sortdb = Some(sortdb);
        peer.stacks_node = Some(node);
    }

    // *now* it should succeed, since tenure 28 was in epoch 2.1
    let (burn_ops, stacks_block, microblocks) = peer.make_tenure(&mut make_tenure);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

    let sortdb = peer.sortdb.take().unwrap();
    let mut node = peer.stacks_node.take().unwrap();

    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    match Relayer::process_new_anchored_block(
        &sortdb.index_conn(),
        &mut node.chainstate,
        &consensus_hash,
        &stacks_block,
        123,
    ) {
        Ok(x) => {
            assert_eq!(
                x,
                BlockAcceptResponse::Accepted,
                "Failed to process valid versioned smart contract block"
            );
        }
        Err(e) => {
            panic!("Got unexpected error {:?}", &e);
        }
    };

    // process it
    peer.coord.handle_new_stacks_block().unwrap();

    // the mempool would accept a versioned contract transaction, since we're not yet at
    // tenure 28
    let versioned_contract = (*versioned_contract_opt.borrow()).clone().unwrap();
    let versioned_contract_len = versioned_contract.serialize_to_vec().len();
    match node.chainstate.will_admit_mempool_tx(
        &sortdb.index_handle(&tip.sortition_id),
        &consensus_hash,
        &stacks_block.block_hash(),
        &versioned_contract,
        versioned_contract_len as u64,
    ) {
        Err(e) => {
            panic!("will_admit_mempool_tx {:?}", &e);
        }
        Ok(_) => {}
    };

    peer.sortdb = Some(sortdb);
    peer.stacks_node = Some(node);
}

// TODO: process bans
// TODO: test sending invalid blocks-available and microblocks-available (should result in a ban)
// TODO: test sending invalid transactions (should result in a ban)
// TODO: test bandwidth limits (sending too much should result in a nack, and then a ban)
