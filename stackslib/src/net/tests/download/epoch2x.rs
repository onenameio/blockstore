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

use std::collections::HashMap;

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::execute;
use clarity::vm::representations::*;
use rand::Rng;
use stacks_common::util::hash::*;
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::VRFProof;

use super::*;
use crate::burnchains::tests::TestMiner;
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::*;
use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::stacks::miner::*;
use crate::chainstate::stacks::tests::*;
use crate::chainstate::stacks::*;
use crate::net::codec::*;
use crate::net::download::BlockDownloader;
use crate::net::inv::inv2x::*;
use crate::net::relay::*;
use crate::net::test::*;
use crate::net::*;
use crate::stacks_common::types::PublicKey;
use crate::util_lib::strings::*;
use crate::util_lib::test::*;

fn get_peer_availability(
    peer: &mut TestPeer,
    start_height: u64,
    end_height: u64,
) -> Vec<(ConsensusHash, Option<BlockHeaderHash>, Vec<NeighborKey>)> {
    let inv_state = peer.network.inv_state.take().unwrap();
    let availability = peer
        .with_network_state(
            |ref mut sortdb,
             ref mut _chainstate,
             ref mut network,
             ref mut _relayer,
             ref mut _mempool| {
                BlockDownloader::get_block_availability(
                    &network.local_peer,
                    &inv_state,
                    sortdb,
                    &mut network.header_cache,
                    start_height,
                    end_height,
                )
            },
        )
        .unwrap();
    peer.network.inv_state = Some(inv_state);
    availability
}

#[test]
fn test_get_block_availability() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 3210, 3211);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 3212, 3213);

        // don't bother downloading blocks
        peer_1_config.connection_opts.disable_block_download = true;
        peer_2_config.connection_opts.disable_block_download = true;

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let reward_cycle_length = peer_1_config.burnchain.pox_constants.reward_cycle_length as u64;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let num_blocks = 10;
        let first_stacks_block_height = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height
        };

        let mut block_data = vec![];

        for i in 0..num_blocks {
            let (mut burn_ops, stacks_block, microblocks) = peer_2.make_default_tenure();

            let (_, burn_header_hash, consensus_hash) =
                peer_2.next_burnchain_block(burn_ops.clone());
            peer_2.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

            peer_1.next_burnchain_block_raw(burn_ops);

            let sn =
                SortitionDB::get_canonical_burn_chain_tip(&peer_2.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            block_data.push((sn.consensus_hash.clone(), stacks_block, microblocks));
        }

        let num_burn_blocks = {
            let sn =
                SortitionDB::get_canonical_burn_chain_tip(peer_1.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            sn.block_height - peer_1.config.burnchain.first_block_height
        };

        let mut round = 0;
        let mut inv_1_count = 0;
        let mut inv_2_count = 0;
        let mut all_blocks_available = false;

        // can only learn about 1 reward cycle's blocks at a time in PoX
        while inv_1_count < reward_cycle_length
            && inv_2_count < reward_cycle_length
            && !all_blocks_available
        {
            let result_1 = peer_1.step();
            let result_2 = peer_2.step();

            inv_1_count = match peer_1.network.inv_state {
                Some(ref inv) => {
                    let mut count = inv.get_inv_sortitions(&peer_2.to_neighbor().addr);

                    // continue until peer 1 knows that peer 2 has blocks
                    let peer_1_availability = get_peer_availability(
                        &mut peer_1,
                        first_stacks_block_height,
                        first_stacks_block_height + reward_cycle_length,
                    );

                    let mut all_availability = true;
                    for (_, _, neighbors) in peer_1_availability.iter() {
                        if neighbors.len() != 1 {
                            // not done yet
                            count = 0;
                            all_availability = false;
                            break;
                        }
                        assert_eq!(neighbors[0], peer_2.config.to_neighbor().addr);
                    }

                    all_blocks_available = all_availability;

                    count
                }
                None => 0,
            };

            inv_2_count = match peer_2.network.inv_state {
                Some(ref inv) => inv.get_inv_sortitions(&peer_1.to_neighbor().addr),
                None => 0,
            };

            // nothing should break
            match peer_1.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.get_broken_peers().len(), 0);
                    assert_eq!(inv.get_diverged_peers().len(), 0);
                }
                None => {}
            }

            match peer_2.network.inv_state {
                Some(ref inv) => {
                    assert_eq!(inv.get_broken_peers().len(), 0);
                    assert_eq!(inv.get_diverged_peers().len(), 0);
                }
                None => {}
            }

            round += 1;
        }

        info!("Completed walk round {} step(s)", round);

        let availability = get_peer_availability(
            &mut peer_1,
            first_stacks_block_height,
            first_stacks_block_height + reward_cycle_length,
        );

        eprintln!("availability.len() == {}", availability.len());
        eprintln!("block_data.len() == {}", block_data.len());

        assert_eq!(availability.len() as u64, reward_cycle_length);
        assert_eq!(block_data.len() as u64, num_blocks);

        for (
            (sn_consensus_hash, stacks_block, microblocks),
            (consensus_hash, stacks_block_hash_opt, neighbors),
        ) in block_data.iter().zip(availability.iter())
        {
            assert_eq!(*consensus_hash, *sn_consensus_hash);
            assert!(stacks_block_hash_opt.is_some());
            assert_eq!(*stacks_block_hash_opt, Some(stacks_block.block_hash()));
        }
    })
}

fn get_blocks_inventory(peer: &mut TestPeer, start_height: u64, end_height: u64) -> BlocksInvData {
    let block_hashes = {
        let num_headers = end_height - start_height;
        let ic = peer.sortdb.as_mut().unwrap().index_conn();
        let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
        let ancestor = SortitionDB::get_ancestor_snapshot(&ic, end_height, &tip.sortition_id)
            .unwrap()
            .unwrap();
        ic.get_stacks_header_hashes(
            num_headers + 1,
            &ancestor.consensus_hash,
            &BlockHeaderCache::new(),
        )
        .unwrap()
    };

    let inv = peer
        .chainstate()
        .get_blocks_inventory(&block_hashes)
        .unwrap();
    inv
}

pub fn run_get_blocks_and_microblocks<T, F, P, C, D>(
    test_name: &str,
    port_base: u16,
    num_peers: usize,
    make_topology: T,
    block_generator: F,
    mut peer_func: P,
    mut check_breakage: C,
    mut done_func: D,
) -> Vec<TestPeer>
where
    T: FnOnce(&mut Vec<TestPeerConfig>),
    F: FnOnce(
        usize,
        &mut Vec<TestPeer>,
    ) -> Vec<(
        ConsensusHash,
        Option<StacksBlock>,
        Option<Vec<StacksMicroblock>>,
    )>,
    P: FnMut(&mut Vec<TestPeer>),
    C: FnMut(&mut TestPeer) -> bool,
    D: FnMut(&mut Vec<TestPeer>) -> bool,
{
    assert!(num_peers > 0);
    let first_sortition_height = 0;

    let mut peer_configs = vec![];
    for i in 0..num_peers {
        let mut peer_config = TestPeerConfig::new(
            test_name,
            port_base + ((2 * i) as u16),
            port_base + ((2 * i + 1) as u16),
        );
        peer_config.burnchain.first_block_height = first_sortition_height;

        peer_configs.push(peer_config);
    }

    make_topology(&mut peer_configs);

    let mut peers = vec![];
    for conf in peer_configs.drain(..) {
        let peer = TestPeer::new(conf);
        peers.push(peer);
    }

    let mut num_blocks = 10;
    let first_stacks_block_height = {
        let sn =
            SortitionDB::get_canonical_burn_chain_tip(&peers[0].sortdb.as_ref().unwrap().conn())
                .unwrap();
        sn.block_height
    };

    let block_data = block_generator(num_blocks, &mut peers);
    num_blocks = block_data.len();

    let num_burn_blocks = {
        let sn =
            SortitionDB::get_canonical_burn_chain_tip(peers[0].sortdb.as_ref().unwrap().conn())
                .unwrap();
        sn.block_height
    };

    let mut dns_clients = vec![];
    let mut dns_threads = vec![];

    for _ in 0..peers.len() {
        let (dns_client, dns_thread_handle) = dns_thread_start(100);
        dns_clients.push(dns_client);
        dns_threads.push(dns_thread_handle);
    }

    let mut round = 0;
    let mut peer_invs = vec![BlocksInvData::empty(); num_peers];

    let mut done = false;

    loop {
        peer_func(&mut peers);

        let mut peers_behind_burnchain = false;
        for i in 0..peers.len() {
            let peer = &mut peers[i];

            test_debug!("======= peer {} step begin =========", i);
            let mut result = peer.step_dns(&mut dns_clients[i]).unwrap();

            let lp = peer.network.local_peer.clone();
            let burnchain = peer.network.burnchain.clone();
            peer.with_db_state(|sortdb, chainstate, relayer, mempool| {
                relayer.process_network_result(
                    &lp,
                    &mut result,
                    &burnchain,
                    sortdb,
                    chainstate,
                    mempool,
                    false,
                    None,
                    None,
                )
            })
            .unwrap();

            test_debug!(
                "Peer {} processes {} blocks and {} microblock streams",
                i,
                result.blocks.len(),
                result.confirmed_microblocks.len()
            );

            peer.with_peer_state(|peer, sortdb, chainstate, mempool| {
                for i in 0..(result.blocks.len() + result.confirmed_microblocks.len() + 1) {
                    peer.coord.handle_new_stacks_block().unwrap();

                    let pox_id = {
                        let ic = sortdb.index_conn();
                        let tip_sort_id =
                            SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                        let sortdb_reader =
                            SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                        sortdb_reader.get_pox_id().unwrap()
                    };

                    test_debug!(
                        "\n\n{:?}: after stacks block, new tip PoX ID is {:?}\n\n",
                        &peer.to_neighbor().addr,
                        &pox_id
                    );
                }
                Ok(())
            })
            .unwrap();

            assert!(check_breakage(peer));

            let peer_num_burn_blocks = {
                let sn =
                    SortitionDB::get_canonical_burn_chain_tip(peer.sortdb.as_ref().unwrap().conn())
                        .unwrap();
                sn.block_height
            };

            peer_invs[i] = get_blocks_inventory(peer, 0, peer_num_burn_blocks);
            peers_behind_burnchain =
                peer_num_burn_blocks != num_burn_blocks || peers_behind_burnchain;

            test_debug!("Peer {} block inventory: {:?}", i, &peer_invs[i]);

            if let Some(ref inv) = peer.network.inv_state {
                test_debug!("Peer {} inventory stats: {:?}", i, &inv.block_stats);
            }

            let (mut inbound, mut outbound) = peer.network.dump_peer_table();

            inbound.sort();
            outbound.sort();

            test_debug!(
                "Peer {} outbound ({}): {}",
                i,
                outbound.len(),
                outbound.join(", ")
            );
            test_debug!(
                "Peer {} inbound ({}):  {}",
                i,
                inbound.len(),
                inbound.join(", ")
            );
            test_debug!("======= peer {} step end   =========", i);
        }

        if !done {
            done = !peers_behind_burnchain;

            for i in 0..num_peers {
                for b in 0..num_blocks {
                    if !peer_invs[i].has_ith_block(
                        ((b as u64) + first_stacks_block_height - first_sortition_height) as u16,
                    ) && block_data[b].1.is_some()
                    {
                        test_debug!(
                            "Peer {} is missing block {} at sortition height {} (between {} and {})",
                            i,
                            b,
                            (b as u64) + first_stacks_block_height - first_sortition_height,
                            first_stacks_block_height - first_sortition_height,
                            first_stacks_block_height - first_sortition_height
                                + (num_blocks as u64),
                        );
                        done = false;
                    }
                }
                for b in 1..(num_blocks - 1) {
                    if !peer_invs[i].has_ith_microblock_stream(
                        ((b as u64) + first_stacks_block_height - first_sortition_height) as u16,
                    ) && block_data[b].2.is_some()
                    {
                        test_debug!(
                            "Peer {} is missing microblock stream {} (between {} and {})",
                            i,
                            (b as u64) + first_stacks_block_height - first_sortition_height,
                            first_stacks_block_height - first_sortition_height,
                            first_stacks_block_height - first_sortition_height
                                + ((num_blocks - 1) as u64),
                        );
                        done = false;
                    }
                }
            }
        }
        for (i, peer) in peers.iter().enumerate() {
            test_debug!(
                "Peer {} has done {} p2p state-machine passes; {} inv syncs, {} download-syncs",
                i,
                peer.network.num_state_machine_passes,
                peer.network.num_inv_sync_passes,
                peer.network.num_downloader_passes
            );
        }

        if done {
            // all blocks obtained, now do custom check
            if done_func(&mut peers) {
                break;
            }
        }

        round += 1;
    }

    info!("Completed walk round {} step(s)", round);

    let mut peer_invs = vec![];
    for peer in peers.iter_mut() {
        let peer_inv = get_blocks_inventory(peer, 0, num_burn_blocks);
        peer_invs.push(peer_inv);

        let availability = get_peer_availability(
            peer,
            first_stacks_block_height - first_sortition_height,
            first_stacks_block_height - first_sortition_height + (num_blocks as u64),
        );

        assert_eq!(availability.len(), num_blocks);
        assert_eq!(block_data.len(), num_blocks);

        for (
            (sn_consensus_hash, stacks_block_opt, microblocks_opt),
            (consensus_hash, stacks_block_hash_opt, neighbors),
        ) in block_data.iter().zip(availability.iter())
        {
            assert_eq!(*consensus_hash, *sn_consensus_hash);

            if stacks_block_hash_opt.is_some() {
                assert!(stacks_block_opt.is_some());
                assert_eq!(
                    *stacks_block_hash_opt,
                    Some(stacks_block_opt.as_ref().unwrap().block_hash())
                );
            } else {
                assert!(stacks_block_opt.is_none());
            }
        }
    }

    drop(dns_clients);
    for handle in dns_threads.drain(..) {
        handle.join().unwrap();
    }

    peers
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_2_peers_download_plain() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3200,
            2,
            |ref mut peer_configs| {
                // build initial network topology
                assert_eq!(peer_configs.len(), 2);

                peer_configs[0].connection_opts.disable_block_advertisement = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();
                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
                    let (mut burn_ops, stacks_block, microblocks) = peers[1].make_default_tenure();

                    let (_, burn_header_hash, consensus_hash) =
                        peers[1].next_burnchain_block(burn_ops.clone());
                    peers[1].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    peers[0].next_burnchain_block_raw(burn_ops);

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[1].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }

                // no block advertisements (should be disabled)
                let _ = peer.for_each_convo_p2p(|event_id, convo| {
                    let cnt = *(convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::BlocksAvailable)
                        .unwrap_or(&0));
                    assert_eq!(
                        cnt, 0,
                        "neighbor event={} got {} BlocksAvailable messages",
                        event_id, cnt
                    );
                    Ok(())
                });

                true
            },
            |_| true,
        );
    })
}

fn make_contract_call_transaction(
    miner: &mut TestMiner,
    sortdb: &mut SortitionDB,
    chainstate: &mut StacksChainState,
    spending_account: &mut TestMiner,
    contract_address: StacksAddress,
    contract_name: &str,
    function_name: &str,
    args: Vec<Value>,
    consensus_hash: &ConsensusHash,
    block_hash: &BlockHeaderHash,
    nonce_offset: u64,
) -> StacksTransaction {
    let tx_cc = {
        let mut tx_cc = StacksTransaction::new(
            TransactionVersion::Testnet,
            spending_account.as_transaction_auth().unwrap(),
            TransactionPayload::new_contract_call(
                contract_address,
                contract_name,
                function_name,
                args,
            )
            .unwrap(),
        );

        let chain_tip = StacksBlockHeader::make_index_block_hash(consensus_hash, block_hash);
        let cur_nonce = chainstate
            .with_read_only_clarity_tx(&sortdb.index_handle_at_tip(), &chain_tip, |clarity_tx| {
                clarity_tx.with_clarity_db_readonly(|clarity_db| {
                    clarity_db
                        .get_account_nonce(&spending_account.origin_address().unwrap().into())
                        .unwrap()
                })
            })
            .unwrap()
            + nonce_offset;

        test_debug!(
            "Nonce of {:?} is {} (+{}) at {}/{}",
            &spending_account.origin_address().unwrap(),
            cur_nonce,
            nonce_offset,
            consensus_hash,
            block_hash
        );

        tx_cc.chain_id = 0x80000000;
        tx_cc.auth.set_origin_nonce(cur_nonce);
        tx_cc.set_tx_fee(MINIMUM_TX_FEE_RATE_PER_BYTE * 500);

        let mut tx_signer = StacksTransactionSigner::new(&tx_cc);
        spending_account.sign_as_origin(&mut tx_signer);

        let tx_cc_signed = tx_signer.get_tx().unwrap();

        test_debug!(
            "make transaction {:?} off of {:?}/{:?}: {:?}",
            &tx_cc_signed.txid(),
            consensus_hash,
            block_hash,
            &tx_cc_signed
        );

        spending_account.set_nonce(cur_nonce + 1);
        tx_cc_signed
    };

    tx_cc
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_2_peers_download_plain_100_blocks() {
    // 20 reward cycles
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            "test_get_blocks_and_microblocks_2_peers_download_plain_100_blocks",
            32100,
            2,
            |ref mut peer_configs| {
                // build initial network topology
                assert_eq!(peer_configs.len(), 2);

                peer_configs[0].connection_opts.disable_block_advertisement = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();
                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);

                // peer[1] has a big initial balance
                let initial_balances = vec![(
                    PrincipalData::from(peer_configs[1].spending_account.origin_address().unwrap()),
                    1_000_000_000_000_000,
                )];

                peer_configs[0].initial_balances = initial_balances.clone();
                peer_configs[1].initial_balances = initial_balances;
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                let spending_account = &mut peers[1].config.spending_account.clone();
                let burnchain = peers[1].config.burnchain.clone();

                // function to make a tenure in which a the peer's miner stacks its STX
                let mut make_stacking_tenure = |miner: &mut TestMiner,
                                                sortdb: &mut SortitionDB,
                                                chainstate: &mut StacksChainState,
                                                vrfproof: VRFProof,
                                                parent_opt: Option<&StacksBlock>,
                                                microblock_parent_opt: Option<
                    &StacksMicroblockHeader,
                >| {
                    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

                    let stacks_tip_opt =
                        NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
                            .unwrap();
                    let parent_tip = match stacks_tip_opt {
                        None => StacksChainState::get_genesis_header_info(chainstate.db()).unwrap(),
                        Some(header) => {
                            let ic = sortdb.index_conn();
                            let snapshot =
                                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                                    &ic,
                                    &tip.sortition_id,
                                    &header.anchored_header.block_hash(),
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
                        miner.get_nonce(),
                        None,
                    );

                    let stack_tx = make_contract_call_transaction(
                            miner,
                            sortdb,
                            chainstate,
                            spending_account,
                            StacksAddress::burn_address(false),
                            "pox",
                            "stack-stx",
                            vec![
                                Value::UInt(1_000_000_000_000_000 / 2),
                                execute("{ version: 0x00, hashbytes: 0x1000000010000000100000010000000100000001 }").unwrap().unwrap(),
                                Value::UInt((tip.block_height + 1) as u128),
                                Value::UInt(12)
                            ],
                            &parent_consensus_hash,
                            &parent_header_hash,
                            0
                        );

                    let mblock_tx = make_contract_call_transaction(
                        miner,
                        sortdb,
                        chainstate,
                        spending_account,
                        StacksAddress::burn_address(false),
                        "pox",
                        "get-pox-info",
                        vec![],
                        &parent_consensus_hash,
                        &parent_header_hash,
                        4,
                    );

                    let mblock_privkey = StacksPrivateKey::new();

                    let mblock_pubkey_hash_bytes = Hash160::from_data(
                        &StacksPublicKey::from_private(&mblock_privkey).to_bytes(),
                    );

                    let mut builder = StacksBlockBuilder::make_block_builder(
                        &burnchain,
                        chainstate.mainnet,
                        &parent_tip,
                        vrfproof,
                        tip.total_burn,
                        mblock_pubkey_hash_bytes,
                    )
                    .unwrap();
                    builder.set_microblock_privkey(mblock_privkey);

                    let (anchored_block, _size, _cost, microblock_opt) =
                        StacksBlockBuilder::make_anchored_block_and_microblock_from_txs(
                            builder,
                            chainstate,
                            &sortdb.index_handle_at_tip(),
                            vec![coinbase_tx, stack_tx],
                            vec![mblock_tx],
                        )
                        .unwrap();

                    (anchored_block, vec![microblock_opt.unwrap()])
                };

                for i in 0..50 {
                    let (mut burn_ops, stacks_block, microblocks) = if i == 1 {
                        peers[1].make_tenure(&mut make_stacking_tenure)
                    } else {
                        peers[1].make_default_tenure()
                    };

                    let (_, burn_header_hash, consensus_hash) =
                        peers[1].next_burnchain_block(burn_ops.clone());
                    peers[1].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                    TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                    peers[0].next_burnchain_block_raw(burn_ops);

                    let sn = SortitionDB::get_canonical_burn_chain_tip(
                        &peers[1].sortdb.as_ref().unwrap().conn(),
                    )
                    .unwrap();
                    block_data.push((
                        sn.consensus_hash.clone(),
                        Some(stacks_block),
                        Some(microblocks),
                    ));
                }
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }

                // no block advertisements (should be disabled)
                let _ = peer.for_each_convo_p2p(|event_id, convo| {
                    let cnt = *(convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::BlocksAvailable)
                        .unwrap_or(&0));
                    assert_eq!(
                        cnt, 0,
                        "neighbor event={} got {} BlocksAvailable messages",
                        event_id, cnt
                    );
                    Ok(())
                });

                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_5_peers_star() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3210,
            5,
            |ref mut peer_configs| {
                // build initial network topology -- a star with
                // peers[0] at the center, with all the blocks
                assert_eq!(peer_configs.len(), 5);
                let mut neighbors = vec![];

                for p in peer_configs.iter_mut() {
                    p.connection_opts.disable_block_advertisement = true;
                    p.connection_opts.max_clients_per_host = 30;
                }

                let peer_0 = peer_configs[0].to_neighbor();
                for i in 1..peer_configs.len() {
                    neighbors.push(peer_configs[i].to_neighbor());
                    peer_configs[i].add_neighbor(&peer_0);
                }

                for n in neighbors.drain(..) {
                    peer_configs[0].add_neighbor(&n);
                }
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
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
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_5_peers_line() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3220,
            5,
            |ref mut peer_configs| {
                // build initial network topology -- a line with
                // peers[0] at the left, with all the blocks
                assert_eq!(peer_configs.len(), 5);
                let mut neighbors = vec![];

                for p in peer_configs.iter_mut() {
                    p.connection_opts.disable_block_advertisement = true;
                    p.connection_opts.max_clients_per_host = 30;
                }

                for i in 0..peer_configs.len() {
                    neighbors.push(peer_configs[i].to_neighbor());
                }

                for i in 0..peer_configs.len() - 1 {
                    peer_configs[i].add_neighbor(&neighbors[i + 1]);
                    peer_configs[i + 1].add_neighbor(&neighbors[i]);
                }
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
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
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_overwhelmed_connections() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3230,
            5,
            |ref mut peer_configs| {
                // build initial network topology -- a star with
                // peers[0] at the center, with all the blocks
                assert_eq!(peer_configs.len(), 5);
                let mut neighbors = vec![];

                for p in peer_configs.iter_mut() {
                    p.connection_opts.disable_block_advertisement = true;
                }

                let peer_0 = peer_configs[0].to_neighbor();

                for i in 1..peer_configs.len() {
                    neighbors.push(peer_configs[i].to_neighbor());
                    peer_configs[i].add_neighbor(&peer_0);

                    // severely restrict the number of allowed
                    // connections in each peer
                    peer_configs[i].connection_opts.max_clients_per_host = 1;
                    peer_configs[i].connection_opts.num_clients = 1;
                    peer_configs[i].connection_opts.idle_timeout = 1;
                    peer_configs[i].connection_opts.max_http_clients = 1;
                }

                for n in neighbors.drain(..) {
                    peer_configs[0].add_neighbor(&n);
                }
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
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
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_overwhelmed_sockets() {
    // this one can go for a while
    with_timeout(1200, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3240,
            5,
            |ref mut peer_configs| {
                // build initial network topology -- a star with
                // peers[0] at the center, with all the blocks
                assert_eq!(peer_configs.len(), 5);
                let mut neighbors = vec![];

                for p in peer_configs.iter_mut() {
                    p.connection_opts.disable_block_advertisement = true;
                }

                let peer_0 = peer_configs[0].to_neighbor();

                for i in 1..peer_configs.len() {
                    neighbors.push(peer_configs[i].to_neighbor());
                    peer_configs[i].add_neighbor(&peer_0);

                    // severely restrict the number of events
                    peer_configs[i].connection_opts.max_sockets = 10;
                }

                for n in neighbors.drain(..) {
                    peer_configs[0].add_neighbor(&n);
                }
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate
                let mut block_data = vec![];
                for _ in 0..num_blocks {
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
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }
                true
            },
            |_| true,
        );
    })
}

#[test]
#[ignore]
#[should_panic(expected = "blocked URL")]
pub fn test_get_blocks_and_microblocks_ban_url() {
    use std::net::TcpListener;
    use std::thread;

    let listener_1 = TcpListener::bind("127.0.0.1:3260").unwrap();
    let listener_2 = TcpListener::bind("127.0.0.1:3262").unwrap();

    let endpoint_thread_1 = thread::spawn(move || {
        let (sock, addr) = listener_1.accept().unwrap();
        test_debug!("Accepted 1 {:?}", &addr);
        sleep_ms(60_000);
    });

    let endpoint_thread_2 = thread::spawn(move || {
        let (sock, addr) = listener_2.accept().unwrap();
        test_debug!("Accepted 2 {:?}", &addr);
        sleep_ms(60_000);
    });

    run_get_blocks_and_microblocks(
        function_name!(),
        3250,
        2,
        |ref mut peer_configs| {
            // build initial network topology
            assert_eq!(peer_configs.len(), 2);

            peer_configs[0].connection_opts.disable_block_advertisement = true;
            peer_configs[1].connection_opts.disable_block_advertisement = true;

            // announce URLs to our fake handlers
            peer_configs[0].data_url =
                UrlString::try_from("http://127.0.0.1:3260".to_string()).unwrap();
            peer_configs[1].data_url =
                UrlString::try_from("http://127.0.0.1:3262".to_string()).unwrap();

            let peer_0 = peer_configs[0].to_neighbor();
            let peer_1 = peer_configs[1].to_neighbor();
            peer_configs[0].add_neighbor(&peer_1);
            peer_configs[1].add_neighbor(&peer_0);
        },
        |num_blocks, ref mut peers| {
            // build up block data to replicate
            let mut block_data = vec![];
            for _ in 0..num_blocks {
                let (mut burn_ops, stacks_block, microblocks) = peers[1].make_default_tenure();

                let (_, burn_header_hash, consensus_hash) =
                    peers[1].next_burnchain_block(burn_ops.clone());
                peers[1].process_stacks_epoch_at_tip(&stacks_block, &microblocks);

                TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                peers[0].next_burnchain_block_raw(burn_ops);

                let sn = SortitionDB::get_canonical_burn_chain_tip(
                    &peers[1].sortdb.as_ref().unwrap().conn(),
                )
                .unwrap();
                block_data.push((
                    sn.consensus_hash.clone(),
                    Some(stacks_block),
                    Some(microblocks),
                ));
            }
            block_data
        },
        |_| {},
        |peer| {
            let mut blocked = 0;
            match peer.network.block_downloader {
                Some(ref dl) => {
                    blocked = dl.blocked_urls.len();
                }
                None => {}
            }
            if blocked >= 1 {
                // NOTE: this is the success criterion
                panic!("blocked URL");
            }
            true
        },
        |_| true,
    );

    endpoint_thread_1.join().unwrap();
    endpoint_thread_2.join().unwrap();
}

#[test]
#[ignore]
pub fn test_get_blocks_and_microblocks_2_peers_download_multiple_microblock_descendants() {
    with_timeout(600, || {
        run_get_blocks_and_microblocks(
            function_name!(),
            3260,
            2,
            |ref mut peer_configs| {
                // build initial network topology
                assert_eq!(peer_configs.len(), 2);

                peer_configs[0].connection_opts.disable_block_advertisement = true;
                peer_configs[1].connection_opts.disable_block_advertisement = true;

                let peer_0 = peer_configs[0].to_neighbor();
                let peer_1 = peer_configs[1].to_neighbor();
                peer_configs[0].add_neighbor(&peer_1);
                peer_configs[1].add_neighbor(&peer_0);
            },
            |num_blocks, ref mut peers| {
                // build up block data to replicate.
                // chainstate looks like this:
                //
                // [tenure-1] <- [mblock] <- [mblock] <- [mblock] <- [mblock] <- ...
                //             \           \           \           \
                //              \           \           \           \
                //               [tenure-2]  [tenure-3]  [tenure-4]  [tenure-5]  ...
                //
                let mut block_data = vec![];
                let mut microblock_stream = vec![];
                let mut first_block_height = 0;
                for i in 0..num_blocks {
                    if i == 0 {
                        let (mut burn_ops, stacks_block, mut microblocks) =
                            peers[1].make_default_tenure();

                        // extend to 10 microblocks
                        while microblocks.len() != num_blocks {
                            let next_microblock_payload = TransactionPayload::SmartContract(
                                TransactionSmartContract {
                                    name: ContractName::try_from(format!(
                                        "hello-world-{}",
                                        thread_rng().gen::<u64>()
                                    ))
                                    .expect("FATAL: valid name"),
                                    code_body: StacksString::from_str(
                                        "(begin (print \"hello world\"))",
                                    )
                                    .expect("FATAL: valid code"),
                                },
                                None,
                            );
                            let mut mblock = microblocks.last().unwrap().clone();
                            let last_nonce = mblock
                                .txs
                                .last()
                                .as_ref()
                                .unwrap()
                                .auth()
                                .get_origin_nonce();
                            let prev_block = mblock.block_hash();

                            let signed_tx = sign_standard_singlesig_tx(
                                next_microblock_payload,
                                &peers[1].miner.privks[0],
                                last_nonce + 1,
                                0,
                            );
                            let txids = vec![signed_tx.txid().as_bytes().to_vec()];
                            let merkle_tree = MerkleTree::<Sha512Trunc256Sum>::new(&txids);
                            let tx_merkle_root = merkle_tree.root();

                            mblock.txs = vec![signed_tx];
                            mblock.header.tx_merkle_root = tx_merkle_root;
                            mblock.header.prev_block = prev_block;
                            mblock.header.sequence += 1;
                            mblock
                                .header
                                .sign(peers[1].miner.microblock_privks.last().as_ref().unwrap())
                                .unwrap();

                            microblocks.push(mblock);
                        }

                        let (_, burn_header_hash, consensus_hash) =
                            peers[1].next_burnchain_block(burn_ops.clone());

                        peers[1].process_stacks_epoch(&stacks_block, &consensus_hash, &microblocks);

                        TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                        peers[0].next_burnchain_block_raw(burn_ops);

                        let sn = SortitionDB::get_canonical_burn_chain_tip(
                            &peers[1].sortdb.as_ref().unwrap().conn(),
                        )
                        .unwrap();

                        microblock_stream = microblocks.clone();
                        first_block_height = sn.block_height as u32;

                        block_data.push((
                            sn.consensus_hash.clone(),
                            Some(stacks_block),
                            Some(microblocks),
                        ));
                    } else {
                        test_debug!("Build child block {}", i);
                        let tip = SortitionDB::get_canonical_burn_chain_tip(
                            &peers[1].sortdb.as_ref().unwrap().conn(),
                        )
                        .unwrap();

                        let chainstate_path = peers[1].chainstate_path.clone();
                        let burnchain = peers[1].config.burnchain.clone();

                        let (mut burn_ops, stacks_block, _) = peers[1].make_tenure(
                            |ref mut miner,
                             ref mut sortdb,
                             ref mut chainstate,
                             vrf_proof,
                             ref parent_opt,
                             ref parent_microblock_header_opt| {
                                let mut parent_tip =
                                    StacksChainState::get_anchored_block_header_info(
                                        chainstate.db(),
                                        &block_data[0].0,
                                        &block_data[0].1.as_ref().unwrap().block_hash(),
                                    )
                                    .unwrap()
                                    .unwrap();

                                parent_tip.microblock_tail =
                                    Some(microblock_stream[i - 1].header.clone());

                                let mut mempool =
                                    MemPoolDB::open_test(false, 0x80000000, &chainstate_path)
                                        .unwrap();
                                let coinbase_tx =
                                    make_coinbase_with_nonce(miner, i, (i + 2) as u64, None);

                                let (anchored_block, block_size, block_execution_cost) =
                                    StacksBlockBuilder::build_anchored_block(
                                        chainstate,
                                        &sortdb.index_handle_at_tip(),
                                        &mut mempool,
                                        &parent_tip,
                                        parent_tip
                                            .anchored_header
                                            .as_stacks_epoch2()
                                            .unwrap()
                                            .total_work
                                            .burn
                                            + 1000,
                                        vrf_proof,
                                        Hash160([i as u8; 20]),
                                        &coinbase_tx,
                                        BlockBuilderSettings::max_value(),
                                        None,
                                        &burnchain,
                                    )
                                    .unwrap();
                                (anchored_block, vec![])
                            },
                        );

                        for burn_op in burn_ops.iter_mut() {
                            if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = burn_op
                            {
                                op.parent_block_ptr = first_block_height;
                                op.block_header_hash = stacks_block.block_hash();
                            }
                        }

                        let (_, burn_header_hash, consensus_hash) =
                            peers[1].next_burnchain_block(burn_ops.clone());

                        peers[1].process_stacks_epoch(&stacks_block, &consensus_hash, &[]);

                        TestPeer::set_ops_burn_header_hash(&mut burn_ops, &burn_header_hash);

                        peers[0].next_burnchain_block_raw(burn_ops);

                        let sn = SortitionDB::get_canonical_burn_chain_tip(
                            &peers[1].sortdb.as_ref().unwrap().conn(),
                        )
                        .unwrap();

                        block_data.push((
                            sn.consensus_hash.clone(),
                            Some(stacks_block),
                            Some(vec![]),
                        ));
                    }
                }
                block_data
            },
            |_| {},
            |peer| {
                // check peer health
                // nothing should break
                match peer.network.block_downloader {
                    Some(ref dl) => {
                        assert_eq!(dl.broken_peers.len(), 0);
                        assert_eq!(dl.dead_peers.len(), 0);
                    }
                    None => {}
                }

                // no block advertisements (should be disabled)
                let _ = peer.for_each_convo_p2p(|event_id, convo| {
                    let cnt = *(convo
                        .stats
                        .msg_rx_counts
                        .get(&StacksMessageID::BlocksAvailable)
                        .unwrap_or(&0));
                    assert_eq!(
                        cnt, 0,
                        "neighbor event={} got {} BlocksAvailable messages",
                        event_id, cnt
                    );
                    Ok(())
                });

                true
            },
            |_| true,
        );
    })
}
