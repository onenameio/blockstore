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

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::thread::JoinHandle;

use clarity::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use clarity::vm::ast::ASTRules;
use clarity::vm::costs::LimitedCostTracker;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, MAX_CALL_STACK_DEPTH};
use rand::Rng;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId, StacksWorkScore, TrieHash};
use stacks_common::types::Address;
use stacks_common::util::hash::{MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::sleep_ms;
use stacks_common::util::vrf::VRFProof;

use super::*;
use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::tests::TestMiner;
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::nakamoto::coordinator::tests::make_token_transfer;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::NakamotoBlockHeader;
use crate::chainstate::stacks::boot::test::{
    key_to_stacks_addr, make_pox_4_lockup, make_signer_key_signature, with_sortdb,
};
use crate::chainstate::stacks::db::blocks::{MINIMUM_TX_FEE, MINIMUM_TX_FEE_RATE_PER_BYTE};
use crate::chainstate::stacks::miner::{BlockBuilderSettings, StacksMicroblockBuilder};
use crate::chainstate::stacks::test::{
    codec_all_transactions, make_codec_test_block, make_codec_test_microblock,
};
use crate::chainstate::stacks::tests::{
    make_coinbase, make_coinbase_with_nonce, make_smart_contract_with_version,
    make_user_stacks_transfer, TestStacksNode,
};
use crate::chainstate::stacks::{Error as ChainstateError, *};
use crate::clarity_vm::clarity::ClarityConnection;
use crate::core::*;
use crate::net::asn::*;
use crate::net::chat::*;
use crate::net::codec::*;
use crate::net::download::*;
use crate::net::http::{HttpRequestContents, HttpRequestPreamble};
use crate::net::httpcore::StacksHttpMessage;
use crate::net::inv::inv2x::*;
use crate::net::relay::{AcceptedNakamotoBlocks, ProcessedNetReceipts, Relayer};
use crate::net::test::*;
use crate::net::tests::download::epoch2x::run_get_blocks_and_microblocks;
use crate::net::tests::inv::nakamoto::make_nakamoto_peers_from_invs;
use crate::net::tests::relay::epoch2x::broadcast_message;
use crate::net::{Error as NetError, *};
use crate::util_lib::test::*;

/// Everything in a TestPeer, except the coordinator (which is encumbered by the lifetime of its
/// chains coordinator's event observer)
struct ExitedPeer {
    pub config: TestPeerConfig,
    pub network: PeerNetwork,
    pub sortdb: Option<SortitionDB>,
    pub miner: TestMiner,
    pub stacks_node: Option<TestStacksNode>,
    pub relayer: Relayer,
    pub mempool: Option<MemPoolDB>,
    pub chainstate_path: String,
    pub indexer: Option<BitcoinIndexer>,
}

impl ExitedPeer {
    /// Instantiate the exited peer from the TestPeer
    fn from_test_peer(peer: TestPeer) -> Self {
        Self {
            config: peer.config,
            network: peer.network,
            sortdb: peer.sortdb,
            miner: peer.miner,
            stacks_node: peer.stacks_node,
            relayer: peer.relayer,
            mempool: peer.mempool,
            chainstate_path: peer.chainstate_path,
            indexer: peer.indexer,
        }
    }

    /// Run the network stack of the exited peer, but no more block processing will take place.
    pub fn run_with_ibd(
        &mut self,
        ibd: bool,
        dns_client: Option<&mut DNSClient>,
    ) -> Result<(NetworkResult, ProcessedNetReceipts), NetError> {
        let mut sortdb = self.sortdb.take().unwrap();
        let mut stacks_node = self.stacks_node.take().unwrap();
        let mut mempool = self.mempool.take().unwrap();
        let indexer = self.indexer.take().unwrap();

        let net_result = self.network.run(
            &indexer,
            &sortdb,
            &mut stacks_node.chainstate,
            &mut mempool,
            dns_client,
            false,
            ibd,
            100,
            &RPCHandlerArgs::default(),
        )?;
        let receipts_res = self.relayer.process_network_result(
            self.network.get_local_peer(),
            &mut net_result.clone(),
            &self.network.burnchain,
            &mut sortdb,
            &mut stacks_node.chainstate,
            &mut mempool,
            ibd,
            None,
            None,
        );

        self.sortdb = Some(sortdb);
        self.stacks_node = Some(stacks_node);
        self.mempool = Some(mempool);
        self.indexer = Some(indexer);

        receipts_res.map(|receipts| (net_result, receipts))
    }
}

/// Messages passed to the unit test from the seed node thread
enum SeedData {
    BurnOps(Vec<BlockstackOperationType>, ConsensusHash),
    Blocks(Vec<NakamotoBlock>),
    Exit(ExitedPeer),
}

/// Messages passed from the unit test to the seed node thread
#[derive(Clone, Debug, PartialEq)]
enum SeedCommand {
    Exit,
}

/// Communication channels from the unit test to the seed node thread
struct FollowerComms {
    data_receiver: Receiver<SeedData>,
    command_sender: SyncSender<SeedCommand>,
}

impl FollowerComms {
    pub fn send_exit(&mut self) {
        self.command_sender
            .send(SeedCommand::Exit)
            .expect("FATAL: seed node hangup");
    }

    pub fn try_recv(&mut self) -> Option<SeedData> {
        match self.data_receiver.try_recv() {
            Ok(data) => Some(data),
            Err(TryRecvError::Empty) => None,
            Err(_) => {
                panic!("FATAL: seed node hangup");
            }
        }
    }
}

/// Communication channels from the seed node thread to the unit test
struct SeedComms {
    data_sender: SyncSender<SeedData>,
    command_receiver: Receiver<SeedCommand>,
}

struct SeedNode {}

impl SeedNode {
    /// Have `peer` produce two reward cycles of length `rc_len`, and forward all sortitions and
    /// Nakamoto blocks back to the unit test.  This consumes `peer`.
    ///
    /// The `peer` will process its blocks locally, and _push_ them to one or more followers.  The
    /// `peer` will wait for there to be at least one network conversation open before advancing,
    /// thereby ensuring reliable delivery of the Nakamoto blocks to at least one follower.  In
    /// addition, the blocks and sortitions will be sent to the unit test via `comms`.
    ///
    /// The contents of `peer` will be sent back to the unit test via an `ExitedPeer` struct, so
    /// the unit test can query it or even run its networking stack.
    pub fn main(mut peer: TestPeer, rc_len: u64, comms: SeedComms) {
        let private_key = StacksPrivateKey::from_seed(&[2]);
        let addr = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&private_key)],
        )
        .unwrap();

        let mut test_signers = peer.config.test_signers.take().unwrap();
        let test_stackers = peer.config.test_stackers.take().unwrap();

        let mut all_blocks: Vec<NakamotoBlock> = vec![];
        let mut all_burn_ops = vec![];
        let mut rc_blocks = vec![];
        let mut rc_burn_ops = vec![];

        // have the peer mine some blocks for two reward cycles
        for i in 0..(2 * rc_len) {
            debug!("Tenure {}", i);
            let (burn_ops, mut tenure_change, miner_key) =
                peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

            // pass along to the follower
            if comms
                .data_sender
                .send(SeedData::BurnOps(burn_ops.clone(), consensus_hash.clone()))
                .is_err()
            {
                warn!("Follower disconnected");
                break;
            }

            let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

            tenure_change.tenure_consensus_hash = consensus_hash.clone();
            tenure_change.burn_view_consensus_hash = consensus_hash.clone();

            let tenure_change_tx = peer
                .miner
                .make_nakamoto_tenure_change(tenure_change.clone());
            let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

            debug!("Next burnchain block: {}", &consensus_hash);

            let num_blocks: usize = (thread_rng().gen::<usize>() % 10) + 1;

            let block_height = peer.get_burn_block_height();

            // do a stx transfer in each block to a given recipient
            let recipient_addr =
                StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
            let blocks_and_sizes = peer.make_nakamoto_tenure(
                tenure_change_tx,
                coinbase_tx,
                &mut test_signers,
                |miner, chainstate, sortdb, blocks_so_far| {
                    let mut txs = vec![];
                    if blocks_so_far.len() < num_blocks {
                        debug!("\n\nProduce block {}\n\n", all_blocks.len());

                        let account = get_account(chainstate, sortdb, &addr);

                        let stx_transfer = make_token_transfer(
                            chainstate,
                            sortdb,
                            &private_key,
                            account.nonce,
                            100,
                            1,
                            &recipient_addr,
                        );
                        txs.push(stx_transfer);
                    }
                    txs
                },
            );

            let mut blocks: Vec<NakamotoBlock> = blocks_and_sizes
                .into_iter()
                .map(|(block, _, _)| block)
                .collect();

            // run network state machine until we have a connection
            loop {
                let network_result_res = peer.run_with_ibd(false, None);
                if let Ok((network_result, _)) = network_result_res {
                    if network_result.num_connected_peers > 0 {
                        break;
                    }
                }
            }

            // relay these blocks
            let local_peer = peer.network.get_local_peer().clone();
            let sortdb = peer.sortdb.take().unwrap();
            let stacks_node = peer.stacks_node.take().unwrap();

            peer.relayer.relay_epoch3_blocks(
                &local_peer,
                &sortdb,
                vec![AcceptedNakamotoBlocks {
                    relayers: vec![],
                    blocks: blocks.clone(),
                }],
            );

            peer.sortdb = Some(sortdb);
            peer.stacks_node = Some(stacks_node);

            // send the blocks to the unit test as well
            if comms
                .data_sender
                .send(SeedData::Blocks(blocks.clone()))
                .is_err()
            {
                warn!("Follower disconnected");
                break;
            }

            // if we're starting a new reward cycle, then save the current one
            let tip = {
                let sort_db = peer.sortdb.as_mut().unwrap();
                SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
            };
            if peer
                .config
                .burnchain
                .is_reward_cycle_start(tip.block_height)
            {
                rc_blocks.push(all_blocks.clone());
                rc_burn_ops.push(all_burn_ops.clone());

                all_burn_ops.clear();
                all_blocks.clear();
            }

            all_blocks.append(&mut blocks);
            all_burn_ops.push(burn_ops);
        }

        peer.config.test_signers = Some(test_signers);
        peer.config.test_stackers = Some(test_stackers);

        let exited_peer = ExitedPeer::from_test_peer(peer);

        // inform the follower that we're done, and pass along the final state of the peer
        if comms.data_sender.send(SeedData::Exit(exited_peer)).is_err() {
            panic!("Follower disconnected");
        }

        // wait for request to exit
        let Ok(SeedCommand::Exit) = comms.command_receiver.recv() else {
            panic!("FATAL: did not receive shutdown request (follower must have crashed)");
        };
    }

    /// Instantiate bidirectional communication channels between the unit test and seed node
    pub fn comms() -> (SeedComms, FollowerComms) {
        let (data_sender, data_receiver) = sync_channel(1024);
        let (command_sender, command_receiver) = sync_channel(1024);

        let seed_comms = SeedComms {
            data_sender,
            command_receiver,
        };

        let follower_comms = FollowerComms {
            data_receiver,
            command_sender,
        };

        (seed_comms, follower_comms)
    }
}

/// Test buffering limits
#[test]
fn test_buffer_data_message() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let (mut peer, _followers) =
        make_nakamoto_peers_from_invs(function_name!(), &observer, 10, 5, bitvecs.clone(), 1);

    let peer_nk = peer.to_neighbor().addr;
    let nakamoto_block = NakamotoBlock {
        header: NakamotoBlockHeader {
            version: 1,
            chain_length: 457,
            burn_spent: 126,
            consensus_hash: ConsensusHash([0x55; 20]),
            parent_block_id: StacksBlockId([0x03; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x05; 32]),
            state_index_root: TrieHash([0x07; 32]),
            timestamp: 8,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::zeros(1).unwrap(),
        },
        txs: vec![],
    };

    let blocks_available = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::BlocksAvailable(BlocksAvailableData {
            available: vec![
                (ConsensusHash([0x11; 20]), BurnchainHeaderHash([0x22; 32])),
                (ConsensusHash([0x33; 20]), BurnchainHeaderHash([0x44; 32])),
            ],
        }),
    );

    let microblocks_available = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::MicroblocksAvailable(BlocksAvailableData {
            available: vec![
                (ConsensusHash([0x11; 20]), BurnchainHeaderHash([0x22; 32])),
                (ConsensusHash([0x33; 20]), BurnchainHeaderHash([0x44; 32])),
            ],
        }),
    );

    let block = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::Blocks(BlocksData {
            blocks: vec![BlocksDatum(
                ConsensusHash([0x11; 20]),
                make_codec_test_block(10, StacksEpochId::Epoch25),
            )],
        }),
    );
    let microblocks = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::Microblocks(MicroblocksData {
            index_anchor_block: StacksBlockId([0x55; 32]),
            microblocks: vec![make_codec_test_microblock(10)],
        }),
    );
    let nakamoto_block = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::NakamotoBlocks(NakamotoBlocksData {
            blocks: vec![nakamoto_block],
        }),
    );
    let stackerdb_chunk = StacksMessage::new(
        1,
        1,
        1,
        &BurnchainHeaderHash([0x01; 32]),
        7,
        &BurnchainHeaderHash([0x07; 32]),
        StacksMessageType::StackerDBPushChunk(StackerDBPushChunkData {
            contract_id: QualifiedContractIdentifier::parse(
                "ST000000000000000000002AMW42H.signers-1-4",
            )
            .unwrap(),
            rc_consensus_hash: ConsensusHash([0x01; 20]),
            chunk_data: StackerDBChunkData {
                slot_id: 0,
                slot_version: 1,
                sig: MessageSignature::empty(),
                data: vec![1, 2, 3, 4, 5],
            },
        }),
    );

    for _ in 0..peer.network.connection_opts.max_buffered_blocks_available {
        assert!(peer
            .network
            .buffer_sortition_data_message(0, &peer_nk, blocks_available.clone()));
    }
    assert!(!peer
        .network
        .buffer_sortition_data_message(0, &peer_nk, blocks_available.clone()));

    for _ in 0..peer
        .network
        .connection_opts
        .max_buffered_microblocks_available
    {
        assert!(peer.network.buffer_sortition_data_message(
            0,
            &peer_nk,
            microblocks_available.clone()
        ));
    }
    assert!(!peer.network.buffer_sortition_data_message(
        0,
        &peer_nk,
        microblocks_available.clone()
    ));

    for _ in 0..peer.network.connection_opts.max_buffered_blocks {
        assert!(peer
            .network
            .buffer_sortition_data_message(0, &peer_nk, block.clone()));
    }
    assert!(!peer
        .network
        .buffer_sortition_data_message(0, &peer_nk, block.clone()));

    for _ in 0..peer.network.connection_opts.max_buffered_microblocks {
        assert!(peer
            .network
            .buffer_sortition_data_message(0, &peer_nk, microblocks.clone()));
    }
    assert!(!peer
        .network
        .buffer_sortition_data_message(0, &peer_nk, microblocks.clone()));

    for _ in 0..peer.network.connection_opts.max_buffered_nakamoto_blocks {
        assert!(peer
            .network
            .buffer_sortition_data_message(0, &peer_nk, nakamoto_block.clone()));
    }
    assert!(!peer
        .network
        .buffer_sortition_data_message(0, &peer_nk, nakamoto_block.clone()));

    for _ in 0..peer.network.connection_opts.max_buffered_stackerdb_chunks {
        assert!(peer
            .network
            .buffer_stacks_data_message(0, &peer_nk, stackerdb_chunk.clone()));
    }
    assert!(!peer
        .network
        .buffer_stacks_data_message(0, &peer_nk, stackerdb_chunk.clone()));
}

/// Verify that Nakmaoto blocks whose sortitions are known will *not* be buffered, but instead
/// forwarded to the relayer for processing.
#[test]
fn test_no_buffer_ready_nakamoto_blocks() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let (peer, mut followers) = make_nakamoto_peers_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
        1,
    );
    let peer_nk = peer.to_neighbor().addr;
    let mut follower = followers.pop().unwrap();

    let test_path = TestPeer::make_test_path(&follower.config);
    let stackerdb_path = format!("{}/stacker_db.sqlite", &test_path);
    let follower_stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();
    let mut follower_relayer = Relayer::from_p2p(&mut follower.network, follower_stacker_dbs);

    // disable the follower's ability to download blocks from the seed peer
    follower.network.connection_opts.disable_block_download = true;
    follower.config.connection_opts.disable_block_download = true;

    let (seed_comms, mut follower_comms) = SeedNode::comms();

    thread::scope(|s| {
        s.spawn(|| {
            SeedNode::main(peer, rc_len, seed_comms);
        });

        let mut seed_exited = false;
        let mut exited_peer = None;
        let (mut follower_dns_client, follower_dns_thread_handle) = dns_thread_start(100);

        while !seed_exited {
            let mut network_result = follower
                .step_with_ibd_and_dns(true, Some(&mut follower_dns_client))
                .ok();

            match follower_comms.try_recv() {
                None => {}
                Some(SeedData::BurnOps(burn_ops, consensus_hash)) => {
                    debug!("Follower got {}: {:?}", &consensus_hash, &burn_ops);
                    let (_, _, follower_consensus_hash) =
                        follower.next_burnchain_block(burn_ops.clone());
                    assert_eq!(follower_consensus_hash, consensus_hash);
                }
                Some(SeedData::Blocks(blocks)) => {
                    debug!("Follower got Nakamoto blocks {:?}", &blocks);

                    let mut sortdb = follower.sortdb.take().unwrap();
                    let mut node = follower.stacks_node.take().unwrap();

                    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

                    // no need to buffer this because we can process it right away
                    let buffer = follower
                        .network
                        .inner_handle_unsolicited_NakamotoBlocksData(
                            &sortdb,
                            &node.chainstate,
                            Some(peer_nk.clone()),
                            &NakamotoBlocksData {
                                blocks: blocks.clone(),
                            },
                        );
                    assert!(!buffer);

                    // we need these blocks, but we don't need to buffer them
                    for block in blocks.iter() {
                        assert!(!follower.network.is_nakamoto_block_bufferable(
                            &sortdb,
                            &node.chainstate,
                            block
                        ));

                        // suppose these blocks were invalid -- they would not be bufferable.
                        // bad signature? not bufferable
                        let mut bad_block = block.clone();
                        let block_sn = SortitionDB::get_block_snapshot_consensus(
                            sortdb.conn(),
                            &bad_block.header.consensus_hash,
                        )
                        .unwrap()
                        .unwrap();
                        bad_block
                            .header
                            .signer_signature
                            .push(bad_block.header.signer_signature.last().cloned().unwrap());
                        assert_eq!(
                            follower
                                .network
                                .find_nakamoto_block_reward_cycle(&sortdb, &bad_block),
                            (
                                Some(
                                    follower
                                        .network
                                        .burnchain
                                        .block_height_to_reward_cycle(block_sn.block_height)
                                        .unwrap()
                                ),
                                true
                            )
                        );
                        assert!(!follower.network.is_nakamoto_block_bufferable(
                            &sortdb,
                            &node.chainstate,
                            &bad_block
                        ));

                        // unrecognized consensus hash
                        let mut bad_block = block.clone();
                        bad_block.header.consensus_hash = ConsensusHash([0xde; 20]);
                        assert_eq!(
                            follower
                                .network
                                .find_nakamoto_block_reward_cycle(&sortdb, &bad_block),
                            (
                                Some(
                                    follower
                                        .network
                                        .burnchain
                                        .block_height_to_reward_cycle(
                                            follower.network.burnchain_tip.block_height
                                        )
                                        .unwrap()
                                ),
                                false
                            )
                        );

                        // stale consensus hash
                        let mut bad_block = block.clone();
                        let ancestor_sn = SortitionDB::get_ancestor_snapshot(
                            &sortdb.index_conn(),
                            1,
                            &tip.sortition_id,
                        )
                        .unwrap()
                        .unwrap();
                        bad_block.header.consensus_hash = ancestor_sn.consensus_hash;
                        assert_eq!(
                            follower
                                .network
                                .find_nakamoto_block_reward_cycle(&sortdb, &bad_block),
                            (
                                Some(
                                    follower
                                        .network
                                        .burnchain
                                        .block_height_to_reward_cycle(ancestor_sn.block_height)
                                        .unwrap()
                                ),
                                true
                            )
                        );
                    }

                    // go process the blocks _as if_ they came from a network result
                    let mut unsolicited = HashMap::new();
                    let msg = StacksMessage::from_chain_view(
                        follower.network.bound_neighbor_key().peer_version,
                        follower.network.bound_neighbor_key().network_id,
                        follower.network.get_chain_view(),
                        StacksMessageType::NakamotoBlocks(NakamotoBlocksData {
                            blocks: blocks.clone(),
                        }),
                    );
                    unsolicited.insert((1, peer_nk.clone()), vec![msg]);

                    if let Some(mut network_result) = network_result.take() {
                        network_result.consume_unsolicited(unsolicited);
                        let num_processed = follower_relayer.process_new_epoch3_blocks(
                            follower.network.get_local_peer(),
                            &mut network_result,
                            &follower.network.burnchain,
                            &mut sortdb,
                            &mut node.chainstate,
                            true,
                            None,
                        );

                        // because we process in order, they should all get processed
                        assert_eq!(num_processed, blocks.len() as u64);
                    }

                    // no need to buffer if we already have the block
                    let buffer = follower
                        .network
                        .inner_handle_unsolicited_NakamotoBlocksData(
                            &sortdb,
                            &node.chainstate,
                            Some(peer_nk.clone()),
                            &NakamotoBlocksData {
                                blocks: blocks.clone(),
                            },
                        );
                    assert!(!buffer);

                    // we don't need these blocks anymore
                    for block in blocks.iter() {
                        assert!(!follower.network.is_nakamoto_block_bufferable(
                            &sortdb,
                            &node.chainstate,
                            block
                        ));
                    }

                    follower.stacks_node = Some(node);
                    follower.sortdb = Some(sortdb);
                }
                Some(SeedData::Exit(exited)) => {
                    debug!("Follower got seed exit");
                    seed_exited = true;
                    exited_peer = Some(exited);
                    follower_comms.send_exit();
                }
            }

            follower.coord.handle_new_burnchain_block().unwrap();
            follower.coord.handle_new_stacks_block().unwrap();
            follower.coord.handle_new_nakamoto_stacks_block().unwrap();
        }

        // compare chain tips
        let sortdb = follower.sortdb.take().unwrap();
        let stacks_node = follower.stacks_node.take().unwrap();
        let follower_burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let follower_stacks_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap();
        follower.stacks_node = Some(stacks_node);
        follower.sortdb = Some(sortdb);

        let mut exited_peer = exited_peer.unwrap();
        let sortdb = exited_peer.sortdb.take().unwrap();
        let stacks_node = exited_peer.stacks_node.take().unwrap();
        let exited_peer_burn_tip =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let exited_peer_stacks_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap();
        exited_peer.stacks_node = Some(stacks_node);
        exited_peer.sortdb = Some(sortdb);

        assert_eq!(exited_peer_burn_tip, follower_burn_tip);
        assert_eq!(exited_peer_stacks_tip, follower_stacks_tip);
    });
}

/// Verify that Nakamoto blocks whose sortitions are not yet known will be buffered, and sent to
/// the relayer once the burnchain advances.
#[test]
fn test_buffer_nonready_nakamoto_blocks() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let (peer, mut followers) = make_nakamoto_peers_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
        1,
    );
    let peer_nk = peer.to_neighbor().addr;
    let mut follower = followers.pop().unwrap();

    let test_path = TestPeer::make_test_path(&follower.config);
    let stackerdb_path = format!("{}/stacker_db.sqlite", &test_path);
    let follower_stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();
    let mut follower_relayer = Relayer::from_p2p(&mut follower.network, follower_stacker_dbs);

    // disable the follower's ability to download blocks from the seed peer
    follower.network.connection_opts.disable_block_download = true;
    follower.config.connection_opts.disable_block_download = true;

    // don't authenticate unsolicited messages, since this test directly pushes them
    follower
        .network
        .connection_opts
        .test_disable_unsolicited_message_authentication = true;
    follower
        .config
        .connection_opts
        .test_disable_unsolicited_message_authentication = true;

    let (seed_comms, mut follower_comms) = SeedNode::comms();

    let mut buffered_burn_ops = VecDeque::new();
    let mut all_blocks = vec![];

    thread::scope(|s| {
        thread::Builder::new()
            .name("seed".into())
            .spawn_scoped(s, || {
                SeedNode::main(peer, rc_len, seed_comms);
            })
            .unwrap();

        let mut seed_exited = false;
        let mut exited_peer = None;
        let (mut follower_dns_client, follower_dns_thread_handle) = dns_thread_start(100);

        while !seed_exited {
            let mut network_result = follower
                .step_with_ibd_and_dns(true, Some(&mut follower_dns_client))
                .ok();

            match follower_comms.try_recv() {
                None => {}
                Some(SeedData::BurnOps(burn_ops, consensus_hash)) => {
                    debug!(
                        "Follower got and will buffer {}: {:?}",
                        &consensus_hash, &burn_ops
                    );
                    buffered_burn_ops.push_back((burn_ops, consensus_hash));
                    if buffered_burn_ops.len() > 1 {
                        let (buffered_burn_ops, buffered_consensus_hash) =
                            buffered_burn_ops.pop_front().unwrap();
                        debug!(
                            "Follower will process {}: {:?}",
                            &buffered_consensus_hash, &buffered_burn_ops
                        );
                        let (_, _, follower_consensus_hash) =
                            follower.next_burnchain_block(buffered_burn_ops.clone());
                        assert_eq!(follower_consensus_hash, buffered_consensus_hash);
                    }
                }
                Some(SeedData::Blocks(blocks)) => {
                    debug!("Follower got Nakamoto blocks {:?}", &blocks);
                    all_blocks.push(blocks.clone());

                    let sortdb = follower.sortdb.take().unwrap();
                    let node = follower.stacks_node.take().unwrap();

                    // we will need to buffer this since the sortition for these blocks hasn't been
                    // processed yet
                    let buffer = follower
                        .network
                        .inner_handle_unsolicited_NakamotoBlocksData(
                            &sortdb,
                            &node.chainstate,
                            Some(peer_nk.clone()),
                            &NakamotoBlocksData {
                                blocks: blocks.clone(),
                            },
                        );
                    assert!(buffer);

                    // we need these blocks, but we can't process them yet
                    for block in blocks.iter() {
                        assert!(follower.network.is_nakamoto_block_bufferable(
                            &sortdb,
                            &node.chainstate,
                            block
                        ));
                    }

                    // pass this and other blocks to the p2p network's unsolicited message handler,
                    // so they can be buffered up and processed.
                    let mut unsolicited_msgs: HashMap<(usize, NeighborKey), Vec<StacksMessage>> =
                        HashMap::new();
                    for (event_id, convo) in follower.network.peers.iter() {
                        for blks in all_blocks.iter() {
                            let msg = StacksMessage::from_chain_view(
                                follower.network.bound_neighbor_key().peer_version,
                                follower.network.bound_neighbor_key().network_id,
                                follower.network.get_chain_view(),
                                StacksMessageType::NakamotoBlocks(NakamotoBlocksData {
                                    blocks: blks.clone(),
                                }),
                            );
                            let nk = convo.to_neighbor_key();
                            if let Some(msgs) = unsolicited_msgs.get_mut(&(*event_id, nk)) {
                                msgs.push(msg);
                            } else {
                                unsolicited_msgs
                                    .insert((*event_id, convo.to_neighbor_key()), vec![msg]);
                            }
                        }
                    }

                    follower.network.handle_unsolicited_sortition_messages(
                        &sortdb,
                        &node.chainstate,
                        unsolicited_msgs,
                        true,
                        true,
                    );

                    follower.stacks_node = Some(node);
                    follower.sortdb = Some(sortdb);
                }
                Some(SeedData::Exit(exited)) => {
                    debug!("Follower got seed exit");

                    // process the last burnchain sortitions
                    while let Some((buffered_burn_ops, buffered_consensus_hash)) =
                        buffered_burn_ops.pop_front()
                    {
                        debug!(
                            "Follower will process {}: {:?}",
                            &buffered_consensus_hash, &buffered_burn_ops
                        );
                        let (_, _, follower_consensus_hash) =
                            follower.next_burnchain_block(buffered_burn_ops.clone());
                        assert_eq!(follower_consensus_hash, buffered_consensus_hash);
                    }

                    // process the last buffered messages
                    let mut sortdb = follower.sortdb.take().unwrap();
                    let mut node = follower.stacks_node.take().unwrap();

                    if let Some(mut network_result) = network_result.take() {
                        follower_relayer.process_new_epoch3_blocks(
                            follower.network.get_local_peer(),
                            &mut network_result,
                            &follower.network.burnchain,
                            &mut sortdb,
                            &mut node.chainstate,
                            true,
                            None,
                        );
                    }

                    follower.stacks_node = Some(node);
                    follower.sortdb = Some(sortdb);

                    network_result = follower
                        .step_with_ibd_and_dns(true, Some(&mut follower_dns_client))
                        .ok();

                    seed_exited = true;
                    exited_peer = Some(exited);
                    follower_comms.send_exit();
                }
            }

            if let Some(mut network_result) = network_result.take() {
                let mut sortdb = follower.sortdb.take().unwrap();
                let mut node = follower.stacks_node.take().unwrap();
                let num_processed = follower_relayer.process_new_epoch3_blocks(
                    follower.network.get_local_peer(),
                    &mut network_result,
                    &follower.network.burnchain,
                    &mut sortdb,
                    &mut node.chainstate,
                    true,
                    None,
                );
                info!("Processed {} unsolicited Nakamoto blocks", num_processed);
                follower.stacks_node = Some(node);
                follower.sortdb = Some(sortdb);
            }

            follower.coord.handle_new_burnchain_block().unwrap();
            follower.coord.handle_new_stacks_block().unwrap();
            follower.coord.handle_new_nakamoto_stacks_block().unwrap();
        }

        // compare chain tips
        let sortdb = follower.sortdb.take().unwrap();
        let stacks_node = follower.stacks_node.take().unwrap();
        let follower_burn_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let follower_stacks_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap();
        follower.stacks_node = Some(stacks_node);
        follower.sortdb = Some(sortdb);

        let mut exited_peer = exited_peer.unwrap();
        let sortdb = exited_peer.sortdb.take().unwrap();
        let stacks_node = exited_peer.stacks_node.take().unwrap();
        let exited_peer_burn_tip =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let exited_peer_stacks_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap();
        exited_peer.stacks_node = Some(stacks_node);
        exited_peer.sortdb = Some(sortdb);

        assert_eq!(
            exited_peer_burn_tip.sortition_id,
            follower_burn_tip.sortition_id
        );
        assert_eq!(exited_peer_stacks_tip, follower_stacks_tip);
    });
}

/// Boot a follower off of a seed node by having the seed node push its blocks to the follower via
/// the p2p stack.  The follower will buffer up Nakamoto blocks and forward them to its relayer as
/// needed.
#[test]
fn test_nakamoto_boot_node_from_block_push() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let (peer, mut followers) = make_nakamoto_peers_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
        1,
    );
    let peer_nk = peer.to_neighbor().addr;
    let mut follower = followers.pop().unwrap();

    let test_path = TestPeer::make_test_path(&follower.config);
    let stackerdb_path = format!("{}/stacker_db.sqlite", &test_path);
    let follower_stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();

    // disable the follower's ability to download blocks from the seed peer
    follower.network.connection_opts.disable_block_download = true;
    follower.config.connection_opts.disable_block_download = true;

    let (seed_comms, mut follower_comms) = SeedNode::comms();

    thread::scope(|s| {
        s.spawn(|| {
            SeedNode::main(peer, rc_len, seed_comms);
        });

        let mut seed_exited = false;
        let mut exited_peer = None;
        let (mut follower_dns_client, follower_dns_thread_handle) = dns_thread_start(100);

        while !seed_exited {
            // follower will forward pushed data to its relayer
            loop {
                let network_result_res =
                    follower.run_with_ibd(true, Some(&mut follower_dns_client));
                if let Ok((network_result, _)) = network_result_res {
                    if network_result.num_connected_peers > 0 {
                        break;
                    }
                }
            }

            match follower_comms.try_recv() {
                None => {}
                Some(SeedData::BurnOps(burn_ops, consensus_hash)) => {
                    debug!("Follower will process {}: {:?}", &consensus_hash, &burn_ops);
                    let (_, _, follower_ch) = follower.next_burnchain_block(burn_ops.clone());
                    assert_eq!(follower_ch, consensus_hash);
                }
                Some(SeedData::Blocks(blocks)) => {
                    debug!("Follower got Nakamoto blocks {:?}", &blocks);
                }
                Some(SeedData::Exit(exited)) => {
                    debug!("Follower got seed exit");

                    seed_exited = true;
                    exited_peer = Some(exited);
                    follower_comms.send_exit();
                }
            }

            follower.coord.handle_new_burnchain_block().unwrap();
            follower.coord.handle_new_stacks_block().unwrap();
            follower.coord.handle_new_nakamoto_stacks_block().unwrap();
        }

        // recover exited peer and get its chain tips
        let mut exited_peer = exited_peer.unwrap();
        let sortdb = exited_peer.sortdb.take().unwrap();
        let stacks_node = exited_peer.stacks_node.take().unwrap();
        let exited_peer_burn_tip =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let exited_peer_stacks_tip =
            NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
                .unwrap();
        exited_peer.stacks_node = Some(stacks_node);
        exited_peer.sortdb = Some(sortdb);

        let mut synced = false;
        for i in 0..100 {
            // let the follower catch up to and keep talking to the exited peer
            exited_peer.run_with_ibd(false, None).unwrap();
            follower
                .run_with_ibd(true, Some(&mut follower_dns_client))
                .unwrap();

            // compare chain tips
            let sortdb = follower.sortdb.take().unwrap();
            let stacks_node = follower.stacks_node.take().unwrap();
            let follower_burn_tip =
                SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let follower_stacks_tip = NakamotoChainState::get_canonical_block_header(
                stacks_node.chainstate.db(),
                &sortdb,
            )
            .unwrap();
            follower.stacks_node = Some(stacks_node);
            follower.sortdb = Some(sortdb);

            debug!("{}: Follower sortition tip: {:?}", i, &follower_burn_tip);
            debug!("{}: Seed sortition tip: {:?}", i, &exited_peer_burn_tip);
            debug!("{}: Follower stacks tip: {:?}", i, &follower_stacks_tip);
            debug!("{}: Seed stacks tip: {:?}", i, &exited_peer_stacks_tip);

            if exited_peer_burn_tip.consensus_hash == follower_burn_tip.consensus_hash
                && exited_peer_stacks_tip == follower_stacks_tip
            {
                synced = true;
                break;
            }
        }

        assert!(synced);
    });
}
