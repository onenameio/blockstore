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

use std::net::SocketAddr;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{QualifiedContractIdentifier, StacksAddressExtensions};
use libstackerdb::SlotMetadata;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    StacksPrivateKey, StacksPublicKey,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use stacks_common::util::pipe::Pipe;

use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::miner::{BlockBuilderSettings, StacksMicroblockBuilder};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksBlockBuilder, StacksBlockHeader, StacksMicroblock,
    StacksTransaction, StacksTransactionSigner, TokenTransferMemo, TransactionAnchorMode,
    TransactionAuth, TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use crate::core::MemPoolDB;
use crate::net::api::{prefix_hex, prefix_opt_hex};
use crate::net::db::PeerDB;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::relay::Relayer;
use crate::net::rpc::ConversationHttp;
use crate::net::test::{TestEventObserver, TestPeer, TestPeerConfig};
use crate::net::tests::inv::nakamoto::make_nakamoto_peers_from_invs_ext;
use crate::net::{
    Attachment, AttachmentInstance, MemPoolEventDispatcher, RPCHandlerArgs, StackerDBConfig,
    StacksNodeState, UrlString,
};

mod callreadonly;
mod get_tenures_fork_info;
mod getaccount;
mod getattachment;
mod getattachmentsinv;
mod getblock;
mod getblock_v3;
mod getblockbyheight;
mod getclaritymarfvalue;
mod getclaritymetadata;
mod getconstantval;
mod getcontractabi;
mod getcontractsrc;
mod getdatavar;
mod getheaders;
mod getinfo;
mod getistraitimplemented;
mod getmapentry;
mod getmicroblocks_confirmed;
mod getmicroblocks_indexed;
mod getmicroblocks_unconfirmed;
mod getneighbors;
mod getpoxinfo;
mod getsigner;
mod getsortition;
mod getstackerdbchunk;
mod getstackerdbmetadata;
mod getstxtransfercost;
mod gettenure;
mod gettenureinfo;
mod gettenuretip;
mod gettransaction_unconfirmed;
mod liststackerdbreplicas;
mod postblock;
mod postblock_proposal;
mod postblock_v3;
mod postfeerate;
mod postmempoolquery;
mod postmicroblock;
mod poststackerdbchunk;
mod posttransaction;

const TEST_CONTRACT: &str = "
    (define-trait test-trait
        (
            (do-test () (response uint uint))
        )
    )
    (define-trait test-trait-2
        (
            (do-test-2 () (response uint uint))
        )
    )

    (define-constant cst 123)
    (define-data-var bar int 0)
    (define-map unit-map { account: principal } { units: int })
    (define-map test-map uint uint)
    (map-set test-map u1 u2)
    (define-public (get-bar) (ok (var-get bar)))
    (define-public (set-bar (x int) (y int))
      (begin (var-set bar (/ x y)) (ok (var-get bar))))
    (define-public (add-unit)
      (begin
        (map-set unit-map { account: tx-sender } { units: 1 } )
        (var-set bar 1)
        (ok 1)))
    (begin
      (map-set unit-map { account: 'ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R } { units: 123 }))

    (define-read-only (ro-confirmed) u1)

    (define-public (do-test) (ok u0))

    ;; stacker DB
    (define-read-only (stackerdb-get-signer-slots)
        (ok (list
          {
            signer: 'ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R,
            num-slots: u3
          }
          {
            signer: 'STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW,
            num-slots: u3
          })))

    (define-read-only (stackerdb-get-config)
        (ok {
            chunk-size: u4096,
            write-freq: u0,
            max-writes: u4096,
            max-neighbors: u32,
            hint-replicas: (list )
        }))
";

const TEST_CONTRACT_UNCONFIRMED: &str = "
(define-read-only (ro-test) (ok 1))
(define-constant cst-unconfirmed 456)
(define-data-var bar-unconfirmed uint u1)
(define-map test-map-unconfirmed int int)
(map-set test-map-unconfirmed 3 4)
(define-public (do-test) (ok u1))
";

/// This helper function drives I/O between a sender and receiver Http conversation.
fn convo_send_recv(sender: &mut ConversationHttp, receiver: &mut ConversationHttp) {
    let (mut pipe_read, mut pipe_write) = Pipe::new();
    pipe_read.set_nonblocking(true);

    loop {
        sender.try_flush().unwrap();
        receiver.try_flush().unwrap();

        pipe_write.try_flush().unwrap();

        let all_relays_flushed =
            receiver.num_pending_outbound() == 0 && sender.num_pending_outbound() == 0;

        let nw = sender.send(&mut pipe_write).unwrap();
        let nr = receiver.recv(&mut pipe_read).unwrap();

        debug!(
            "test_rpc: all_relays_flushed = {} ({},{}), nr = {}, nw = {}",
            all_relays_flushed,
            receiver.num_pending_outbound(),
            sender.num_pending_outbound(),
            nr,
            nw
        );
        if all_relays_flushed && nr == 0 && nw == 0 {
            debug!("test_rpc: Breaking send_recv");
            break;
        }
    }
}

/// TestRPC state
pub struct TestRPC<'a> {
    pub privk1: StacksPrivateKey,
    pub privk2: StacksPrivateKey,
    pub peer_1: TestPeer<'a>,
    pub peer_2: TestPeer<'a>,
    pub peer_1_indexer: BitcoinIndexer,
    pub peer_2_indexer: BitcoinIndexer,
    pub convo_1: ConversationHttp,
    pub convo_2: ConversationHttp,
    /// hash of the chain tip
    pub canonical_tip: StacksBlockId,
    /// block header hash of the chain tip
    pub tip_hash: BlockHeaderHash,
    /// block height of the chain tip
    pub tip_height: u64,
    /// consensus hash of the chain tip
    pub consensus_hash: ConsensusHash,
    /// hash of last microblock
    pub microblock_tip_hash: BlockHeaderHash,
    /// list of mempool transactions
    pub mempool_txids: Vec<Txid>,
    /// list of microblock transactions
    pub microblock_txids: Vec<Txid>,
    /// next block to post, and its consensus hash
    pub next_block: Option<(ConsensusHash, StacksBlock)>,
    /// next microblock to post (may already be posted)
    pub next_microblock: Option<StacksMicroblock>,
    /// transactions that can be posted to the mempool
    pub sendable_txs: Vec<StacksTransaction>,
    /// whether or not to maintain unconfirmed microblocks (e.g. this is false for nakamoto)
    pub unconfirmed_state: bool,
}

impl<'a> TestRPC<'a> {
    pub fn setup(test_name: &str) -> TestRPC<'a> {
        Self::setup_ex(test_name, true)
    }

    pub fn setup_ex(test_name: &str, process_microblock: bool) -> TestRPC<'a> {
        // ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R
        let privk1 = StacksPrivateKey::from_hex(
            "9f1f85a512a96a244e4c0d762788500687feb97481639572e3bffbd6860e6ab001",
        )
        .unwrap();

        // STVN97YYA10MY5F6KQJHKNYJNM24C4A1AT39WRW
        let privk2 = StacksPrivateKey::from_hex(
            "94c319327cc5cd04da7147d32d836eb2e4c44f4db39aa5ede7314a761183d0c701",
        )
        .unwrap();
        let microblock_privkey = StacksPrivateKey::new();
        let microblock_pubkeyhash =
            Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));

        let addr1 = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk1)],
        )
        .unwrap();
        let addr2 = StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(&privk2)],
        )
        .unwrap();

        let mut peer_1_config = TestPeerConfig::new(&format!("{}-peer1", test_name), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(&format!("{}-peer2", test_name), 0, 0);

        peer_1_config.private_key = privk1.clone();
        peer_2_config.private_key = privk2.clone();

        peer_1_config.connection_opts.read_only_call_limit = ExecutionCost {
            write_length: 0,
            write_count: 0,
            read_length: 2000,
            read_count: 3,
            runtime: 2000000,
        };
        peer_1_config.connection_opts.maximum_call_argument_size = 4096;
        peer_1_config.connection_opts.auth_token = Some("password".to_string());

        peer_2_config.connection_opts.read_only_call_limit = ExecutionCost {
            write_length: 0,
            write_count: 0,
            read_length: 2000,
            read_count: 3,
            runtime: 2000000,
        };
        peer_2_config.connection_opts.maximum_call_argument_size = 4096;
        peer_2_config.connection_opts.auth_token = Some("password".to_string());

        // stacker DBs get initialized thru reconfiguration when the above block gets processed
        peer_1_config.add_stacker_db(
            QualifiedContractIdentifier::new(addr1.clone().into(), "hello-world".into()),
            StackerDBConfig::noop(),
        );
        peer_2_config.add_stacker_db(
            QualifiedContractIdentifier::new(addr1.clone().into(), "hello-world".into()),
            StackerDBConfig::noop(),
        );

        let peer_1_indexer = BitcoinIndexer::new_unit_test(&peer_1_config.burnchain.working_dir);
        let peer_2_indexer = BitcoinIndexer::new_unit_test(&peer_2_config.burnchain.working_dir);

        peer_1_config.initial_balances = vec![
            (addr1.to_account_principal(), 1000000000),
            (addr2.to_account_principal(), 1000000000),
        ];

        peer_2_config.initial_balances = vec![
            (addr1.to_account_principal(), 1000000000),
            (addr2.to_account_principal(), 1000000000),
        ];

        peer_1_config.add_neighbor(&peer_2_config.to_neighbor());
        peer_2_config.add_neighbor(&peer_1_config.to_neighbor());

        let burnchain = peer_1_config.burnchain.clone();

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // mine one block with a contract in it
        // first the coinbase
        // make a coinbase for this miner
        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32]), None, None),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();

        // next the contract
        let contract = TEST_CONTRACT;
        let mut tx_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_smart_contract("hello-world", contract, None).unwrap(),
        );

        tx_contract.chain_id = 0x80000000;
        tx_contract.auth.set_origin_nonce(1);
        tx_contract.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_contract);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_contract_signed = tx_signer.get_tx().unwrap();

        // update account and state in a microblock that will be unconfirmed
        let mut tx_cc = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_contract_call(addr1.clone(), "hello-world", "add-unit", vec![])
                .unwrap(),
        );

        tx_cc.chain_id = 0x80000000;
        tx_cc.auth.set_origin_nonce(2);
        tx_cc.set_tx_fee(123);

        let mut tx_signer = StacksTransactionSigner::new(&tx_cc);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_cc_signed = tx_signer.get_tx().unwrap();
        let tx_cc_len = {
            let mut bytes = vec![];
            tx_cc_signed.consensus_serialize(&mut bytes).unwrap();
            bytes.len() as u64
        };

        // make an unconfirmed contract
        let unconfirmed_contract = TEST_CONTRACT_UNCONFIRMED;
        let mut tx_unconfirmed_contract = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::new_smart_contract(
                "hello-world-unconfirmed",
                &unconfirmed_contract.to_string(),
                None,
            )
            .unwrap(),
        );

        tx_unconfirmed_contract.chain_id = 0x80000000;
        tx_unconfirmed_contract.auth.set_origin_nonce(3);
        tx_unconfirmed_contract.set_tx_fee(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx_unconfirmed_contract);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_unconfirmed_contract_signed = tx_signer.get_tx().unwrap();
        let tx_unconfirmed_contract_len = {
            let mut bytes = vec![];
            tx_unconfirmed_contract_signed
                .consensus_serialize(&mut bytes)
                .unwrap();
            bytes.len() as u64
        };

        // force peer 2 to know about peer 1
        {
            let tx = peer_2.network.peerdb.tx_begin().unwrap();
            let mut neighbor = peer_1.config.to_neighbor();
            neighbor.last_contact_time = get_epoch_time_secs();
            PeerDB::try_insert_peer(
                &tx,
                &neighbor,
                &[QualifiedContractIdentifier::new(
                    addr1.clone().into(),
                    "hello-world".into(),
                )],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        // force peer 1 to know about peer 2
        {
            let tx = peer_1.network.peerdb.tx_begin().unwrap();
            let mut neighbor = peer_2.config.to_neighbor();
            neighbor.last_contact_time = get_epoch_time_secs();
            PeerDB::try_insert_peer(&tx, &neighbor, &[]).unwrap();
            tx.commit().unwrap();
        }

        let tip =
            SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
                .unwrap();
        let mut anchor_cost = ExecutionCost::ZERO;
        let mut anchor_size = 0;

        // make a block
        // Put the coinbase and smart-contract in the anchored block.
        // Put the contract-call in the microblock
        let (burn_ops, stacks_block, microblocks) = peer_1.make_tenure(
            |ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, _| {
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

                let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                    &burnchain,
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    microblock_pubkeyhash,
                )
                .unwrap();
                let (anchored_block, anchored_block_size, anchored_block_cost) =
                    StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![tx_coinbase_signed.clone(), tx_contract_signed.clone()],
                    )
                    .unwrap();

                anchor_size = anchored_block_size;
                anchor_cost = anchored_block_cost;

                (anchored_block, vec![])
            },
        );

        let (_, _, consensus_hash) = peer_1.next_burnchain_block(burn_ops.clone());
        peer_2.next_burnchain_block(burn_ops.clone());

        peer_1.process_stacks_epoch_at_tip(&stacks_block, &[]);
        peer_2.process_stacks_epoch_at_tip(&stacks_block, &[]);

        // build 1-block microblock stream with the contract-call and the unconfirmed contract
        let microblock = {
            let sortdb = peer_1.sortdb.take().unwrap();
            Relayer::setup_unconfirmed_state(peer_1.chainstate(), &sortdb).unwrap();
            let mblock = {
                let sort_iconn = sortdb.index_handle_at_tip();
                let mut microblock_builder = StacksMicroblockBuilder::new(
                    stacks_block.block_hash(),
                    consensus_hash.clone(),
                    peer_1.chainstate(),
                    &sort_iconn,
                    BlockBuilderSettings::max_value(),
                )
                .unwrap();
                let microblock = microblock_builder
                    .mine_next_microblock_from_txs(
                        vec![
                            (tx_cc_signed, tx_cc_len),
                            (tx_unconfirmed_contract_signed, tx_unconfirmed_contract_len),
                        ],
                        &microblock_privkey,
                    )
                    .unwrap();
                microblock
            };
            peer_1.sortdb = Some(sortdb);
            mblock
        };

        let microblock_txids = microblock.txs.iter().map(|tx| tx.txid()).collect();
        let canonical_tip =
            StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
        let tip_hash = stacks_block.block_hash();

        if process_microblock {
            // store microblock stream
            peer_1
                .chainstate()
                .preprocess_streamed_microblock(
                    &consensus_hash,
                    &stacks_block.block_hash(),
                    &microblock,
                )
                .unwrap();
            peer_2
                .chainstate()
                .preprocess_streamed_microblock(
                    &consensus_hash,
                    &stacks_block.block_hash(),
                    &microblock,
                )
                .unwrap();

            // process microblock stream to generate unconfirmed state
            let sortdb1 = peer_1.sortdb.take().unwrap();
            let sortdb2 = peer_2.sortdb.take().unwrap();
            peer_1
                .chainstate()
                .reload_unconfirmed_state(&sortdb1.index_handle_at_tip(), canonical_tip.clone())
                .unwrap();
            peer_2
                .chainstate()
                .reload_unconfirmed_state(&sortdb2.index_handle_at_tip(), canonical_tip.clone())
                .unwrap();
            peer_1.sortdb = Some(sortdb1);
            peer_2.sortdb = Some(sortdb2);
        }

        let mut mempool_txids = vec![];

        // stuff some transactions into peer_2's mempool
        // (relates to mempool query tests)
        // Also, create some transactions that could be sent
        let mut mempool = peer_2.mempool.take().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();
        let mut sendable_txs = vec![];
        for i in 0..20 {
            let pk = StacksPrivateKey::new();
            let addr = StacksAddress::from_public_keys(
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
                &AddressHashMode::SerializeP2PKH,
                1,
                &vec![StacksPublicKey::from_private(&pk)],
            )
            .unwrap();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&privk2).unwrap(),
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
            tx.set_origin_nonce(i);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk2).unwrap();
            let tx = tx_signer.get_tx().unwrap();

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            if i < 10 {
                // should succeed
                MemPoolDB::try_add_tx(
                    &mut mempool_tx,
                    peer_1.chainstate(),
                    &consensus_hash,
                    &stacks_block.block_hash(),
                    true,
                    txid.clone(),
                    tx_bytes,
                    tx_fee,
                    stacks_block.header.total_work.work,
                    &origin_addr,
                    origin_nonce,
                    &sponsor_addr,
                    sponsor_nonce,
                    None,
                )
                .unwrap();

                mempool_txids.push(txid);
            } else {
                sendable_txs.push(tx);
            }
        }
        mempool_tx.commit().unwrap();
        peer_2.mempool.replace(mempool);

        let peer_1_sortdb = peer_1.sortdb.take().unwrap();
        let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();
        let _ = peer_1
            .network
            .refresh_burnchain_view(
                &peer_1_indexer,
                &peer_1_sortdb,
                &mut peer_1_stacks_node.chainstate,
                false,
            )
            .unwrap();
        peer_1.sortdb = Some(peer_1_sortdb);
        peer_1.stacks_node = Some(peer_1_stacks_node);

        let peer_2_sortdb = peer_2.sortdb.take().unwrap();
        let mut peer_2_stacks_node = peer_2.stacks_node.take().unwrap();
        let _ = peer_2
            .network
            .refresh_burnchain_view(
                &peer_2_indexer,
                &peer_2_sortdb,
                &mut peer_2_stacks_node.chainstate,
                false,
            )
            .unwrap();
        peer_2.sortdb = Some(peer_2_sortdb);
        peer_2.stacks_node = Some(peer_2_stacks_node);

        // insert some fake Atlas attachment data
        let attachment = Attachment {
            content: vec![0, 1, 2, 3, 4],
        };

        let attachment_instance = AttachmentInstance {
            content_hash: attachment.hash(),
            attachment_index: 123,
            stacks_block_height: 1,
            index_block_hash: canonical_tip.clone(),
            metadata: "000102030405".to_string(),
            contract_id: QualifiedContractIdentifier::parse("ST000000000000000000002AMW42H.bns")
                .unwrap(),
            tx_id: Txid([0x22; 32]),
            canonical_stacks_tip_height: Some(1),
        };

        peer_1
            .network
            .get_atlasdb_mut()
            .insert_initial_attachment_instance(&attachment_instance)
            .unwrap();
        peer_2
            .network
            .get_atlasdb_mut()
            .insert_initial_attachment_instance(&attachment_instance)
            .unwrap();

        peer_1
            .network
            .get_atlasdb_mut()
            .insert_instantiated_attachment(&attachment)
            .unwrap();
        peer_2
            .network
            .get_atlasdb_mut()
            .insert_instantiated_attachment(&attachment)
            .unwrap();

        // next tip, coinbase
        let tip =
            SortitionDB::get_canonical_burn_chain_tip(&peer_1.sortdb.as_ref().unwrap().conn())
                .unwrap();

        let mut tx_coinbase = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&privk1).unwrap(),
            TransactionPayload::Coinbase(CoinbasePayload([0x00; 32]), None, None),
        );
        tx_coinbase.chain_id = 0x80000000;
        tx_coinbase.anchor_mode = TransactionAnchorMode::OnChainOnly;
        tx_coinbase.auth.set_origin_nonce(4);

        let mut tx_signer = StacksTransactionSigner::new(&tx_coinbase);
        tx_signer.sign_origin(&privk1).unwrap();
        let tx_coinbase_signed = tx_signer.get_tx().unwrap();

        // make another block for the test framework to POST
        let (next_burn_ops, next_stacks_block, _) = peer_1.make_tenure(
            |ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, _| {
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

                let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                    &burnchain,
                    &parent_tip,
                    vrf_proof,
                    tip.total_burn,
                    microblock_pubkeyhash,
                )
                .unwrap();
                let (anchored_block, anchored_block_size, anchored_block_cost) =
                    StacksBlockBuilder::make_anchored_block_from_txs(
                        block_builder,
                        chainstate,
                        &sortdb.index_handle_at_tip(),
                        vec![tx_coinbase_signed.clone()],
                    )
                    .unwrap();

                anchor_size = anchored_block_size;
                anchor_cost = anchored_block_cost;

                (anchored_block, vec![])
            },
        );

        let (_, _, next_consensus_hash) = peer_1.next_burnchain_block(next_burn_ops.clone());
        peer_2.next_burnchain_block(next_burn_ops.clone());

        let view_1 = peer_1.get_burnchain_view().unwrap();
        let view_2 = peer_2.get_burnchain_view().unwrap();

        // extract ports allocated to us
        let peer_1_http = peer_1.config.http_port;
        let peer_2_http = peer_2.config.http_port;

        debug!("test_rpc: Peer 1 HTTP port: {}", &peer_1_http);
        debug!("test_rpc: Peer 2 HTTP port: {}", &peer_2_http);

        // store a chunk in the peers' stackerdb
        let data = "hello world".as_bytes();
        let data_hash = Sha512Trunc256Sum::from_data(data);
        let mut slot_metadata = SlotMetadata::new_unsigned(0, 1, data_hash);
        slot_metadata.sign(&privk1).unwrap();

        for peer_server in [&mut peer_1, &mut peer_2] {
            let contract_id = QualifiedContractIdentifier::parse(
                "ST2DS4MSWSGJ3W9FBC6BVT0Y92S345HY8N3T6AV7R.hello-world",
            )
            .unwrap();
            let tx = peer_server
                .network
                .stackerdbs
                .tx_begin(StackerDBConfig::noop())
                .unwrap();
            tx.try_replace_chunk(&contract_id, &slot_metadata, "hello world".as_bytes())
                .unwrap();
            tx.commit().unwrap();
        }

        let convo_1 = ConversationHttp::new(
            format!("127.0.0.1:{}", peer_1_http)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from("http://peer1.com".to_string()).unwrap()),
            peer_1.to_peer_host(),
            &peer_1.config.connection_opts,
            0,
            32,
        );

        let convo_2 = ConversationHttp::new(
            format!("127.0.0.1:{}", peer_2_http)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from("http://peer2.com".to_string()).unwrap()),
            peer_2.to_peer_host(),
            &peer_2.config.connection_opts,
            1,
            32,
        );

        let tip_height: u64 = 1;

        TestRPC {
            privk1,
            privk2,
            peer_1,
            peer_2,
            peer_1_indexer,
            peer_2_indexer,
            convo_1,
            convo_2,
            canonical_tip,
            tip_hash,
            tip_height,
            consensus_hash,
            microblock_tip_hash: microblock.block_hash(),
            mempool_txids,
            microblock_txids,
            next_block: Some((next_consensus_hash, next_stacks_block)),
            next_microblock: Some(microblock),
            sendable_txs,
            unconfirmed_state: true,
        }
    }

    /// Set up the peers as Nakamoto nodes
    pub fn setup_nakamoto(test_name: &str, observer: &'a TestEventObserver) -> TestRPC<'a> {
        let bitvecs = vec![vec![
            true, true, true, true, true, true, true, true, true, true,
        ]];

        let (mut peer, mut other_peers) = make_nakamoto_peers_from_invs_ext(
            function_name!(),
            observer,
            bitvecs.clone(),
            |boot_plan| {
                boot_plan
                    .with_pox_constants(10, 3)
                    .with_extra_peers(1)
                    .with_initial_balances(vec![])
                    .with_malleablized_blocks(false)
            },
        );
        let mut other_peer = other_peers.pop().unwrap();

        let peer_1_indexer = BitcoinIndexer::new_unit_test(&peer.config.burnchain.working_dir);
        let peer_2_indexer =
            BitcoinIndexer::new_unit_test(&other_peer.config.burnchain.working_dir);

        let convo_1 = ConversationHttp::new(
            format!("127.0.0.1:{}", peer.config.http_port)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from("http://peer1.com".to_string()).unwrap()),
            peer.to_peer_host(),
            &peer.config.connection_opts,
            0,
            32,
        );

        let convo_2 = ConversationHttp::new(
            format!("127.0.0.1:{}", other_peer.config.http_port)
                .parse::<SocketAddr>()
                .unwrap(),
            Some(UrlString::try_from("http://peer2.com".to_string()).unwrap()),
            other_peer.to_peer_host(),
            &other_peer.config.connection_opts,
            1,
            32,
        );

        let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
        let nakamoto_tip = {
            let sortdb = peer.sortdb.take().unwrap();
            let tip =
                NakamotoChainState::get_canonical_block_header(peer.chainstate().db(), &sortdb)
                    .unwrap()
                    .unwrap();
            peer.sortdb = Some(sortdb);
            tip
        };

        // sanity check
        let other_tip =
            SortitionDB::get_canonical_burn_chain_tip(other_peer.sortdb().conn()).unwrap();
        let other_nakamoto_tip = {
            let sortdb = other_peer.sortdb.take().unwrap();
            let tip = NakamotoChainState::get_canonical_block_header(
                other_peer.chainstate().db(),
                &sortdb,
            )
            .unwrap()
            .unwrap();
            other_peer.sortdb = Some(sortdb);
            tip
        };

        assert_eq!(tip, other_tip);
        assert_eq!(nakamoto_tip, other_nakamoto_tip);

        TestRPC {
            privk1: peer.config.private_key.clone(),
            privk2: other_peer.config.private_key.clone(),
            peer_1: peer,
            peer_2: other_peer,
            peer_1_indexer,
            peer_2_indexer,
            convo_1,
            convo_2,
            canonical_tip: nakamoto_tip.index_block_hash(),
            consensus_hash: nakamoto_tip.consensus_hash.clone(),
            tip_hash: nakamoto_tip.anchored_header.block_hash(),
            tip_height: nakamoto_tip.stacks_block_height,
            microblock_tip_hash: BlockHeaderHash([0x00; 32]),
            mempool_txids: vec![],
            microblock_txids: vec![],
            next_block: None,
            next_microblock: None,
            sendable_txs: vec![],
            unconfirmed_state: false,
        }
    }

    pub fn run(self, requests: Vec<StacksHttpRequest>) -> Vec<StacksHttpResponse> {
        self.run_with_observer(requests, None)
    }

    /// Run zero or more HTTP requests on this setup RPC test harness.
    /// Return the list of responses.
    pub fn run_with_observer(
        self,
        requests: Vec<StacksHttpRequest>,
        event_observer: Option<&dyn MemPoolEventDispatcher>,
    ) -> Vec<StacksHttpResponse> {
        let mut peer_1 = self.peer_1;
        let mut peer_2 = self.peer_2;
        let peer_1_indexer = self.peer_1_indexer;
        let peer_2_indexer = self.peer_2_indexer;
        let mut convo_1 = self.convo_1;
        let mut convo_2 = self.convo_2;
        let unconfirmed_state = self.unconfirmed_state;

        let mut responses = vec![];
        for request in requests.into_iter() {
            peer_1.refresh_burnchain_view();
            peer_2.refresh_burnchain_view();

            convo_1.send_request(request.clone()).unwrap();
            let mut peer_1_mempool = peer_1.mempool.take().unwrap();
            let peer_2_mempool = peer_2.mempool.take().unwrap();

            debug!("test_rpc: Peer 1 sends to Peer 2");
            convo_send_recv(&mut convo_1, &mut convo_2);

            // hack around the borrow-checker
            let peer_1_sortdb = peer_1.sortdb.take().unwrap();
            let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();

            if unconfirmed_state {
                Relayer::setup_unconfirmed_state(
                    &mut peer_1_stacks_node.chainstate,
                    &peer_1_sortdb,
                )
                .unwrap();
            }

            {
                let mut rpc_args = RPCHandlerArgs::default();
                rpc_args.event_observer = event_observer;
                let mut node_state = StacksNodeState::new(
                    &mut peer_1.network,
                    &peer_1_sortdb,
                    &mut peer_1_stacks_node.chainstate,
                    &mut peer_1_mempool,
                    &rpc_args,
                    false,
                );
                convo_1.chat(&mut node_state).unwrap();
            }

            peer_1.sortdb = Some(peer_1_sortdb);
            peer_1.stacks_node = Some(peer_1_stacks_node);
            peer_1.mempool = Some(peer_1_mempool);
            peer_2.mempool = Some(peer_2_mempool);

            debug!("test_rpc: Peer 2 sends to Peer 1");

            // hack around the borrow-checker
            let peer_2_sortdb = peer_2.sortdb.take().unwrap();
            let mut peer_2_stacks_node = peer_2.stacks_node.take().unwrap();
            let mut peer_2_mempool = peer_2.mempool.take().unwrap();

            let _ = peer_2
                .network
                .refresh_burnchain_view(
                    &peer_2_indexer,
                    &peer_2_sortdb,
                    &mut peer_2_stacks_node.chainstate,
                    false,
                )
                .unwrap();

            if unconfirmed_state {
                Relayer::setup_unconfirmed_state(
                    &mut peer_2_stacks_node.chainstate,
                    &peer_2_sortdb,
                )
                .unwrap();
            }

            {
                let mut rpc_args = RPCHandlerArgs::default();
                rpc_args.event_observer = event_observer;
                let mut node_state = StacksNodeState::new(
                    &mut peer_2.network,
                    &peer_2_sortdb,
                    &mut peer_2_stacks_node.chainstate,
                    &mut peer_2_mempool,
                    &rpc_args,
                    false,
                );
                convo_2.chat(&mut node_state).unwrap();
            }

            peer_2.sortdb = Some(peer_2_sortdb);
            peer_2.stacks_node = Some(peer_2_stacks_node);
            peer_2.mempool = Some(peer_2_mempool);

            convo_send_recv(&mut convo_2, &mut convo_1);

            debug!("test_rpc: Peer 1 flush");

            // hack around the borrow-checker
            convo_send_recv(&mut convo_1, &mut convo_2);

            let peer_1_sortdb = peer_1.sortdb.take().unwrap();
            let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();

            let _ = peer_1
                .network
                .refresh_burnchain_view(
                    &peer_1_indexer,
                    &peer_1_sortdb,
                    &mut peer_1_stacks_node.chainstate,
                    false,
                )
                .unwrap();

            if unconfirmed_state {
                Relayer::setup_unconfirmed_state(
                    &mut peer_1_stacks_node.chainstate,
                    &peer_1_sortdb,
                )
                .unwrap();
            }

            peer_1.sortdb = Some(peer_1_sortdb);
            peer_1.stacks_node = Some(peer_1_stacks_node);

            let resp_opt = loop {
                debug!("Peer 1 try get response");
                convo_send_recv(&mut convo_1, &mut convo_2);
                {
                    let peer_1_sortdb = peer_1.sortdb.take().unwrap();
                    let mut peer_1_stacks_node = peer_1.stacks_node.take().unwrap();
                    let mut peer_1_mempool = peer_1.mempool.take().unwrap();

                    let rpc_args = RPCHandlerArgs::default();
                    let mut node_state = StacksNodeState::new(
                        &mut peer_1.network,
                        &peer_1_sortdb,
                        &mut peer_1_stacks_node.chainstate,
                        &mut peer_1_mempool,
                        &rpc_args,
                        false,
                    );

                    convo_1.chat(&mut node_state).unwrap();

                    peer_1.sortdb = Some(peer_1_sortdb);
                    peer_1.stacks_node = Some(peer_1_stacks_node);
                    peer_1.mempool = Some(peer_1_mempool);
                }

                convo_1.try_flush().unwrap();

                info!("Try get response from request {:?}", &request);

                // should have gotten a reply
                let resp_opt = convo_1.try_get_response();
                if resp_opt.is_some() {
                    break resp_opt;
                }
            };

            assert!(resp_opt.is_some());

            let resp = resp_opt.unwrap();
            responses.push(resp);
        }

        return responses;
    }
}

/// General testing function to test RPC calls.
/// This function sets up two TestPeers and their respective chainstates, and loads them up with
/// some sample blocks and microblocks.  The blocks will contain a smart contract transaction
/// called `hello-world` with the code `TEST_CONTRACT` above.  In addition, a microblock will be
/// created off of the block with a contract-call to `add-unit`.  The second TestPeer will also
/// have a populated mempool, while the first will not.
///
/// This function causes the first peer to send `request` to the second peer from the first peer,
/// and will return the `StacksHttpResponse` generated by the second peer.
pub fn test_rpc(test_name: &str, requests: Vec<StacksHttpRequest>) -> Vec<StacksHttpResponse> {
    let test = TestRPC::setup(test_name);
    test.run(requests)
}

#[test]
fn prefixed_opt_hex_serialization() {
    let tests_32b = [
        None,
        Some([0u8; 32]),
        Some([15; 32]),
        Some([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ]),
    ];

    for test in tests_32b.iter() {
        let inp = test.clone().map(BurnchainHeaderHash);
        let mut out_buff = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut out_buff);
        prefix_opt_hex::serialize(&inp, &mut serializer).unwrap();
        let hex_str = String::from_utf8(out_buff).unwrap();
        eprintln!("{hex_str}");

        let mut deserializer = serde_json::Deserializer::from_str(&hex_str);
        let out: Option<BurnchainHeaderHash> =
            prefix_opt_hex::deserialize(&mut deserializer).unwrap();

        assert_eq!(out, inp);
        if test.is_some() {
            assert_eq!(
                hex_str,
                format!("\"0x{}\"", to_hex(&inp.as_ref().unwrap().0))
            );
        } else {
            assert_eq!(hex_str, "null");
        }
    }
}

#[test]
fn prefixed_hex_bad_desers() {
    let inp = "\"1\"";
    let mut opt_deserializer = serde_json::Deserializer::from_str(inp);
    assert_eq!(
        prefix_opt_hex::deserialize::<_, BurnchainHeaderHash>(&mut opt_deserializer)
            .unwrap_err()
            .to_string(),
        "invalid length 1, expected at least length 2 string".to_string(),
    );
    let inp = "\"0x\"";
    let mut opt_deserializer = serde_json::Deserializer::from_str(inp);
    assert_eq!(
        prefix_opt_hex::deserialize::<_, BurnchainHeaderHash>(&mut opt_deserializer)
            .unwrap_err()
            .to_string(),
        "bad length 0 for hex string".to_string(),
    );
    let inp = "\"0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00\"";
    let mut opt_deserializer = serde_json::Deserializer::from_str(inp);
    assert_eq!(
        prefix_opt_hex::deserialize::<_, BurnchainHeaderHash>(&mut opt_deserializer)
            .unwrap_err()
            .to_string(),
        "bad length 66 for hex string".to_string(),
    );
}

#[test]
fn prefixed_hex_serialization() {
    let tests_32b = [
        [0u8; 32],
        [1; 32],
        [15; 32],
        [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15,
        ],
    ];

    for test in tests_32b.iter() {
        let inp = BurnchainHeaderHash(test.clone());
        let mut out_buff = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut out_buff);
        prefix_hex::serialize(&inp, &mut serializer).unwrap();
        let hex_str = String::from_utf8(out_buff).unwrap();
        eprintln!("{hex_str}");

        let mut deserializer = serde_json::Deserializer::from_str(&hex_str);
        let out: BurnchainHeaderHash = prefix_hex::deserialize(&mut deserializer).unwrap();

        assert_eq!(out, inp);
        assert_eq!(hex_str, format!("\"0x{}\"", to_hex(&inp.0)));
    }
}
