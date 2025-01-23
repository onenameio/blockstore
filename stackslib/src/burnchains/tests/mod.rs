// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

pub mod affirmation;
pub mod burnchain;
pub mod db;

use std::collections::HashMap;

use stacks_common::address::*;
use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId, VRFSeed};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::*;
use stacks_common::util::secp256k1::*;
use stacks_common::util::vrf::*;

use super::*;
use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::db::*;
use crate::burnchains::{Burnchain, *};
use crate::chainstate::burn::db::sortdb::*;
use crate::chainstate::burn::operations::{BlockstackOperationType, *};
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::comm::*;
use crate::chainstate::coordinator::*;
use crate::chainstate::stacks::*;
use crate::core::{STACKS_EPOCH_2_4_MARKER, STACKS_EPOCH_3_0_MARKER};
use crate::cost_estimates::{CostEstimator, FeeEstimator};
use crate::stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use crate::util_lib::db::*;

// all SPV headers will have this timestamp, so that multiple burnchain nodes will always have the
// same SPV header timestamps regardless of when they are instantiated.
pub const BURNCHAIN_TEST_BLOCK_TIME: u64 = 1629739098;

impl Txid {
    pub fn from_test_data(
        block_height: u64,
        vtxindex: u32,
        burn_header_hash: &BurnchainHeaderHash,
        noise: u64,
    ) -> Txid {
        let mut bytes = vec![];
        bytes.extend_from_slice(&block_height.to_be_bytes());
        bytes.extend_from_slice(&vtxindex.to_be_bytes());
        bytes.extend_from_slice(burn_header_hash.as_bytes());
        bytes.extend_from_slice(&noise.to_be_bytes());
        let h = DoubleSha256::from_data(&bytes[..]);
        let mut hb = [0u8; 32];
        hb.copy_from_slice(h.as_bytes());

        Txid(hb)
    }
}

impl BurnchainBlockHeader {
    pub fn from_parent_snapshot(
        parent_sn: &BlockSnapshot,
        block_hash: BurnchainHeaderHash,
        num_txs: u64,
    ) -> BurnchainBlockHeader {
        BurnchainBlockHeader {
            block_height: parent_sn.block_height + 1,
            block_hash,
            parent_block_hash: parent_sn.burn_header_hash.clone(),
            num_txs,
            timestamp: get_epoch_time_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestBurnchainBlock {
    pub block_height: u64,
    pub parent_snapshot: BlockSnapshot,
    pub txs: Vec<BlockstackOperationType>,
    pub fork_id: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct TestBurnchainFork {
    pub start_height: u64,
    pub mined: u64,
    pub tip_index_root: TrieHash,
    pub tip_header_hash: BurnchainHeaderHash,
    pub tip_sortition_id: SortitionId,
    pub pending_blocks: Vec<TestBurnchainBlock>,
    pub blocks: Vec<TestBurnchainBlock>,
    pub fork_id: u64,
}

pub struct TestBurnchainNode {
    pub sortdb: SortitionDB,
    pub dirty: bool,
    pub burnchain: Burnchain,
}

#[derive(Debug, Clone)]
pub struct TestMiner {
    pub burnchain: Burnchain,
    pub privks: Vec<StacksPrivateKey>,
    pub num_sigs: u16,
    pub hash_mode: AddressHashMode,
    pub microblock_privks: Vec<StacksPrivateKey>,
    pub vrf_keys: Vec<VRFPrivateKey>,
    pub vrf_key_map: HashMap<VRFPublicKey, VRFPrivateKey>,
    pub block_commits: Vec<LeaderBlockCommitOp>,
    pub id: usize,
    pub nonce: u64,
    pub spent_at_nonce: HashMap<u64, u128>, // how much uSTX this miner paid in a given tx's nonce
    pub test_with_tx_fees: bool, // set to true to make certain helper methods attach a pre-defined tx fee
    pub chain_id: u32,
}

pub struct TestMinerFactory {
    pub key_seed: [u8; 32],
    pub next_miner_id: usize,
    pub chain_id: u32,
}

impl TestMiner {
    pub fn new(
        burnchain: &Burnchain,
        privks: Vec<StacksPrivateKey>,
        num_sigs: u16,
        hash_mode: &AddressHashMode,
        chain_id: u32,
    ) -> TestMiner {
        TestMiner {
            burnchain: burnchain.clone(),
            privks,
            num_sigs,
            hash_mode: hash_mode.clone(),
            microblock_privks: vec![],
            vrf_keys: vec![],
            vrf_key_map: HashMap::new(),
            block_commits: vec![],
            id: 0,
            nonce: 0,
            spent_at_nonce: HashMap::new(),
            test_with_tx_fees: true,
            chain_id,
        }
    }

    pub fn last_VRF_public_key(&self) -> Option<VRFPublicKey> {
        match self.vrf_keys.len() {
            0 => None,
            x => Some(VRFPublicKey::from_private(&self.vrf_keys[x - 1])),
        }
    }

    pub fn last_block_commit(&self) -> Option<LeaderBlockCommitOp> {
        self.block_commits.last().cloned()
    }

    pub fn block_commit_at(&self, idx: usize) -> Option<LeaderBlockCommitOp> {
        assert!(idx < self.block_commits.len());
        self.block_commits.get(idx).cloned()
    }

    pub fn num_block_commits(&self) -> usize {
        self.block_commits.len()
    }

    pub fn next_VRF_key(&mut self) -> VRFPrivateKey {
        let pk = if self.vrf_keys.is_empty() {
            // first key is simply the 32-byte hash of the secret state
            let mut buf: Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[
                (self.num_sigs >> 8) as u8,
                (self.num_sigs & 0xff) as u8,
                self.hash_mode as u8,
            ]);
            let h = Sha256Sum::from_data(&buf[..]);
            VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
        } else {
            // next key is just the hash of the last
            let h = Sha256Sum::from_data(self.vrf_keys[self.vrf_keys.len() - 1].as_bytes());
            VRFPrivateKey::from_bytes(h.as_bytes()).unwrap()
        };

        self.vrf_keys.push(pk.clone());
        self.vrf_key_map
            .insert(VRFPublicKey::from_private(&pk), pk.clone());
        pk
    }

    pub fn next_microblock_privkey(&mut self) -> StacksPrivateKey {
        let pk = if self.microblock_privks.is_empty() {
            // first key is simply the 32-byte hash of the secret state
            let mut buf: Vec<u8> = vec![];
            for i in 0..self.privks.len() {
                buf.extend_from_slice(&self.privks[i].to_bytes()[..]);
            }
            buf.extend_from_slice(&[
                (self.num_sigs >> 8) as u8,
                (self.num_sigs & 0xff) as u8,
                self.hash_mode as u8,
            ]);
            let h = Sha256Sum::from_data(&buf[..]);
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        } else {
            // next key is the hash of the last
            let h = Sha256Sum::from_data(
                &self.microblock_privks[self.microblock_privks.len() - 1].to_bytes(),
            );
            StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
        };

        self.microblock_privks.push(pk.clone());
        pk
    }

    pub fn make_proof(
        &self,
        vrf_pubkey: &VRFPublicKey,
        last_sortition_hash: &SortitionHash,
    ) -> Option<VRFProof> {
        test_debug!(
            "Make proof from {} over {}",
            vrf_pubkey.to_hex(),
            last_sortition_hash
        );
        match self.vrf_key_map.get(vrf_pubkey) {
            Some(ref prover_key) => {
                let proof = VRF::prove(prover_key, &last_sortition_hash.as_bytes().to_vec());
                let valid =
                    match VRF::verify(vrf_pubkey, &proof, &last_sortition_hash.as_bytes().to_vec())
                    {
                        Ok(v) => v,
                        Err(e) => false,
                    };
                assert!(valid);
                Some(proof)
            }
            None => None,
        }
    }

    pub fn as_transaction_auth(&self) -> Option<TransactionAuth> {
        match self.hash_mode {
            AddressHashMode::SerializeP2PKH => TransactionAuth::from_p2pkh(&self.privks[0]),
            AddressHashMode::SerializeP2SH => {
                TransactionAuth::from_p2sh(&self.privks, self.num_sigs)
            }
            AddressHashMode::SerializeP2WPKH => TransactionAuth::from_p2wpkh(&self.privks[0]),
            AddressHashMode::SerializeP2WSH => {
                TransactionAuth::from_p2wsh(&self.privks, self.num_sigs)
            }
        }
    }

    pub fn origin_address(&self) -> Option<StacksAddress> {
        match self.as_transaction_auth() {
            Some(auth) => Some(auth.origin().address_testnet()),
            None => None,
        }
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn set_nonce(&mut self, n: u64) {
        self.nonce = n;
    }

    pub fn sign_as_origin(&mut self, tx_signer: &mut StacksTransactionSigner) {
        let num_keys = if self.privks.len() < self.num_sigs as usize {
            self.privks.len()
        } else {
            self.num_sigs as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_origin(&self.privks[i]).unwrap();
        }

        self.nonce += 1
    }

    pub fn sign_as_sponsor(&mut self, tx_signer: &mut StacksTransactionSigner) {
        let num_keys = if self.privks.len() < self.num_sigs as usize {
            self.privks.len()
        } else {
            self.num_sigs as usize
        };

        for i in 0..num_keys {
            tx_signer.sign_sponsor(&self.privks[i]).unwrap();
        }

        self.nonce += 1
    }
}

// creates miners deterministically
impl TestMinerFactory {
    pub fn new() -> TestMinerFactory {
        TestMinerFactory {
            key_seed: [0u8; 32],
            next_miner_id: 1,
            chain_id: CHAIN_ID_TESTNET,
        }
    }

    pub fn next_private_key(&mut self) -> StacksPrivateKey {
        let h = Sha256Sum::from_data(&self.key_seed);
        self.key_seed.copy_from_slice(h.as_bytes());

        StacksPrivateKey::from_slice(h.as_bytes()).unwrap()
    }

    pub fn next_miner(
        &mut self,
        burnchain: &Burnchain,
        num_keys: u16,
        num_sigs: u16,
        hash_mode: AddressHashMode,
    ) -> TestMiner {
        let mut keys = vec![];
        for i in 0..num_keys {
            keys.push(self.next_private_key());
        }

        test_debug!("New miner: {:?} {}:{:?}", &hash_mode, num_sigs, &keys);
        let mut m = TestMiner::new(burnchain, keys, num_sigs, &hash_mode, self.chain_id);
        m.id = self.next_miner_id;
        self.next_miner_id += 1;
        m
    }
}

impl TestBurnchainBlock {
    pub fn new(parent_snapshot: &BlockSnapshot, fork_id: u64) -> TestBurnchainBlock {
        let burn_header_hash = BurnchainHeaderHash::from_test_data(
            parent_snapshot.block_height + 1,
            &parent_snapshot.index_root,
            fork_id,
        );
        TestBurnchainBlock {
            parent_snapshot: parent_snapshot.clone(),
            block_height: parent_snapshot.block_height + 1,
            txs: vec![
                // make sure that no block-commit gets vtxindex == 0 unless explicitly structured.
                // This prestx mocks a burnchain coinbase
                BlockstackOperationType::PreStx(PreStxOp {
                    output: StacksAddress::burn_address(false),
                    txid: Txid::from_test_data(
                        parent_snapshot.block_height + 1,
                        0,
                        &burn_header_hash,
                        128,
                    ),
                    vtxindex: 0,
                    block_height: parent_snapshot.block_height + 1,
                    burn_header_hash,
                }),
            ],
            fork_id,
            timestamp: get_epoch_time_secs(),
        }
    }

    pub fn add_leader_key_register(&mut self, miner: &mut TestMiner) -> LeaderKeyRegisterOp {
        let next_vrf_key = miner.next_VRF_key();
        let mut txop =
            LeaderKeyRegisterOp::new_from_secrets(miner.num_sigs, &miner.hash_mode, &next_vrf_key)
                .unwrap();

        txop.vtxindex = self.txs.len() as u32;
        txop.block_height = self.block_height;
        txop.burn_header_hash = BurnchainHeaderHash::from_test_data(
            txop.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        );
        txop.txid =
            Txid::from_test_data(txop.block_height, txop.vtxindex, &txop.burn_header_hash, 0);
        txop.consensus_hash = self.parent_snapshot.consensus_hash.clone();

        let miner_pubkey_hash160 = miner.nakamoto_miner_hash160();
        txop.set_nakamoto_signing_key(&miner_pubkey_hash160);

        self.txs
            .push(BlockstackOperationType::LeaderKeyRegister(txop.clone()));

        txop
    }

    pub(crate) fn inner_add_block_commit(
        &mut self,
        ic: &SortitionDBConn,
        miner: &mut TestMiner,
        block_hash: &BlockHeaderHash,
        burn_fee: u64,
        leader_key: &LeaderKeyRegisterOp,
        fork_snapshot: Option<&BlockSnapshot>,
        parent_block_snapshot: Option<&BlockSnapshot>,
        new_seed: Option<VRFSeed>,
        epoch_marker: u8,
        parent_is_shadow: bool,
    ) -> LeaderBlockCommitOp {
        let pubks = miner
            .privks
            .iter()
            .map(|ref pk| StacksPublicKey::from_private(pk))
            .collect();
        let apparent_sender =
            BurnchainSigner::mock_parts(miner.hash_mode.clone(), miner.num_sigs as usize, pubks);

        let last_snapshot = match fork_snapshot {
            Some(sn) => sn.clone(),
            None => SortitionDB::get_canonical_burn_chain_tip(ic).unwrap(),
        };

        let last_snapshot_with_sortition = match parent_block_snapshot {
            Some(sn) => sn.clone(),
            None => SortitionDB::get_first_block_snapshot(ic).unwrap(),
        };

        let new_seed = new_seed.unwrap_or_else(|| {
            // prove on the last-ever sortition's hash to produce the new seed
            let proof = miner
                .make_proof(&leader_key.public_key, &last_snapshot.sortition_hash)
                .expect(&format!(
                    "FATAL: no private key for {}",
                    leader_key.public_key.to_hex()
                ));

            VRFSeed::from_proof(&proof)
        });

        let get_commit_res = SortitionDB::get_block_commit(
            ic.conn(),
            &last_snapshot_with_sortition.winning_block_txid,
            &last_snapshot_with_sortition.sortition_id,
        )
        .expect("FATAL: failed to read block commit");

        if parent_is_shadow {
            assert!(
                get_commit_res.is_none(),
                "FATAL: shadow parent should not have a block-commit"
            );
        }

        let input = SortitionDB::get_last_block_commit_by_sender(ic.conn(), &apparent_sender)
            .unwrap()
            .map(|commit| (commit.txid.clone(), 1 + (commit.commit_outs.len() as u32)))
            .unwrap_or((Txid([0x00; 32]), 0));

        test_debug!("Last input from {} is {:?}", &apparent_sender, &input);

        let mut txop = match get_commit_res {
            Some(parent) => {
                test_debug!(
                    "Block-commit for {} (burn height {}) builds on leader block-commit {:?}",
                    block_hash,
                    self.block_height,
                    &parent
                );
                let txop = LeaderBlockCommitOp::new(
                    block_hash,
                    self.block_height,
                    &new_seed,
                    parent.block_height as u32,
                    parent.vtxindex as u16,
                    leader_key.block_height as u32,
                    leader_key.vtxindex as u16,
                    burn_fee,
                    &input,
                    &apparent_sender,
                );
                txop
            }
            None => {
                let txop = if parent_is_shadow {
                    test_debug!(
                        "Block-commit for {} (burn height {}) builds on shadow sortition",
                        block_hash,
                        self.block_height
                    );

                    LeaderBlockCommitOp::new(
                        block_hash,
                        self.block_height,
                        &new_seed,
                        last_snapshot_with_sortition.block_height as u32,
                        0,
                        leader_key.block_height as u32,
                        leader_key.vtxindex as u16,
                        burn_fee,
                        &input,
                        &apparent_sender,
                    )
                } else {
                    // initial
                    test_debug!(
                        "Block-commit for {} (burn height {}) builds on genesis",
                        block_hash,
                        self.block_height,
                    );
                    LeaderBlockCommitOp::initial(
                        block_hash,
                        self.block_height,
                        &new_seed,
                        leader_key,
                        burn_fee,
                        &input,
                        &apparent_sender,
                    )
                };
                txop
            }
        };

        txop.set_burn_height(self.block_height);
        txop.vtxindex = self.txs.len() as u32;
        txop.burn_header_hash = BurnchainHeaderHash::from_test_data(
            txop.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        ); // NOTE: override this if you intend to insert into the sortdb!
        txop.txid =
            Txid::from_test_data(txop.block_height, txop.vtxindex, &txop.burn_header_hash, 0);

        txop.memo = vec![epoch_marker << 3];
        self.txs
            .push(BlockstackOperationType::LeaderBlockCommit(txop.clone()));

        miner.block_commits.push(txop.clone());
        txop
    }

    /// Add an epoch 2.x block-commit
    pub fn add_leader_block_commit(
        &mut self,
        ic: &SortitionDBConn,
        miner: &mut TestMiner,
        block_hash: &BlockHeaderHash,
        burn_fee: u64,
        leader_key: &LeaderKeyRegisterOp,
        fork_snapshot: Option<&BlockSnapshot>,
        parent_block_snapshot: Option<&BlockSnapshot>,
    ) -> LeaderBlockCommitOp {
        self.inner_add_block_commit(
            ic,
            miner,
            block_hash,
            burn_fee,
            leader_key,
            fork_snapshot,
            parent_block_snapshot,
            None,
            STACKS_EPOCH_2_4_MARKER,
            false,
        )
    }

    pub fn patch_from_chain_tip(&mut self, parent_snapshot: &BlockSnapshot) {
        assert_eq!(parent_snapshot.block_height + 1, self.block_height);

        for i in 0..self.txs.len() {
            match self.txs[i] {
                BlockstackOperationType::LeaderKeyRegister(ref mut data) => {
                    assert_eq!(data.block_height, self.block_height);
                    data.consensus_hash = parent_snapshot.consensus_hash.clone();
                }
                _ => {}
            }
        }
    }

    pub fn mine(&self, db: &mut SortitionDB, burnchain: &Burnchain) -> BlockSnapshot {
        let block_hash = BurnchainHeaderHash::from_test_data(
            self.block_height,
            &self.parent_snapshot.index_root,
            self.fork_id,
        );
        let mock_bitcoin_block = BitcoinBlock::new(
            self.block_height,
            &block_hash,
            &self.parent_snapshot.burn_header_hash,
            vec![],
            get_epoch_time_secs(),
        );
        let block = BurnchainBlock::Bitcoin(mock_bitcoin_block);

        test_debug!(
            "Process block {} {}",
            block.block_height(),
            &block.block_hash()
        );

        let header = block.header();
        let sort_id = SortitionId::stubbed(&header.parent_block_hash);
        let mut sortition_db_handle = SortitionHandleTx::begin(db, &sort_id).unwrap();

        let parent_snapshot = sortition_db_handle
            .get_block_snapshot(&header.parent_block_hash, &sort_id)
            .unwrap()
            .expect("FATAL: failed to get burnchain linkage info");

        let blockstack_txs = self.txs.clone();

        let burnchain_db =
            BurnchainDB::connect(&burnchain.get_burnchaindb_path(), &burnchain, true).unwrap();

        let new_snapshot = sortition_db_handle
            .process_block_txs(
                false,
                &parent_snapshot,
                &header,
                burnchain,
                blockstack_txs,
                None,
                PoxId::stubbed(),
                None,
                0,
            )
            .unwrap();
        sortition_db_handle.commit().unwrap();

        new_snapshot.0
    }

    pub fn mine_pox<
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        R: RewardSetProvider,
        CE: CostEstimator,
        FE: FeeEstimator,
        B: BurnchainHeaderReader,
    >(
        &self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
        coord: &mut ChainsCoordinator<'_, T, N, R, CE, FE, B>,
    ) -> BlockSnapshot {
        let mut indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
        let parent_hdr = indexer
            .read_burnchain_header(self.block_height.saturating_sub(1))
            .unwrap()
            .expect(&format!(
                "BUG: could not read block at height {}",
                self.block_height.saturating_sub(1)
            ));

        let now = BURNCHAIN_TEST_BLOCK_TIME;
        let block_hash = BurnchainHeaderHash::from_bitcoin_hash(
            &BitcoinIndexer::mock_bitcoin_header(&parent_hdr.block_hash, now as u32).bitcoin_hash(),
        );
        let mock_bitcoin_block = BitcoinBlock::new(
            self.block_height,
            &block_hash,
            &self.parent_snapshot.burn_header_hash,
            vec![],
            now,
        );
        let block = BurnchainBlock::Bitcoin(mock_bitcoin_block);
        let header = BurnchainBlockHeader {
            block_height: block.block_height(),
            block_hash: block_hash.clone(),
            parent_block_hash: parent_hdr.block_hash.clone(),
            num_txs: block.header().num_txs,
            timestamp: block.header().timestamp,
        };

        test_debug!(
            "Process PoX block {} {}: {:?}",
            block.block_height(),
            &block.block_hash(),
            &header
        );

        let mut burnchain_db = BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap();
        indexer.raw_store_header(header.clone()).unwrap();
        burnchain_db
            .raw_store_burnchain_block(burnchain, &indexer, header.clone(), self.txs.clone())
            .unwrap();

        coord.handle_new_burnchain_block().unwrap();

        let snapshot = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();

        assert_eq!(snapshot.burn_header_hash, header.block_hash);
        assert_eq!(snapshot.burn_header_hash, block.block_hash());
        snapshot
    }
}

impl TestBurnchainFork {
    pub fn new(
        start_height: u64,
        start_header_hash: &BurnchainHeaderHash,
        start_index_root: &TrieHash,
        fork_id: u64,
    ) -> TestBurnchainFork {
        TestBurnchainFork {
            start_height,
            mined: 0,
            tip_header_hash: start_header_hash.clone(),
            tip_sortition_id: SortitionId::stubbed(&start_header_hash),
            tip_index_root: start_index_root.clone(),
            blocks: vec![],
            pending_blocks: vec![],
            fork_id,
        }
    }

    pub fn fork(&self) -> TestBurnchainFork {
        let mut new_fork = (*self).clone();
        new_fork.fork_id += 1;
        new_fork
    }

    pub fn append_block(&mut self, b: TestBurnchainBlock) {
        self.pending_blocks.push(b);
    }

    pub fn get_tip(&mut self, ic: &SortitionDBConn) -> BlockSnapshot {
        test_debug!(
            "Get tip snapshot at {} (sortition ID {})",
            &self.tip_header_hash,
            &self.tip_sortition_id
        );
        SortitionDB::get_block_snapshot(ic, &self.tip_sortition_id)
            .unwrap()
            .unwrap()
    }

    pub fn next_block(&mut self, ic: &SortitionDBConn) -> TestBurnchainBlock {
        let fork_tip = self.get_tip(ic);
        TestBurnchainBlock::new(&fork_tip, self.fork_id)
    }

    pub fn mine_pending_blocks(
        &mut self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
    ) -> BlockSnapshot {
        let mut snapshot = {
            let ic = db.index_conn();
            self.get_tip(&ic)
        };

        for mut block in self.pending_blocks.drain(..) {
            // fill in consensus hash and block hash, which we may not have known at the call
            // to next_block (since we can call next_block() many times without mining blocks)
            block.patch_from_chain_tip(&snapshot);

            snapshot = block.mine(db, burnchain);

            self.blocks.push(block);
            self.mined += 1;
            self.tip_index_root = snapshot.index_root;
            self.tip_header_hash = snapshot.burn_header_hash;
            self.tip_sortition_id = snapshot.sortition_id;
        }

        // give back the new chain tip
        snapshot
    }

    pub fn mine_pending_blocks_pox<
        T: BlockEventDispatcher,
        N: CoordinatorNotices,
        R: RewardSetProvider,
        CE: CostEstimator,
        FE: FeeEstimator,
        B: BurnchainHeaderReader,
    >(
        &mut self,
        db: &mut SortitionDB,
        burnchain: &Burnchain,
        coord: &mut ChainsCoordinator<'_, T, N, R, CE, FE, B>,
    ) -> BlockSnapshot {
        let mut snapshot = {
            let ic = db.index_conn();
            self.get_tip(&ic)
        };

        for mut block in self.pending_blocks.drain(..) {
            // fill in consensus hash and block hash, which we may not have known at the call
            // to next_block (since we can call next_block() many times without mining blocks)
            block.patch_from_chain_tip(&snapshot);

            snapshot = block.mine_pox(db, burnchain, coord);

            self.blocks.push(block);
            self.mined += 1;
            self.tip_index_root = snapshot.index_root;
            self.tip_header_hash = snapshot.burn_header_hash;
            self.tip_sortition_id = snapshot.sortition_id;
        }

        // give back the new chain tip
        snapshot
    }
}

impl TestBurnchainNode {
    pub fn new() -> TestBurnchainNode {
        let first_block_height = 100;
        let first_block_hash = BurnchainHeaderHash([0u8; 32]);
        let db = SortitionDB::connect_test(first_block_height, &first_block_hash).unwrap();
        TestBurnchainNode {
            sortdb: db,
            dirty: false,
            burnchain: Burnchain::default_unittest(first_block_height, &first_block_hash),
        }
    }

    pub fn mine_fork(&mut self, fork: &mut TestBurnchainFork) -> BlockSnapshot {
        fork.mine_pending_blocks(&mut self.sortdb, &self.burnchain)
    }
}

fn process_next_sortition(
    node: &mut TestBurnchainNode,
    fork: &mut TestBurnchainFork,
    miners: &mut [TestMiner],
    prev_keys: &[LeaderKeyRegisterOp],
    block_hashes: &[BlockHeaderHash],
) -> (
    BlockSnapshot,
    Vec<LeaderKeyRegisterOp>,
    Vec<LeaderBlockCommitOp>,
) {
    assert_eq!(miners.len(), block_hashes.len());

    let mut block = {
        let ic = node.sortdb.index_conn();
        fork.next_block(&ic)
    };

    let mut next_commits = vec![];
    let mut next_prev_keys = vec![];

    if !prev_keys.is_empty() {
        assert_eq!(miners.len(), prev_keys.len());

        // make a Stacks block (hash) for each of the prior block's keys
        for j in 0..miners.len() {
            let block_commit_op = {
                let ic = node.sortdb.index_conn();
                let hash = block_hashes[j].clone();
                block.add_leader_block_commit(
                    &ic,
                    &mut miners[j],
                    &hash,
                    ((j + 1) as u64) * 1000,
                    &prev_keys[j],
                    None,
                    None,
                )
            };
            next_commits.push(block_commit_op);
        }
    }

    // have each leader register a VRF key
    for j in 0..miners.len() {
        let key_register_op = block.add_leader_key_register(&mut miners[j]);
        next_prev_keys.push(key_register_op);
    }

    test_debug!("Mine {} transactions", block.txs.len());

    fork.append_block(block);
    let tip_snapshot = node.mine_fork(fork);

    (tip_snapshot, next_prev_keys, next_commits)
}

fn verify_keys_accepted(node: &mut TestBurnchainNode, prev_keys: &[LeaderKeyRegisterOp]) {
    // all keys accepted
    for key in prev_keys.iter() {
        let tx_opt = SortitionDB::get_burnchain_transaction(node.sortdb.conn(), &key.txid).unwrap();
        assert!(tx_opt.is_some());

        let tx = tx_opt.unwrap();
        match tx {
            BlockstackOperationType::LeaderKeyRegister(ref op) => {
                assert_eq!(*op, *key);
            }
            _ => {
                assert!(false);
            }
        }
    }
}

fn verify_commits_accepted(node: &TestBurnchainNode, next_block_commits: &[LeaderBlockCommitOp]) {
    // all commits accepted
    for commit in next_block_commits.iter() {
        let tx_opt =
            SortitionDB::get_burnchain_transaction(node.sortdb.conn(), &commit.txid).unwrap();
        assert!(tx_opt.is_some());

        let tx = tx_opt.unwrap();
        match tx {
            BlockstackOperationType::LeaderBlockCommit(ref op) => {
                assert_eq!(*op, *commit);
            }
            _ => {
                assert!(false);
            }
        }
    }
}

#[test]
fn mine_10_stacks_blocks_1_fork() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );
    let mut prev_keys = vec![];

    for i in 0..10 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (next_snapshot, mut next_prev_keys, next_block_commits) = process_next_sortition(
            &mut node,
            &mut fork,
            &mut miners,
            &prev_keys,
            &next_block_hashes,
        );

        verify_keys_accepted(&mut node, &prev_keys);
        verify_commits_accepted(&node, &next_block_commits);

        prev_keys.clear();
        prev_keys.append(&mut next_prev_keys);
    }
}

#[test]
fn mine_10_stacks_blocks_2_forks_disjoint() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );
    let mut prev_keys_1 = vec![];

    // one fork for 5 blocks...
    for i in 0..5 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (next_snapshot, mut next_prev_keys, next_block_commits) = process_next_sortition(
            &mut node,
            &mut fork_1,
            &mut miners,
            &prev_keys_1,
            &next_block_hashes,
        );

        verify_keys_accepted(&mut node, &prev_keys_1);
        verify_commits_accepted(&node, &next_block_commits);

        prev_keys_1.clear();
        prev_keys_1.append(&mut next_prev_keys);
    }

    let mut fork_2 = fork_1.fork();
    let mut prev_keys_2 = prev_keys_1[5..].to_vec();
    prev_keys_1.truncate(5);

    let mut miners_1 = vec![];
    let mut miners_2 = vec![];

    let mut miners_iter = miners.into_iter();
    for i in 0..5 {
        let m = miners_iter.next().unwrap();
        miners_1.push(m);
    }
    for i in 0..5 {
        let m = miners_iter.next().unwrap();
        miners_2.push(m);
    }

    // two disjoint forks for 5 blocks...
    for i in 5..10 {
        let mut next_block_hashes_1 = vec![];
        for j in 0..miners_1.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_1.push(hash);
        }

        let mut next_block_hashes_2 = vec![];
        for j in 0..miners_2.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + (5 + j) + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_2.push(hash);
        }

        let (next_snapshot_1, mut next_prev_keys_1, next_block_commits_1) = process_next_sortition(
            &mut node,
            &mut fork_1,
            &mut miners_1,
            &prev_keys_1,
            &next_block_hashes_1,
        );
        let (next_snapshot_2, mut next_prev_keys_2, next_block_commits_2) = process_next_sortition(
            &mut node,
            &mut fork_2,
            &mut miners_2,
            &prev_keys_2,
            &next_block_hashes_2,
        );

        assert!(next_snapshot_1.burn_header_hash != next_snapshot_2.burn_header_hash);

        verify_keys_accepted(&mut node, &prev_keys_1);
        verify_commits_accepted(&node, &next_block_commits_1);

        verify_keys_accepted(&mut node, &prev_keys_2);
        verify_commits_accepted(&node, &next_block_commits_2);

        prev_keys_1.clear();
        prev_keys_1.append(&mut next_prev_keys_1);

        prev_keys_2.clear();
        prev_keys_2.append(&mut next_prev_keys_2);
    }
}

#[test]
fn mine_10_stacks_blocks_2_forks_disjoint_same_blocks() {
    let mut node = TestBurnchainNode::new();
    let mut miner_factory = TestMinerFactory::new();

    let mut miners = vec![];
    for i in 0..10 {
        miners.push(miner_factory.next_miner(
            &node.burnchain,
            1,
            1,
            AddressHashMode::SerializeP2PKH,
        ));
    }

    let first_snapshot = SortitionDB::get_first_block_snapshot(node.sortdb.conn()).unwrap();
    let mut fork_1 = TestBurnchainFork::new(
        first_snapshot.block_height,
        &first_snapshot.burn_header_hash,
        &first_snapshot.index_root,
        0,
    );
    let mut prev_keys_1 = vec![];

    // one fork for 5 blocks...
    for i in 0..5 {
        let mut next_block_hashes = vec![];
        for j in 0..miners.len() {
            let hash = BlockHeaderHash([(i * 10 + j + miners.len()) as u8; 32]);
            next_block_hashes.push(hash);
        }

        let (snapshot, mut next_prev_keys, next_block_commits) = process_next_sortition(
            &mut node,
            &mut fork_1,
            &mut miners,
            &prev_keys_1,
            &next_block_hashes,
        );

        verify_keys_accepted(&mut node, &prev_keys_1);
        verify_commits_accepted(&node, &next_block_commits);

        prev_keys_1.clear();
        prev_keys_1.append(&mut next_prev_keys);
    }

    let mut fork_2 = fork_1.fork();
    let mut prev_keys_2 = prev_keys_1[5..].to_vec();
    prev_keys_1.truncate(5);

    let mut miners_1 = vec![];
    let mut miners_2 = vec![];

    let mut miners_iter = miners.into_iter();
    for i in 0..5 {
        let m = miners_iter.next().unwrap();
        miners_1.push(m);
    }
    for i in 0..5 {
        let m = miners_iter.next().unwrap();
        miners_2.push(m);
    }

    // two disjoint forks for 5 blocks, but miners in each fork mine the same blocks.
    // This tests that we can accept two burnchain forks that each contain the same stacks
    // block history.
    for i in 5..10 {
        let mut next_block_hashes_1 = vec![];
        for j in 0..miners_1.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_1.push(hash);
        }

        let mut next_block_hashes_2 = vec![];
        for j in 0..miners_2.len() {
            let hash = BlockHeaderHash(
                [(i * (miners_1.len() + miners_2.len()) + j + miners_1.len() + miners_2.len())
                    as u8; 32],
            );
            next_block_hashes_2.push(hash);
        }

        let (snapshot_1, mut next_prev_keys_1, next_block_commits_1) = process_next_sortition(
            &mut node,
            &mut fork_1,
            &mut miners_1,
            &prev_keys_1,
            &next_block_hashes_1,
        );
        let (snapshot_2, mut next_prev_keys_2, next_block_commits_2) = process_next_sortition(
            &mut node,
            &mut fork_2,
            &mut miners_2,
            &prev_keys_2,
            &next_block_hashes_2,
        );

        assert!(snapshot_1.burn_header_hash != snapshot_2.burn_header_hash);
        assert!(snapshot_1.consensus_hash != snapshot_2.consensus_hash);

        // same blocks mined in both forks
        assert_eq!(next_block_commits_1.len(), next_block_commits_2.len());
        for i in 0..next_block_commits_1.len() {
            assert_eq!(
                next_block_commits_1[i].block_header_hash,
                next_block_commits_2[i].block_header_hash
            );
        }

        verify_keys_accepted(&mut node, &prev_keys_1);
        verify_commits_accepted(&node, &next_block_commits_1);

        verify_keys_accepted(&mut node, &prev_keys_2);
        verify_commits_accepted(&node, &next_block_commits_2);

        prev_keys_1.clear();
        prev_keys_1.append(&mut next_prev_keys_1);

        prev_keys_2.clear();
        prev_keys_2.append(&mut next_prev_keys_2);
    }
}
