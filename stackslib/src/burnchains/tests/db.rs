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

use std::cmp;

use rusqlite::ToSql;
use stacks_common::address::AddressHashMode;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BtcTx;
use stacks_common::deps_common::bitcoin::network::serialize::deserialize;
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::util::hash::*;

use super::*;
use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::bitcoin::address::*;
use crate::burnchains::bitcoin::blocks::*;
use crate::burnchains::bitcoin::*;
use crate::burnchains::db::apply_blockstack_txs_safety_checks;
use crate::burnchains::{Error as BurnchainError, PoxConstants, BLOCKSTACK_MAGIC_MAINNET};
use crate::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::tests::next_txid;
use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::*;
use crate::core::{StacksEpochId, BITCOIN_REGTEST_FIRST_BLOCK_HASH};
use crate::util_lib::db::Error as DBError;

impl BurnchainDB {
    pub fn get_first_header(&self) -> Result<BurnchainBlockHeader, BurnchainError> {
        let qry = "SELECT * FROM burnchain_db_block_headers ORDER BY block_height ASC, block_hash DESC LIMIT 1";
        let opt = query_row(&self.conn, qry, NO_PARAMS)?;
        opt.ok_or(BurnchainError::MissingParentBlock)
    }

    /// Get back all of the parsed burnchain operations for a given block.
    /// Used in testing to replay burnchain data.
    #[cfg(test)]
    pub fn get_burnchain_block_ops(
        &self,
        block_hash: &BurnchainHeaderHash,
    ) -> Result<Vec<BlockstackOperationType>, BurnchainError> {
        use rusqlite::params;

        let sql = "SELECT op FROM burnchain_db_block_ops WHERE block_hash = ?1";
        let args = params![block_hash];
        let mut ops: Vec<BlockstackOperationType> = query_rows(&self.conn, sql, args)?;
        ops.sort_by_key(|op| op.vtxindex());
        Ok(ops)
    }

    pub fn raw_store_burnchain_block<B: BurnchainHeaderReader>(
        &mut self,
        burnchain: &Burnchain,
        indexer: &B,
        header: BurnchainBlockHeader,
        mut blockstack_ops: Vec<BlockstackOperationType>,
    ) -> Result<(), BurnchainError> {
        apply_blockstack_txs_safety_checks(header.block_height, &mut blockstack_ops);

        let db_tx = self.tx_begin()?;

        test_debug!(
            "Store raw block {},{} (parent {}) with {} ops",
            &header.block_hash,
            header.block_height,
            &header.parent_block_hash,
            blockstack_ops.len()
        );

        db_tx.store_burnchain_db_entry(&header)?;
        db_tx.store_blockstack_ops(burnchain, indexer, &header, &blockstack_ops)?;

        db_tx.commit()?;

        Ok(())
    }
}

impl BurnchainHeaderReader for Vec<BurnchainBlockHeader> {
    fn read_burnchain_headers(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<BurnchainBlockHeader>, DBError> {
        if start_height >= self.len() as u64 {
            return Ok(vec![]);
        }
        let end = cmp::min(end_height, self.len() as u64) as usize;
        Ok(self[(start_height as usize)..end].to_vec())
    }

    fn get_burnchain_headers_height(&self) -> Result<u64, DBError> {
        Ok(self.len() as u64)
    }

    fn find_burnchain_header_height(
        &self,
        burn_header_hash: &BurnchainHeaderHash,
    ) -> Result<Option<u64>, DBError> {
        for hdr in self.iter() {
            if hdr.block_hash == *burn_header_hash {
                return Ok(Some(hdr.block_height));
            }
        }
        Ok(None)
    }
}

fn make_tx(hex_str: &str) -> BtcTx {
    let tx_bin = hex_bytes(hex_str).unwrap();
    deserialize(&tx_bin.to_vec()).unwrap()
}

#[test]
fn test_store_and_fetch() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();
    burnchain.pox_constants.sunset_start = 999;
    burnchain.pox_constants.sunset_end = 1000;

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(&first_block_header.timestamp, &0);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let headers = vec![first_block_header.clone()];
    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
        )
        .unwrap();
    assert_eq!(ops.len(), 0);

    let vtxindex = 1;
    let noncanon_block_height = 400;
    let non_canon_hash = BurnchainHeaderHash([2; 32]);

    let fixtures = operations::leader_key_register::tests::get_test_fixtures(
        vtxindex,
        noncanon_block_height,
        non_canon_hash,
    );

    let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);
    let mut broadcast_ops = vec![];
    let mut expected_ops = vec![];

    for (ix, tx_fixture) in fixtures.iter().enumerate() {
        let tx = make_tx(&tx_fixture.txstr);
        let burnchain_tx = parser
            .parse_tx(&tx, ix + 1, StacksEpochId::Epoch2_05)
            .unwrap();
        if let Some(res) = &tx_fixture.result {
            let mut res = res.clone();
            res.vtxindex = (ix + 1).try_into().unwrap();
            expected_ops.push(res.clone());
        }
        broadcast_ops.push(burnchain_tx);
    }

    let non_canonical_block = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        400,
        &non_canon_hash,
        &first_bhh,
        broadcast_ops,
        350,
    ));

    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &non_canonical_block,
            StacksEpochId::Epoch21,
        )
        .unwrap();
    assert_eq!(ops.len(), expected_ops.len());
    for op in ops.iter() {
        let expected_op = expected_ops
            .iter()
            .find(|candidate| candidate.txid == op.txid())
            .expect("FAILED to find parsed op in expected ops");
        if let BlockstackOperationType::LeaderKeyRegister(op) = op {
            assert_eq!(op, expected_op);
        } else {
            panic!("EXPECTED to parse a LeaderKeyRegister");
        }
    }

    let BurnchainBlockData { header, ops } =
        BurnchainDB::get_burnchain_block(burnchain_db.conn(), &non_canon_hash).unwrap();
    assert_eq!(ops.len(), expected_ops.len());
    for op in ops.iter() {
        let expected_op = expected_ops
            .iter()
            .find(|candidate| candidate.txid == op.txid())
            .expect("FAILED to find parsed op in expected ops");
        if let BlockstackOperationType::LeaderKeyRegister(op) = op {
            assert_eq!(op, expected_op);
        } else {
            panic!("EXPECTED to parse a LeaderKeyRegister");
        }
    }
    assert_eq!(&header, &non_canonical_block.header());

    // when we get a block header by its height, it's canonical
    for (height, header) in headers.iter().enumerate() {
        let hdr = BurnchainDB::get_burnchain_header(burnchain_db.conn(), &headers, height as u64)
            .unwrap()
            .unwrap();
        assert!(headers.iter().find(|h| **h == hdr).is_some());
        assert_ne!(hdr, non_canonical_block.header());
    }

    let looked_up_canon = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&looked_up_canon, &canonical_block.header());

    let BurnchainBlockData { header, ops } =
        BurnchainDB::get_burnchain_block(burnchain_db.conn(), &canon_hash).unwrap();
    assert_eq!(ops.len(), 0);
    assert_eq!(&header, &looked_up_canon);
}

#[test]
fn test_classify_stack_stx() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();
    burnchain.pox_constants.sunset_start = 999;
    burnchain.pox_constants.sunset_end = 1000;

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(&first_block_header.timestamp, &0);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let mut headers = vec![first_block_header.clone()];
    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
        )
        .unwrap();
    assert_eq!(ops.len(), 0);

    // let's mine a block with a pre-stack-stx tx, and a stack-stx tx,
    //    the stack-stx tx should _fail_ to verify, because there's no
    //    corresponding pre-stack-stx.

    let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

    let pre_stack_stx_0_txid = Txid([5; 32]);
    let pre_stack_stx_0 = BitcoinTransaction {
        txid: pre_stack_stx_0_txid.clone(),
        vtxindex: 0,
        opcode: Opcodes::PreStx as u8,
        data: vec![0; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one will not have a corresponding pre_stack_stx tx.
    let stack_stx_0 = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 1,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one will have a corresponding pre_stack_stx tx.
    let stack_stx_0_second_attempt = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 2,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_stack_stx_0_txid.clone(), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([2; 20]),
            }),
        }],
    };

    // this one won't have a corresponding pre_stack_stx tx.
    let stack_stx_1 = BitcoinTransaction {
        txid: Txid([3; 32]),
        vtxindex: 3,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    // this one won't use the correct output
    let stack_stx_2 = BitcoinTransaction {
        txid: Txid([8; 32]),
        vtxindex: 4,
        opcode: Opcodes::StackStx as u8,
        data: vec![1; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_stack_stx_0_txid.clone(), 2),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
        }],
    };

    let ops_0 = vec![pre_stack_stx_0, stack_stx_0];

    let ops_1 = vec![stack_stx_1, stack_stx_0_second_attempt, stack_stx_2];

    let block_height_0 = 501;
    let block_hash_0 = BurnchainHeaderHash([2; 32]);
    let block_height_1 = 502;
    let block_hash_1 = BurnchainHeaderHash([3; 32]);

    let num_txs_ops_0: u64 = ops_0.len() as u64;
    let block_0 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_0,
        &block_hash_0,
        &first_bhh,
        ops_0,
        350,
    ));

    headers.push(BurnchainBlockHeader {
        block_height: first_block_header.block_height + 1,
        block_hash: block_hash_0.clone(),
        parent_block_hash: first_bhh.clone(),
        num_txs: num_txs_ops_0,
        timestamp: first_block_header.timestamp + 1,
    });

    let num_txs_ops_1: u64 = ops_1.len() as u64;
    let block_1 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_1,
        &block_hash_1,
        &block_hash_0,
        ops_1,
        360,
    ));

    headers.push(BurnchainBlockHeader {
        block_height: first_block_header.block_height + 2,
        block_hash: block_hash_1.clone(),
        parent_block_hash: block_hash_0.clone(),
        num_txs: num_txs_ops_1,
        timestamp: first_block_header.timestamp + 2,
    });

    let processed_ops_0 = burnchain_db
        .store_new_burnchain_block(&burnchain, &headers, &block_0, StacksEpochId::Epoch21)
        .unwrap();

    assert_eq!(
        processed_ops_0.len(),
        1,
        "Only pre_stack_stx op should have been accepted"
    );

    let processed_ops_1 = burnchain_db
        .store_new_burnchain_block(&burnchain, &headers, &block_1, StacksEpochId::Epoch21)
        .unwrap();

    assert_eq!(
        processed_ops_1.len(),
        1,
        "Only one stack_stx op should have been accepted"
    );

    let expected_pre_stack_addr =
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([1; 20]),
        });

    let expected_reward_addr = PoxAddress::Standard(
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([2; 20]),
        }),
        Some(AddressHashMode::SerializeP2PKH),
    );

    if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
        assert_eq!(&op.output, &expected_pre_stack_addr);
    } else {
        panic!("EXPECTED to parse a pre stack stx op");
    }

    if let BlockstackOperationType::StackStx(op) = &processed_ops_1[0] {
        assert_eq!(&op.sender, &expected_pre_stack_addr);
        assert_eq!(&op.reward_addr, &expected_reward_addr);
        assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 1);
    } else {
        panic!("EXPECTED to parse a stack stx op");
    }
}

pub fn make_simple_block_commit(
    burnchain: &Burnchain,
    parent: Option<&LeaderBlockCommitOp>,
    burn_header: &BurnchainBlockHeader,
    block_hash: BlockHeaderHash,
) -> LeaderBlockCommitOp {
    let block_height = burn_header.block_height;
    let mut new_op = LeaderBlockCommitOp {
        sunset_burn: 0,
        treatment: vec![],
        block_header_hash: block_hash,
        new_seed: VRFSeed([1u8; 32]),
        parent_block_ptr: 0,
        parent_vtxindex: 0,
        key_block_ptr: 0,
        key_vtxindex: 0,
        memo: vec![0],

        commit_outs: vec![
            PoxAddress::standard_burn_address(false),
            PoxAddress::standard_burn_address(false),
        ],

        burn_fee: 10000,
        input: (next_txid(), 0),
        apparent_sender: BurnchainSigner::mock_parts(
            AddressHashMode::SerializeP2PKH,
            1,
            vec![StacksPublicKey::from_hex(
                "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
            )
            .unwrap()],
        ),

        txid: next_txid(),
        vtxindex: 0,
        block_height,
        burn_parent_modulus: ((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
        burn_header_hash: burn_header.block_hash.clone(),
    };

    if burnchain.is_in_prepare_phase(block_height) {
        new_op.commit_outs = vec![PoxAddress::standard_burn_address(false)];
    }

    if let Some(ref op) = parent {
        new_op.parent_block_ptr = op.block_height as u32;
        new_op.parent_vtxindex = op.vtxindex as u16;
    };

    new_op
}

fn burn_db_test_pox() -> PoxConstants {
    PoxConstants::new(
        5,
        3,
        2,
        3,
        0,
        u64::MAX - 1,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    )
}

#[test]
fn test_get_commit_at() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 1,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    for i in 0..5 {
        let block_header = &headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );
        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                &burnchain,
                &headers,
                block_header,
                &vec![BlockstackOperationType::LeaderBlockCommit(cmt.clone())],
            )
            .unwrap();

        cmts.push(cmt.clone());
        parent = Some(cmt);
    }

    for i in 0..5 {
        let cmt = BurnchainDB::get_commit_at(
            &burnchain_db.conn(),
            &headers,
            (first_height + i) as u32,
            0,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cmt, cmts[i as usize]);
    }

    let cmt = BurnchainDB::get_commit_at(&burnchain_db.conn(), &headers, 5, 0)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, cmts[4]);

    // fork off the last stored commit block
    let fork_hdr = BurnchainHeaderHash([90; 32]);
    let fork_block_header = BurnchainBlockHeader {
        block_height: 5,
        block_hash: fork_hdr,
        parent_block_hash: BurnchainHeaderHash([4; 32]),
        num_txs: 1,
        timestamp: 4,
    };

    let mut fork_cmt = cmts[4].clone();
    fork_cmt.burn_header_hash = fork_hdr.clone();
    fork_cmt.vtxindex += 1;

    let mut fork_headers = headers.clone();
    fork_headers[5] = fork_block_header.clone();

    burnchain_db
        .store_new_burnchain_block_ops_unchecked(
            &burnchain,
            &fork_headers,
            &fork_block_header,
            &vec![BlockstackOperationType::LeaderBlockCommit(fork_cmt.clone())],
        )
        .unwrap();

    let cmt = BurnchainDB::get_commit_at(&burnchain_db.conn(), &headers, 5, 0)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, cmts[4]);

    let cmt = BurnchainDB::get_commit_at(&burnchain_db.conn(), &fork_headers, 5, 1)
        .unwrap()
        .unwrap();
    assert_eq!(cmt, fork_cmt);
}

#[test]
fn test_get_set_check_anchor_block() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 1,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    for i in 0..5 {
        let block_header = &headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );
        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                &burnchain,
                &headers,
                block_header,
                &vec![BlockstackOperationType::LeaderBlockCommit(cmt.clone())],
            )
            .unwrap();

        cmts.push(cmt.clone());
        parent = Some(cmt);
    }

    assert!(!BurnchainDB::has_anchor_block(burnchain_db.conn(), 1).unwrap());

    {
        let tx = burnchain_db.tx_begin().unwrap();
        tx.set_anchor_block(&cmts[3], 1).unwrap();
        tx.commit().unwrap();
    }

    assert!(BurnchainDB::has_anchor_block(burnchain_db.conn(), 1).unwrap());
    assert_eq!(
        BurnchainDB::get_anchor_block_commit(burnchain_db.conn(), &cmts[3].burn_header_hash, 1)
            .unwrap()
            .unwrap()
            .0,
        cmts[3]
    );
    assert!(BurnchainDB::is_anchor_block(
        burnchain_db.conn(),
        &cmts[3].burn_header_hash,
        &cmts[3].txid
    )
    .unwrap());
}

#[test]
fn test_update_block_descendancy() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];
    let mut cmts_genesis = vec![];
    let mut cmts_invalid = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 3,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    let mut am_id = 0;

    for i in 0..5 {
        let block_header = &headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );

        // make a second commit that builds off of genesis
        let mut cmt_genesis = cmt.clone();
        cmt_genesis.parent_block_ptr = 0;
        cmt_genesis.parent_vtxindex = 0;
        cmt_genesis.block_header_hash = BlockHeaderHash([((i + 1) as u8) | 0xa0; 32]);
        cmt_genesis.txid = next_txid();

        // make an invalid commit
        let mut cmt_invalid = cmt.clone();
        cmt_invalid.parent_vtxindex += 1;
        cmt_invalid.block_header_hash = BlockHeaderHash([((i + 1) as u8) | 0xc0; 32]);
        cmt_invalid.txid = next_txid();

        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                &burnchain,
                &headers,
                block_header,
                &vec![
                    BlockstackOperationType::LeaderBlockCommit(cmt.clone()),
                    BlockstackOperationType::LeaderBlockCommit(cmt_genesis.clone()),
                    BlockstackOperationType::LeaderBlockCommit(cmt_invalid.clone()),
                ],
            )
            .unwrap();

        cmts.push(cmt.clone());
        cmts_genesis.push(cmt_genesis.clone());
        cmts_invalid.push(cmt_invalid.clone());

        parent = Some(cmt);

        if i == 0 {
            am_id = {
                let tx = burnchain_db.tx_begin().unwrap();
                tx.set_anchor_block(&cmts[0], 1).unwrap();
                let am_id = tx
                    .insert_block_commit_affirmation_map(&AffirmationMap::decode("p").unwrap())
                    .unwrap();
                tx.update_block_commit_affirmation(&cmts[0], Some(1), am_id)
                    .unwrap();
                tx.commit().unwrap();
                am_id
            };
            assert_ne!(am_id, 0);
        }
    }

    // each valid commit should have cmts[0]'s affirmation map
    for i in 1..5 {
        let cmt_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts[i]).unwrap();
        assert_eq!(cmt_am_id.unwrap(), am_id);

        let genesis_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts_genesis[i])
                .unwrap();
        assert_eq!(genesis_am_id.unwrap(), 0);

        let invalid_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts_invalid[i])
                .unwrap();
        assert_eq!(invalid_am_id.unwrap(), 0);
    }
}

#[test]
fn test_update_block_descendancy_with_fork() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 0;
    let first_height = 1;

    let mut burnchain = Burnchain::regtest(":memory:");
    burnchain.pox_constants = burn_db_test_pox();
    burnchain.first_block_height = first_height;
    burnchain.first_block_hash = first_bhh.clone();
    burnchain.first_block_timestamp = first_timestamp;

    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();

    let mut headers = vec![first_block_header.clone()];
    let mut fork_headers = vec![first_block_header.clone()];

    let mut parent = None;
    let mut parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut cmts = vec![];
    let mut cmts_genesis = vec![];
    let mut cmts_invalid = vec![];

    let mut fork_parent = None;
    let mut fork_parent_block_header: Option<BurnchainBlockHeader> = None;
    let mut fork_cmts = vec![];

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 3,
            timestamp: i,
        };

        headers.push(block_header.clone());
        parent_block_header = Some(block_header);
    }

    for i in 0..5 {
        let hdr = BurnchainHeaderHash([(i + 128 + 1) as u8; 32]);
        let block_header = BurnchainBlockHeader {
            block_height: first_height + i,
            block_hash: hdr,
            parent_block_hash: parent_block_header
                .as_ref()
                .map(|blk| blk.block_hash.clone())
                .unwrap_or(first_block_header.block_hash.clone()),
            num_txs: 3,
            timestamp: i,
        };

        fork_headers.push(block_header.clone());
        fork_parent_block_header = Some(block_header);
    }

    let mut am_id = 0;
    let mut fork_am_id = 0;

    for i in 0..5 {
        let block_header = &headers[i + 1];
        let fork_block_header = &fork_headers[i + 1];

        let cmt = make_simple_block_commit(
            &burnchain,
            parent.as_ref(),
            block_header,
            BlockHeaderHash([((i + 1) as u8) | 0x80; 32]),
        );

        // make a second commit that builds off of genesis
        let mut cmt_genesis = cmt.clone();
        cmt_genesis.parent_block_ptr = 0;
        cmt_genesis.parent_vtxindex = 0;
        cmt_genesis.block_header_hash = BlockHeaderHash([((i + 1) as u8) | 0xa0; 32]);
        cmt_genesis.txid = next_txid();

        // make an invalid commit
        let mut cmt_invalid = cmt.clone();
        cmt_invalid.parent_vtxindex += 1;
        cmt_invalid.block_header_hash = BlockHeaderHash([((i + 1) as u8) | 0xc0; 32]);
        cmt_invalid.txid = next_txid();

        // make a commit on the fork
        let mut fork_cmt = cmt.clone();
        fork_cmt.burn_header_hash = fork_block_header.block_hash.clone();
        fork_cmt.vtxindex = 100;
        fork_cmt.parent_vtxindex = 100;

        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                &burnchain,
                &headers,
                block_header,
                &vec![
                    BlockstackOperationType::LeaderBlockCommit(cmt.clone()),
                    BlockstackOperationType::LeaderBlockCommit(cmt_genesis.clone()),
                    BlockstackOperationType::LeaderBlockCommit(cmt_invalid.clone()),
                ],
            )
            .unwrap();

        burnchain_db
            .store_new_burnchain_block_ops_unchecked(
                &burnchain,
                &fork_headers,
                fork_block_header,
                &vec![BlockstackOperationType::LeaderBlockCommit(fork_cmt.clone())],
            )
            .unwrap();

        cmts.push(cmt.clone());
        cmts_genesis.push(cmt_genesis.clone());
        cmts_invalid.push(cmt_invalid.clone());
        fork_cmts.push(fork_cmt.clone());

        parent = Some(cmt);
        fork_parent = Some(fork_cmt);

        if i == 0 {
            am_id = {
                let tx = burnchain_db.tx_begin().unwrap();
                tx.set_anchor_block(&cmts[0], 1).unwrap();
                let am_id = tx
                    .insert_block_commit_affirmation_map(&AffirmationMap::decode("p").unwrap())
                    .unwrap();
                tx.update_block_commit_affirmation(&cmts[0], Some(1), am_id)
                    .unwrap();
                tx.commit().unwrap();
                am_id
            };
            assert_ne!(am_id, 0);

            fork_am_id = {
                let tx = burnchain_db.tx_begin().unwrap();
                tx.set_anchor_block(&fork_cmts[0], 1).unwrap();
                let fork_am_id = tx
                    .insert_block_commit_affirmation_map(&AffirmationMap::decode("a").unwrap())
                    .unwrap();
                tx.update_block_commit_affirmation(&fork_cmts[0], Some(1), fork_am_id)
                    .unwrap();
                tx.commit().unwrap();
                fork_am_id
            };
            assert_ne!(fork_am_id, 0);
        }
    }

    // each valid commit should have cmts[0]'s affirmation map
    for i in 1..5 {
        let cmt_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts[i]).unwrap();
        assert_eq!(cmt_am_id.unwrap(), am_id);

        let genesis_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts_genesis[i])
                .unwrap();
        assert_eq!(genesis_am_id.unwrap(), 0);

        let invalid_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &cmts_invalid[i])
                .unwrap();
        assert_eq!(invalid_am_id.unwrap(), 0);
    }

    // each valid commit should have fork_cmts[0]'s affirmation map
    for i in 1..5 {
        let cmt_am_id =
            BurnchainDB::get_block_commit_affirmation_id(burnchain_db.conn(), &fork_cmts[i])
                .unwrap();
        assert_eq!(cmt_am_id.unwrap(), fork_am_id);
    }
}

#[test]
fn test_classify_delegate_stx() {
    let first_bhh = BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap();
    let first_timestamp = 321;
    let first_height = 0;

    let mut burnchain = Burnchain::regtest(":memory:");
    let mut burnchain_db = BurnchainDB::connect(":memory:", &burnchain, true).unwrap();

    burnchain.pox_constants = PoxConstants::test_default();

    let first_block_header = burnchain_db.get_canonical_chain_tip().unwrap();
    assert_eq!(&first_block_header.block_hash, &first_bhh);
    assert_eq!(&first_block_header.block_height, &first_height);
    assert_eq!(
        &first_block_header.parent_block_hash,
        &BurnchainHeaderHash::sentinel()
    );

    let canon_hash = BurnchainHeaderHash([1; 32]);

    let canonical_block =
        BurnchainBlock::Bitcoin(BitcoinBlock::new(500, &canon_hash, &first_bhh, vec![], 485));
    let mut headers = vec![first_block_header.clone(), canonical_block.header().clone()];

    let ops = burnchain_db
        .store_new_burnchain_block(
            &burnchain,
            &headers,
            &canonical_block,
            StacksEpochId::Epoch21,
        )
        .unwrap();
    assert_eq!(ops.len(), 0);

    // let's mine a block with a pre-stx tx, and an invalid delegate-stx tx,
    //    the delegate-stx tx should _fail_ to verify, because there's it
    //    doesn't set the txid of the pre-stx in its input.

    let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

    let pre_delegate_stx_0_txid = Txid([5; 32]);
    let pre_delegate_stx_0 = BitcoinTransaction {
        txid: pre_delegate_stx_0_txid.clone(),
        vtxindex: 0,
        opcode: Opcodes::PreStx as u8,
        data: vec![0; 80],
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // Set up the data field for the delegate stx transactions
    let mut data = vec![1; 80];
    // Make it so that reward_addr_index = Some(1)
    for i in 17..20 {
        data[i] = 0;
    }

    // this one will not have a corresponding pre_stx tx.
    let delegate_stx_0 = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 1,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // this one will have a corresponding pre_stx tx.
    let delegate_stx_0_second_attempt = BitcoinTransaction {
        txid: Txid([4; 32]),
        vtxindex: 2,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_delegate_stx_0_txid.clone(), 1),
        }
        .into()],
        outputs: vec![
            BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                }
                .into(),
            },
            BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                }
                .into(),
            },
        ],
    };

    // this one won't have a corresponding pre_stx tx.
    let delegate_stx_1 = BitcoinTransaction {
        txid: Txid([3; 32]),
        vtxindex: 3,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (Txid([0; 32]), 1),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    // This one won't use the correct output from the pre stx transaction.
    // It tries to use the second output from the pre stx tx, which DNE.
    let delegate_stx_2 = BitcoinTransaction {
        txid: Txid([8; 32]),
        vtxindex: 4,
        opcode: Opcodes::DelegateStx as u8,
        data: data.clone(),
        data_amt: 0,
        inputs: vec![BitcoinTxInputStructured {
            keys: vec![],
            num_required: 0,
            in_type: BitcoinInputType::Standard,
            tx_ref: (pre_delegate_stx_0_txid.clone(), 2),
        }
        .into()],
        outputs: vec![BitcoinTxOutput {
            units: 10,
            address: LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }
            .into(),
        }],
    };

    let ops_0 = vec![pre_delegate_stx_0, delegate_stx_0];

    let ops_1 = vec![
        delegate_stx_1,
        delegate_stx_0_second_attempt,
        delegate_stx_2,
    ];

    let block_height_0 = 501;
    let block_hash_0 = BurnchainHeaderHash([2; 32]);
    let block_height_1 = 502;
    let block_hash_1 = BurnchainHeaderHash([3; 32]);

    let ops_0_length = ops_0.len();
    let ops_1_length = ops_1.len();
    let block_0 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_0,
        &block_hash_0,
        &first_bhh,
        ops_0,
        350,
    ));

    let block_1 = BurnchainBlock::Bitcoin(BitcoinBlock::new(
        block_height_1,
        &block_hash_1,
        &block_hash_0,
        ops_1,
        360,
    ));

    headers.push(block_0.header().clone());
    headers.push(block_1.header().clone());

    test_debug!("store ops ({}) for block 0", ops_0_length);
    let processed_ops_0 = burnchain_db
        .store_new_burnchain_block(&burnchain, &headers, &block_0, StacksEpochId::Epoch21)
        .unwrap();

    assert_eq!(
        processed_ops_0.len(),
        1,
        "Only pre_delegate_stx op should have been accepted"
    );

    test_debug!("store ops ({}) for block 1", ops_1_length);
    let processed_ops_1 = burnchain_db
        .store_new_burnchain_block(&burnchain, &headers, &block_1, StacksEpochId::Epoch21)
        .unwrap();

    assert_eq!(
        processed_ops_1.len(),
        1,
        "Only one delegate_stx op should have been accepted"
    );

    let expected_pre_delegate_addr =
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([1; 20]),
        });

    let expected_delegate_addr = PoxAddress::Standard(
        StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
            addrtype: LegacyBitcoinAddressType::PublicKeyHash,
            network_id: BitcoinNetworkType::Mainnet,
            bytes: Hash160([2; 20]),
        }),
        Some(AddressHashMode::SerializeP2PKH),
    );

    let expected_reward_addr = Some((
        1,
        PoxAddress::Standard(
            StacksAddress::from_legacy_bitcoin_address(&LegacyBitcoinAddress {
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                network_id: BitcoinNetworkType::Mainnet,
                bytes: Hash160([1; 20]),
            }),
            Some(AddressHashMode::SerializeP2PKH),
        ),
    ));

    if let BlockstackOperationType::PreStx(op) = &processed_ops_0[0] {
        assert_eq!(&op.output, &expected_pre_delegate_addr);
    } else {
        panic!("EXPECTED to parse a pre delegate stx op");
    }

    if let BlockstackOperationType::DelegateStx(op) = &processed_ops_1[0] {
        assert_eq!(&op.sender, &expected_pre_delegate_addr);
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.delegate_to, StacksAddress::new(22, Hash160([2u8; 20])));
        assert_eq!(&op.reward_addr, &expected_reward_addr);
        assert_eq!(op.until_burn_height, Some(u64::from_be_bytes([1; 8])));
    } else {
        panic!("EXPECTED to parse a delegate stx op");
    }
}
