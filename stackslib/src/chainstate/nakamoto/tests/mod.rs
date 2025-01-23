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

use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::fs;

use clarity::types::chainstate::{PoxId, SortitionId, StacksBlockId};
use clarity::util::secp256k1::Secp256k1PrivateKey;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::Value;
use libstackerdb::StackerDBChunkData;
use rand::distributions::Standard;
use rand::{thread_rng, Rng, RngCore};
use rusqlite::types::ToSql;
use rusqlite::{params, Connection};
use stacks_common::address::AddressHashMode;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::{
    CHAIN_ID_MAINNET, CHAIN_ID_TESTNET, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey,
    StacksPublicKey, StacksWorkScore, TrieHash, VRFSeed,
};
use stacks_common::types::{Address, PrivateKey, StacksEpoch, StacksEpochId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};
use stdext::prelude::Integer;
use stx_genesis::GenesisData;

use crate::burnchains::{BurnchainSigner, PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::tests::make_fork_run;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::leader_block_commit::BURN_BLOCK_MINED_AT_MODULUS;
use crate::chainstate::burn::operations::{
    BlockstackOperationType, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::{BlockSnapshot, OpsHash, SortitionHash};
use crate::chainstate::coordinator::tests::{
    get_burnchain, get_burnchain_db, get_chainstate, get_rw_sortdb, get_sortition_db, p2pkh_from,
    pox_addr_from, setup_states_with_epochs,
};
use crate::chainstate::nakamoto::coordinator::tests::boot_nakamoto;
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::nakamoto::staging_blocks::{
    NakamotoBlockObtainMethod, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::nakamoto::tenure::NakamotoTenureEvent;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::nakamoto::{
    query_row, NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, SortitionHandle,
    FIRST_STACKS_BLOCK_ID,
};
use crate::chainstate::stacks::boot::{
    NakamotoSignerEntry, RewardSet, MINERS_NAME, SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{
    ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName,
    ChainstateBNSNamespace, StacksAccount, StacksBlockHeaderTypes, StacksChainState,
    StacksHeaderInfo,
};
use crate::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksTransaction,
    StacksTransactionSigner, TenureChangeCause, TenureChangePayload, TokenTransferMemo,
    TransactionAnchorMode, TransactionAuth, TransactionContractCall, TransactionPayload,
    TransactionPostConditionMode, TransactionSmartContract, TransactionVersion,
};
use crate::core;
use crate::core::{StacksEpochExtension, STACKS_EPOCH_3_0_MARKER};
use crate::net::codec::test::check_codec_and_corruption;
use crate::net::stackerdb::MINER_SLOT_COUNT;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as db_error;
use crate::util_lib::strings::StacksString;

impl NakamotoStagingBlocksConnRef<'_> {
    pub fn get_all_blocks_in_tenure(
        &self,
        tenure_id_consensus_hash: &ConsensusHash,
        tip: &StacksBlockId,
    ) -> Result<Vec<NakamotoBlock>, ChainstateError> {
        let mut blocks = vec![];
        let mut cursor = tip.clone();
        let qry = "SELECT data FROM nakamoto_staging_blocks WHERE index_block_hash = ?1";
        loop {
            let Some(block_data): Option<Vec<u8>> = query_row(self, qry, params![cursor])? else {
                break;
            };
            let block = NakamotoBlock::consensus_deserialize(&mut block_data.as_slice())?;
            if &block.header.consensus_hash != tenure_id_consensus_hash {
                break;
            }
            cursor = block.header.parent_block_id.clone();
            blocks.push(block);
        }
        blocks.reverse();
        Ok(blocks)
    }
}

/// Get an address's account
pub fn get_account(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    addr: &StacksAddress,
) -> StacksAccount {
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
        .unwrap()
        .unwrap();
    debug!(
        "Canonical block header is {}/{} ({}): {:?}",
        &tip.consensus_hash,
        &tip.anchored_header.block_hash(),
        &tip.index_block_hash(),
        &tip
    );

    let snapshot = SortitionDB::get_block_snapshot_consensus(&sortdb.conn(), &tip.consensus_hash)
        .unwrap()
        .unwrap();
    chainstate
        .with_read_only_clarity_tx(
            &sortdb.index_handle(&snapshot.sortition_id),
            &tip.index_block_hash(),
            |clarity_conn| {
                StacksChainState::get_account(clarity_conn, &addr.to_account_principal())
            },
        )
        .unwrap()
}

fn test_path(name: &str) -> String {
    format!("/tmp/stacks-node-tests/nakamoto-tests/{}", name)
}

pub mod node;

#[test]
fn codec_nakamoto_header() {
    let header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![MessageSignature::from_bytes(&[0x01; 65]).unwrap()],
        pox_treatment: BitVec::zeros(8).unwrap(),
    };

    let mut bytes = vec![
        // version
        0x01, // chain length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // burn spent
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // consensus hash
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04, 0x04, // parent block id
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, // tx merkle root
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, // state index root
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, // timestamp
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // miner signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // signatures length
        0x00, 0x00, 0x00, 0x01, // stacker signature (mocked)
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01,
    ];

    let signer_bitvec_serialization = "00080000000100";
    bytes.append(&mut hex_bytes(signer_bitvec_serialization).unwrap());

    check_codec_and_corruption(&header, &bytes);
}

#[test]
pub fn test_nakamoto_first_tenure_block_syntactic_validation() {
    let private_key = StacksPrivateKey::new();
    let header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    // sortition-inducing tenure change
    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };

    // non-sortition-inducing tenure change
    let tenure_extend_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x04; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::Extended,
        pubkey_hash: Hash160([0x02; 20]),
    };

    let invalid_tenure_change_payload = TenureChangePayload {
        // bad parent block ID
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x00; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };

    let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof.clone()));

    // invalid coinbase payload -- needs a proof
    let invalid_coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, None);

    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(tenure_change_payload.clone()),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut tenure_extend_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(tenure_extend_payload.clone()),
    );
    tenure_extend_tx.chain_id = 0x80000000;
    tenure_extend_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut invalid_tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(invalid_tenure_change_payload.clone()),
    );
    invalid_tenure_change_tx.chain_id = 0x80000000;
    invalid_tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut invalid_coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        invalid_coinbase_payload.clone(),
    );
    invalid_coinbase_tx.chain_id = 0x80000000;
    invalid_coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut stx_transfer = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(
            recipient_addr.to_account_principal(),
            1,
            TokenTransferMemo([0x00; 34]),
        ),
    );
    stx_transfer.chain_id = 0x80000000;
    stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;

    // no tenure change if the block doesn't have a tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    ); // empty blocks not allowed

    // syntactically invalid block if there's a sortition-inducing tenure change but no coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there's a coinbase but not tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there's a coinbase and tenure change, but the coinbase is
    // missing a proof
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone(), invalid_coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there is more than one coinbase transaction
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if the coinbase comes before a tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![coinbase_tx.clone(), tenure_change_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there is a tenure change after the coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
            tenure_change_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntatically invalid block if there's an invalid tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            invalid_tenure_change_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically valid tenure-start block only if we have a syntactically valid tenure change and a syntactically
    // valid coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(true));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), Some(&coinbase_tx));
    assert_eq!(
        block.get_tenure_change_tx_payload(),
        Some(&tenure_change_payload)
    );
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), Some(&proof));
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically valid non-tenure-start block only if we have a syntactically valid tenure change which is not sortition-induced,
    // or we don't have one at all.
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(true));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(
        block.get_tenure_extend_tx_payload(),
        Some(&tenure_extend_payload)
    );
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically valid non-tenure-start block only if we have a syntactically valid tenure change which is not sortition-induced,
    // or we don't have one at all.
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone(), stx_transfer.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(true));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(
        block.get_tenure_extend_tx_payload(),
        Some(&tenure_extend_payload)
    );
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically invalid if there's more than one tenure change, no matter what
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone(), tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid if there's a tx before the one tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![stx_transfer.clone(), tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // invalid if there are multiple tenure changes
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );
}

/// Tests for non-MARF'ed block storage
#[test]
pub fn test_load_store_update_nakamoto_blocks() {
    let test_name = function_name!();
    let path = test_path(&test_name);
    let pox_constants = PoxConstants::new(5, 3, 3, 25, 5, 0, 0, 0, 0, 0, 0);
    let epochs = StacksEpoch::unit_test_3_0_only(1);
    let _ = std::fs::remove_dir_all(&path);
    let burnchain_conf = get_burnchain(&path, Some(pox_constants.clone()));

    setup_states_with_epochs(
        &[&path],
        &[],
        &[],
        Some(pox_constants.clone()),
        None,
        StacksEpochId::Epoch30,
        Some(epochs),
    );

    let private_key = StacksPrivateKey::new();
    let epoch2_proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let epoch2_proof = VRFProof::from_bytes(&epoch2_proof_bytes[..].to_vec()).unwrap();

    let nakamoto_proof_bytes = hex_bytes("973c815ac3e81a4aff3243f3d8310d24ab9783acd6caa4dcfab20a3744584b2f966acf08140e1a7e1e685695d51b1b511f4f19260a21887244a6c47f7637b8bdeaf5eafe85c1975bab75bc0668fe8a0b").unwrap();
    let nakamoto_proof = VRFProof::from_bytes(&nakamoto_proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload = TransactionPayload::Coinbase(
        CoinbasePayload([0x12; 32]),
        None,
        Some(nakamoto_proof.clone()),
    );

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let epoch2_txs = vec![coinbase_tx.clone()];
    let epoch2_tx_merkle_root = {
        let txid_vecs: Vec<_> = epoch2_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let epoch2_header = StacksBlockHeader {
        version: 0,
        total_work: StacksWorkScore {
            burn: 123,
            work: 456,
        },
        proof: epoch2_proof.clone(),
        parent_block: BlockHeaderHash([0x11; 32]),
        parent_microblock: BlockHeaderHash([0x00; 32]),
        parent_microblock_sequence: 0,
        tx_merkle_root: epoch2_tx_merkle_root,
        state_index_root: TrieHash([0x55; 32]),
        microblock_pubkey_hash: Hash160([0x66; 20]),
    };
    let epoch2_consensus_hash = ConsensusHash([0x03; 20]);
    let epoch2_parent_block_id =
        StacksBlockId::new(&epoch2_consensus_hash, &epoch2_header.block_hash());

    let epoch2_header_info = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Epoch2(epoch2_header.clone()),
        microblock_tail: None,
        stacks_block_height: epoch2_header.total_work.work,
        index_root: TrieHash([0x56; 32]),
        consensus_hash: epoch2_consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x77; 32]),
        burn_header_height: 100,
        burn_header_timestamp: 1000,
        anchored_block_size: 12345,
        burn_view: None,
    };

    let epoch2_execution_cost = ExecutionCost {
        write_length: 100,
        write_count: 101,
        read_length: 102,
        read_count: 103,
        runtime: 104,
    };

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: epoch2_consensus_hash.clone(),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: epoch2_parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };

    let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload.clone());
    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut stx_transfer_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(recipient_addr.into(), 123, TokenTransferMemo([0u8; 34])),
    );
    stx_transfer_tx.chain_id = 0x80000000;
    stx_transfer_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut stx_transfer_tx_3 = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(recipient_addr.into(), 124, TokenTransferMemo([0u8; 34])),
    );
    stx_transfer_tx_3.chain_id = 0x80000000;
    stx_transfer_tx_3.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut stx_transfer_tx_4 = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(recipient_addr.into(), 125, TokenTransferMemo([0u8; 34])),
    );
    stx_transfer_tx_4.chain_id = 0x80000000;
    stx_transfer_tx_4.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let nakamoto_txs = vec![tenure_change_tx.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root = {
        let txid_vecs: Vec<_> = nakamoto_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_2 = vec![stx_transfer_tx.clone()];
    let nakamoto_tx_merkle_root_2 = {
        let txid_vecs: Vec<_> = nakamoto_txs_2
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_3 = vec![stx_transfer_tx_3.clone()];
    let nakamoto_tx_merkle_root_3 = {
        let txid_vecs: Vec<_> = nakamoto_txs_3
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_4 = vec![stx_transfer_tx_4.clone()];
    let nakamoto_tx_merkle_root_4 = {
        let txid_vecs: Vec<_> = nakamoto_txs_4
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let header_signatures = vec![
        MessageSignature::from_bytes(&[0x01; 65]).unwrap(),
        MessageSignature::from_bytes(&[0x02; 65]).unwrap(),
    ];

    let nakamoto_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: epoch2_parent_block_id.clone(),
        tx_merkle_root: nakamoto_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: header_signatures.clone(),
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nakamoto_header_info = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
        burn_view: Some(nakamoto_header.consensus_hash),
    };

    let epoch2_block = StacksBlock {
        header: epoch2_header.clone(),
        txs: epoch2_txs,
    };

    let nakamoto_block = NakamotoBlock {
        header: nakamoto_header.clone(),
        txs: nakamoto_txs,
    };

    let nakamoto_execution_cost = ExecutionCost {
        write_length: 200,
        write_count: 201,
        read_length: 202,
        read_count: 203,
        runtime: 204,
    };

    // second nakamoto block
    let nakamoto_header_2 = NakamotoBlockHeader {
        version: 1,
        chain_length: 458,
        burn_spent: 127,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: nakamoto_header.block_id(),
        tx_merkle_root: nakamoto_tx_merkle_root_2,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nakamoto_header_info_2 = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header_2.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header_2.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header_2.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
        burn_view: Some(nakamoto_header_2.consensus_hash),
    };

    let nakamoto_block_2 = NakamotoBlock {
        header: nakamoto_header_2.clone(),
        txs: nakamoto_txs_2,
    };

    let nakamoto_execution_cost_2 = ExecutionCost {
        write_length: 200,
        write_count: 201,
        read_length: 202,
        read_count: 203,
        runtime: 204,
    };

    // third nakamoto block
    let nakamoto_header_3 = NakamotoBlockHeader {
        version: 1,
        chain_length: 459,
        burn_spent: 128,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: nakamoto_header_2.block_id(),
        tx_merkle_root: nakamoto_tx_merkle_root_3,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nakamoto_header_info_3 = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header_3.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header_2.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header_2.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
        burn_view: Some(nakamoto_header_3.consensus_hash),
    };

    let nakamoto_block_3 = NakamotoBlock {
        header: nakamoto_header_3.clone(),
        txs: nakamoto_txs_3.clone(),
    };

    // third nakamoto block, but with a higher signing weight
    let nakamoto_header_3_weight_2 = NakamotoBlockHeader {
        version: 1,
        chain_length: 459,
        burn_spent: 128,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: nakamoto_header_2.block_id(),
        tx_merkle_root: nakamoto_tx_merkle_root_3,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![MessageSignature::from_bytes(&[0x01; 65]).unwrap()],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nakamoto_header_info_3_weight_2 = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header_3_weight_2.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header_2.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header_2.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
        burn_view: Some(nakamoto_header_3.consensus_hash),
    };

    let nakamoto_block_3_weight_2 = NakamotoBlock {
        header: nakamoto_header_3_weight_2.clone(),
        txs: nakamoto_txs_3.clone(),
    };

    // fourth nakamoto block -- confirms nakamoto_block_3_weight_2
    let nakamoto_header_4 = NakamotoBlockHeader {
        version: 1,
        chain_length: 460,
        burn_spent: 128,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: nakamoto_header_3_weight_2.block_id(),
        tx_merkle_root: nakamoto_tx_merkle_root_4,
        state_index_root: TrieHash([0x71; 32]),
        timestamp: 10,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let nakamoto_header_info_4 = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header_4.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header_4.chain_length,
        index_root: TrieHash([0x71; 32]),
        consensus_hash: nakamoto_header_3_weight_2.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
        burn_view: Some(nakamoto_header_4.consensus_hash),
    };

    let nakamoto_block_4 = NakamotoBlock {
        header: nakamoto_header_4.clone(),
        txs: nakamoto_txs_4.clone(),
    };

    // nakamoto block 3 only differs in signers
    assert_eq!(
        nakamoto_block_3.block_id(),
        nakamoto_block_3_weight_2.block_id()
    );
    assert_eq!(
        nakamoto_block_3.header.signer_signature_hash(),
        nakamoto_block_3_weight_2.header.signer_signature_hash()
    );

    let mut total_nakamoto_execution_cost = nakamoto_execution_cost.clone();
    total_nakamoto_execution_cost
        .add(&nakamoto_execution_cost_2)
        .unwrap();

    let nakamoto_tenure = NakamotoTenureEvent {
        tenure_id_consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        prev_tenure_id_consensus_hash: tenure_change_payload.prev_tenure_consensus_hash.clone(),
        burn_view_consensus_hash: tenure_change_payload.burn_view_consensus_hash.clone(),
        cause: tenure_change_payload.cause,
        block_hash: nakamoto_block.header.block_hash(),
        block_id: nakamoto_block.header.block_id(),
        coinbase_height: epoch2_header.total_work.work + 1,
        num_blocks_confirmed: 1,
    };

    let mut chainstate = get_chainstate(&path);

    // store epoch2 and nakamoto headers
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();

        StacksChainState::insert_stacks_block_header(
            &tx,
            &epoch2_parent_block_id,
            &epoch2_header_info,
            &epoch2_execution_cost,
            1,
        )
        .unwrap();

        // tenure length doesn't apply to epoch2 blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &epoch2_header_info.index_block_hash()
            )
            .unwrap(),
            0
        );

        // but, this upcoming tenure-change payload should be the first-ever tenure-change payload!
        assert!(NakamotoChainState::check_first_nakamoto_tenure_change(
            &tx,
            &tenure_change_payload
        )
        .unwrap()
        .is_some());

        // no tenure yet, so zero blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(&tx, &nakamoto_block.header.block_id(),)
                .unwrap(),
            0
        );

        // add the tenure for these blocks
        NakamotoChainState::insert_nakamoto_tenure(
            &tx,
            &nakamoto_header,
            epoch2_header.total_work.work + 1,
            &tenure_change_payload,
        )
        .unwrap();

        // no blocks yet, so zero blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(&tx, &nakamoto_block.header.block_id(),)
                .unwrap(),
            0
        );

        // this succeeds now
        NakamotoChainState::insert_stacks_block_header(
            &tx,
            &nakamoto_header_info,
            &nakamoto_header,
            Some(&nakamoto_proof),
            &nakamoto_execution_cost,
            &nakamoto_execution_cost,
            true,
            1,
            300,
        )
        .unwrap();
        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block,
            false,
            1,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();

        // tenure has one block
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(&tx, &nakamoto_block.header.block_id(),)
                .unwrap(),
            1
        );

        // this succeeds now
        NakamotoChainState::insert_stacks_block_header(
            &tx,
            &nakamoto_header_info_2,
            &nakamoto_header_2,
            None,
            &nakamoto_execution_cost,
            &total_nakamoto_execution_cost,
            false,
            2,
            400,
        )
        .unwrap();

        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_2,
            false,
            1,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();

        // tenure has two blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &nakamoto_block_2.header.block_id(),
            )
            .unwrap(),
            2
        );
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(&tx, &nakamoto_block.header.block_id(),)
                .unwrap(),
            1
        );

        // store, but do not process, a block
        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3,
            false,
            1,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();
        assert_eq!(
            staging_tx
                .conn()
                .get_nakamoto_block(&nakamoto_header_3.block_id())
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_3
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3.consensus_hash,
                    &nakamoto_header_3.block_hash(),
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3.block_id(), false, false, 1)
        );

        // store, but do not process, the same block with a heavier weight
        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3_weight_2,
            false,
            2,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();
        assert_eq!(
            staging_tx
                .conn()
                .get_nakamoto_block(&nakamoto_header_3_weight_2.block_id())
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_3_weight_2
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3.consensus_hash,
                    &nakamoto_header_3.block_hash(),
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3_weight_2.block_id(), false, false, 2)
        );

        staging_tx.commit().unwrap();
        tx.commit().unwrap();
    }

    // can load Nakamoto block, but only the Nakamoto block
    let nakamoto_blocks_db = chainstate.nakamoto_blocks_db();
    let first_nakamoto_block = nakamoto_blocks_db
        .get_nakamoto_block(&nakamoto_header.block_id())
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(first_nakamoto_block, nakamoto_block,);
    // Double check that the signatures match
    assert_eq!(
        first_nakamoto_block.header.signer_signature,
        header_signatures
    );
    assert_eq!(
        nakamoto_blocks_db
            .get_nakamoto_block(&nakamoto_header_2.block_id())
            .unwrap()
            .unwrap()
            .0,
        nakamoto_block_2
    );
    assert_eq!(
        nakamoto_blocks_db
            .get_nakamoto_block(&epoch2_header_info.index_block_hash())
            .unwrap(),
        None
    );

    // nakamoto block should be treated as processed because even though the processed flag is not
    // set, the header is present (meaning that we're in-between processing the block and marking
    // it processed in the staging DB)
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.nakamoto_blocks_db(),
            chainstate.db(),
            &nakamoto_header.consensus_hash,
            &nakamoto_header.block_hash()
        )
        .unwrap()
        .unwrap(),
        (true, false)
    );

    // however, in the staging DB, this block is not yet marked as processed
    assert_eq!(
        chainstate
            .nakamoto_blocks_db()
            .get_block_processed_and_signed_weight(
                &nakamoto_header.consensus_hash,
                &nakamoto_header.block_hash(),
            )
            .unwrap()
            .unwrap(),
        (nakamoto_header.block_id(), false, false, 1)
    );

    // same goes for block 2
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.nakamoto_blocks_db(),
            chainstate.db(),
            &nakamoto_header_2.consensus_hash,
            &nakamoto_header_2.block_hash()
        )
        .unwrap()
        .unwrap(),
        (true, false)
    );
    assert_eq!(
        chainstate
            .nakamoto_blocks_db()
            .get_block_processed_and_signed_weight(
                &nakamoto_header.consensus_hash,
                &nakamoto_header_2.block_hash(),
            )
            .unwrap()
            .unwrap(),
        (nakamoto_header_2.block_id(), false, false, 1)
    );

    // block 3 has only been stored, but no header has been added
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.nakamoto_blocks_db(),
            chainstate.db(),
            &nakamoto_header_3_weight_2.consensus_hash,
            &nakamoto_header_3_weight_2.block_hash()
        )
        .unwrap()
        .unwrap(),
        (false, false)
    );

    assert_eq!(
        chainstate
            .nakamoto_blocks_db()
            .get_block_processed_and_signed_weight(
                &nakamoto_header_3_weight_2.consensus_hash,
                &nakamoto_header_3_weight_2.block_hash()
            )
            .unwrap()
            .unwrap(),
        (nakamoto_header_3_weight_2.block_id(), false, false, 2)
    );

    // this method doesn't return data for epoch2
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.nakamoto_blocks_db(),
            chainstate.db(),
            &epoch2_header_info.consensus_hash,
            &epoch2_header.block_hash()
        )
        .unwrap(),
        None
    );

    // set nakamoto block processed, and store a sibling if it's the chain tip
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();

        staging_tx
            .set_block_processed(&nakamoto_header_3_weight_2.block_id())
            .unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header_3_weight_2.consensus_hash,
                &nakamoto_header_3_weight_2.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, false)
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3_weight_2.consensus_hash,
                    &nakamoto_header_3_weight_2.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3_weight_2.block_id(), true, false, 2)
        );

        // store a sibling with more weight, even though this block has been processed.
        // This is allowed because we don't commit to signatures.
        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3,
            false,
            3,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();
        assert_eq!(
            staging_tx
                .conn()
                .get_nakamoto_block(&nakamoto_header_3.block_id())
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_3
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3.consensus_hash,
                    &nakamoto_header_3.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3.block_id(), true, false, 3)
        );
    }

    // set nakamoto block processed, and store a processed children, and verify that we'll still
    // accept siblings with higher signing power.
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();

        // set block 3 weight 2 processed
        staging_tx
            .set_block_processed(&nakamoto_header_3_weight_2.block_id())
            .unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header_3_weight_2.consensus_hash,
                &nakamoto_header_3_weight_2.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, false)
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3_weight_2.consensus_hash,
                    &nakamoto_header_3_weight_2.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3_weight_2.block_id(), true, false, 2)
        );

        // store block 4, which descends from block 3 weight 2
        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_4,
            false,
            1,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();
        assert_eq!(
            staging_tx
                .conn()
                .get_nakamoto_block(&nakamoto_header_4.block_id())
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_4
        );

        // set block 4 processed
        staging_tx
            .set_block_processed(&nakamoto_header_4.block_id())
            .unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header_4.consensus_hash,
                &nakamoto_header_4.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, false)
        );

        NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3,
            false,
            3,
            NakamotoBlockObtainMethod::Downloaded,
        )
        .unwrap();
        assert_eq!(
            staging_tx
                .conn()
                .get_nakamoto_block(&nakamoto_header_3.block_id())
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_3
        );
    }
    // set nakamoto block orphaned
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();
        staging_tx
            .set_block_orphaned(&nakamoto_header_3_weight_2.block_id())
            .unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header_3_weight_2.consensus_hash,
                &nakamoto_header_3_weight_2.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, true)
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3_weight_2.consensus_hash,
                    &nakamoto_header_3_weight_2.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3_weight_2.block_id(), true, true, 2)
        );

        // can't re-store it, even if its signing power is better
        assert!(!NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3_weight_2,
            false,
            3,
            NakamotoBlockObtainMethod::Downloaded
        )
        .unwrap());
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header_3_weight_2.consensus_hash,
                &nakamoto_header_3_weight_2.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, true)
        );

        // can't store a sibling with the same sighash either, since if a block with the given sighash is orphaned, then
        // it doesn't matter how many signers it has
        assert!(!NakamotoChainState::store_block_if_better(
            &staging_tx,
            &nakamoto_block_3,
            false,
            3,
            NakamotoBlockObtainMethod::Downloaded
        )
        .unwrap());
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header_3.consensus_hash,
                    &nakamoto_header_3.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header_3_weight_2.block_id(), true, true, 2)
        );
    }
    // orphan nakamoto block by parent
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();
        staging_tx
            .set_block_orphaned(&nakamoto_header.parent_block_id)
            .unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                staging_tx.conn(),
                &tx,
                &nakamoto_header.consensus_hash,
                &nakamoto_header.block_hash()
            )
            .unwrap()
            .unwrap(),
            (false, true)
        );
        assert_eq!(
            staging_tx
                .conn()
                .get_block_processed_and_signed_weight(
                    &nakamoto_header.consensus_hash,
                    &nakamoto_header.block_hash()
                )
                .unwrap()
                .unwrap(),
            (nakamoto_header.block_id(), false, true, 1)
        );
    }

    // can query the tenure-start and epoch2 headers by block ID
    assert_eq!(
        NakamotoChainState::get_block_header(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        nakamoto_header_info
    );
    assert_eq!(
        NakamotoChainState::get_block_header(chainstate.db(), &nakamoto_header_2.block_id())
            .unwrap()
            .unwrap(),
        nakamoto_header_info_2
    );
    assert_eq!(
        NakamotoChainState::get_block_header(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap()
        .unwrap(),
        epoch2_header_info
    );

    // can get total tenure cost for nakamoto blocks, but not epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        nakamoto_execution_cost
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(
            chainstate.db(),
            &nakamoto_header_2.block_id()
        )
        .unwrap()
        .unwrap(),
        total_nakamoto_execution_cost
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap(),
        None
    );

    // can get total tenure tx fees for nakamoto blocks, but not in epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_total_tenure_tx_fees_at(
            chainstate.db(),
            &nakamoto_header.block_id()
        )
        .unwrap()
        .unwrap(),
        300
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_tx_fees_at(
            chainstate.db(),
            &nakamoto_header_2.block_id()
        )
        .unwrap()
        .unwrap(),
        400
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_tx_fees_at(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap(),
        None
    );

    // can get nakamoto VRF proof only for nakamoto blocks
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_vrf_proof(
            chainstate.db(),
            &nakamoto_header.block_id(),
        )
        .unwrap()
        .unwrap(),
        nakamoto_proof
    );
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_vrf_proof(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap(),
        None
    );

    // next ready nakamoto block is None unless both the burn block and stacks parent block have
    // been processed
    {
        let (tx, staging_tx) = chainstate.headers_and_staging_tx_begin().unwrap();
        let staging_conn = staging_tx.conn();

        assert_eq!(staging_conn.next_ready_nakamoto_block(&tx).unwrap(), None);

        // set parent epoch2 block processed
        staging_tx
            .set_block_processed(&epoch2_header_info.index_block_hash())
            .unwrap();

        // but it's not enough -- child's consensus hash needs to be burn_processable
        assert_eq!(staging_conn.next_ready_nakamoto_block(&tx).unwrap(), None);

        // set burn processed
        staging_tx
            .set_burn_block_processed(&nakamoto_header.consensus_hash)
            .unwrap();

        // this works now
        assert_eq!(
            staging_conn
                .next_ready_nakamoto_block(&tx)
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block
        );

        // set parent nakamoto block processed
        staging_tx
            .set_block_processed(&nakamoto_header_info.index_block_hash())
            .unwrap();

        // next nakamoto block
        assert_eq!(
            staging_conn
                .next_ready_nakamoto_block(&tx)
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_2
        );
    }
}

/// Tests:
/// * NakamotoBlockHeader::check_miner_signature
/// * NakamotoBlockHeader::check_tenure_tx
/// * NakamotoBlockHeader::is_shadow_block
/// * NakamotoBlockHeader::check_normal_coinbase_tx
/// * NakamotoBlockHeader::check_shadow_coinbase_tx
#[test]
fn test_nakamoto_block_static_verification() {
    let private_key = StacksPrivateKey::new();
    let private_key_2 = StacksPrivateKey::new();

    let vrf_privkey = VRFPrivateKey::new();
    let vrf_pubkey = VRFPublicKey::from_private(&vrf_privkey);
    let sortition_hash = SortitionHash([0x01; 32]);
    let vrf_proof = VRF::prove(&vrf_privkey, sortition_hash.as_bytes());

    let burn_recipient = StacksAddress::burn_address(false).to_account_principal();
    let alt_recipient = StacksAddress::p2pkh(false, &StacksPublicKey::from_private(&private_key_2))
        .to_account_principal();

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(vrf_proof.clone()));

    let coinbase_recipient_payload = TransactionPayload::Coinbase(
        CoinbasePayload([0x12; 32]),
        Some(alt_recipient),
        Some(vrf_proof.clone()),
    );

    let coinbase_shadow_recipient_payload = TransactionPayload::Coinbase(
        CoinbasePayload([0x12; 32]),
        Some(burn_recipient),
        Some(vrf_proof.clone()),
    );

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut coinbase_recipient_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_recipient_payload.clone(),
    );
    coinbase_recipient_tx.chain_id = 0x80000000;
    coinbase_recipient_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut coinbase_shadow_recipient_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_shadow_recipient_payload.clone(),
    );
    coinbase_shadow_recipient_tx.chain_id = 0x80000000;
    coinbase_shadow_recipient_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(&private_key)),
    };

    let tenure_change_payload_bad_ch = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x05; 20]), // wrong
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(&private_key)),
    };

    let tenure_change_payload_bad_miner_sig = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]), // wrong
    };

    let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload.clone());
    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_tx_payload_bad_ch =
        TransactionPayload::TenureChange(tenure_change_payload_bad_ch.clone());
    let mut tenure_change_tx_bad_ch = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload_bad_ch.clone(),
    );
    tenure_change_tx_bad_ch.chain_id = 0x80000000;
    tenure_change_tx_bad_ch.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_tx_payload_bad_miner_sig =
        TransactionPayload::TenureChange(tenure_change_payload_bad_miner_sig.clone());
    let mut tenure_change_tx_bad_miner_sig = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload_bad_miner_sig.clone(),
    );
    tenure_change_tx_bad_miner_sig.chain_id = 0x80000000;
    tenure_change_tx_bad_miner_sig.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let nakamoto_txs = vec![tenure_change_tx.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root = {
        let txid_vecs: Vec<_> = nakamoto_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_recipient_txs = vec![tenure_change_tx.clone(), coinbase_recipient_tx.clone()];
    let nakamoto_recipient_tx_merkle_root = {
        let txid_vecs: Vec<_> = nakamoto_recipient_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_shadow_recipient_txs = vec![
        tenure_change_tx.clone(),
        coinbase_shadow_recipient_tx.clone(),
    ];
    let nakamoto_shadow_recipient_tx_merkle_root = {
        let txid_vecs: Vec<_> = nakamoto_shadow_recipient_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_bad_ch = vec![tenure_change_tx_bad_ch.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root_bad_ch = {
        let txid_vecs: Vec<_> = nakamoto_txs_bad_ch
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_bad_miner_sig =
        vec![tenure_change_tx_bad_miner_sig.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root_bad_miner_sig = {
        let txid_vecs: Vec<_> = nakamoto_txs_bad_miner_sig
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let mut nakamoto_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };
    nakamoto_header.sign_miner(&private_key).unwrap();

    let nakamoto_block = NakamotoBlock {
        header: nakamoto_header.clone(),
        txs: nakamoto_txs,
    };

    let mut nakamoto_header_bad_ch = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root_bad_ch,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };
    nakamoto_header_bad_ch.sign_miner(&private_key).unwrap();

    let nakamoto_block_bad_ch = NakamotoBlock {
        header: nakamoto_header_bad_ch.clone(),
        txs: nakamoto_txs_bad_ch,
    };

    let mut nakamoto_header_bad_miner_sig = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root_bad_miner_sig,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };
    nakamoto_header_bad_miner_sig
        .sign_miner(&private_key)
        .unwrap();

    let nakamoto_block_bad_miner_sig = NakamotoBlock {
        header: nakamoto_header_bad_miner_sig.clone(),
        txs: nakamoto_txs_bad_miner_sig,
    };

    let mut nakamoto_recipient_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_recipient_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };
    nakamoto_recipient_header.sign_miner(&private_key).unwrap();

    let nakamoto_recipient_block = NakamotoBlock {
        header: nakamoto_recipient_header.clone(),
        txs: nakamoto_recipient_txs,
    };

    let mut nakamoto_shadow_recipient_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_shadow_recipient_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };
    nakamoto_shadow_recipient_header
        .sign_miner(&private_key)
        .unwrap();

    let nakamoto_shadow_recipient_block = NakamotoBlock {
        header: nakamoto_shadow_recipient_header.clone(),
        txs: nakamoto_shadow_recipient_txs,
    };

    assert_eq!(
        nakamoto_block.header.recover_miner_pk().unwrap(),
        StacksPublicKey::from_private(&private_key)
    );
    assert_eq!(
        nakamoto_block.recover_miner_pubkh().unwrap(),
        tenure_change_payload.pubkey_hash
    );

    assert!(nakamoto_block
        .check_miner_signature(&tenure_change_payload.pubkey_hash)
        .is_ok());
    assert!(nakamoto_block
        .check_miner_signature(&Hash160::from_node_public_key(
            &StacksPublicKey::from_private(&private_key_2)
        ))
        .is_err());

    assert!(nakamoto_block.check_tenure_tx().is_ok());
    assert!(nakamoto_block_bad_ch.check_tenure_tx().is_err());
    assert!(nakamoto_block_bad_miner_sig.check_tenure_tx().is_err());

    let vrf_alt_privkey = VRFPrivateKey::new();
    let vrf_alt_pubkey = VRFPublicKey::from_private(&vrf_alt_privkey);

    assert!(nakamoto_block
        .check_normal_coinbase_tx(&vrf_pubkey, &sortition_hash)
        .is_ok());
    assert!(nakamoto_block
        .check_normal_coinbase_tx(&vrf_pubkey, &SortitionHash([0x02; 32]))
        .is_err());
    assert!(nakamoto_block
        .check_normal_coinbase_tx(&vrf_alt_pubkey, &sortition_hash)
        .is_err());

    let mut shadow_block = nakamoto_shadow_recipient_block.clone();
    shadow_block.header.version |= 0x80;

    assert!(!nakamoto_shadow_recipient_block.is_shadow_block());
    assert!(shadow_block.is_shadow_block());

    // miner key not checked for shadow blocks
    assert!(shadow_block
        .check_miner_signature(&Hash160::from_node_public_key(
            &StacksPublicKey::from_private(&private_key_2)
        ))
        .is_ok());

    // shadow block VRF is not checked
    assert!(shadow_block.check_shadow_coinbase_tx(false).is_ok());

    // shadow blocks need burn recipeints for coinbases
    let mut shadow_block_no_recipient = nakamoto_block.clone();
    shadow_block_no_recipient.header.version |= 0x80;

    assert!(shadow_block_no_recipient.is_shadow_block());
    assert!(shadow_block_no_recipient
        .check_shadow_coinbase_tx(false)
        .is_err());

    let mut shadow_block_alt_recipient = nakamoto_block.clone();
    shadow_block_alt_recipient.header.version |= 0x80;

    assert!(shadow_block_alt_recipient.is_shadow_block());
    assert!(shadow_block_alt_recipient
        .check_shadow_coinbase_tx(false)
        .is_err());

    // tenure tx requirements still hold for shadow blocks
    let mut shadow_nakamoto_block = nakamoto_block.clone();
    let mut shadow_nakamoto_block_bad_ch = nakamoto_block_bad_ch.clone();
    let mut shadow_nakamoto_block_bad_miner_sig = nakamoto_block_bad_miner_sig.clone();

    shadow_nakamoto_block.header.version |= 0x80;
    shadow_nakamoto_block_bad_ch.header.version |= 0x80;
    shadow_nakamoto_block_bad_miner_sig.header.version |= 0x80;

    shadow_nakamoto_block
        .header
        .sign_miner(&private_key)
        .unwrap();
    shadow_nakamoto_block_bad_ch
        .header
        .sign_miner(&private_key)
        .unwrap();
    shadow_nakamoto_block_bad_miner_sig
        .header
        .sign_miner(&private_key)
        .unwrap();

    assert!(shadow_nakamoto_block.is_shadow_block());
    assert!(shadow_nakamoto_block_bad_ch.is_shadow_block());
    assert!(shadow_nakamoto_block_bad_miner_sig.is_shadow_block());

    assert!(shadow_nakamoto_block.check_tenure_tx().is_ok());
    assert!(shadow_nakamoto_block_bad_ch.check_tenure_tx().is_err());
    assert!(shadow_nakamoto_block_bad_miner_sig
        .check_tenure_tx()
        .is_err());
}

/// Test that we can generate a .miners stackerdb config.
/// The config must be stable across sortitions -- if a miner is given slot i, then it continues
/// to have slot i in subsequent sortitions.
#[test]
fn test_make_miners_stackerdb_config() {
    let (mut test_signers, test_stackers) = TestStacker::common_signing_set();
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let naka_miner_hash160 = peer.miner.nakamoto_miner_hash160();
    let miner_keys: Vec<_> = (0..10).map(|_| StacksPrivateKey::new()).collect();
    let miner_hash160s: Vec<_> = miner_keys
        .iter()
        .map(|miner_privkey| {
            let miner_pubkey = StacksPublicKey::from_private(miner_privkey);
            let miner_hash160 = Hash160::from_node_public_key(&miner_pubkey);
            miner_hash160
        })
        .collect();
    let miner_addrs: Vec<_> = miner_hash160s
        .iter()
        .map(|miner_hash160| StacksAddress {
            version: 1,
            bytes: miner_hash160.clone(),
        })
        .collect();

    debug!("miners = {:#?}", &miner_hash160s);

    // extract chainstate, sortdb, and stackerdbs -- we don't need the peer anymore
    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();
    let mut last_snapshot = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let stackerdbs = peer.network.stackerdbs;
    let miners_contract_id = boot_code_id(MINERS_NAME, false);

    // make leader keys for each miner
    let mut miners = vec![];
    for (i, miner_hash160) in miner_hash160s.iter().enumerate() {
        let id = i as u8 + 1; // Add 1 to avoid 0-ed Txid.
        let vrf_privkey = VRFPrivateKey::new();
        let vrf_pubkey = VRFPublicKey::from_private(&vrf_privkey);
        let miner = LeaderKeyRegisterOp {
            consensus_hash: last_snapshot.consensus_hash.clone(),
            public_key: vrf_pubkey,
            memo: miner_hash160.0.to_vec(),
            txid: Txid([id; 32]),
            vtxindex: 1 + (id as u32),
            block_height: last_snapshot.block_height + 1,
            burn_header_hash: last_snapshot.burn_header_hash.clone(),
        };
        miners.push(miner);
    }

    let mut stackerdb_configs = vec![];
    let mut stackerdb_chunks = vec![];

    // synthesize some sortitions and corresponding winning block-commits
    for (i, miner) in miners.iter().enumerate() {
        // no winner every 3rd sortition
        let sortition = i % 3 != 0;
        let id = i as u8 + 1; // Add 1 to avoid 0-ed IDs.
        let winning_txid = if sortition {
            Txid([id; 32])
        } else {
            Txid([0x00; 32])
        };
        let winning_block_hash = BlockHeaderHash([id; 32]);
        let snapshot = BlockSnapshot {
            accumulated_coinbase_ustx: 0,
            pox_valid: true,
            block_height: last_snapshot.block_height + 1,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash([id; 32]),
            sortition_id: SortitionId([id; 32]),
            parent_sortition_id: last_snapshot.sortition_id.clone(),
            parent_burn_header_hash: last_snapshot.burn_header_hash.clone(),
            consensus_hash: ConsensusHash([id; 20]),
            ops_hash: OpsHash([id; 32]),
            total_burn: 0,
            sortition,
            sortition_hash: SortitionHash([id; 32]),
            winning_block_txid: winning_txid.clone(),
            winning_stacks_block_hash: winning_block_hash.clone(),
            index_root: TrieHash([0u8; 32]),
            num_sortitions: last_snapshot.num_sortitions + if sortition { 1 } else { 0 },
            stacks_block_accepted: false,
            stacks_block_height: last_snapshot.stacks_block_height,
            arrival_index: 0,
            canonical_stacks_tip_height: last_snapshot.canonical_stacks_tip_height + 10,
            canonical_stacks_tip_hash: BlockHeaderHash([id; 32]),
            canonical_stacks_tip_consensus_hash: ConsensusHash([id; 20]),
            miner_pk_hash: None,
        };
        let winning_block_commit = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([id; 32]),
            new_seed: VRFSeed([id; 32]),
            parent_block_ptr: last_snapshot.block_height as u32,
            parent_vtxindex: 1,
            // miners take turns winning
            key_block_ptr: miner.block_height as u32,
            key_vtxindex: miner.vtxindex as u16,
            memo: vec![STACKS_EPOCH_3_0_MARKER],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: winning_txid.clone(),
            vtxindex: 1,
            block_height: snapshot.block_height,
            burn_parent_modulus: ((snapshot.block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: snapshot.burn_header_hash.clone(),
            treatment: vec![],
        };

        let winning_ops = if i == 0 {
            // first snapshot includes leader keys
            miners
                .clone()
                .into_iter()
                .map(BlockstackOperationType::LeaderKeyRegister)
                .collect()
        } else {
            // subsequent ones include block-commits
            if sortition {
                vec![BlockstackOperationType::LeaderBlockCommit(
                    winning_block_commit,
                )]
            } else {
                vec![]
            }
        };

        let mut tx = SortitionHandleTx::begin(sort_db, &last_snapshot.sortition_id).unwrap();
        let _index_root = tx
            .append_chain_tip_snapshot(
                &last_snapshot,
                &snapshot,
                &winning_ops,
                &[],
                None,
                None,
                None,
            )
            .unwrap();
        tx.test_update_canonical_stacks_tip(
            &snapshot.sortition_id,
            &snapshot.canonical_stacks_tip_consensus_hash,
            &snapshot.canonical_stacks_tip_hash,
            snapshot.canonical_stacks_tip_height,
        )
        .unwrap();
        tx.commit().unwrap();

        last_snapshot = SortitionDB::get_block_snapshot(sort_db.conn(), &snapshot.sortition_id)
            .unwrap()
            .unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        // check the stackerdb config as of this chain tip
        let stackerdb_config = NakamotoChainState::make_miners_stackerdb_config(sort_db, &tip)
            .unwrap()
            .0;
        eprintln!(
            "stackerdb_config at i = {} (sorition? {}): {:?}",
            &i, sortition, &stackerdb_config
        );

        stackerdb_configs.push(stackerdb_config);

        // make a stackerdb chunk for a hypothetical block
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: 2,
            burn_spent: 3,
            consensus_hash: ConsensusHash([0x04; 20]),
            parent_block_id: StacksBlockId([0x05; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            timestamp: 8,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::zeros(1).unwrap(),
        };
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let miner_privkey = &miner_keys[i];
        let miner_pubkey = StacksPublicKey::from_private(miner_privkey);
        let slot_id = NakamotoChainState::get_miner_slot(&sort_db, &tip, &tip.consensus_hash)
            .expect("Failed to get miner slot");
        if sortition {
            let slot_id = slot_id.expect("No miner slot exists for this miner").start;
            let slot_version = stackerdbs
                .get_slot_version(&miners_contract_id, slot_id)
                .expect("Failed to get slot version")
                .unwrap_or(0)
                .saturating_add(1);
            let block_bytes = block.serialize_to_vec();
            let mut chunk = StackerDBChunkData::new(slot_id, slot_version, block_bytes);
            chunk.sign(&miner_keys[i]).expect("Failed to sign chunk");
            assert_eq!(chunk.slot_version, 1);
            assert_eq!(chunk.data, block.serialize_to_vec());
            stackerdb_chunks.push(chunk);
        } else {
            // We are not a miner anymore and should not have any slot
            assert!(slot_id.is_none());
        }
    }
    // miners are "stable" across snapshots
    let miner_hashbytes: Vec<_> = stackerdb_configs
        .iter()
        .map(|config| {
            (
                config.signers[0].0.bytes.clone(),
                config.signers[1].0.bytes.clone(),
            )
        })
        .collect();

    // active miner alternates slots (part of stability)
    let first_miner_slot = 0;
    let second_miner_slot = first_miner_slot + MINER_SLOT_COUNT;
    assert_eq!(stackerdb_chunks[0].slot_id, first_miner_slot);
    assert_eq!(stackerdb_chunks[1].slot_id, second_miner_slot);
    assert_eq!(stackerdb_chunks[2].slot_id, first_miner_slot);
    assert_eq!(stackerdb_chunks[3].slot_id, second_miner_slot);
    assert_eq!(stackerdb_chunks[4].slot_id, first_miner_slot);
    assert_eq!(stackerdb_chunks[5].slot_id, second_miner_slot);

    assert!(stackerdb_chunks[0].verify(&miner_addrs[1]).unwrap());
    assert!(stackerdb_chunks[1].verify(&miner_addrs[2]).unwrap());
    assert!(stackerdb_chunks[2].verify(&miner_addrs[4]).unwrap());
    assert!(stackerdb_chunks[3].verify(&miner_addrs[5]).unwrap());
    assert!(stackerdb_chunks[4].verify(&miner_addrs[7]).unwrap());
    assert!(stackerdb_chunks[5].verify(&miner_addrs[8]).unwrap());

    // There is no block commit associated with the first ever sortition.
    // Both the first and second writers will be the same miner (the default for the test peer)
    assert_eq!(miner_hashbytes[0].0, naka_miner_hash160);
    assert_eq!(miner_hashbytes[0].1, naka_miner_hash160);
    assert_eq!(miner_hashbytes[1].1, naka_miner_hash160);

    assert_eq!(miner_hashbytes[1].0, miner_hash160s[1]);
    assert_eq!(miner_hashbytes[2].0, miner_hash160s[1]);
    assert_eq!(miner_hashbytes[3].0, miner_hash160s[1]);

    assert_eq!(miner_hashbytes[2].1, miner_hash160s[2]);
    assert_eq!(miner_hashbytes[3].1, miner_hash160s[2]);
    assert_eq!(miner_hashbytes[4].1, miner_hash160s[2]);

    assert_eq!(miner_hashbytes[4].0, miner_hash160s[4]);
    assert_eq!(miner_hashbytes[5].0, miner_hash160s[4]);
    assert_eq!(miner_hashbytes[6].0, miner_hash160s[4]);

    assert_eq!(miner_hashbytes[5].1, miner_hash160s[5]);
    assert_eq!(miner_hashbytes[6].1, miner_hash160s[5]);
    assert_eq!(miner_hashbytes[7].1, miner_hash160s[5]);

    assert_eq!(miner_hashbytes[7].0, miner_hash160s[7]);
    assert_eq!(miner_hashbytes[8].0, miner_hash160s[7]);
    assert_eq!(miner_hashbytes[9].0, miner_hash160s[7]);

    assert_eq!(miner_hashbytes[8].1, miner_hash160s[8]);
    assert_eq!(miner_hashbytes[9].1, miner_hash160s[8]);
}

#[test]
fn parse_vote_for_aggregate_public_key_valid() {
    let signer_private_key = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u64();
    let signer_index_arg = Value::UInt(signer_index as u128);

    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key.clone()).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let valid_function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];
    let valid_tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr,
            contract_name,
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args,
        }),
    };
    let params = NakamotoSigners::parse_vote_for_aggregate_public_key(&valid_tx).unwrap();
    assert_eq!(params.signer_index, signer_index);
    assert_eq!(params.aggregate_key, aggregate_key);
    assert_eq!(params.voting_round, round);
    assert_eq!(params.reward_cycle, reward_cycle);
}

#[test]
fn parse_vote_for_aggregate_public_key_invalid() {
    let signer_private_key = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr: StacksAddress = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u32();
    let signer_index_arg = Value::UInt(signer_index as u128);
    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let valid_function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];

    let mut invalid_contract_address = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: StacksAddress::p2pkh(
                false,
                &StacksPublicKey::from_private(&signer_private_key),
            ),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_contract_address.set_origin_nonce(1);

    let mut invalid_contract_name = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: "bad-signers-contract-name".into(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_contract_name.set_origin_nonce(1);

    let mut invalid_signers_vote_function = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: "some-other-function".into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_signers_vote_function.set_origin_nonce(1);

    let mut invalid_function_arg_signer_index = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                aggregate_key_arg.clone(),
                aggregate_key_arg.clone(),
                round_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_signer_index.set_origin_nonce(1);

    let mut invalid_function_arg_key = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                signer_index_arg.clone(),
                round_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_key.set_origin_nonce(1);

    let mut invalid_function_arg_round = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                aggregate_key_arg.clone(),
                aggregate_key_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_round.set_origin_nonce(1);

    let mut invalid_function_arg_reward_cycle = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                aggregate_key_arg.clone(),
                round_arg.clone(),
                aggregate_key_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_reward_cycle.set_origin_nonce(1);

    let mut account_nonces = std::collections::HashMap::new();
    account_nonces.insert(invalid_contract_name.origin_address(), 1);
    for (i, tx) in vec![
        invalid_contract_address,
        invalid_contract_name,
        invalid_signers_vote_function,
        invalid_function_arg_signer_index,
        invalid_function_arg_key,
        invalid_function_arg_round,
        invalid_function_arg_reward_cycle,
    ]
    .iter()
    .enumerate()
    {
        assert!(
            NakamotoSigners::parse_vote_for_aggregate_public_key(&tx).is_none(),
            "{}",
            format!("parsed the {i}th transaction: {tx:?}")
        );
    }
}

#[test]
fn valid_vote_transaction() {
    let signer_private_key = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u32();
    let signer_index_arg = Value::UInt(signer_index as u128);

    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let valid_function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];
    let mut valid_tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr,
            contract_name,
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args,
        }),
    };
    valid_tx.set_origin_nonce(1);
    let mut account_nonces = std::collections::HashMap::new();
    account_nonces.insert(valid_tx.origin_address(), 1);
    assert!(NakamotoSigners::valid_vote_transaction(
        &account_nonces,
        &valid_tx,
        mainnet
    ));
}

#[test]
fn valid_vote_transaction_malformed_transactions() {
    let signer_private_key = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr: StacksAddress = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u32();
    let signer_index_arg = Value::UInt(signer_index as u128);

    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let valid_function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];
    // Create a invalid transaction that is not a contract call
    let mut invalid_not_contract_call = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::SmartContract(
            TransactionSmartContract {
                name: "test-contract".into(),
                code_body: StacksString::from_str("(/ 1 0)").unwrap(),
            },
            None,
        ),
    };
    invalid_not_contract_call.set_origin_nonce(1);

    let mut invalid_contract_address = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: StacksAddress::p2pkh(
                mainnet,
                &StacksPublicKey::from_private(&signer_private_key),
            ),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_contract_address.set_origin_nonce(1);

    let mut invalid_contract_name = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: "bad-signers-contract-name".into(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_contract_name.set_origin_nonce(1);

    let mut invalid_network = StacksTransaction {
        version: TransactionVersion::Mainnet,
        chain_id: CHAIN_ID_MAINNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_network.set_origin_nonce(1);

    let mut invalid_signers_vote_function = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: "some-other-function".into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_signers_vote_function.set_origin_nonce(1);

    let mut invalid_function_arg_signer_index = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                aggregate_key_arg.clone(),
                aggregate_key_arg.clone(),
                round_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_signer_index.set_origin_nonce(1);

    let mut invalid_function_arg_key = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                signer_index_arg.clone(),
                round_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_key.set_origin_nonce(1);

    let mut invalid_function_arg_round = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                aggregate_key_arg.clone(),
                aggregate_key_arg.clone(),
                reward_cycle_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_round.set_origin_nonce(1);

    let mut invalid_function_arg_reward_cycle = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: vec![
                signer_index_arg.clone(),
                aggregate_key_arg.clone(),
                round_arg.clone(),
                aggregate_key_arg.clone(),
            ],
        }),
    };
    invalid_function_arg_reward_cycle.set_origin_nonce(1);

    let mut invalid_nonce = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: valid_function_args.clone(),
        }),
    };
    invalid_nonce.set_origin_nonce(0); // old nonce

    let mut account_nonces = std::collections::HashMap::new();
    account_nonces.insert(invalid_not_contract_call.origin_address(), 1);
    for tx in vec![
        invalid_not_contract_call,
        invalid_contract_address,
        invalid_contract_name,
        invalid_signers_vote_function,
        invalid_function_arg_signer_index,
        invalid_function_arg_key,
        invalid_function_arg_round,
        invalid_function_arg_reward_cycle,
        invalid_nonce,
        invalid_network,
    ] {
        assert!(!NakamotoSigners::valid_vote_transaction(
            &account_nonces,
            &tx,
            mainnet
        ));
    }
}

#[test]
fn filter_one_transaction_per_signer_multiple_addresses() {
    let signer_private_key_1 = StacksPrivateKey::new();
    let signer_private_key_2 = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr: StacksAddress = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u32();
    let signer_index_arg = Value::UInt(signer_index as u128);

    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];

    let mut valid_tx_1_address_1 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key_1).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_1_address_1.set_origin_nonce(1);

    let mut valid_tx_2_address_1 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key_1).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_2_address_1.set_origin_nonce(2);

    let mut valid_tx_3_address_1 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key_1).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_3_address_1.set_origin_nonce(3);

    let mut valid_tx_1_address_2 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key_2).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_1_address_2.set_origin_nonce(1);

    let mut valid_tx_2_address_2 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key_2).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr,
            contract_name,
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args,
        }),
    };
    valid_tx_2_address_2.set_origin_nonce(2);
    let mut filtered_transactions = HashMap::new();
    let mut account_nonces = std::collections::HashMap::new();
    account_nonces.insert(valid_tx_1_address_1.origin_address(), 1);
    account_nonces.insert(valid_tx_1_address_2.origin_address(), 1);
    NakamotoSigners::update_filtered_transactions(
        &mut filtered_transactions,
        &account_nonces,
        false,
        vec![
            valid_tx_1_address_1.clone(),
            valid_tx_3_address_1,
            valid_tx_1_address_2.clone(),
            valid_tx_2_address_2,
            valid_tx_2_address_1,
        ],
    );
    let txs: Vec<_> = filtered_transactions.into_values().collect();
    assert_eq!(txs.len(), 2);
    assert!(txs.contains(&valid_tx_1_address_1));
    assert!(txs.contains(&valid_tx_1_address_2));
}

#[test]
fn filter_one_transaction_per_signer_duplicate_nonces() {
    let signer_private_key = StacksPrivateKey::new();
    let mainnet = false;
    let chainid = CHAIN_ID_TESTNET;
    let vote_contract_id = boot_code_id(SIGNERS_VOTING_NAME, mainnet);
    let contract_addr: StacksAddress = vote_contract_id.issuer.into();
    let contract_name = vote_contract_id.name.clone();

    let signer_index = thread_rng().next_u32();
    let signer_index_arg = Value::UInt(signer_index as u128);

    let aggregate_key: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(33).collect();
    let aggregate_key_arg = Value::buff_from(aggregate_key).expect("Failed to create buff");
    let round = thread_rng().next_u64();
    let round_arg = Value::UInt(round as u128);

    let reward_cycle = thread_rng().next_u64();
    let reward_cycle_arg = Value::UInt(reward_cycle as u128);

    let function_args = vec![
        signer_index_arg.clone(),
        aggregate_key_arg.clone(),
        round_arg.clone(),
        reward_cycle_arg.clone(),
    ];

    let mut valid_tx_1 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_1.set_origin_nonce(0);

    let mut valid_tx_2 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args: function_args.clone(),
        }),
    };
    valid_tx_2.set_origin_nonce(0);

    let mut valid_tx_3 = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: CHAIN_ID_TESTNET,
        auth: TransactionAuth::from_p2pkh(&signer_private_key).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_addr,
            contract_name,
            function_name: SIGNERS_VOTING_FUNCTION_NAME.into(),
            function_args,
        }),
    };
    valid_tx_3.set_origin_nonce(0);

    let mut account_nonces = std::collections::HashMap::new();
    account_nonces.insert(valid_tx_1.origin_address(), 0);
    let mut txs = vec![valid_tx_2, valid_tx_1, valid_tx_3];
    let mut filtered_transactions = HashMap::new();
    NakamotoSigners::update_filtered_transactions(
        &mut filtered_transactions,
        &account_nonces,
        false,
        txs.clone(),
    );
    let filtered_txs: Vec<_> = filtered_transactions.into_values().collect();
    txs.sort_by_key(|tx| tx.txid());
    assert_eq!(filtered_txs.len(), 1);
    assert!(filtered_txs.contains(&txs.first().expect("failed to get first tx")));
}

pub mod nakamoto_block_signatures {
    use super::*;

    /// Helper function make a reward set with (PrivateKey, weight) tuples
    fn make_reward_set(signers: &[(Secp256k1PrivateKey, u32)]) -> RewardSet {
        let mut reward_set = RewardSet::empty();
        reward_set.signers = Some(
            signers
                .iter()
                .map(|(s, w)| {
                    let mut signing_key = [0u8; 33];
                    signing_key.copy_from_slice(
                        &Secp256k1PublicKey::from_private(s)
                            .to_bytes_compressed()
                            .as_slice(),
                    );
                    NakamotoSignerEntry {
                        signing_key,
                        stacked_amt: 100_u128,
                        weight: *w,
                    }
                })
                .collect(),
        );
        reward_set
    }

    #[test]
    // Test that signatures succeed with exactly 70% of the votes
    pub fn test_exactly_enough_votes() {
        let signers = [
            (Secp256k1PrivateKey::default(), 35),
            (Secp256k1PrivateKey::default(), 35),
            (Secp256k1PrivateKey::default(), 30),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block with the first two signers
        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .take(2)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        header
            .verify_signer_signatures(&reward_set)
            .expect("Failed to verify signatures");
    }

    #[test]
    /// Test that signatures fail with just under 70% of the votes
    pub fn test_just_not_enough_votes() {
        let signers = [
            (Secp256k1PrivateKey::default(), 3500),
            (Secp256k1PrivateKey::default(), 3499),
            (Secp256k1PrivateKey::default(), 3001),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block with the first two signers
        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .take(2)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected insufficient signatures to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                assert!(msg.contains("Not enough signatures"));
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    /// Base success case - 3 signers of equal weight, all signing the block
    pub fn test_nakamoto_block_verify_signatures() {
        let signers = [
            Secp256k1PrivateKey::default(),
            Secp256k1PrivateKey::default(),
            Secp256k1PrivateKey::default(),
        ];

        let reward_set =
            make_reward_set(&signers.iter().map(|s| (s.clone(), 100)).collect::<Vec<_>>());

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block sighash for each signer

        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .map(|s| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        header
            .verify_signer_signatures(&reward_set)
            .expect("Failed to verify signatures");
        // assert!(&header.verify_signer_signatures(&reward_set).is_ok());
    }

    #[test]
    /// Fully signed block, but not in order
    fn test_out_of_order_signer_signatures() {
        let signers = [
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block for each signer, but in reverse
        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .rev()
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected out of order signatures to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                assert!(msg.contains("out of order"));
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    // Test with 3 equal signers, and only two sign
    fn test_insufficient_signatures() {
        let signers = [
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block with just the first two signers
        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .take(2)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected insufficient signatures to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                assert!(msg.contains("Not enough signatures"));
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    // Test with 4 signers, but one has 75% weight. Only the whale signs
    // and the block is valid
    fn test_single_signature_threshold() {
        let signers = [
            (Secp256k1PrivateKey::default(), 75),
            (Secp256k1PrivateKey::default(), 10),
            (Secp256k1PrivateKey::default(), 5),
            (Secp256k1PrivateKey::default(), 10),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        // Sign the block with just the whale
        let message = header.signer_signature_hash().0;
        let signer_signature = signers
            .iter()
            .take(1)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        header.signer_signature = signer_signature;

        header
            .verify_signer_signatures(&reward_set)
            .expect("Failed to verify signatures");
    }

    #[test]
    // Test with a signature that didn't come from the signer set
    fn test_invalid_signer() {
        let signers = [(Secp256k1PrivateKey::default(), 100)];

        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        let message = header.signer_signature_hash().0;

        // Sign with all signers
        let mut signer_signature = signers
            .iter()
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        let invalid_signature = Secp256k1PrivateKey::default()
            .sign(&message)
            .expect("Failed to sign block sighash");

        signer_signature.push(invalid_signature);

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected invalid signature to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                assert!(msg.contains("not found in the reward set"));
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    fn test_duplicate_signatures() {
        let signers = [
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
        ];
        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        let message = header.signer_signature_hash().0;

        // First, sign with the first 2 signers
        let mut signer_signature = signers
            .iter()
            .take(2)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        // Sign again with the first signer
        let duplicate_signature = signers[0]
            .0
            .sign(&message)
            .expect("Failed to sign block sighash");

        signer_signature.push(duplicate_signature);

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected duplicate signature to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                assert!(msg.contains("Signatures are out of order"));
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    // Test where a signature used a different message
    fn test_signature_invalid_message() {
        let signers = [
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
        ];

        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        let message = header.signer_signature_hash().0;

        let mut signer_signature = signers
            .iter()
            .take(3)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        // With the 4th signer, use a junk message
        let message = [0u8; 32];

        let bad_signature = signers[3]
            .0
            .sign(&message)
            .expect("Failed to sign block sighash");

        signer_signature.push(bad_signature);

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected invalid message to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {}
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    // Test where a signature is not recoverable
    fn test_unrecoverable_signature() {
        let signers = [
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
            (Secp256k1PrivateKey::default(), 100),
        ];

        let reward_set = make_reward_set(&signers);

        let mut header = NakamotoBlockHeader::empty();

        let message = header.signer_signature_hash().0;

        let mut signer_signature = signers
            .iter()
            .take(3)
            .map(|(s, _)| s.sign(&message).expect("Failed to sign block sighash"))
            .collect::<Vec<_>>();

        // Now append an unrecoverable signature
        signer_signature.push(MessageSignature::empty());

        header.signer_signature = signer_signature;

        match header.verify_signer_signatures(&reward_set) {
            Ok(_) => panic!("Expected invalid message to fail"),
            Err(ChainstateError::InvalidStacksBlock(msg)) => {
                if !msg.contains("Unable to recover public key") {
                    panic!("Unexpected error msg: {}", msg);
                }
            }
            _ => panic!("Expected InvalidStacksBlock error"),
        }
    }

    #[test]
    pub fn test_compute_voting_weight_threshold() {
        assert_eq!(
            NakamotoBlockHeader::compute_voting_weight_threshold(100_u32).unwrap(),
            70_u32,
        );

        assert_eq!(
            NakamotoBlockHeader::compute_voting_weight_threshold(10_u32).unwrap(),
            7_u32,
        );

        assert_eq!(
            NakamotoBlockHeader::compute_voting_weight_threshold(3000_u32).unwrap(),
            2100_u32,
        );

        assert_eq!(
            NakamotoBlockHeader::compute_voting_weight_threshold(4000_u32).unwrap(),
            2800_u32,
        );

        // Round-up check
        assert_eq!(
            NakamotoBlockHeader::compute_voting_weight_threshold(511_u32).unwrap(),
            358_u32,
        );
    }
}
