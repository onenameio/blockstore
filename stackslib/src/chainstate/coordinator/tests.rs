// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, RwLock};

use clarity::vm::clarity::TransactionConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::BurnStateDB;
use clarity::vm::errors::Error as InterpreterError;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityVersion, Value};
use lazy_static::lazy_static;
use rand::RngCore;
use rusqlite::Connection;
use stacks_common::address::AddressHashMode;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::deps_common::bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
use stacks_common::deps_common::bitcoin::util::hash::Sha256dHash;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, SortitionId, StacksAddress, StacksBlockId,
    TrieHash, VRFSeed,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{to_hex, Hash160};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::*;
use stacks_common::{address, types, util};

use crate::burnchains::affirmation::*;
use crate::burnchains::bitcoin::address::BitcoinAddress;
use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::db::*;
use crate::burnchains::tests::db::*;
use crate::burnchains::*;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::distribution::BurnSamplePoint;
use crate::chainstate::burn::operations::leader_block_commit::*;
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::*;
use crate::chainstate::coordinator::{Error as CoordError, *};
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType32};
use crate::chainstate::stacks::boot::{
    PoxStartCycleInfo, COSTS_2_NAME, POX_1_NAME, POX_2_NAME, POX_3_NAME,
};
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::{ClarityTx, StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::miner::BlockBuilder;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::ClarityConnection;
use crate::core::*;
use crate::monitoring::increment_stx_blocks_processed_counter;
use crate::util_lib::boot::{boot_code_addr, boot_code_id};
use crate::util_lib::strings::StacksString;
use crate::{chainstate, core};

lazy_static! {
    pub static ref BURN_BLOCK_HEADERS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    pub static ref TXIDS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    pub static ref MBLOCK_PUBKHS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
    pub static ref STACKS_BLOCK_HEADERS: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));
}

fn test_path(name: &str) -> String {
    format!(
        "/tmp/stacks-node-tests/coordinator-tests/{}/{}",
        get_epoch_time_secs(),
        name
    )
}

pub fn next_block_hash() -> BlockHeaderHash {
    let cur = STACKS_BLOCK_HEADERS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    BlockHeaderHash::from_bytes(&bytes).unwrap()
}

pub fn next_burn_header_hash() -> BurnchainHeaderHash {
    let cur = BURN_BLOCK_HEADERS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[0; 24]);
    BurnchainHeaderHash::from_bytes(&bytes).unwrap()
}

pub fn next_txid() -> Txid {
    let cur = TXIDS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[1; 24]);
    Txid::from_bytes(&bytes).unwrap()
}

pub fn next_hash160() -> Hash160 {
    let cur = MBLOCK_PUBKHS.fetch_add(1, Ordering::SeqCst);
    let mut bytes = vec![];
    bytes.extend_from_slice(&cur.to_le_bytes());
    bytes.extend_from_slice(&[2; 12]);
    Hash160::from_bytes(&bytes).unwrap()
}

/// Produce a burn block, insert it into burnchain_db, and insert it into others as well
pub fn produce_burn_block<'a, I: Iterator<Item = &'a mut BurnchainDB>>(
    burnchain_conf: &Burnchain,
    burnchain_db: &mut BurnchainDB,
    par: &BurnchainHeaderHash,
    mut ops: Vec<BlockstackOperationType>,
    others: I,
) -> BurnchainHeaderHash {
    let BurnchainBlockData {
        header: par_header, ..
    } = BurnchainDB::get_burnchain_block(&burnchain_db.conn(), par).unwrap();
    assert_eq!(&par_header.block_hash, par);
    let block_height = par_header.block_height + 1;
    for op in ops.iter_mut() {
        op.set_block_height(block_height);
    }

    produce_burn_block_do_not_set_height(burnchain_conf, burnchain_db, par, ops, others)
}

fn get_burn_distribution(conn: &Connection, sortition: &SortitionId) -> Vec<BurnSamplePoint> {
    conn.query_row(
        "SELECT data FROM snapshot_burn_distributions WHERE sortition_id = ?",
        &[sortition],
        |row| {
            let data_str: String = row.get_unwrap(0);
            Ok(serde_json::from_str(&data_str).unwrap())
        },
    )
    .unwrap()
}

fn produce_burn_block_do_not_set_height<'a, I: Iterator<Item = &'a mut BurnchainDB>>(
    burnchain_conf: &Burnchain,
    burnchain_db: &mut BurnchainDB,
    par: &BurnchainHeaderHash,
    mut ops: Vec<BlockstackOperationType>,
    others: I,
) -> BurnchainHeaderHash {
    let BurnchainBlockData {
        header: par_header, ..
    } = BurnchainDB::get_burnchain_block(&burnchain_db.conn(), par).unwrap();
    assert_eq!(&par_header.block_hash, par);
    let block_height = par_header.block_height + 1;
    let timestamp = par_header.timestamp + 1;
    let num_txs = ops.len() as u64;

    let bitcoin_header = BlockHeader {
        bits: 0,
        merkle_root: Sha256dHash([0u8; 32]),
        nonce: 0,
        prev_blockhash: par.to_bitcoin_hash(),
        time: timestamp as u32,
        version: 0x20000000,
    };

    let block_hash = BurnchainHeaderHash::from_bitcoin_hash(&bitcoin_header.bitcoin_hash());

    let header = BurnchainBlockHeader {
        block_height,
        timestamp,
        num_txs,
        block_hash: block_hash.clone(),
        parent_block_hash: par.clone(),
    };

    let mut indexer = BitcoinIndexer::new_unit_test(&burnchain_conf.working_dir);
    indexer.raw_store_header(header.clone()).unwrap();

    for op in ops.iter_mut() {
        op.set_burn_header_hash(block_hash.clone());
    }

    burnchain_db
        .raw_store_burnchain_block(burnchain_conf, &indexer, header.clone(), ops.clone())
        .unwrap();

    let this_reward_cycle = burnchain_conf
        .block_height_to_reward_cycle(block_height)
        .unwrap_or(0);

    let prev_reward_cycle = burnchain_conf
        .block_height_to_reward_cycle(block_height.saturating_sub(1))
        .unwrap_or(0);

    if this_reward_cycle != prev_reward_cycle {
        // at reward cycle boundary
        test_debug!(
            "Update PoX affirmation maps for reward cycle {} ({}) block {} cycle-length {}",
            prev_reward_cycle,
            this_reward_cycle,
            block_height,
            burnchain_conf.pox_constants.reward_cycle_length
        );
        update_pox_affirmation_maps(burnchain_db, &indexer, prev_reward_cycle, burnchain_conf)
            .unwrap();
    }

    for other in others {
        other
            .raw_store_burnchain_block(burnchain_conf, &indexer, header.clone(), ops.clone())
            .unwrap();

        if this_reward_cycle != prev_reward_cycle {
            update_pox_affirmation_maps(other, &indexer, prev_reward_cycle, burnchain_conf)
                .unwrap();
        }
    }

    block_hash
}

pub fn p2pkh_from(sk: &StacksPrivateKey) -> StacksAddress {
    let pk = StacksPublicKey::from_private(sk);
    StacksAddress::from_public_keys(
        chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &address::AddressHashMode::SerializeP2PKH,
        1,
        &vec![pk],
    )
    .unwrap()
}

pub fn pox_addr_from(sk: &StacksPrivateKey) -> PoxAddress {
    let stacks_addr = p2pkh_from(sk);
    PoxAddress::Standard(stacks_addr, Some(AddressHashMode::SerializeP2PKH))
}

pub fn setup_states(
    paths: &[&str],
    vrf_keys: &[VRFPrivateKey],
    committers: &[StacksPrivateKey],
    pox_consts: Option<PoxConstants>,
    initial_balances: Option<Vec<(PrincipalData, u64)>>,
    stacks_epoch_id: StacksEpochId,
) {
    setup_states_with_epochs(
        paths,
        vrf_keys,
        committers,
        pox_consts,
        initial_balances,
        stacks_epoch_id,
        None,
    );
}

pub fn setup_states_2_1(
    paths: &[&str],
    vrf_keys: &[VRFPrivateKey],
    committers: &[StacksPrivateKey],
    pox_consts: Option<PoxConstants>,
    initial_balances: Option<Vec<(PrincipalData, u64)>>,
) {
    setup_states_with_epochs(
        paths,
        vrf_keys,
        committers,
        pox_consts,
        initial_balances,
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 0)),
    )
}

pub fn setup_states_with_epochs(
    paths: &[&str],
    vrf_keys: &[VRFPrivateKey],
    committers: &[StacksPrivateKey],
    pox_consts: Option<PoxConstants>,
    initial_balances: Option<Vec<(PrincipalData, u64)>>,
    stacks_epoch_id: StacksEpochId,
    epochs_opt: Option<EpochList>,
) {
    let mut burn_block = None;
    let mut others = vec![];

    for path in paths.iter() {
        let burnchain = get_burnchain(path, pox_consts.clone());
        let epochs = epochs_opt.clone().unwrap_or(StacksEpoch::unit_test(
            stacks_epoch_id,
            burnchain.first_block_height,
        ));
        let sortition_db = SortitionDB::connect(
            &burnchain.get_db_path(),
            burnchain.first_block_height,
            &burnchain.first_block_hash,
            burnchain.first_block_timestamp.into(),
            &epochs,
            burnchain.pox_constants.clone(),
            None,
            true,
        )
        .unwrap();

        let burnchain_blocks_db =
            BurnchainDB::connect(&burnchain.get_burnchaindb_path(), &burnchain, true).unwrap();

        if burn_block.is_none() {
            let first_sortition =
                SortitionDB::get_canonical_burn_chain_tip(sortition_db.conn()).unwrap();
            let first_consensus_hash = &first_sortition.consensus_hash;

            // build a bunch of VRF key registers

            let mut registers = vec![];
            for (ix, (sk, miner_sk)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
                let public_key = VRFPublicKey::from_private(sk);
                let consensus_hash = first_consensus_hash.clone();
                let memo = vec![0];
                let vtxindex = 1 + ix as u32;
                let block_height = 0;
                let burn_header_hash = BurnchainHeaderHash([0; 32]);
                let txid = next_txid();

                registers.push(BlockstackOperationType::LeaderKeyRegister(
                    LeaderKeyRegisterOp {
                        public_key,
                        consensus_hash,
                        memo,
                        vtxindex,
                        block_height,
                        burn_header_hash,
                        txid,
                    },
                ));
            }

            burn_block.replace((
                burnchain_blocks_db,
                first_sortition.burn_header_hash,
                registers,
                *path,
            ));
        } else {
            others.push(burnchain_blocks_db);
        }
    }

    let (mut burnchain_blocks_db, burn_header_hash, registers, path) = burn_block.take().unwrap();
    let burnchain = get_burnchain(path, pox_consts.clone());

    produce_burn_block(
        &burnchain,
        &mut burnchain_blocks_db,
        &burn_header_hash,
        registers,
        others.iter_mut(),
    );

    let block_limit = ExecutionCost::max_value();
    let initial_balances = initial_balances.unwrap_or(vec![]);
    for path in paths.iter() {
        let burnchain = get_burnchain(path, pox_consts.clone());

        let mut boot_data = ChainStateBootData::new(&burnchain, initial_balances.clone(), None);

        let post_flight_callback = move |clarity_tx: &mut ClarityTx| {
            let contract = boot_code_id("pox", false);
            let sender = PrincipalData::from(contract.clone());

            clarity_tx.connection().as_transaction(|conn| {
                conn.run_contract_call(
                    &sender,
                    None,
                    &contract,
                    "set-burnchain-parameters",
                    &[
                        Value::UInt(burnchain.first_block_height as u128),
                        Value::UInt(burnchain.pox_constants.prepare_length as u128),
                        Value::UInt(burnchain.pox_constants.reward_cycle_length as u128),
                        Value::UInt(burnchain.pox_constants.pox_rejection_fraction as u128),
                    ],
                    |_, _| false,
                )
                .expect("Failed to set burnchain parameters in PoX contract");
            });
        };

        boot_data.post_flight_callback = Some(Box::new(post_flight_callback));

        let (chain_state_db, _) = StacksChainState::open_and_exec(
            false,
            0x80000000,
            &format!("{}/chainstate/", path),
            Some(&mut boot_data),
            None,
        )
        .unwrap();
    }
}

pub struct NullEventDispatcher;

impl BlockEventDispatcher for NullEventDispatcher {
    fn announce_block(
        &self,
        _block: &StacksBlockEventData,
        _metadata: &StacksHeaderInfo,
        _receipts: &[StacksTransactionReceipt],
        _parent: &StacksBlockId,
        _winner_txid: Txid,
        _rewards: &[MinerReward],
        _rewards_info: Option<&MinerRewardInfo>,
        _parent_burn_block_hash: BurnchainHeaderHash,
        _parent_burn_block_height: u32,
        _parent_burn_block_timestamp: u64,
        _anchor_block_cost: &ExecutionCost,
        _confirmed_mblock_cost: &ExecutionCost,
        _pox_constants: &PoxConstants,
        _reward_set_data: &Option<RewardSetData>,
        _signer_bitvec: &Option<BitVec<4000>>,
        _block_timestamp: Option<u64>,
        _coinbase_height: u64,
    ) {
        assert!(
            false,
            "We should never try to announce to the null dispatcher"
        );
    }

    fn announce_burn_block(
        &self,
        _burn_block: &BurnchainHeaderHash,
        _burn_block_height: u64,
        _rewards: Vec<(PoxAddress, u64)>,
        _burns: u64,
        _slot_holders: Vec<PoxAddress>,
        _consensus_hash: &ConsensusHash,
    ) {
    }
}

pub fn make_coordinator<'a>(
    path: &str,
    burnchain: Option<Burnchain>,
) -> ChainsCoordinator<
    'a,
    NullEventDispatcher,
    (),
    OnChainRewardSetProvider<'a, NullEventDispatcher>,
    (),
    (),
    BitcoinIndexer,
> {
    let burnchain = burnchain.unwrap_or_else(|| get_burnchain(path, None));
    let indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
    ChainsCoordinator::test_new(
        &burnchain,
        0x80000000,
        path,
        OnChainRewardSetProvider(None),
        indexer,
    )
}

pub fn make_coordinator_atlas<'a>(
    path: &str,
    burnchain: Option<Burnchain>,
    atlas_config: Option<AtlasConfig>,
) -> ChainsCoordinator<
    'a,
    NullEventDispatcher,
    (),
    OnChainRewardSetProvider<'a, NullEventDispatcher>,
    (),
    (),
    BitcoinIndexer,
> {
    let burnchain = burnchain.unwrap_or_else(|| get_burnchain(path, None));
    let indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
    ChainsCoordinator::test_new_full(
        &burnchain,
        0x80000000,
        path,
        OnChainRewardSetProvider(None),
        None,
        indexer,
        atlas_config,
    )
}

struct StubbedRewardSetProvider(Vec<PoxAddress>);

impl RewardSetProvider for StubbedRewardSetProvider {
    fn get_reward_set(
        &self,
        _current_burn_height: u64,
        chainstate: &mut StacksChainState,
        burnchain: &Burnchain,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, chainstate::coordinator::Error> {
        Ok(RewardSet {
            rewarded_addresses: self.0.clone(),
            start_cycle_state: PoxStartCycleInfo {
                missed_reward_slots: vec![],
            },
            signers: None,
            pox_ustx_threshold: None,
        })
    }

    fn get_reward_set_nakamoto(
        &self,
        chainstate: &mut StacksChainState,
        cycle: u64,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
    ) -> Result<RewardSet, CoordError> {
        panic!("Stubbed reward set provider cannot be invoked in nakamoto")
    }
}

fn make_reward_set_coordinator<'a>(
    path: &str,
    addrs: Vec<PoxAddress>,
    pox_consts: Option<PoxConstants>,
) -> ChainsCoordinator<'a, NullEventDispatcher, (), StubbedRewardSetProvider, (), (), BitcoinIndexer>
{
    let burnchain = get_burnchain(path, None);
    let indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
    ChainsCoordinator::test_new(
        &get_burnchain(path, pox_consts),
        0x80000000,
        path,
        StubbedRewardSetProvider(addrs),
        indexer,
    )
}

pub fn get_burnchain(path: &str, pox_consts: Option<PoxConstants>) -> Burnchain {
    let mut b = Burnchain::regtest(&format!("{}/burnchain/db/", path));
    b.pox_constants = pox_consts.unwrap_or_else(|| {
        PoxConstants::new(
            5,
            3,
            3,
            25,
            5,
            u64::MAX,
            u64::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        )
    });
    b
}

pub fn get_sortition_db(path: &str, pox_consts: Option<PoxConstants>) -> SortitionDB {
    let burnchain = get_burnchain(path, pox_consts);
    SortitionDB::open(
        &burnchain.get_db_path(),
        false,
        burnchain.pox_constants.clone(),
    )
    .unwrap()
}

pub fn get_rw_sortdb(path: &str, pox_consts: Option<PoxConstants>) -> SortitionDB {
    let burnchain = get_burnchain(path, pox_consts);
    SortitionDB::open(
        &burnchain.get_db_path(),
        true,
        burnchain.pox_constants.clone(),
    )
    .unwrap()
}

pub fn get_burnchain_db(path: &str, pox_consts: Option<PoxConstants>) -> BurnchainDB {
    let burnchain = get_burnchain(path, pox_consts);
    BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap()
}

pub fn get_chainstate_path_str(path: &str) -> String {
    format!("{}/chainstate/", path)
}

pub fn get_chainstate(path: &str) -> StacksChainState {
    let (chainstate, _) =
        StacksChainState::open(false, 0x80000000, &get_chainstate_path_str(path), None).unwrap();
    chainstate
}

fn make_genesis_block(
    burnchain: &Burnchain,
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    parent_block: &BlockHeaderHash,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
) -> (BlockstackOperationType, StacksBlock) {
    make_genesis_block_with_recipients(
        burnchain,
        sort_db,
        state,
        parent_block,
        miner,
        my_burn,
        vrf_key,
        key_index,
        None,
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork.
fn make_genesis_block_with_recipients(
    burnchain: &Burnchain,
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    parent_block: &BlockHeaderHash,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
    );
    tx.chain_id = 0x80000000;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    let parent_stacks_header = StacksHeaderInfo::regtest_genesis();

    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let mut builder = StacksBlockBuilder::make_regtest_block_builder(
        burnchain,
        &parent_stacks_header,
        proof.clone(),
        0,
        next_hash160(),
    )
    .unwrap();

    let iconn = sort_db.index_handle_at_tip();
    let mut miner_epoch_info = builder.pre_epoch_begin(state, &iconn, true).unwrap();
    let ast_rules = miner_epoch_info.ast_rules.clone();
    let mut epoch_tx = builder
        .epoch_begin(&iconn, &mut miner_epoch_info)
        .unwrap()
        .0;

    builder
        .try_mine_tx(&mut epoch_tx, &coinbase_op, ast_rules)
        .unwrap();

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx).unwrap();

    let commit_outs = if let Some(recipients) = recipients {
        let mut commit_outs = recipients
            .recipients
            .iter()
            .map(|(a, _)| a.clone())
            .collect::<Vec<PoxAddress>>();
        if commit_outs.len() == 1 {
            commit_outs.push(PoxAddress::standard_burn_address(false));
        }
        commit_outs
    } else {
        vec![]
    };

    let commit_op = LeaderBlockCommitOp {
        sunset_burn: 0,
        treatment: vec![],
        block_header_hash: block.block_hash(),
        burn_fee: my_burn,
        input: (Txid([0; 32]), 0),
        apparent_sender: BurnchainSigner::mock_parts(
            address::AddressHashMode::SerializeP2PKH,
            1,
            vec![StacksPublicKey::from_private(miner)],
        ),
        key_block_ptr: 1, // all registers happen in block height 1
        key_vtxindex: (1 + key_index) as u16,
        memo: vec![STACKS_EPOCH_2_4_MARKER],
        new_seed: VRFSeed::from_proof(&proof),
        commit_outs,

        parent_block_ptr: 0,
        parent_vtxindex: 0,

        txid: next_txid(),

        vtxindex: 1,
        block_height: 0,
        burn_parent_modulus: (BURN_BLOCK_MINED_AT_MODULUS - 1) as u8,
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

fn make_stacks_block(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_recipients(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        None,
    )
}

fn make_stacks_block_from_parent_sortition(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    parent_sortition: BlockSnapshot,
) -> (BlockstackOperationType, StacksBlock) {
    // NOTE: assumes no sunset
    make_stacks_block_with_input(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        None,
        0,
        false,
        (Txid([0; 32]), 0),
        Some(parent_sortition),
        &[],
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block_with_recipients(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_recipients_and_sunset_burn(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        recipients,
        0,
        false,
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
fn make_stacks_block_with_recipients_and_sunset_burn(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
    sunset_burn: u64,
    post_sunset_burn: bool,
) -> (BlockstackOperationType, StacksBlock) {
    make_stacks_block_with_input(
        sort_db,
        state,
        burnchain,
        parent_block,
        parent_height,
        miner,
        my_burn,
        vrf_key,
        key_index,
        recipients,
        sunset_burn,
        post_sunset_burn,
        (Txid([0; 32]), 0),
        None,
        &[],
    )
}

/// build a stacks block with just the coinbase off of
///  parent_block, in the canonical sortition fork of SortitionDB.
/// parent_block _must_ be included in the StacksChainState
/// `txs`: transactions to try to include in block
fn make_stacks_block_with_input(
    sort_db: &SortitionDB,
    state: &mut StacksChainState,
    burnchain: &Burnchain,
    parent_block: &BlockHeaderHash,
    parent_height: u64,
    miner: &StacksPrivateKey,
    my_burn: u64,
    vrf_key: &VRFPrivateKey,
    key_index: u32,
    recipients: Option<&RewardSetInfo>,
    sunset_burn: u64,
    post_sunset_burn: bool,
    input: (Txid, u32),
    parents_sortition_opt: Option<BlockSnapshot>,
    txs: &[StacksTransaction],
) -> (BlockstackOperationType, StacksBlock) {
    let tx_auth = TransactionAuth::from_p2pkh(miner).unwrap();

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
    );
    tx.chain_id = 0x80000000;
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    tx_signer.sign_origin(miner).unwrap();

    let coinbase_op = tx_signer.get_tx().unwrap();

    let sortition_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let parents_sortition = if let Some(sn) = parents_sortition_opt {
        sn
    } else {
        SortitionDB::get_block_snapshot_for_winning_stacks_block(
            &sort_db.index_conn(),
            &sortition_tip.sortition_id,
            parent_block,
        )
        .unwrap()
        .unwrap()
    };

    eprintln!(
        "Find parents stacks header: {} in sortition {} (height {}, parent {}/{},{}, index block hash {})",
        &parent_block, &parents_sortition.sortition_id, parents_sortition.block_height, &parents_sortition.consensus_hash, parent_block, parent_height, &StacksBlockHeader::make_index_block_hash(&parents_sortition.consensus_hash, &parent_block)
    );

    let parent_vtxindex =
        SortitionDB::get_block_winning_vtxindex(sort_db.conn(), &parents_sortition.sortition_id)
            .unwrap()
            .unwrap();

    let parent_stacks_header = StacksChainState::get_anchored_block_header_info(
        state.db(),
        &parents_sortition.consensus_hash,
        parent_block,
    )
    .unwrap()
    .unwrap();

    eprintln!("Build off of {:?}", &parent_stacks_header);

    let proof = VRF::prove(vrf_key, sortition_tip.sortition_hash.as_bytes());

    let total_burn = parents_sortition.total_burn;

    let iconn = sort_db.index_handle_at_tip();

    let mut builder = StacksBlockBuilder::make_regtest_block_builder(
        burnchain,
        &parent_stacks_header,
        proof.clone(),
        total_burn,
        next_hash160(),
    )
    .unwrap();
    let mut miner_epoch_info = builder.pre_epoch_begin(state, &iconn, true).unwrap();
    let ast_rules = miner_epoch_info.ast_rules.clone();
    let mut epoch_tx = builder
        .epoch_begin(&iconn, &mut miner_epoch_info)
        .unwrap()
        .0;

    builder
        .try_mine_tx(&mut epoch_tx, &coinbase_op, ast_rules)
        .unwrap();

    for tx in txs {
        builder.try_mine_tx(&mut epoch_tx, tx, ast_rules).unwrap();
    }

    let block = builder.mine_anchored_block(&mut epoch_tx);
    builder.epoch_finish(epoch_tx).unwrap();

    let commit_outs = if let Some(recipients) = recipients {
        let mut commit_outs = recipients
            .recipients
            .iter()
            .map(|(a, _)| a.clone())
            .collect::<Vec<PoxAddress>>();
        if commit_outs.len() == 1 {
            // Padding with burn address if required
            commit_outs.push(PoxAddress::standard_burn_address(false));
        }
        commit_outs
    } else if post_sunset_burn || burnchain.is_in_prepare_phase(parent_height + 1) {
        test_debug!("block-commit in {} will burn", parent_height + 1);
        vec![PoxAddress::standard_burn_address(false)]
    } else {
        vec![]
    };

    let commit_op = LeaderBlockCommitOp {
        sunset_burn,
        treatment: vec![],
        block_header_hash: block.block_hash(),
        burn_fee: my_burn,
        input,
        apparent_sender: BurnchainSigner::mock_parts(
            address::AddressHashMode::SerializeP2PKH,
            1,
            vec![StacksPublicKey::from_private(miner)],
        ),
        key_block_ptr: 1, // all registers happen in block height 1
        key_vtxindex: (1 + key_index) as u16,
        memo: vec![STACKS_EPOCH_2_4_MARKER],
        new_seed: VRFSeed::from_proof(&proof),
        commit_outs,

        parent_block_ptr: parents_sortition.block_height as u32,
        parent_vtxindex,

        txid: next_txid(),
        vtxindex: 1 + key_index,
        block_height: 0,
        burn_parent_modulus: (BURN_BLOCK_MINED_AT_MODULUS - 1) as u8,
        burn_header_hash: BurnchainHeaderHash([0; 32]),
    };

    (BlockstackOperationType::LeaderBlockCommit(commit_op), block)
}

#[test]
fn missed_block_commits_2_05() {
    let path = &test_path("missed_block_commits_2_05");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        5,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states_with_epochs(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 1000000)),
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    let mut last_input: Option<(Txid, u32)> = None;
    let b = get_burnchain(path, None);

    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();

        // NOTE: this will accidentally succeed -- the calculation for the recipients is wrong for
        // late block-commits, but 2.05 accepts them anyway.
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&b, reward_cycle_info.as_ref())
            .unwrap();

        let b = get_burnchain(path, pox_consts.clone());
        let mut ops = vec![];
        if ix % (MINING_COMMITMENT_WINDOW as usize) == 4 {
            let (mut bad_op, _) = make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height - 2,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            );
            // NOTE: intended for block block_height - 2
            last_input = Some((
                bad_op.txid(),
                if b.is_in_prepare_phase(next_mock_header.block_height - 2 + 1) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            bad_op.set_block_height(next_mock_header.block_height);
            if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = bad_op {
                op.burn_parent_modulus =
                    ((next_mock_header.block_height - 2) % BURN_BLOCK_MINED_AT_MODULUS) as u8;
                op.vtxindex = 3;
            } else {
                panic!("Should be leader block commit");
            }
            test_debug!(
                "bad_op meant for block {}: {:?}",
                burnchain_tip.block_height - 2 + 1,
                &bad_op
            );
            ops.push(bad_op);
        }

        let (mut good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            )
        };

        good_op.set_block_height(next_mock_header.block_height);

        let expected_winner = good_op.txid();
        ops.push(good_op);

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();

        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            // produce an empty block!
            produce_burn_block(
                &burnchain_conf,
                &mut burnchain,
                &burnchain_tip.block_hash,
                vec![],
                [].iter_mut(),
            );
        } else {
            // produce a block with one good op,
            last_input = Some((
                expected_winner,
                if b.is_in_prepare_phase(next_mock_header.block_height) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            produce_burn_block_do_not_set_height(
                &burnchain_conf,
                &mut burnchain,
                &burnchain_tip.block_hash,
                ops,
                [].iter_mut(),
            );
        }
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let burn_distribution = get_burn_distribution(sort_db.conn(), &tip.sortition_id);
        eprintln!("{}", ix);
        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            assert!(
                !tip.sortition,
                "Sortition should not have occurred because the only block commit was invalid"
            );
            // duplicate the last stacks_block
            stacks_blocks.push(stacks_blocks[ix - 1].clone());
        } else {
            // how many commit do we expect to see counted in the current window?
            let expected_window_commits = if ix >= (MINING_COMMITMENT_WINDOW as usize) {
                (MINING_COMMITMENT_WINDOW - 1) as usize
            } else if ix >= 3 {
                ix
            } else {
                ix + 1
            };
            // there were 2 burn blocks before we started mining
            let expected_window_size = cmp::min(MINING_COMMITMENT_WINDOW as usize, ix + 3);

            let min_burn = 1;
            let median_burn = if expected_window_commits > expected_window_size / 2 {
                10000
            } else if expected_window_size % 2 == 0
                && expected_window_commits == expected_window_size / 2
            {
                (10000 + 1) / 2
            } else {
                1
            };
            let last_burn = if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
                0
            } else {
                10000
            };

            if b.is_in_prepare_phase(next_mock_header.block_height) {
                // in prepare phase -- no smoothing takes place
                assert_eq!(
                    burn_distribution[0].burns, last_burn,
                    "Burn distribution should not do windowing at ix = {} block_height = {}",
                    ix, next_mock_header.block_height
                )
            } else {
                // in reward phase -- apply min median
                assert_eq!(
                    burn_distribution[0].burns,
                    cmp::min(last_burn, median_burn),
                    "Burn distribution should match at ix = {} block_height = {}",
                    ix,
                    next_mock_header.block_height
                );
            }

            assert_eq!(&tip.winning_block_txid, &expected_winner);

            // load the block into staging
            let block_hash = block.header.block_hash();

            assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
            stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

            preprocess_block(&mut chainstate, &sort_db, &tip, block);

            // handle the stacks block
            coord.handle_new_stacks_block().unwrap();
        }
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    // 1 block of every $MINING_COMMITMENT_WINDOW is missed
    let missed_blocks = vrf_keys.len() / (MINING_COMMITMENT_WINDOW as usize);
    let expected_height = vrf_keys.len() - missed_blocks;
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(expected_height as u128),
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 5 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

/// Test new epoch 2.1 features for handling missed commits.
/// The main difference between this and the 2.05 variant is that missed block-commits here
/// will be rejected if they have different PoX outputs than those expected by their intended
/// sortition.  This test generates block-commits exactly like the 2.05 test (which creates
/// block-commits with bad PoX outputs), and verifies that the burn window is adjusted differently
/// in 2.1 due to the bad missed block-commit *not* counting towards the miner's sortition weight.
#[test]
fn missed_block_commits_2_1() {
    let path = &test_path("missed_block_commits_2_1");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        5,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states_with_epochs(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 0)),
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    let mut last_input: Option<(Txid, u32)> = None;
    let b = get_burnchain(path, None);
    let mut last_bad_op_height = 0;

    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();

        // NOTE: these get used in the late block-commit as well, which will make it invalid (new
        // in 2.1)
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&b, reward_cycle_info.as_ref())
            .unwrap();

        let b = get_burnchain(path, pox_consts.clone());
        let mut ops = vec![];
        if ix % (MINING_COMMITMENT_WINDOW as usize) == 4 {
            // make a bad op, and deliberately use the wrong recipients.
            // This will validate if the commit lands in the reward phase (because we're PoB -- all
            // the outputs are the same), but will fail if it lands in the prepare phase (because
            // the number of outputs will be wrong).
            let (mut bad_op, _) = make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height - 2,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            );
            // NOTE: intended for block block_height - 2
            last_input = Some((
                bad_op.txid(),
                if b.is_in_prepare_phase(next_mock_header.block_height - 2 + 1) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            bad_op.set_block_height(next_mock_header.block_height);
            if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = bad_op {
                op.burn_parent_modulus =
                    ((next_mock_header.block_height - 2) % BURN_BLOCK_MINED_AT_MODULUS) as u8;
                op.vtxindex = 3;
            } else {
                panic!("Should be leader block commit");
            }
            test_debug!(
                "bad_op meant for block {}: {:?}",
                burnchain_tip.block_height - 2 + 1,
                &bad_op
            );
            ops.push(bad_op);
            last_bad_op_height = next_mock_header.block_height;
            info!("bad block-commit in {}", last_bad_op_height);
        }

        let (mut good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            )
        };

        good_op.set_block_height(next_mock_header.block_height);

        let expected_winner = good_op.txid();
        ops.push(good_op);

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();

        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            // produce an empty block!
            produce_burn_block(
                &b,
                &mut burnchain,
                &burnchain_tip.block_hash,
                vec![],
                [].iter_mut(),
            );
        } else {
            // produce a block with one good op,
            last_input = Some((
                expected_winner,
                if b.is_in_prepare_phase(next_mock_header.block_height) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            produce_burn_block_do_not_set_height(
                &b,
                &mut burnchain,
                &burnchain_tip.block_hash,
                ops,
                [].iter_mut(),
            );
        }
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let burn_distribution = get_burn_distribution(sort_db.conn(), &tip.sortition_id);
        eprintln!("{}", ix);
        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            assert!(
                !tip.sortition,
                "Sortition should not have occurred because the only block commit was invalid"
            );
            // duplicate the last stacks_block
            stacks_blocks.push(stacks_blocks[ix - 1].clone());
        } else {
            // how many commits do we expect to see counted in the current window?
            let mut expected_window_commits = if ix >= (MINING_COMMITMENT_WINDOW as usize) {
                (MINING_COMMITMENT_WINDOW - 1) as usize
            } else if ix >= 3 {
                ix
            } else {
                ix + 1
            };
            // there were 2 burn blocks before we started mining
            let expected_window_size = cmp::min(MINING_COMMITMENT_WINDOW as usize, ix + 3);

            // did we have a bad missed commit in this window?
            // bad missed commits land in the prepare phase.
            let have_bad_missed_commit = b.is_in_prepare_phase(last_bad_op_height)
                && ix >= MINING_COMMITMENT_WINDOW.into()
                && last_bad_op_height + (MINING_COMMITMENT_WINDOW as u64) > tip.block_height;
            if have_bad_missed_commit {
                // bad commit breaks the chain if its PoX outputs are invalid
                if ix >= 24 && ix < 29 {
                    expected_window_commits = (tip.block_height - last_bad_op_height + 1) as usize;
                }
                info!(
                    "Expect bad block-commit in window from height {} (tip={}, window={})",
                    last_bad_op_height, tip.block_height, expected_window_commits
                );
            }

            info!(
                "ix = {}: expected_window_commits = {}, expected_window_size = {}",
                ix, expected_window_commits, expected_window_size
            );

            let min_burn = 1;
            let median_burn = if expected_window_commits > expected_window_size / 2 {
                10000
            } else if expected_window_size % 2 == 0
                && expected_window_commits == expected_window_size / 2
            {
                (10000 + 1) / 2
            } else {
                1
            };
            let last_burn = if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
                0
            } else {
                10000
            };

            if b.is_in_prepare_phase(next_mock_header.block_height) {
                // in prepare phase -- no smoothing takes place
                assert_eq!(
                    burn_distribution[0].burns, last_burn,
                    "Burn distribution should not do windowing at ix = {} block_height = {}",
                    ix, next_mock_header.block_height
                )
            } else {
                // in reward phase -- apply min median
                assert_eq!(
                    burn_distribution[0].burns,
                    cmp::min(last_burn, median_burn),
                    "Burn distribution should match at ix = {} block_height = {}",
                    ix,
                    next_mock_header.block_height
                );
            }

            assert_eq!(&tip.winning_block_txid, &expected_winner);

            // load the block into staging
            let block_hash = block.header.block_hash();

            assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
            stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

            preprocess_block(&mut chainstate, &sort_db, &tip, block);

            // handle the stacks block
            coord.handle_new_stacks_block().unwrap();
        }
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    // 1 block of every $MINING_COMMITMENT_WINDOW is missed
    let missed_blocks = vrf_keys.len() / (MINING_COMMITMENT_WINDOW as usize);
    let expected_height = vrf_keys.len() - missed_blocks;
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(expected_height as u128),
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 5 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

/// Verify that a block-commit that is too late in epoch 2.1 (e.g. miss distance > 1) will break
/// the UTXO chain
#[test]
fn late_block_commits_2_1() {
    let path = &test_path("late_block_commits_2_1");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        10,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states_with_epochs(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 0)),
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    let mut last_input: Option<(Txid, u32)> = None;
    let b = get_burnchain(path, None);
    let mut last_bad_op_height = 0;

    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();

        // NOTE: this will accidentally succeed -- the calculation for the recipients is wrong, but
        // it's all PoB here anyway so late block-commits will continue to be accepted.
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&b, reward_cycle_info.as_ref())
            .unwrap();

        let b = get_burnchain(path, pox_consts.clone());
        let mut ops = vec![];

        if ix % (MINING_COMMITMENT_WINDOW as usize) == 4 {
            let (mut bad_op, _) = make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height - 3,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            );
            // NOTE: intended for block block_height - 3
            last_input = Some((
                bad_op.txid(),
                if b.is_in_prepare_phase(next_mock_header.block_height - 3 + 1) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            bad_op.set_block_height(next_mock_header.block_height);
            if let BlockstackOperationType::LeaderBlockCommit(ref mut op) = bad_op {
                op.burn_parent_modulus =
                    ((next_mock_header.block_height - 3) % BURN_BLOCK_MINED_AT_MODULUS) as u8;
                op.vtxindex = 3;
            } else {
                panic!("Should be leader block commit");
            }
            test_debug!(
                "bad_op meant for block {}: {:?}",
                burnchain_tip.block_height - 3 + 1,
                &bad_op
            );
            ops.push(bad_op);
            last_bad_op_height = next_mock_header.block_height;
            info!("bad block-commit in {}", last_bad_op_height);
        }

        let (mut good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                0,
                false,
                last_input.as_ref().unwrap().clone(),
                None,
                &[],
            )
        };

        good_op.set_block_height(next_mock_header.block_height);

        let expected_winner = good_op.txid();
        ops.push(good_op);

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();

        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            // produce an empty block!
            produce_burn_block(
                &b,
                &mut burnchain,
                &burnchain_tip.block_hash,
                vec![],
                [].iter_mut(),
            );
        } else {
            // produce a block with one good op,
            last_input = Some((
                expected_winner,
                if b.is_in_prepare_phase(next_mock_header.block_height) {
                    2
                } else {
                    (OUTPUTS_PER_COMMIT as u32) + 1
                },
            ));
            produce_burn_block_do_not_set_height(
                &b,
                &mut burnchain,
                &burnchain_tip.block_hash,
                ops,
                [].iter_mut(),
            );
        }
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let burn_distribution = get_burn_distribution(sort_db.conn(), &tip.sortition_id);
        eprintln!("{}", ix);
        if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
            assert!(
                !tip.sortition,
                "Sortition should not have occurred because the only block commit was invalid"
            );
            // duplicate the last stacks_block
            stacks_blocks.push(stacks_blocks[ix - 1].clone());
        } else {
            // how many commit do we expect to see counted in the current window?
            let mut expected_window_commits = if ix >= (MINING_COMMITMENT_WINDOW as usize) {
                (MINING_COMMITMENT_WINDOW - 1) as usize
            } else if ix >= 3 {
                ix
            } else {
                ix + 1
            };
            // there were 2 burn blocks before we started mining
            let expected_window_size = cmp::min(MINING_COMMITMENT_WINDOW as usize, ix + 3);

            // did we have a bad missed commit in this window?
            let have_bad_missed_commit = ix >= 4
                && last_bad_op_height + (MINING_COMMITMENT_WINDOW as u64) > tip.block_height;
            if have_bad_missed_commit {
                // bad commit breaks the chain if its miss distance is too high.
                expected_window_commits = (tip.block_height - last_bad_op_height + 1) as usize;
                info!(
                    "Expect bad block-commit in window from height {} (tip={}, window={})",
                    last_bad_op_height, tip.block_height, expected_window_commits
                );
            }

            info!("ix = {}: expected_window_commits = {}, expected_window_size = {}, last_bad_op_height = {}", ix, expected_window_commits, expected_window_size, last_bad_op_height);

            let min_burn = 1;
            let median_burn = if expected_window_commits > expected_window_size / 2 {
                10000
            } else if expected_window_size % 2 == 0
                && expected_window_commits == expected_window_size / 2
            {
                (10000 + 1) / 2
            } else {
                1
            };
            let last_burn = if ix % (MINING_COMMITMENT_WINDOW as usize) == 3 {
                0
            } else {
                10000
            };

            if b.is_in_prepare_phase(next_mock_header.block_height) {
                // in prepare phase -- no smoothing takes place
                assert_eq!(
                    burn_distribution[0].burns, last_burn,
                    "Burn distribution should not do windowing at ix = {} block_height = {}",
                    ix, next_mock_header.block_height
                );
                info!(
                    "ix = {} (pp): burn_distribution[0].burns == {:?}",
                    ix, burn_distribution[0].burns
                );
            } else {
                // in reward phase -- apply min median
                assert_eq!(
                    burn_distribution[0].burns,
                    cmp::min(last_burn, median_burn),
                    "Burn distribution should match at ix = {} block_height = {}",
                    ix,
                    next_mock_header.block_height
                );
                info!(
                    "ix = {} (rp): burn_distribution[0].burns == {:?}",
                    ix, burn_distribution[0].burns
                );
            }

            assert_eq!(&tip.winning_block_txid, &expected_winner);

            // load the block into staging
            let block_hash = block.header.block_hash();

            assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
            stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

            preprocess_block(&mut chainstate, &sort_db, &tip, block);

            // handle the stacks block
            coord.handle_new_stacks_block().unwrap();
        }
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);

    // 1 block of every $MINING_COMMITMENT_WINDOW is missed
    let missed_blocks = vrf_keys.len() / (MINING_COMMITMENT_WINDOW as usize);
    let expected_height = vrf_keys.len() - missed_blocks;
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(expected_height as u128),
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "1111111",
                   "PoX ID should reflect the 5 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

#[test]
fn test_simple_setup() {
    let path = &test_path("simple-setup");
    // setup a second set of states that won't see the broadcasted blocks
    let path_blinded = &test_path("simple-setup.blinded");
    let _r = std::fs::remove_dir_all(path);
    let _r = std::fs::remove_dir_all(path_blinded);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path, path_blinded],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, None);
    let mut coord_blind = make_coordinator(path_blinded, None);

    coord.handle_new_burnchain_block().unwrap();
    coord_blind.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    let sort_db_blind = get_sortition_db(path_blinded, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db_blind
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // at first, sortition_ids shouldn't have diverged
    //  but once the first reward cycle begins, they should diverge.
    let mut sortition_ids_diverged = false;
    let mut parent = BlockHeaderHash([0; 32]);
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks = vec![];
    let mut anchor_blocks = vec![];
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);
        let b = get_burnchain(path, None);
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let burnchain_blinded = get_burnchain_db(path_blinded, None);

        let (op, block) = if ix == 0 {
            make_genesis_block(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        } else {
            make_stacks_block(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        };

        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![op],
            [burnchain_blinded].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();
        coord_blind.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            // the "blinded" sortition db and the one that's processed all the blocks
            //   should have diverged in sortition_ids now...
            sortition_ids_diverged = true;
            // store the anchor block for this sortition for later checking
            let ic = sort_db.index_handle_at_tip();
            let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
            anchor_blocks.push(bhh);
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
        if sortition_ids_diverged {
            assert_ne!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should have diverged by block height = {}",
                blinded_tip.block_height
            );
        } else {
            assert_eq!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should not have diverged at block height = {}",
                blinded_tip.block_height
            );
        }

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        parent = block_hash;
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(50)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 10 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(
            &pox_id.to_string(),
            "110000000000",
            "PoX ID should reflect the initial 'known' reward cycle at genesis"
        );
    }

    let mut pox_id_string = "1".to_string();
    // now let's start revealing stacks blocks to the blinded coordinator
    for (sortition_id, block) in stacks_blocks.iter() {
        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            sortition_id,
            block,
        );

        let pox_id_at_tip = {
            let ic = sort_db_blind.index_handle_at_tip();
            ic.get_pox_id().unwrap()
        };

        let block_hash = block.header.block_hash();
        if anchor_blocks.contains(&block_hash) {
            // just processed an anchor block, we should expect to have a pox_id
            //   that has one more one!
            pox_id_string.push('1');
        }

        println!("=> {}", pox_id_string);
        assert_eq!(
            pox_id_at_tip.to_string(),
            // right-pad pox_id_string to 11 characters
            format!("1{:0<11}", pox_id_string)
        );
    }
}

#[test]
fn test_sortition_with_reward_set() {
    let path = &test_path("simple-reward-set");
    let _r = std::fs::remove_dir_all(path);

    let mut vrf_keys: Vec<_> = (0..150).map(|_| VRFPrivateKey::new()).collect();
    let mut committers: Vec<_> = (0..150).map(|_| StacksPrivateKey::new()).collect();

    let reward_set_size = 4;
    let reward_set: Vec<_> = (0..reward_set_size)
        .map(|_| pox_addr_from(&StacksPrivateKey::new()))
        .collect();

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_reward_set_coordinator(path, reward_set, None);

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // split up the vrf keys and committers so that we have some that will be mining "correctly"
    //   and some that will be producing bad outputs

    let BURNER_OFFSET = 50;
    let mut vrf_key_burners = vrf_keys.split_off(50);
    let mut miner_burners = committers.split_off(50);

    let WRONG_OUTS_OFFSET = 100;
    let vrf_key_wrong_outs = vrf_key_burners.split_off(50);
    let miner_wrong_outs = miner_burners.split_off(50);

    let b = get_burnchain(path, None);

    // track the reward set consumption
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let vrf_burner = &vrf_key_burners[ix];
        let miner_burner = &miner_burners[ix];

        let vrf_wrong_out = &vrf_key_wrong_outs[ix];
        let miner_wrong_out = &miner_wrong_outs[ix];

        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else if ix == 49 {
            // lets mine off a block that _isn't_ a descendant of our PoX anchor
            stacks_blocks[1].1.header.block_hash()
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            if started_first_reward_cycle {
                assert_eq!(reward_recipients.len(), reward_set_size);
            }
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        }
        let next_block_recipients = get_rw_sortdb(path, None)
            .test_get_next_block_recipients(&b, reward_cycle_info.as_ref())
            .unwrap();
        if let Some(ref next_block_recipients) = next_block_recipients {
            for (addr, _) in next_block_recipients.recipients.iter() {
                assert!(
                    !reward_recipients.contains(addr),
                    "Reward set should not already contain address {}",
                    addr
                );
                eprintln!("At iteration: {}, inserting address ... {}", ix, addr);
                reward_recipients.insert(addr.clone());
            }
        }

        let b = get_burnchain(path, None);
        let (good_op, mut block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        };

        let mut expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if started_first_reward_cycle {
            // make the bad commitments
            // only create bad "burn" commitments if we know they'll be rejected:
            //   (a) we're in a reward cycle _and_ (b) there are expected recipients
            if next_block_recipients.is_some() {
                let (all_burn_op, all_burn_block) = make_stacks_block_with_recipients(
                    &sort_db,
                    &mut chainstate,
                    &b,
                    &parent,
                    burnchain_tip.block_height,
                    miner_burner,
                    10000,
                    vrf_burner,
                    (ix + BURNER_OFFSET) as u32,
                    None,
                );
                if ix == 49 {
                    // at this ix, _all_burn_block_ should be the winner
                    //   because "parent" isn't a descendant of the PoX anchor
                    expected_winner = all_burn_op.txid();
                    block = all_burn_block;
                }
                ops.push(all_burn_op);
            }

            // sometime have the wrong _number_ of recipients,
            //   other times just have the wrong set of recipients
            let recipients = if ix % 2 == 0 {
                vec![(pox_addr_from(miner_wrong_out), 0)]
            } else {
                (0..OUTPUTS_PER_COMMIT)
                    .map(|ix| (pox_addr_from(&StacksPrivateKey::new()), ix as u16))
                    .collect()
            };
            let bad_block_recipients = Some(RewardSetInfo {
                anchor_block: BlockHeaderHash([0; 32]),
                recipients,
                allow_nakamoto_punishment: false,
            });
            let (bad_outs_op, _) = make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner_wrong_out,
                10000,
                vrf_burner,
                (ix + WRONG_OUTS_OFFSET) as u32,
                bad_block_recipients.as_ref(),
            );
            ops.push(bad_outs_op);
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            started_first_reward_cycle = true;
            // store the anchor block for this sortition for later checking
            let ic = sort_db.index_handle_at_tip();
            let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
            anchor_blocks.push(bhh);
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        // we only got to block height 49, because of the little fork at the end.
        Value::UInt(49)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 10 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

#[test]
fn test_sortition_with_burner_reward_set() {
    let path = &test_path("burner-reward-set");
    let _r = std::fs::remove_dir_all(path);

    let mut vrf_keys: Vec<_> = (0..150).map(|_| VRFPrivateKey::new()).collect();
    let mut committers: Vec<_> = (0..150).map(|_| StacksPrivateKey::new()).collect();

    let reward_set_size = 3;
    let mut reward_set: Vec<_> = (0..reward_set_size - 1)
        .map(|_| PoxAddress::standard_burn_address(false))
        .collect();
    reward_set.push(pox_addr_from(&StacksPrivateKey::new()));

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_reward_set_coordinator(path, reward_set, None);

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // split up the vrf keys and committers so that we have some that will be mining "correctly"
    //   and some that will be producing bad outputs

    let BURNER_OFFSET = 50;
    let mut vrf_key_burners = vrf_keys.split_off(50);
    let mut miner_burners = committers.split_off(50);

    let WRONG_OUTS_OFFSET = 100;
    let vrf_key_wrong_outs = vrf_key_burners.split_off(50);
    let miner_wrong_outs = miner_burners.split_off(50);

    let b = get_burnchain(path, None);

    // track the reward set consumption
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let vrf_burner = &vrf_key_burners[ix];
        let miner_burner = &miner_burners[ix];

        let vrf_wrong_out = &vrf_key_wrong_outs[ix];
        let miner_wrong_out = &miner_wrong_outs[ix];

        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            if started_first_reward_cycle {
                assert_eq!(reward_recipients.len(), 2);
            }
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        }
        let next_block_recipients = get_rw_sortdb(path, None)
            .test_get_next_block_recipients(&b, reward_cycle_info.as_ref())
            .unwrap();
        if let Some(ref next_block_recipients) = next_block_recipients {
            for (addr, _) in next_block_recipients.recipients.iter() {
                if !addr.is_burn() {
                    assert!(
                        !reward_recipients.contains(addr),
                        "Reward set should not already contain address {}",
                        addr
                    );
                }
                eprintln!("At iteration: {}, inserting address ... {}", ix, addr);
                reward_recipients.insert(addr.clone());
            }
        }

        let b = get_burnchain(path, None);
        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        };

        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if started_first_reward_cycle {
            // sometime have the wrong _number_ of recipients,
            //   other times just have the wrong set of recipients
            let recipients = if ix % 2 == 0 {
                vec![(pox_addr_from(miner_wrong_out), 0)]
            } else {
                (0..OUTPUTS_PER_COMMIT)
                    .map(|ix| (pox_addr_from(&StacksPrivateKey::new()), ix as u16))
                    .collect()
            };
            let bad_block_recipients = Some(RewardSetInfo {
                anchor_block: BlockHeaderHash([0; 32]),
                recipients,
                allow_nakamoto_punishment: false,
            });
            let (bad_outs_op, _) = make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner_wrong_out,
                10000,
                vrf_burner,
                (ix + WRONG_OUTS_OFFSET) as u32,
                bad_block_recipients.as_ref(),
            );
            ops.push(bad_outs_op);
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            started_first_reward_cycle = true;
            // store the anchor block for this sortition for later checking
            let ic = sort_db.index_handle_at_tip();
            let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
            anchor_blocks.push(bhh);
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(50)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 10 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

#[test]
fn test_pox_btc_ops() {
    let path = &test_path("pox-btc-ops");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_v1_unlock_ht = u32::MAX;
    let pox_v2_unlock_ht = u32::MAX;
    let pox_v3_unlock_ht = u32::MAX;
    let pox_consts = Some(PoxConstants::new(
        5,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        pox_v1_unlock_ht,
        pox_v2_unlock_ht,
        pox_v3_unlock_ht,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // track the reward set consumption
    let mut reward_cycle_count = 0;
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            reward_cycle_count += 1;
            if reward_cycle_count > 2 && reward_cycle_count < 6 {
                assert_eq!(reward_recipients.len(), 1);
            }
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        }
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&burnchain_conf, reward_cycle_info.as_ref())
            .unwrap();
        if next_mock_header.block_height >= sunset_ht {
            assert!(next_block_recipients.is_none());
        }

        if let Some(ref next_block_recipients) = next_block_recipients {
            for (addr, _) in next_block_recipients.recipients.iter() {
                eprintln!("At iteration: {}, inserting address ... {}", ix, addr);
                reward_recipients.insert(addr.clone());
            }
        }

        let b = get_burnchain(path, None);

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        };

        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if ix == 0 {
            // add a pre-stack-stx op
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: stacker.clone(),
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 1 {
            ops.push(BlockstackOperationType::StackStx(StackStxOp {
                sender: stacker.clone(),
                reward_addr: rewards.clone(),
                stacked_ustx: stacked_amt,
                num_cycles: 4,
                signer_key: Some(StacksPublicKeyBuffer([0x02; 33])),
                max_amount: Some(u128::MAX),
                auth_id: Some(0u32),
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        }

        // check our locked balance
        if ix > 0 {
            let stacks_tip =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
            let mut chainstate = get_chainstate(path);
            let (stacker_balance, burn_height) = chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            (
                                db.get_account_stx_balance(&stacker.clone().into()).unwrap(),
                                db.get_current_block_height(),
                            )
                        })
                    },
                )
                .unwrap();

            if ix > 2 && reward_cycle_count < 6 {
                assert_eq!(
                    stacker_balance.amount_unlocked(),
                    (balance as u128) - stacked_amt,
                    "Lock should be active"
                );
                assert_eq!(stacker_balance.amount_locked(), stacked_amt);
            } else {
                assert_eq!(
                    stacker_balance
                        .get_available_balance_at_burn_block(
                            burn_height as u64,
                            pox_v1_unlock_ht,
                            pox_v2_unlock_ht,
                            pox_v3_unlock_ht
                        )
                        .unwrap(),
                    balance as u128,
                    "No lock should be active"
                );
            }
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            if new_burnchain_tip.block_height < sunset_ht {
                started_first_reward_cycle = true;
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
                anchor_blocks.push(bhh);
            } else {
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                assert!(
                    ic.get_last_anchor_block_hash().unwrap().is_none(),
                    "No PoX anchor block should be chosen after PoX sunset"
                );
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(50)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 5 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

#[test]
fn test_stx_transfer_btc_ops() {
    let path = &test_path("stx_transfer-btc-ops");
    let _r = std::fs::remove_dir_all(path);

    let pox_v1_unlock_ht = u32::MAX;
    let pox_v2_unlock_ht = u32::MAX;
    let pox_v3_unlock_ht = u32::MAX;
    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        5,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        pox_v1_unlock_ht,
        pox_v2_unlock_ht,
        pox_v3_unlock_ht,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let recipient = p2pkh_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let transfer_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // track the reward set consumption
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            assert_eq!(reward_recipients.len(), 0);
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        }
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&burnchain_conf, reward_cycle_info.as_ref())
            .unwrap();
        if next_mock_header.block_height >= sunset_ht {
            assert!(next_block_recipients.is_none());
        }

        if let Some(ref next_block_recipients) = next_block_recipients {
            for (addr, _) in next_block_recipients.recipients.iter() {
                eprintln!("At iteration: {}, inserting address ... {}", ix, addr);
                reward_recipients.insert(addr.clone());
            }
        }

        let b = get_burnchain(path, pox_consts.clone());
        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        };

        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if ix == 0 {
            // add a pre-stack-stx op
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: stacker.clone(),
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: recipient.clone(),
                txid: next_txid(),
                vtxindex: 6,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 1 {
            ops.push(BlockstackOperationType::TransferStx(TransferStxOp {
                sender: stacker.clone(),
                recipient: recipient.clone(),
                transfered_ustx: transfer_amt,
                memo: vec![],
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 2 {
            // shouldn't be accepted -- transfer amount is too large
            ops.push(BlockstackOperationType::TransferStx(TransferStxOp {
                sender: recipient.clone(),
                recipient: stacker.clone(),
                transfered_ustx: transfer_amt + 1,
                memo: vec![],
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        }

        // check our locked balance
        if ix > 0 {
            let stacks_tip =
                SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
            let mut chainstate = get_chainstate(path);
            let (sender_balance, burn_height) = chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            (
                                db.get_account_stx_balance(&stacker.clone().into()).unwrap(),
                                db.get_current_block_height(),
                            )
                        })
                    },
                )
                .unwrap();

            let (recipient_balance, burn_height) = chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            (
                                db.get_account_stx_balance(&recipient.clone().into())
                                    .unwrap(),
                                db.get_current_block_height(),
                            )
                        })
                    },
                )
                .unwrap();

            if ix > 2 {
                assert_eq!(
                    sender_balance
                        .get_available_balance_at_burn_block(
                            burn_height as u64,
                            pox_v1_unlock_ht,
                            pox_v2_unlock_ht,
                            pox_v3_unlock_ht,
                        )
                        .unwrap(),
                    (balance as u128) - transfer_amt,
                    "Transfer should have decremented balance"
                );
                assert_eq!(
                    recipient_balance
                        .get_available_balance_at_burn_block(
                            burn_height as u64,
                            pox_v1_unlock_ht,
                            pox_v2_unlock_ht,
                            pox_v3_unlock_ht,
                        )
                        .unwrap(),
                    transfer_amt,
                    "Recipient should have incremented balance"
                );
            } else {
                assert_eq!(
                    sender_balance
                        .get_available_balance_at_burn_block(
                            burn_height as u64,
                            pox_v1_unlock_ht,
                            pox_v2_unlock_ht,
                            pox_v3_unlock_ht,
                        )
                        .unwrap(),
                    balance as u128,
                );
                assert_eq!(
                    recipient_balance
                        .get_available_balance_at_burn_block(
                            burn_height as u64,
                            pox_v1_unlock_ht,
                            pox_v2_unlock_ht,
                            pox_v3_unlock_ht,
                        )
                        .unwrap(),
                    0,
                );
            }
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            if new_burnchain_tip.block_height < sunset_ht {
                started_first_reward_cycle = true;
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
                anchor_blocks.push(bhh);
            } else {
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                assert!(
                    ic.get_last_anchor_block_hash().unwrap().is_none(),
                    "No PoX anchor block should be chosen after PoX sunset"
                );
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(50)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111",
                   "PoX ID should reflect the 5 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

// This helper function retrieves the delegation info from the delegate address
// from the pox-2 contract.
// Given an address, it retrieves the fields `amount-ustx` and `pox-addr` from the map
// `delegation-state` in pox-2.
fn get_delegation_info_pox_2(
    chainstate: &mut StacksChainState,
    burn_dbconn: &dyn BurnStateDB,
    parent_tip: &StacksBlockId,
    del_addr: &StacksAddress,
) -> Option<(u128, Option<PoxAddress>)> {
    let result = chainstate
        .with_read_only_clarity_tx(burn_dbconn, parent_tip, |conn| {
            conn.with_readonly_clarity_env(
                false,
                CHAIN_ID_TESTNET,
                ClarityVersion::Clarity2,
                PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                None,
                LimitedCostTracker::new_free(),
                |env| {
                    let eval_str = format!(
                        "(contract-call? '{}.pox-2 get-delegation-info '{})",
                        &boot_code_addr(false),
                        del_addr
                    );

                    let result = env.eval_raw(&eval_str).unwrap();
                    Ok(result)
                },
            )
            .unwrap()
        })
        .unwrap()
        .expect_optional()
        .unwrap();
    match result {
        None => None,
        Some(tuple) => {
            let data = tuple.expect_tuple().unwrap().data_map;
            let delegated_amt = data
                .get("amount-ustx")
                .cloned()
                .unwrap()
                .expect_u128()
                .unwrap();
            let reward_addr_opt = if let Some(reward_addr) = data
                .get("pox-addr")
                .cloned()
                .unwrap()
                .expect_optional()
                .unwrap()
            {
                Some(PoxAddress::try_from_pox_tuple(false, &reward_addr).unwrap())
            } else {
                None
            };
            Some((delegated_amt, reward_addr_opt))
        }
    }
}

// This test ensures that delegate stx burn ops are applied as expected.
// In this test, the burn chain does not fork at all.
// First, a DelegateSTX operation is sent in burn block n. The stacks
// blockchain does not fork for the next 10 blocks, and the test verifies
// that this delegation persists for the next 40 or so blocks.
// Second, a DelegateSTX operation is sent in burn block m. This time,
// the stacks blockchain forks off the stacks block built off of burn
// block m for the next 10 blocks. The test verifies that this delegate
// stx operation is only processed and active in the stacks block built off
// of burn blocks m+1 to m+7 inclusive. From block m+8 onward, the
// delegation does not persist.
//
// The chain in this test looks something like this, where Bi represents the
// ith burn block, and Sj represents the jth stacks block.

//          1st op sent       2nd op sent
//              ^                 ^
// B2 -> .. -> B12 -> B13 -> ... B22 -> B23 -> B24 -> B25 -> B26 -> ... -> B32 -> B33
// S0 -> .. -> S10 -> S11 -> ... S20 -> S21
//                                \ _ _ _ _ _  S22
//                                \ _ _ _ _ _ _ _ _  S23
//                                \ _ _ _ _ _ _ _ _ _ _ _ _  S24
//                                  ....
//                                \ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ S30 -> S31 -> ...
#[test]
fn test_delegate_stx_btc_ops() {
    let path = &test_path("delegate-stx-btc-ops");
    let _r = std::fs::remove_dir_all(path);

    let pox_v1_unlock_ht = 12;
    let pox_v2_unlock_ht = u32::MAX;
    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        100,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        pox_v1_unlock_ht,
        pox_v2_unlock_ht,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let first_del = p2pkh_from(&StacksPrivateKey::new());
    let second_del = p2pkh_from(&StacksPrivateKey::new());
    let delegator_addr = p2pkh_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let delegated_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![
        (first_del.clone().into(), balance),
        (second_del.clone().into(), balance),
    ];

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        // The stacks chain will look something like this
        // S0 -> S1 -> S2 -> ... S20 -> S21
        //                          \ _ S22
        //                          \ _ S23
        //                          \ _ S24
        //                            ....
        //                          \ _ S30 -> S31 -> ...
        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else if ix >= 22 && ix <= 30 {
            stacks_blocks[20].1.header.block_hash()
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                None,
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                None,
            )
        };

        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];
        let reward_addr = PoxAddress::Standard(
            StacksAddress::from_string("ST76D2FMXZ7D2719PNE4N71KPSX84XCCNCMYC940").unwrap(),
            Some(AddressHashMode::SerializeP2PKH),
        );
        if ix == 0 {
            // add a pre-stx op
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: first_del.clone(),
                txid: next_txid(),
                vtxindex: 4,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: first_del.clone(),
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: second_del.clone(),
                txid: next_txid(),
                vtxindex: 6,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 1 {
            // The effects of this operation should never materialize,
            // since this operation was sent before 2.1 is active.
            ops.push(BlockstackOperationType::DelegateStx(DelegateStxOp {
                sender: first_del.clone(),
                delegate_to: delegator_addr.clone(),
                reward_addr: None,
                delegated_ustx: delegated_amt * 3,
                until_burn_height: None,
                txid: next_txid(),
                vtxindex: 4,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 10 {
            ops.push(BlockstackOperationType::DelegateStx(DelegateStxOp {
                sender: first_del.clone(),
                delegate_to: delegator_addr.clone(),
                reward_addr: Some((1, reward_addr.clone())),
                delegated_ustx: delegated_amt,
                until_burn_height: None,
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 20 {
            ops.push(BlockstackOperationType::DelegateStx(DelegateStxOp {
                sender: second_del.clone(),
                delegate_to: delegator_addr.clone(),
                reward_addr: None,
                delegated_ustx: delegated_amt * 2,
                until_burn_height: None,
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let parent_tip = StacksBlockId::new(&tip.consensus_hash, &block_hash);

        // check our delegated balance after Epoch 2.1 begins (at burn height 8)
        let mut chainstate = get_chainstate(path);
        if ix >= 6 {
            eprintln!(
                "ix = {}, parent tip = {} = {}/{}, tip height is {}",
                ix, &parent_tip, &tip.consensus_hash, &block_hash, tip.block_height
            );
            let first_delegation_info = get_delegation_info_pox_2(
                &mut chainstate,
                &sort_db.index_handle_at_tip(),
                &parent_tip,
                &first_del,
            );
            let second_delegation_info = get_delegation_info_pox_2(
                &mut chainstate,
                &sort_db.index_handle_at_tip(),
                &parent_tip,
                &second_del,
            );

            // Check that the effects of the delegate stx op sent when ix==10
            // are materialized for ix=11... (we check that the
            // changes endure for the following blocks)
            if ix >= 11 {
                assert_eq!(
                    first_delegation_info,
                    Some((delegated_amt, Some(reward_addr.clone()))),
                    "The first delegation should be active"
                );
            } else {
                assert_eq!(
                    first_delegation_info, None,
                    "The first delegation should not be active"
                );
            }

            // Check that the effects of the delegate stx op sent when ix==20
            // are materialized for ix=21..27 (n to n+6 inclusive), where each of these
            // blocks fork off of the state from iteration ix=20.
            // Want to ensure that a burnchain operation sent in a burn block
            // is picked up by stacks blocks on the same burnchain block
            // up to 6 stacks blocks in the future, even if the stacks blockchain is forking.
            if ix >= 21 && ix <= 27 {
                assert_eq!(
                    second_delegation_info,
                    Some((delegated_amt * 2, None)),
                    "The second delegation should be active"
                );
            } else {
                assert_eq!(
                    second_delegation_info, None,
                    "The second delegation should not be active"
                );
            }
        }
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(41)
    );

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11")
    }
}

#[test]
fn test_initial_coinbase_reward_distributions() {
    let path = "/tmp/initial_coinbase_reward_distributions";
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        5,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let rewards = p2pkh_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch20,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    // produce some burn blocks without sortitions:
    for _ix in 0..50 {
        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &burnchain_conf,
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![],
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();
    }
    let initial_missed_blocks = {
        let burnchain = get_burnchain_db(path, pox_consts.clone());
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        // +1 here, because the # of missed blocks is (first_sortition_height - first_burn_block_height)
        burnchain_tip.block_height + 1
    };

    let initial_block_bonus = (initial_missed_blocks as u128 * MICROSTACKS_PER_STACKS as u128)
        * 1_000
        / (INITIAL_MINING_BONUS_WINDOW as u128);

    // now we'll mine 20 burn blocks, every other one with a sortition.
    //   we should get:
    //   block  0: initial_block_bonus + 1_000STX
    //   block  1: no sortition
    //   block  2: 2*(initial_block_bonus + 1_000)
    //   ...
    //   block  8: 2*(initial_block_bonus + 1_000)
    //   block  9: no sortition
    //   block 10: 1_000 + (initial_block_bonus + 1_000)
    //   block 11: no sortition
    //   block 12: 2_000
    //   block 13: no sortition
    //   block 14: 2_000

    for ix in 0..20 {
        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        eprintln!("BURNCHAIN TIP HEIGHT = {}", burnchain_tip.block_height);
        if ix % 2 == 1 {
            produce_burn_block(
                &burnchain_conf,
                &mut burnchain,
                &burnchain_tip.block_hash,
                vec![],
                [].iter_mut(),
            );
            coord.handle_new_burnchain_block().unwrap();
        } else {
            let vrf_key = &vrf_keys[ix];
            let miner = &committers[ix];

            let mut chainstate = get_chainstate(path);

            let parent = if ix == 0 {
                BlockHeaderHash([0; 32])
            } else {
                stacks_blocks[ix / 2 - 1].1.header.block_hash()
            };

            let b = get_burnchain(path, pox_consts.clone());
            let (good_op, block) = if ix == 0 {
                make_genesis_block_with_recipients(
                    &b,
                    &sort_db,
                    &mut chainstate,
                    &parent,
                    miner,
                    10000,
                    vrf_key,
                    ix as u32,
                    None,
                )
            } else {
                make_stacks_block_with_recipients(
                    &sort_db,
                    &mut chainstate,
                    &b,
                    &parent,
                    burnchain_tip.block_height,
                    miner,
                    1000,
                    vrf_key,
                    ix as u32,
                    None,
                )
            };
            let expected_winner = good_op.txid();
            let ops = vec![good_op];

            let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
            produce_burn_block(
                &b,
                &mut burnchain,
                &burnchain_tip.block_hash,
                ops,
                [].iter_mut(),
            );
            // handle the sortition
            coord.handle_new_burnchain_block().unwrap();

            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
            assert_eq!(&tip.winning_block_txid, &expected_winner);

            // load the block into staging
            let block_hash = block.header.block_hash();

            assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
            stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

            preprocess_block(&mut chainstate, &sort_db, &tip, block);

            // handle the stacks block
            coord.handle_new_stacks_block().unwrap();
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

        let base_coinbase = 1_000 * MICROSTACKS_PER_STACKS as u128;
        eprintln!(
            "At index = {}, total: {}",
            ix,
            tip.accumulated_coinbase_ustx + base_coinbase
        );

        if ix % 2 == 1 {
            assert!(!tip.sortition, "Odd indexes should not produce sortitions");
        } else if ix == 0 {
            assert_eq!(
                tip.accumulated_coinbase_ustx + base_coinbase,
                initial_block_bonus + base_coinbase
            );
        } else if ix < 10 {
            assert_eq!(
                tip.accumulated_coinbase_ustx + base_coinbase,
                2 * (initial_block_bonus + base_coinbase)
            );
        } else if ix == 10 {
            assert_eq!(
                tip.accumulated_coinbase_ustx + base_coinbase,
                initial_block_bonus + (2 * base_coinbase)
            );
        } else {
            assert_eq!(
                tip.accumulated_coinbase_ustx + base_coinbase,
                2 * base_coinbase
            );
        }
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(10)
    );
}

// This test ensures the epoch transition is applied at the proper block boundaries, and that the
// epoch transition is only applied once. If it were to be applied more than once, the test would
// panic when trying to re-create the costs-2 contract.
#[test]
fn test_epoch_switch_cost_contract_instantiation() {
    let path = &test_path("epoch-switch-cost-contract-instantiation");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..10).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..10).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    for ix in 0..6 {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        // The line going down represents the epoch boundary. Want to ensure that the costs-2
        // contract DNE for all blocks before the boundary, and does exist for blocks after the
        // boundary.
        //        |
        // G  -> A -> B
        //        |\
        //        | \
        //        |  C -> D
        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else if ix == 3 {
            stacks_blocks[ix - 2].1.header.block_hash()
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                None,
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                None,
            )
        };

        let expected_winner = good_op.txid();
        let ops = vec![good_op];

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &burnchain_conf,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
        let burn_block_height = tip.block_height;

        // check that the expected stacks epoch ID is equal to the actual stacks epoch ID
        let expected_epoch = match burn_block_height {
            x if x < 4 => StacksEpochId::Epoch20,
            _ => StacksEpochId::Epoch2_05,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| conn.with_clarity_db_readonly(|db| db
                        .get_stacks_epoch(burn_block_height as u32)
                        .unwrap())
                )
                .unwrap()
                .epoch_id,
            expected_epoch
        );

        // These expectations are according to according to hard-coded values in
        // `StacksEpoch::unit_test_2_05`.
        let expected_runtime = match burn_block_height {
            x if x < 4 => u64::MAX,
            _ => 205205,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_stacks_epoch(burn_block_height as u32).unwrap()
                        })
                    },
                )
                .unwrap()
                .block_limit
                .runtime,
            expected_runtime
        );

        // check that costs-2 contract DNE before epoch 2.05, and that it does exist after
        let does_costs_2_contract_exist = chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| {
                    conn.with_clarity_db_readonly(|db| {
                        db.get_contract(&boot_code_id(COSTS_2_NAME, false))
                    })
                },
            )
            .unwrap();
        if burn_block_height < 4 {
            assert!(does_costs_2_contract_exist.is_err())
        } else {
            assert!(does_costs_2_contract_exist.is_ok())
        }
    }
}

// This test ensures the epoch transition from 2.05 to 2.1 is applied at the proper block boundaries,
// and that the epoch transition is only applied once. If it were to be applied more than once,
// the test would panic when trying to re-create the pox-2 contract.
#[test]
fn test_epoch_switch_pox_2_contract_instantiation() {
    let path = &test_path("epoch-switch-pox-contract-instantiation");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        10,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..15).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..15).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch21,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    for ix in 0..14 {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        // Want to ensure that the pox-2 contract DNE for all blocks before the epoch transition height,
        // and does exist for blocks after the boundary.
        //                              Epoch 2.1 transition
        //                                       ^
        //.. B1 -> B2 -> B3 -> B4 -> B5 -> B6 -> B7 -> B8 -> B9 -> ..
        //   S0 -> S1 -> S2 -> S3 -> S4 -> S5 -> S6
        //                                  \
        //                                    \
        //                                      _ _ _  S7 -> S8 -> ..
        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else if ix == 7 {
            stacks_blocks[ix - 2].1.header.block_hash()
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                None,
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                None,
            )
        };

        let expected_winner = good_op.txid();
        let ops = vec![good_op];

        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
        let burn_block_height = tip.block_height;

        // check that the expected stacks epoch ID is equal to the actual stacks epoch ID
        let expected_epoch = match burn_block_height {
            x if x < 4 => StacksEpochId::Epoch20,
            x if x >= 4 && x < 8 => StacksEpochId::Epoch2_05,
            x => StacksEpochId::Epoch21,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| conn.with_clarity_db_readonly(|db| db
                        .get_stacks_epoch(burn_block_height as u32)
                        .unwrap())
                )
                .unwrap()
                .epoch_id,
            expected_epoch
        );

        // These expectations are according to according to hard-coded values in
        // `StacksEpoch::unit_test_2_1`.
        let expected_runtime = match burn_block_height {
            x if x < 4 => u64::MAX,
            x if x >= 4 && x < 8 => 205205,
            x => 210210,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_stacks_epoch(burn_block_height as u32).unwrap()
                        })
                    },
                )
                .unwrap()
                .block_limit
                .runtime,
            expected_runtime
        );

        // check that pox-2 contract DNE before epoch 2.1, and that it does exist after
        let does_pox_2_contract_exist = chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| {
                    conn.with_clarity_db_readonly(|db| {
                        db.get_contract(&boot_code_id(POX_2_NAME, false))
                    })
                },
            )
            .unwrap();

        if burn_block_height < 8 {
            assert!(does_pox_2_contract_exist.is_err())
        } else {
            assert!(does_pox_2_contract_exist.is_ok())
        }
    }
}

// This test ensures the epoch transition from 2.3 to 2.4 is applied at the proper block boundaries,
// and that the epoch transition is only applied once. If it were to be applied more than once,
// the test would panic when trying to re-create the pox-3 contract.
#[test]
fn test_epoch_switch_pox_3_contract_instantiation() {
    let path = "/tmp/stacks-blockchain-epoch-switch-pox-3-contract-instantiation";
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        10,
        14,
        u32::MAX,
        16,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..25).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..25).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch24,
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    for ix in 0..24 {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        // Want to ensure that the pox-3 contract DNE for all blocks before the epoch 2.4 transition height,
        // and does exist for blocks after the boundary.
        //    Epoch 2.1 transition        Epoch 2.2 transition        Epoch 2.3 transition      Epoch 2.4 transition
        //             ^                         ^                           ^                           ^
        //..  -> B6 -> B7 -> B8 -> B9 -> B10 -> B11 -> B12 -> B13 -> B14 -> B15 -> B16 -> B17 -> B18 -> B19
        //..  -> S5 -> S6 -> S7 -> S8 -> S9 -> S10  -> S11 -> S12 -> S13 -> S14 -> S15 -> S16 -> S17 -> S18
        //                                                            \
        //                                                              \
        //                                                                _ _ _  S19 -> S20 -> ..
        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else if ix == 15 {
            stacks_blocks[ix - 2].1.header.block_hash()
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                None,
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                None,
            )
        };

        let expected_winner = good_op.txid();
        let ops = vec![good_op];

        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
        let burn_block_height = tip.block_height;

        // check that the expected stacks epoch ID is equal to the actual stacks epoch ID
        let expected_epoch = match burn_block_height {
            x if x < 4 => StacksEpochId::Epoch20,
            x if x >= 4 && x < 8 => StacksEpochId::Epoch2_05,
            x if x >= 8 && x < 12 => StacksEpochId::Epoch21,
            x if x >= 12 && x < 16 => StacksEpochId::Epoch22,
            x if x >= 16 && x < 20 => StacksEpochId::Epoch23,
            _ => StacksEpochId::Epoch24,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| conn.with_clarity_db_readonly(|db| db
                        .get_stacks_epoch(burn_block_height as u32)
                        .unwrap())
                )
                .unwrap()
                .epoch_id,
            expected_epoch
        );

        // These expectations are according to according to hard-coded values in
        // `StacksEpoch::unit_test_2_4`.
        let expected_runtime = match burn_block_height {
            x if x < 4 => u64::MAX,
            x if x >= 4 && x < 8 => 205205,
            x => 210210,
        };
        assert_eq!(
            chainstate
                .with_read_only_clarity_tx(
                    &sort_db.index_handle_at_tip(),
                    &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                    |conn| {
                        conn.with_clarity_db_readonly(|db| {
                            db.get_stacks_epoch(burn_block_height as u32).unwrap()
                        })
                    },
                )
                .unwrap()
                .block_limit
                .runtime,
            expected_runtime
        );

        // check that pox-3 contract DNE before epoch 2.4, and that it does exist after
        let does_pox_3_contract_exist = chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| {
                    conn.with_clarity_db_readonly(|db| {
                        db.get_contract(&boot_code_id(POX_3_NAME, false))
                    })
                },
            )
            .unwrap();

        if burn_block_height < 20 {
            assert!(does_pox_3_contract_exist.is_err())
        } else {
            assert!(does_pox_3_contract_exist.is_ok())
        }
    }
}

#[test]
fn atlas_stop_start() {
    let path = &test_path("atlas_stop_start");
    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        10,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    // publish a simple contract used to generate atlas attachment instances
    let atlas_contract_content = "
      (define-data-var attachment-index uint u1)
      (define-public (make-attach (zonefile-hash (buff 20)))
       (let ((current-index (var-get attachment-index)))
         (print {
           attachment: {
            hash: zonefile-hash,
            attachment-index: current-index,
            metadata: \"test-meta\"
           }
         })
         (var-set attachment-index (+ u1 current-index))
         (ok true)))";
    let atlas_name: clarity::vm::ContractName = "atlas-test".into();

    let vrf_keys: Vec<_> = (0..15).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..15).map(|_| StacksPrivateKey::new()).collect();

    let signer_sk = StacksPrivateKey::new();
    let signer_pk = p2pkh_from(&signer_sk);
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(signer_pk.clone().into(), balance)];
    let atlas_qci = QualifiedContractIdentifier::new(signer_pk.clone().into(), atlas_name.clone());
    // include our simple contract in the atlas config
    let mut atlas_config = AtlasConfig::new(false);
    atlas_config.contracts.insert(atlas_qci.clone());

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
    );

    let mut coord = make_coordinator_atlas(
        path,
        Some(burnchain_conf.clone()),
        Some(atlas_config.clone()),
    );

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    let mut contract_publish = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&signer_sk).unwrap(),
        TransactionPayload::SmartContract(
            TransactionSmartContract {
                name: atlas_name.clone(),
                code_body: StacksString::from_str(atlas_contract_content).unwrap(),
            },
            None,
        ),
    );
    contract_publish.chain_id = 0x80000000;
    contract_publish.anchor_mode = TransactionAnchorMode::OnChainOnly;
    contract_publish.auth.set_origin_nonce(0);
    contract_publish.auth.set_tx_fee(100);
    let mut signer = StacksTransactionSigner::new(&contract_publish);
    signer.sign_origin(&signer_sk).unwrap();
    let contract_publish = signer.get_tx().unwrap();

    let make_attachments: Vec<StacksTransaction> = (0..5)
        .map(|ix| {
            (
                ix,
                StacksTransaction::new(
                    TransactionVersion::Testnet,
                    TransactionAuth::from_p2pkh(&signer_sk).unwrap(),
                    TransactionPayload::ContractCall(TransactionContractCall {
                        address: signer_pk.clone(),
                        contract_name: atlas_name.clone(),
                        function_name: "make-attach".into(),
                        function_args: vec![Value::buff_from(vec![ix; 20]).unwrap()],
                    }),
                ),
            )
        })
        .map(|(ix, mut cc_tx)| {
            cc_tx.chain_id = 0x80000000;
            cc_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
            cc_tx.auth.set_origin_nonce(ix as u64 + 1);
            cc_tx.auth.set_tx_fee(100);
            let mut signer = StacksTransactionSigner::new(&cc_tx);
            signer.sign_origin(&signer_sk).unwrap();
            signer.get_tx().unwrap()
        })
        .collect();

    for ix in 0..3 {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());

        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();

        let txs = if ix == 1 {
            vec![contract_publish.clone()]
        } else if ix == 2 {
            make_attachments.clone()
        } else {
            vec![]
        };

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                None,
            )
        } else {
            make_stacks_block_with_input(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                None,
                0,
                false,
                (Txid([0; 32]), 0),
                None,
                &txs,
            )
        };

        let expected_winner = good_op.txid();
        let ops = vec![good_op];

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
        let burn_block_height = tip.block_height;

        // check that the bns contract exists
        let does_bns_contract_exist = chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| {
                    conn.with_clarity_db_readonly(|db| db.get_contract(&boot_code_id("bns", false)))
                },
            )
            .unwrap();

        assert!(does_bns_contract_exist.is_ok());
    }

    // okay, we've broadcasted some transactions, lets check that the atlas db has a queue
    let atlas_queue = coord
        .atlas_db
        .as_ref()
        .unwrap()
        .queued_attachments()
        .unwrap();
    assert_eq!(
        atlas_queue.len(),
        make_attachments.len(),
        "Should be as many queued attachments, as attachment txs submitted"
    );

    // now, we'll shut down all the coordinator connections and reopen them
    //  to ensure that the queue remains in place
    let coord = (); // dispose of the coordinator, closing all its connections
    let coord = make_coordinator_atlas(path, Some(burnchain_conf), Some(atlas_config));

    let atlas_queue = coord
        .atlas_db
        .as_ref()
        .unwrap()
        .queued_attachments()
        .unwrap();
    assert_eq!(
        atlas_queue.len(),
        make_attachments.len(),
        "Should be as many queued attachments, as attachment txs submitted"
    );
}

fn get_total_stacked_info(
    chainstate: &mut StacksChainState,
    burn_dbconn: &dyn BurnStateDB,
    parent_tip: &StacksBlockId,
    reward_cycle: u64,
    is_pox_2: bool,
) -> Result<u128, InterpreterError> {
    chainstate
        .with_read_only_clarity_tx(burn_dbconn, parent_tip, |conn| {
            conn.with_readonly_clarity_env(
                false,
                CHAIN_ID_TESTNET,
                ClarityVersion::Clarity2,
                PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                None,
                LimitedCostTracker::new_free(),
                |env| {
                    let eval_str = format!(
                        "(contract-call? '{}.{} get-total-ustx-stacked u{})",
                        &boot_code_addr(false),
                        if is_pox_2 { POX_2_NAME } else { POX_1_NAME },
                        reward_cycle
                    );

                    let result = env.eval_raw(&eval_str).map(|v| v.expect_u128().unwrap());
                    Ok(result)
                },
            )
            .unwrap()
        })
        .unwrap()
}

// This test verifies that the correct contract is used for PoX for stacking operations.
// Need to ensure that after v1_unlock_height, stacking operations are executed in the "pox-2" contract.
// After the transition to Epoch 2.1 but before v1_unlock_height, stacking operations that are
// sent should occur in the "pox.clar" contract.
#[test]
fn test_epoch_verify_active_pox_contract() {
    let path = &test_path("verify-active-pox-contract");
    let _r = std::fs::remove_dir_all(path);

    let pox_v1_unlock_ht = 12;
    let pox_v2_unlock_ht = u32::MAX;
    let sunset_ht = 8000;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        7010,
        sunset_ht,
        pox_v1_unlock_ht,
        pox_v2_unlock_ht,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..20).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..20).map(|_| StacksPrivateKey::new()).collect();

    let stacker = p2pkh_from(&StacksPrivateKey::new());
    let stacker_2 = p2pkh_from(&StacksPrivateKey::new());
    let rewards = pox_addr_from(&StacksPrivateKey::new());
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![
        (stacker.clone().into(), balance),
        (stacker_2.clone().into(), balance),
    ];

    let first_block_ht = burnchain_conf.first_block_height;
    setup_states_with_epochs(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(
            first_block_ht,
            first_block_ht + 4,
            first_block_ht + 8,
        )),
    );

    let mut coord = make_coordinator(path, Some(burnchain_conf.clone()));

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    for ix in 0..20 {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        // Want to ensure that the correct PoX contract is used in the various phases.
        // The pox-2 contract should be used for stacking operations at and after B12.
        // Bi represents the ith burn block, and Sj represents the jth stacks block.
        //
        //                              Epoch 2.1 transition         active pox contract switch
        //                                       ^                                ^
        //.. B1 -> B2 -> B3 -> B4 -> B5 -> B6 -> B7 -> B8 -> B9 -> B10 -> B11 -> B12
        //   S0 -> S1 -> S2 -> S3 -> S4 -> S5 -> S6 -> S7 -> S8 -> S9 -> S10  -> S11
        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());

        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();

        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&burnchain_conf, reward_cycle_info.as_ref())
            .unwrap();

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                1000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        };

        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if ix == 0 {
            // add a pre-stack-stx op
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: stacker.clone(),
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: stacker_2.clone(),
                txid: next_txid(),
                vtxindex: 6,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
            ops.push(BlockstackOperationType::PreStx(PreStxOp {
                output: stacker_2.clone(),
                txid: next_txid(),
                vtxindex: 7,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 1 {
            // This operation leads to a lock in the `pox.clar` contract
            ops.push(BlockstackOperationType::StackStx(StackStxOp {
                sender: stacker.clone(),
                reward_addr: rewards.clone(),
                stacked_ustx: stacked_amt,
                num_cycles: 1,
                signer_key: None,
                max_amount: None,
                auth_id: None,
                txid: next_txid(),
                vtxindex: 5,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == 7 {
            // This will be sent in the first block of epoch 2.1, and will lead
            // to a state change in `pox.clar`.
            // The active contract is `pox.clar`, since the v1_unlock_height
            // has not been reached.
            ops.push(BlockstackOperationType::StackStx(StackStxOp {
                sender: stacker_2.clone(),
                reward_addr: rewards.clone(),
                stacked_ustx: stacked_amt * 2,
                num_cycles: 5,
                signer_key: None,
                max_amount: None,
                auth_id: None,
                txid: next_txid(),
                vtxindex: 6,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        } else if ix == pox_v1_unlock_ht as usize - 1 {
            // This will be sent when the burn_block_height == v1_unlock_height,
            // and leads to a state change in `pox-2.clar`.
            ops.push(BlockstackOperationType::StackStx(StackStxOp {
                sender: stacker_2.clone(),
                reward_addr: rewards.clone(),
                stacked_ustx: stacked_amt * 4,
                num_cycles: 1,
                signer_key: None,
                max_amount: None,
                auth_id: None,
                txid: next_txid(),
                vtxindex: 7,
                block_height: 0,
                burn_header_hash: BurnchainHeaderHash([0; 32]),
            }));
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();

        let burn_block_height = tip.block_height;

        let parent_tip = StacksBlockId::new(&tip.consensus_hash, &block_hash);
        let curr_reward_cycle = b.block_height_to_reward_cycle(burn_block_height).unwrap();

        // Query the pox.clar contract to ensure the total stacked amount is as expected
        let amount_locked_pox_1_res = get_total_stacked_info(
            &mut chainstate,
            &sort_db.index_handle_at_tip(),
            &parent_tip,
            curr_reward_cycle,
            false,
        );

        let amount_locked_pox_1 = amount_locked_pox_1_res
            .expect("Should be able to query pox.clar for total locked ustx");

        let active_pox_contract = b.pox_constants.active_pox_contract(burn_block_height);

        if burn_block_height <= pox_v1_unlock_ht.into() {
            assert_eq!(active_pox_contract, POX_1_NAME);
            if curr_reward_cycle == 1 {
                // This is a result of the first stack stx sent.
                assert_eq!(amount_locked_pox_1, stacked_amt);
            } else if curr_reward_cycle == 2 {
                // This assertion checks that we are in Epoch 2.1
                assert!(burn_block_height >= 8);
                // This is a result of the second stack stx sent.
                assert_eq!(amount_locked_pox_1, stacked_amt * 2);
            } else {
                assert_eq!(amount_locked_pox_1, 0);
            }
        } else {
            // After the v1_unlock_height, the total stacked amount does not change, since
            // the third `stack-stx` operation does not alter this amount.
            assert_eq!(amount_locked_pox_1, stacked_amt * 2);
            assert_eq!(active_pox_contract, POX_2_NAME);
        }

        // Query the pox-2.clar contract to ensure the total stacked amount is as expected
        let amount_locked_pox_2_res = get_total_stacked_info(
            &mut chainstate,
            &sort_db.index_handle_at_tip(),
            &parent_tip,
            curr_reward_cycle,
            true,
        );

        if burn_block_height >= 8 {
            let amount_locked_pox_2 = amount_locked_pox_2_res
                .expect("Should be able to query pox-2.clar for total locked ustx");
            if curr_reward_cycle == 3 {
                // This assertion checks that the burn height is at or after the v1_unlock_height
                assert!(burn_block_height >= pox_v1_unlock_ht as u64);
                // This is a result of the third stack stx sent.
                assert_eq!(amount_locked_pox_2, stacked_amt * 4);
            } else {
                assert_eq!(amount_locked_pox_2, 0);
            }
        } else {
            // The query fails before since the `pox-2.clar` contract is uninitialized.
            assert!(amount_locked_pox_2_res.is_err());
        }
    }
}

fn test_sortition_with_sunset() {
    let path = &test_path("sortition-with-sunset");

    let _r = std::fs::remove_dir_all(path);

    let sunset_ht = 80;
    let pox_consts = Some(PoxConstants::new(
        6,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let mut vrf_keys: Vec<_> = (0..200).map(|_| VRFPrivateKey::new()).collect();
    let mut committers: Vec<_> = (0..200).map(|_| StacksPrivateKey::new()).collect();

    let reward_set_size = pox_consts.as_ref().unwrap().reward_slots() as usize;
    assert_eq!(reward_set_size, 6);
    let reward_set: Vec<_> = (0..reward_set_size)
        .map(|_| pox_addr_from(&StacksPrivateKey::new()))
        .collect();

    setup_states(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_reward_set_coordinator(path, reward_set, pox_consts.clone());

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // split up the vrf keys and committers so that we have some that will be mining "correctly"
    //   and some that will be producing bad outputs

    let WRONG_OUTS_OFFSET = 100;
    let vrf_key_wrong_outs = vrf_keys.split_off(WRONG_OUTS_OFFSET);
    let miner_wrong_outs = committers.split_off(WRONG_OUTS_OFFSET);

    // track the reward set consumption
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let vrf_wrong_out = &vrf_key_wrong_outs[ix];
        let miner_wrong_out = &miner_wrong_outs[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        let cur_epoch =
            SortitionDB::get_stacks_epoch(sort_db.conn(), next_mock_header.block_height)
                .unwrap()
                .unwrap();

        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            if started_first_reward_cycle {
                let last_reward_cycle_block = (sunset_ht
                    / (pox_consts.as_ref().unwrap().reward_cycle_length as u64))
                    * (pox_consts.as_ref().unwrap().reward_cycle_length as u64);
                if burnchain_tip.block_height == last_reward_cycle_block {
                    eprintln!(
                        "End of PoX (at sunset height {}): reward set size is {}",
                        burnchain_tip.block_height,
                        reward_recipients.len()
                    );
                    assert_eq!(reward_recipients.len(), 6); // still hasn't cleared yet, so still 6
                } else if burnchain_tip.block_height
                    > last_reward_cycle_block
                        + (pox_consts.as_ref().unwrap().reward_cycle_length as u64)
                {
                    eprintln!("End of PoX (beyond sunset height {} and in next reward cycle): reward set size is {}", burnchain_tip.block_height, reward_recipients.len());
                    assert_eq!(reward_recipients.len(), 0);
                } else if burnchain_tip.block_height > last_reward_cycle_block {
                    eprintln!(
                        "End of PoX (beyond sunset height {}): reward set size is {}",
                        burnchain_tip.block_height,
                        reward_recipients.len()
                    );
                    assert_eq!(reward_recipients.len(), 2); // still haven't cleared this yet, so still 2
                } else {
                    eprintln!(
                        "End of PoX (before sunset height {}): reward set size is {}",
                        burnchain_tip.block_height,
                        reward_recipients.len()
                    );
                    assert_eq!(reward_recipients.len(), reward_set_size);
                }
            }
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        }
        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&burnchain_conf, reward_cycle_info.as_ref())
            .unwrap();
        if next_mock_header.block_height >= sunset_ht {
            assert!(next_block_recipients.is_none());
        }

        if let Some(ref next_block_recipients) = next_block_recipients {
            // this is only Some(..) if we're pre-sunset
            assert!(burnchain_tip.block_height <= sunset_ht);
            for (addr, _) in next_block_recipients.recipients.iter() {
                if !addr.is_burn() {
                    assert!(
                        !reward_recipients.contains(addr),
                        "Reward set should not already contain address {}",
                        addr
                    );
                }
                reward_recipients.insert(addr.clone());
            }
            eprintln!(
                "at {}: reward_recipients ({}) = {:?}",
                burnchain_tip.block_height,
                reward_recipients.len(),
                reward_recipients
            );
        }

        let sunset_burn = burnchain_conf.expected_sunset_burn(
            next_mock_header.block_height,
            10000,
            cur_epoch.epoch_id,
        );
        let rest_commit = 10000 - sunset_burn;
        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients_and_sunset_burn(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                rest_commit,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                sunset_burn + (rand::random::<u8>() as u64),
                next_mock_header.block_height >= sunset_ht,
            )
        };

        eprintln!("good op: {:?}", &good_op);
        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if sunset_burn > 0 {
            let (bad_outs_op, _) = make_stacks_block_with_recipients_and_sunset_burn(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_wrong_out,
                (ix + WRONG_OUTS_OFFSET) as u32,
                next_block_recipients.as_ref(),
                sunset_burn - 1,
                false,
            );
            ops.push(bad_outs_op);
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            if new_burnchain_tip.block_height < sunset_ht {
                started_first_reward_cycle = true;
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
                anchor_blocks.push(bhh);
            } else {
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                assert!(
                    ic.get_last_anchor_block_hash().unwrap().is_none(),
                    "No PoX anchor block should be chosen after PoX sunset"
                );
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(100)
    );
    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111111111",
                   "PoX ID should reflect the 10 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

/// Verify that the PoX sunset is stopped at the 2.1 epoch switch.
/// Runs a mocked blockchain for 100 sortitions.
/// PoX sunset begins at block 10, and completes at block 80.
/// Epoch 2.1 activates at block 50 (n.b. reward cycles are 6 blocks long)
#[test]
fn test_sortition_with_sunset_and_epoch_switch() {
    let path = &test_path("sortition-with-sunset-and-epoch-switch");
    let _r = std::fs::remove_dir_all(path);

    let rc_len = 6;
    let sunset_ht = 80;
    let epoch_switch_ht = 50;
    let v1_unlock_ht = 56;
    let pox_consts = Some(PoxConstants::new(
        rc_len,
        3,
        3,
        25,
        5,
        10,
        sunset_ht,
        v1_unlock_ht,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));

    let burnchain_conf = get_burnchain(path, pox_consts.clone());

    let mut vrf_keys: Vec<_> = (0..200).map(|_| VRFPrivateKey::new()).collect();
    let mut committers: Vec<_> = (0..200).map(|_| StacksPrivateKey::new()).collect();

    let reward_set_size = pox_consts.as_ref().unwrap().reward_slots() as usize;
    assert_eq!(reward_set_size, 6);
    let reward_set: Vec<_> = (0..reward_set_size)
        .map(|_| pox_addr_from(&StacksPrivateKey::new()))
        .collect();

    setup_states_with_epochs(
        &[path],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch20,
        Some(StacksEpoch::all(0, 5, epoch_switch_ht)),
    );

    let mut coord = make_reward_set_coordinator(path, reward_set, pox_consts.clone());

    coord.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    let mut started_first_reward_cycle = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // split up the vrf keys and committers so that we have some that will be mining "correctly"
    //   and some that will be producing bad outputs

    let WRONG_OUTS_OFFSET = 100;
    let vrf_key_wrong_outs = vrf_keys.split_off(WRONG_OUTS_OFFSET);
    let miner_wrong_outs = committers.split_off(WRONG_OUTS_OFFSET);

    // track the reward set consumption.
    // epoch switch to 2.1 disables the in-progress sunset
    let mut reward_recipients = HashSet::new();
    for ix in 0..vrf_keys.len() {
        let vrf_key = &vrf_keys[ix];
        let miner = &committers[ix];

        let vrf_wrong_out = &vrf_key_wrong_outs[ix];
        let miner_wrong_out = &miner_wrong_outs[ix];

        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let mut chainstate = get_chainstate(path);

        let parent = if ix == 0 {
            BlockHeaderHash([0; 32])
        } else {
            stacks_blocks[ix - 1].1.header.block_hash()
        };

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let next_mock_header = BurnchainBlockHeader {
            block_height: burnchain_tip.block_height + 1,
            block_hash: BurnchainHeaderHash([0; 32]),
            parent_block_hash: burnchain_tip.block_hash,
            num_txs: 0,
            timestamp: 1,
        };

        let reward_cycle_info = coord.get_reward_cycle_info(&next_mock_header).unwrap();
        let cur_epoch =
            SortitionDB::get_stacks_epoch(sort_db.conn(), next_mock_header.block_height)
                .unwrap()
                .unwrap();

        if reward_cycle_info.is_some() {
            // did we process a reward set last cycle? check if the
            //  recipient set size matches our expectation
            if started_first_reward_cycle {
                let last_reward_cycle_block = (sunset_ht
                    / (pox_consts.as_ref().unwrap().reward_cycle_length as u64))
                    * (pox_consts.as_ref().unwrap().reward_cycle_length as u64);

                if cur_epoch.epoch_id < StacksEpochId::Epoch21 {
                    if burnchain_tip.block_height == last_reward_cycle_block {
                        eprintln!(
                            "End of PoX (at sunset height {}): reward set size is {}",
                            burnchain_tip.block_height,
                            reward_recipients.len()
                        );
                        assert_eq!(reward_recipients.len(), 6); // still hasn't cleared yet, so still 6
                    } else if burnchain_tip.block_height
                        > last_reward_cycle_block
                            + (pox_consts.as_ref().unwrap().reward_cycle_length as u64)
                    {
                        eprintln!("End of PoX (beyond sunset height {} and in next reward cycle): reward set size is {}", burnchain_tip.block_height, reward_recipients.len());
                        assert_eq!(reward_recipients.len(), 0);
                    } else if burnchain_tip.block_height > last_reward_cycle_block {
                        eprintln!(
                            "End of PoX (beyond sunset height {}): reward set size is {}",
                            burnchain_tip.block_height,
                            reward_recipients.len()
                        );
                        assert_eq!(reward_recipients.len(), 2); // still haven't cleared this yet, so still 2
                    } else {
                        eprintln!(
                            "End of PoX (before sunset height {}): reward set size is {}",
                            burnchain_tip.block_height,
                            reward_recipients.len()
                        );
                        assert_eq!(reward_recipients.len(), reward_set_size);
                    }
                } else {
                    assert!(burnchain_tip.block_height > epoch_switch_ht);
                    eprintln!(
                        "In epoch 2.1 at height {}: reward set size is {}",
                        burnchain_tip.block_height,
                        reward_recipients.len()
                    );
                    assert_eq!(reward_recipients.len(), reward_set_size);
                }
            }
            // clear the reward recipients tracker, since those
            //  recipients are now eligible again in the new reward cycle
            reward_recipients.clear();
        } else if started_first_reward_cycle
            && burnchain_conf.is_reward_cycle_start(next_mock_header.block_height)
        {
            // unreachable -- Epoch 2.1 activates at block 50, so we never reach the PoX sunset.
            // So, we should always have a reward set once we pass the first reward cycle.
            panic!("FATAL: Epoch 2.1 switch did not prevent PoX from disabling");
        }

        let next_block_recipients = get_rw_sortdb(path, pox_consts.clone())
            .test_get_next_block_recipients(&burnchain_conf, reward_cycle_info.as_ref())
            .unwrap();
        if cur_epoch.epoch_id < StacksEpochId::Epoch21 && next_mock_header.block_height >= sunset_ht
        {
            assert!(next_block_recipients.is_none());
        }

        if let Some(ref next_block_recipients) = next_block_recipients {
            // this is only Some(..) if we're pre-sunset or in epoch 2.1
            assert!(
                burnchain_tip.block_height <= sunset_ht
                    || cur_epoch.epoch_id >= StacksEpochId::Epoch21
            );
            for (addr, _) in next_block_recipients.recipients.iter() {
                if !addr.is_burn() {
                    assert!(
                        !reward_recipients.contains(addr),
                        "Reward set should not already contain address {}",
                        addr
                    );
                }
                reward_recipients.insert(addr.clone());
            }
            eprintln!(
                "at {}: reward_recipients ({}) = {:?}",
                burnchain_tip.block_height,
                reward_recipients.len(),
                reward_recipients
            );
        }

        let sunset_burn = burnchain_conf.expected_sunset_burn(
            next_mock_header.block_height,
            10000,
            cur_epoch.epoch_id,
        );
        if cur_epoch.epoch_id >= StacksEpochId::Epoch21 {
            assert_eq!(sunset_burn, 0);
        }
        let rest_commit = 10000 - sunset_burn;
        let b = get_burnchain(path, pox_consts.clone());

        let (good_op, block) = if ix == 0 {
            make_genesis_block_with_recipients(
                &b,
                &sort_db,
                &mut chainstate,
                &parent,
                miner,
                10000,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
            )
        } else {
            make_stacks_block_with_recipients_and_sunset_burn(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                rest_commit,
                vrf_key,
                ix as u32,
                next_block_recipients.as_ref(),
                sunset_burn + (rand::random::<u8>() as u64),
                next_mock_header.block_height >= sunset_ht
                    && cur_epoch.epoch_id < StacksEpochId::Epoch21,
            )
        };

        eprintln!("good op in {}: {:?}", cur_epoch.epoch_id, &good_op);
        let expected_winner = good_op.txid();
        let mut ops = vec![good_op];

        if sunset_burn > 0 && cur_epoch.epoch_id < StacksEpochId::Epoch21 {
            // this is a "good op" post-2.1, since the sunset is disabled
            let (bad_outs_op, _) = make_stacks_block_with_recipients_and_sunset_burn(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_wrong_out,
                (ix + WRONG_OUTS_OFFSET) as u32,
                next_block_recipients.as_ref(),
                sunset_burn - 1,
                false,
            );
            ops.push(bad_outs_op);
        }

        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        produce_burn_block(
            &burnchain_conf,
            &mut burnchain,
            &burnchain_tip.block_hash,
            ops,
            [].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            if new_burnchain_tip.block_height < sunset_ht {
                started_first_reward_cycle = true;
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
                anchor_blocks.push(bhh);
            } else {
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                if cur_epoch.epoch_id < StacksEpochId::Epoch21 {
                    assert!(
                        ic.get_last_anchor_block_hash().unwrap().is_none(),
                        "No PoX anchor block should be chosen after PoX sunset"
                    );
                } else {
                    assert!(
                        ic.get_last_anchor_block_hash().unwrap().is_some(),
                        "PoX anchor block should be chosen after Epoch 2.1"
                    );
                }
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        assert_eq!(&tip.winning_block_txid, &expected_winner);

        // load the block into staging
        let block_hash = block.header.block_hash();

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let mut chainstate = get_chainstate(path);
    assert_eq!(
        chainstate
            .with_read_only_clarity_tx(
                &sort_db.index_handle_at_tip(),
                &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
                |conn| conn
                    .with_readonly_clarity_env(
                        false,
                        CHAIN_ID_TESTNET,
                        ClarityVersion::Clarity1,
                        PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| env.eval_raw("block-height")
                    )
                    .unwrap()
            )
            .unwrap(),
        Value::UInt(100)
    );
    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(),
                   "111111111111111111",
                   "PoX ID should reflect the 10 reward cycles _with_ a known anchor block, plus the 'initial' known reward cycle at genesis");
    }
}

#[test]
// This test should panic until the MARF stability issue
// https://github.com/blockstack/stacks-blockchain/issues/1805
// is resolved:
#[should_panic]
/// Test a block that is processable in 2 PoX forks:
///   block "11" should be processable in both `111` and `110`
///   (because its parent is block `0`, and nobody stacks in
///    this test, all block commits must burn)
fn test_pox_processable_block_in_different_pox_forks() {
    let path = &test_path("pox_processable_block_in_different_pox_forks");
    // setup a second set of states that won't see the broadcasted blocks
    let path_blinded = &test_path("pox_processable_block_in_different_pox_forks.blinded");
    let _r = std::fs::remove_dir_all(path);
    let _r = std::fs::remove_dir_all(path_blinded);

    let pox_consts = Some(PoxConstants::new(
        5,
        2,
        2,
        25,
        5,
        u64::MAX - 1,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    ));
    let b = get_burnchain(path, pox_consts.clone());
    let b_blind = get_burnchain(path_blinded, pox_consts.clone());

    let vrf_keys: Vec<_> = (0..20).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..20).map(|_| StacksPrivateKey::new()).collect();

    setup_states_with_epochs(
        &[path, path_blinded],
        &vrf_keys,
        &committers,
        pox_consts.clone(),
        None,
        StacksEpochId::Epoch2_05,
        None,
    );

    let mut coord = make_coordinator(path, Some(b));
    let mut coord_blind = make_coordinator(path_blinded, Some(b_blind));

    coord.handle_new_burnchain_block().unwrap();
    coord_blind.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    let sort_db_blind = get_sortition_db(path_blinded, pox_consts.clone());

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db_blind
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];

    // setup:
    // sort:1                   6                   11                      16                       21
    //      |----- rc 0 --------|------ rc 1 -------|----- rc 2 ------------|-------- rc 3 ----------|----- rc 4
    // ix:  X - 0 - 1 - 2 - 3 - 4 - 5 - 6 - 7 - 8 - 9
    //           \_____________________________________ 10 _ 11 _ 12 _ 13 _ 14 _ 15 _ 16 _ 17 _ 18 _ 19
    //
    //
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path, pox_consts.clone());
        let burnchain_blind = get_burnchain_db(path_blinded, pox_consts.clone());
        let mut chainstate = get_chainstate(path);
        let mut chainstate_blind = get_chainstate(path_blinded);
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let burnchain_tip_blind = burnchain_blind.get_canonical_chain_tip().unwrap();
        let b = get_burnchain(path, pox_consts.clone());
        let b_blind = get_burnchain(path_blinded, pox_consts.clone());

        eprintln!("Making block {}", ix);
        let (op, block) = if ix == 0 {
            make_genesis_block(
                &b,
                &sort_db,
                &mut chainstate,
                &BlockHeaderHash([0; 32]),
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        } else {
            let parent = if ix == 10 {
                stacks_blocks[0].1.header.block_hash()
            } else {
                stacks_blocks[ix - 1].1.header.block_hash()
            };
            if ix < 10 {
                make_stacks_block(
                    &sort_db,
                    &mut chainstate,
                    &b,
                    &parent,
                    burnchain_tip.block_height,
                    miner,
                    10000,
                    vrf_key,
                    ix as u32,
                )
            } else {
                make_stacks_block(
                    &sort_db_blind,
                    &mut chainstate_blind,
                    &b_blind,
                    &parent,
                    burnchain_tip_blind.block_height,
                    miner,
                    10000,
                    vrf_key,
                    ix as u32,
                )
            }
        };
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![op],
            [burnchain_blind].iter_mut(),
        );

        loop {
            let missing_anchor_opt = coord
                .handle_new_burnchain_block()
                .unwrap()
                .into_missing_block_hash();
            if let Some(missing_anchor) = missing_anchor_opt {
                eprintln!(
                    "Unblinded database reports missing anchor block {:?} (ix={})",
                    &missing_anchor, ix
                );
                for (_, blk) in stacks_blocks.iter() {
                    if blk.block_hash() == missing_anchor {
                        let ic = sort_db.index_conn();
                        let tip =
                            SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
                        let sn = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                            &ic,
                            &tip.sortition_id,
                            &blk.block_hash(),
                        )
                        .unwrap()
                        .unwrap();

                        // feed this missing reward cycle data
                        let rc = b_blind
                            .block_height_to_reward_cycle(sn.block_height)
                            .unwrap();
                        let start_height = b_blind.reward_cycle_to_block_height(rc);
                        for height in start_height..sn.block_height {
                            let asn =
                                SortitionDB::get_ancestor_snapshot(&ic, height, &tip.sortition_id)
                                    .unwrap()
                                    .unwrap();
                            for (_, blk) in stacks_blocks.iter() {
                                if blk.block_hash() == asn.winning_stacks_block_hash {
                                    eprintln!("Unblinded database accepts missing anchor block ancestor {} of {} (ix={})", &blk.block_hash(), &missing_anchor, ix);
                                    preprocess_block(&mut chainstate, &sort_db, &asn, blk.clone());
                                    coord.handle_new_stacks_block().unwrap();
                                    break;
                                }
                            }
                        }

                        // *now* process this anchor block
                        eprintln!(
                            "Unblinded database processes missing anchor block {} (ix={})",
                            &missing_anchor, ix
                        );
                        preprocess_block(&mut chainstate, &sort_db, &sn, blk.clone());
                        coord.handle_new_stacks_block().unwrap();
                        break;
                    }
                }
            } else {
                coord.handle_new_stacks_block().unwrap();
                break;
            }
        }

        coord_blind.handle_new_burnchain_block().unwrap();
        coord_blind.handle_new_stacks_block().unwrap();

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();

        if ix < 10 {
            // load the block into staging and process it on the un-blinded sortition DB
            let block_hash = block.header.block_hash();
            eprintln!(
                "Block hash={}, parent={}, height={}, ix={} (not blind)",
                &block_hash, &block.header.parent_block, block.header.total_work.work, ix
            );

            assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
            stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

            preprocess_block(&mut chainstate, &sort_db, &tip, block.clone());

            // handle the stacks block
            coord.handle_new_stacks_block().unwrap();
        }
        if ix == 0 || ix >= 10 {
            // load the block into staging and process it on the blinded sortition DB
            let block_hash = block.header.block_hash();
            eprintln!(
                "Block hash={}, parent={}, height={}, ix={} (blind)",
                &block_hash, &block.header.parent_block, block.header.total_work.work, ix
            );

            assert_eq!(&blinded_tip.winning_stacks_block_hash, &block_hash);
            if ix != 0 {
                stacks_blocks.push((blinded_tip.sortition_id.clone(), block.clone()));
            }

            preprocess_block(&mut chainstate_blind, &sort_db_blind, &blinded_tip, block);

            // handle the stacks block
            coord_blind.handle_new_stacks_block().unwrap();
        }
        if ix == 18 {
            // right at the end of reward cycle 3 -- feed in the blocks from the blinded DB into
            // the unblinded DB
            for (i, (_, block)) in stacks_blocks.iter().enumerate() {
                if i >= 10 && i <= ix {
                    eprintln!("Mirror blocks from blinded DB to unblinded DB (simulates downloading them) i={}", i);
                    let ic = sort_db_blind.index_conn();
                    let sn = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                    preprocess_block(&mut chainstate, &sort_db, &sn, block.clone());
                    let _ = coord.handle_new_stacks_block();
                }
            }
        }
        if ix > 18 {
            // starting in reward cycle 4 -- this should NOT panic
            eprintln!("Mirror block {} to unblinded DB", ix);
            preprocess_block(&mut chainstate, &sort_db, &tip, stacks_blocks[ix].1.clone());
            let _ = coord.handle_new_stacks_block();
        }
    }

    // both the blinded and unblined chains should now have the same view
    let block_height = eval_at_chain_tip(path, &sort_db, "block-height");
    assert_eq!(block_height, Value::UInt(11));

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(11));

    // because of the affirmations, the canonical PoX ID deliberately omits anchor blocks
    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "110011");
    }
    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "110011");
    }

    // same canonical Stacks chain tip
    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    let stacks_tip_blind =
        SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db_blind.conn()).unwrap();
    assert_eq!(stacks_tip, stacks_tip_blind);

    // same final consensus hash, at the start of height 20
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();

    assert!(tip.sortition);
    assert!(blinded_tip.sortition);
    assert_eq!(
        tip.winning_stacks_block_hash,
        blinded_tip.winning_stacks_block_hash
    );
    assert_eq!(tip.burn_header_hash, blinded_tip.burn_header_hash);
    assert_eq!(tip.consensus_hash, blinded_tip.consensus_hash);
    assert_eq!(tip.block_height, 21);
    assert_eq!(blinded_tip.block_height, 21);
}

#[test]
fn test_pox_no_anchor_selected() {
    let path = &test_path("pox_fork_no_anchor_selected");
    // setup a second set of states that won't see the broadcasted blocks
    let path_blinded = &test_path("pox_fork_no_anchor_selected.blinded");
    let _r = std::fs::remove_dir_all(path);
    let _r = std::fs::remove_dir_all(path_blinded);

    let vrf_keys: Vec<_> = (0..10).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..10).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path, path_blinded],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, None);
    let mut coord_blind = make_coordinator(path_blinded, None);

    coord.handle_new_burnchain_block().unwrap();
    coord_blind.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    let sort_db_blind = get_sortition_db(path_blinded, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db_blind
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // at first, sortition_ids shouldn't have diverged
    //  but once the first reward cycle begins, they should diverge.
    let mut sortition_ids_diverged = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // setup:
    //   0 - 1 - 2 - 3 - 4 - 5 - 6
    //    \_ 7   \_ 8 _ 9
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);
        let b = get_burnchain(path, None);
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let burnchain_blinded = get_burnchain_db(path_blinded, None);

        eprintln!("Making block {}", ix);
        let (op, block) = if ix == 0 {
            make_genesis_block(
                &b,
                &sort_db,
                &mut chainstate,
                &BlockHeaderHash([0; 32]),
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        } else {
            let parent = if ix == 7 {
                stacks_blocks[0].1.header.block_hash()
            } else if ix == 8 {
                stacks_blocks[2].1.header.block_hash()
            } else {
                stacks_blocks[ix - 1].1.header.block_hash()
            };
            make_stacks_block(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        };

        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![op],
            [burnchain_blinded].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();
        coord_blind.handle_new_burnchain_block().unwrap();

        let b = get_burnchain(path, None);
        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            eprintln!(
                "Reward cycle start at height={}",
                new_burnchain_tip.block_height
            );
            // processed first anchor block, not expecting a second one!
            if anchor_blocks.len() == 1 {
                let ic = sort_db.index_handle_at_tip();
                assert!(
                    ic.get_last_anchor_block_hash().unwrap().is_none(),
                    "No anchor block should have been chosen!"
                );
            } else {
                // the "blinded" sortition db and the one that's processed all the blocks
                //   should have diverged in sortition_ids now...
                sortition_ids_diverged = true;
                // store the anchor block for this sortition for later checking
                let ic = sort_db.index_handle_at_tip();
                let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
                eprintln!(
                    "Anchor block={}, selected at height={}",
                    &bhh,
                    SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &sort_db.index_conn(),
                        &ic.context.chain_tip,
                        &bhh
                    )
                    .unwrap()
                    .unwrap()
                    .block_height
                );
                anchor_blocks.push(bhh);
            }
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
        if sortition_ids_diverged {
            assert_ne!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should have diverged by block height = {}",
                blinded_tip.block_height
            );
        } else {
            assert_eq!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should not have diverged at block height = {}",
                blinded_tip.block_height
            );
        }

        // load the block into staging
        let block_hash = block.header.block_hash();
        eprintln!("Block hash={}, ix={}", &block_hash, ix);

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let block_height = eval_at_chain_tip(path, &sort_db, "block-height");
    assert_eq!(block_height, Value::UInt(7));

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(0));

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "1111");
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "1101");
    }

    for (sort_id, block) in stacks_blocks.iter() {
        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            &sort_id,
            block,
        );
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "1111");
    }

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(7));
}

#[test]
fn test_pox_fork_out_of_order() {
    let path = &test_path("pox_fork_out_of_order");
    // setup a second set of states that won't see the broadcasted blocks
    let path_blinded = &test_path("pox_fork_out_of_order.blinded");
    let _r = std::fs::remove_dir_all(path);
    let _r = std::fs::remove_dir_all(path_blinded);

    let vrf_keys: Vec<_> = (0..15).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..15).map(|_| StacksPrivateKey::new()).collect();

    setup_states(
        &[path, path_blinded],
        &vrf_keys,
        &committers,
        None,
        None,
        StacksEpochId::Epoch2_05,
    );

    let mut coord = make_coordinator(path, None);
    let mut coord_blind = make_coordinator(path_blinded, None);

    coord.handle_new_burnchain_block().unwrap();
    coord_blind.handle_new_burnchain_block().unwrap();

    let sort_db = get_sortition_db(path, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    let sort_db_blind = get_sortition_db(path_blinded, None);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
    assert_eq!(tip.block_height, 1);
    assert_eq!(tip.sortition, false);
    let (_, ops) = sort_db_blind
        .get_sortition_result(&tip.sortition_id)
        .unwrap()
        .unwrap();

    // we should have all the VRF registrations accepted
    assert_eq!(ops.accepted_ops.len(), vrf_keys.len());
    assert_eq!(ops.consumed_leader_keys.len(), 0);

    // at first, sortition_ids shouldn't have diverged
    //  but once the first reward cycle begins, they should diverge.
    let mut sortition_ids_diverged = false;
    // process sequential blocks, and their sortitions...
    let mut stacks_blocks: Vec<(SortitionId, StacksBlock)> = vec![];
    let mut anchor_blocks = vec![];

    // setup:
    //  2 forks: 0 - 1 - 2 - 3 - 4 - 5 - 11 - 12 - 13 - 14 - 15
    //            \_ 6 _ 7 _ 8 _ 9 _ 10
    for (ix, (vrf_key, miner)) in vrf_keys.iter().zip(committers.iter()).enumerate() {
        let mut burnchain = get_burnchain_db(path, None);
        let mut chainstate = get_chainstate(path);
        let burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        let burnchain_blinded = get_burnchain_db(path_blinded, None);
        let b = get_burnchain(path, None);

        eprintln!("Making block {}", ix);
        let (op, block) = if ix == 0 {
            make_genesis_block(
                &b,
                &sort_db,
                &mut chainstate,
                &BlockHeaderHash([0; 32]),
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        } else {
            let parent = if ix == 1 {
                stacks_blocks[0].1.header.block_hash()
            } else if ix == 6 {
                stacks_blocks[0].1.header.block_hash()
            } else if ix == 11 {
                stacks_blocks[5].1.header.block_hash()
            } else {
                stacks_blocks[ix - 1].1.header.block_hash()
            };
            make_stacks_block(
                &sort_db,
                &mut chainstate,
                &b,
                &parent,
                burnchain_tip.block_height,
                miner,
                10000,
                vrf_key,
                ix as u32,
            )
        };
        produce_burn_block(
            &b,
            &mut burnchain,
            &burnchain_tip.block_hash,
            vec![op],
            [burnchain_blinded].iter_mut(),
        );
        // handle the sortition
        coord.handle_new_burnchain_block().unwrap();
        coord_blind.handle_new_burnchain_block().unwrap();

        let new_burnchain_tip = burnchain.get_canonical_chain_tip().unwrap();
        if b.is_reward_cycle_start(new_burnchain_tip.block_height) {
            eprintln!(
                "Reward cycle start at height={}",
                new_burnchain_tip.block_height
            );
            // the "blinded" sortition db and the one that's processed all the blocks
            //   should have diverged in sortition_ids now...
            sortition_ids_diverged = true;
            // store the anchor block for this sortition for later checking
            let ic = sort_db.index_handle_at_tip();
            let bhh = ic.get_last_anchor_block_hash().unwrap().unwrap();
            eprintln!(
                "Anchor block={}, selected at height={}",
                &bhh,
                SortitionDB::get_block_snapshot_for_winning_stacks_block(
                    &sort_db.index_conn(),
                    &ic.context.chain_tip,
                    &bhh
                )
                .unwrap()
                .unwrap()
                .block_height
            );

            anchor_blocks.push(bhh);
        }

        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let blinded_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db_blind.conn()).unwrap();
        if sortition_ids_diverged {
            assert_ne!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should have diverged by block height = {}",
                blinded_tip.block_height
            );
        } else {
            assert_eq!(
                tip.sortition_id, blinded_tip.sortition_id,
                "Sortitions should not have diverged at block height = {}",
                blinded_tip.block_height
            );
        }

        // load the block into staging
        let block_hash = block.header.block_hash();
        eprintln!("Block hash={}, ix={}", &block_hash, ix);

        assert_eq!(&tip.winning_stacks_block_hash, &block_hash);
        stacks_blocks.push((tip.sortition_id.clone(), block.clone()));

        preprocess_block(&mut chainstate, &sort_db, &tip, block);

        // handle the stacks block
        coord.handle_new_stacks_block().unwrap();
    }

    let block_height = eval_at_chain_tip(path, &sort_db, "block-height");
    assert_eq!(block_height, Value::UInt(10));

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(0));

    {
        let ic = sort_db.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11111");
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11000");
    }

    // now, we reveal to the blinded coordinator, but out of order.
    //  reveal block 0 first,
    //   then the 6-7-8-9-10 fork.
    //   then reveal 1-2-3-4-5
    //   then reveal 11-12-13-14

    reveal_block(
        path_blinded,
        &sort_db_blind,
        &mut coord_blind,
        &stacks_blocks[0].0,
        &stacks_blocks[0].1,
    );

    // after revealing ``0``, we should now have the anchor block for
    //   the 6-7-8-9-10 fork

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11110");
    }

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(1));

    // reveal [6-10]
    for (_sort_id, block) in stacks_blocks[6..=10].iter() {
        // cannot use sort_id from stacks_blocks, because the blinded coordinator
        //   has different sortition_id's for blocks 6-10 (because it's missing
        //   the 2nd anchor block).
        let sort_id = SortitionDB::get_block_snapshot_for_winning_stacks_block(
            &sort_db_blind.index_conn(),
            &SortitionDB::get_canonical_sortition_tip(sort_db_blind.conn()).unwrap(),
            &block.header.block_hash(),
        )
        .unwrap()
        .unwrap()
        .sortition_id;
        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            &sort_id,
            block,
        );
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11110");
    }

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(6));

    let block_hash = eval_at_chain_tip(
        path_blinded,
        &sort_db_blind,
        "(get-block-info? header-hash u5)",
    );
    assert_eq!(
        block_hash,
        Value::some(
            Value::buff_from(stacks_blocks[9].1.header.block_hash().as_bytes().to_vec()).unwrap()
        )
        .unwrap()
    );

    // reveal [1-5]
    for (_sort_id, block) in stacks_blocks[1..=5].iter() {
        // cannot use sort_id from stacks_blocks, because the blinded coordinator
        //   has different sortition_id's for blocks 6-10 (because it's missing
        //   the 2nd anchor block).
        let sort_id = SortitionDB::get_block_snapshot_for_winning_stacks_block(
            &sort_db_blind.index_conn(),
            &SortitionDB::get_canonical_sortition_tip(sort_db_blind.conn()).unwrap(),
            &block.header.block_hash(),
        )
        .unwrap()
        .unwrap()
        .sortition_id;

        // before processing the last of these blocks, the stacks_block[9] should still
        //   be the canonical tip
        let block_hash = eval_at_chain_tip(
            path_blinded,
            &sort_db_blind,
            "(get-block-info? header-hash u5)",
        );
        assert_eq!(
            block_hash,
            Value::some(
                Value::buff_from(stacks_blocks[9].1.header.block_hash().as_bytes().to_vec())
                    .unwrap()
            )
            .unwrap()
        );

        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            &sort_id,
            block,
        );
    }

    {
        let ic = sort_db_blind.index_handle_at_tip();
        let pox_id = ic.get_pox_id().unwrap();
        assert_eq!(&pox_id.to_string(), "11111");
    }

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(6));

    // reveal [11-14]
    for (_sort_id, block) in stacks_blocks[11..].iter() {
        // cannot use sort_id from stacks_blocks, because the blinded coordinator
        //   has different sortition_id's for blocks 6-10 (because it's missing
        //   the 2nd anchor block).
        let sort_id = SortitionDB::get_block_snapshot_for_winning_stacks_block(
            &sort_db_blind.index_conn(),
            &SortitionDB::get_canonical_sortition_tip(sort_db_blind.conn()).unwrap(),
            &block.header.block_hash(),
        )
        .unwrap()
        .unwrap()
        .sortition_id;

        reveal_block(
            path_blinded,
            &sort_db_blind,
            &mut coord_blind,
            &sort_id,
            block,
        );
    }

    let block_height = eval_at_chain_tip(path_blinded, &sort_db_blind, "block-height");
    assert_eq!(block_height, Value::UInt(10));

    let block_hash = eval_at_chain_tip(
        path_blinded,
        &sort_db_blind,
        "(get-block-info? header-hash u9)",
    );
    assert_eq!(
        block_hash,
        Value::some(
            Value::buff_from(stacks_blocks[13].1.header.block_hash().as_bytes().to_vec()).unwrap()
        )
        .unwrap()
    );
}

fn eval_at_chain_tip(chainstate_path: &str, sort_db: &SortitionDB, eval: &str) -> Value {
    let stacks_tip = SortitionDB::get_canonical_stacks_chain_tip_hash(sort_db.conn()).unwrap();
    test_debug!(
        "Canonical chain tip at {} is {:?}",
        chainstate_path,
        &stacks_tip
    );
    let mut chainstate = get_chainstate(chainstate_path);
    chainstate
        .with_read_only_clarity_tx(
            &sort_db.index_handle_at_tip(),
            &StacksBlockId::new(&stacks_tip.0, &stacks_tip.1),
            |conn| {
                conn.with_readonly_clarity_env(
                    false,
                    CHAIN_ID_TESTNET,
                    ClarityVersion::Clarity1,
                    PrincipalData::parse("SP3Q4A5WWZ80REGBN0ZXNE540ECJ9JZ4A765Q5K2Q").unwrap(),
                    None,
                    LimitedCostTracker::new_free(),
                    |env| env.eval_raw(eval),
                )
                .unwrap()
            },
        )
        .unwrap()
}

fn reveal_block<T: BlockEventDispatcher, N: CoordinatorNotices, U: RewardSetProvider>(
    chainstate_path: &str,
    sort_db: &SortitionDB,
    coord: &mut ChainsCoordinator<T, N, U, (), (), BitcoinIndexer>,
    my_sortition: &SortitionId,
    block: &StacksBlock,
) {
    let mut chainstate = get_chainstate(chainstate_path);
    let sortition = SortitionDB::get_block_snapshot(sort_db.conn(), &my_sortition)
        .unwrap()
        .unwrap();
    preprocess_block(&mut chainstate, sort_db, &sortition, block.clone());
    coord.handle_new_stacks_block().unwrap();
}

fn preprocess_block(
    chain_state: &mut StacksChainState,
    sort_db: &SortitionDB,
    my_sortition: &BlockSnapshot,
    block: StacksBlock,
) {
    let ic = sort_db.index_conn();
    let parent_consensus_hash = SortitionDB::get_block_snapshot_for_winning_stacks_block(
        &ic,
        &my_sortition.sortition_id,
        &block.header.parent_block,
    )
    .unwrap()
    .unwrap()
    .consensus_hash;
    // Preprocess the anchored block
    chain_state
        .preprocess_anchored_block(
            &ic,
            &my_sortition.consensus_hash,
            &block,
            &parent_consensus_hash,
            5,
        )
        .unwrap();
}

#[test]
fn test_check_chainstate_db_versions() {
    let path = &test_path("check_chainstate_db_versions");
    let _ = std::fs::remove_dir_all(path);

    let sortdb_path = format!("{}/sortdb", &path);
    let chainstate_path = format!("{}/chainstate", &path);

    let epoch_2 = StacksEpoch {
        epoch_id: StacksEpochId::Epoch20,
        start_height: 0,
        end_height: 10000,
        block_limit: BLOCK_LIMIT_MAINNET_20.clone(),
        network_epoch: PEER_VERSION_EPOCH_2_0,
    };
    let epoch_2_05 = StacksEpoch {
        epoch_id: StacksEpochId::Epoch2_05,
        start_height: 0,
        end_height: 10000,
        block_limit: BLOCK_LIMIT_MAINNET_205.clone(),
        network_epoch: PEER_VERSION_EPOCH_2_05,
    };

    // should work just fine in epoch 2 if the DBs don't exist
    assert!(
        check_chainstate_db_versions(&[epoch_2.clone()], &sortdb_path, &chainstate_path).unwrap()
    );

    // should work just fine in epoch 2.05 if the DBs don't exist
    assert!(
        check_chainstate_db_versions(&[epoch_2_05.clone()], &sortdb_path, &chainstate_path)
            .unwrap()
    );

    StacksChainState::make_chainstate_dirs(&chainstate_path).unwrap();

    let sortdb_v1 =
        SortitionDB::connect_v1(&sortdb_path, 100, &BurnchainHeaderHash([0x00; 32]), 0, true)
            .unwrap();
    let chainstate_v1 = StacksChainState::open_db_without_migrations(
        false,
        CHAIN_ID_TESTNET,
        &StacksChainState::header_index_root_path(PathBuf::from(&chainstate_path))
            .to_str()
            .unwrap(),
    )
    .unwrap();

    assert!(fs::metadata(&chainstate_path).is_ok());
    assert!(fs::metadata(&sortdb_path).is_ok());
    assert_eq!(
        StacksChainState::get_db_config_from_path(&chainstate_path)
            .unwrap()
            .version,
        "1"
    );
    assert_eq!(
        SortitionDB::get_db_version_from_path(&sortdb_path)
            .unwrap()
            .unwrap(),
        "1"
    );

    // should work just fine in epoch 2
    assert!(
        check_chainstate_db_versions(&[epoch_2.clone()], &sortdb_path, &chainstate_path).unwrap()
    );

    // should fail in epoch 2.05
    assert!(
        !check_chainstate_db_versions(&[epoch_2_05.clone()], &sortdb_path, &chainstate_path)
            .unwrap()
    );
}
