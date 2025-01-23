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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::DerefMut;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::{BurnStateDB, ClarityDatabase};
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions, TupleData,
};
use clarity::vm::{ClarityVersion, ContractName, SymbolicExpression, Value};
use lazy_static::{__Deref, lazy_static};
use rusqlite::types::{FromSql, FromSqlError, ToSql};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest as Sha2Digest, Sha512_256};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_MESSAGE_LEN,
    MAX_PAYLOAD_LEN,
};
use stacks_common::consts::{
    self, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, MINER_REWARD_MATURITY,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId,
    StacksPrivateKey, StacksPublicKey, TrieHash, VRFSeed,
};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{to_hex, Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey, VRF};

use crate::burnchains::{Burnchain, PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::{
    get_ancestor_sort_id, get_ancestor_sort_id_tx, get_block_commit_by_txid, SortitionDB,
    SortitionHandle, SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::burn::operations::{
    DelegateStxOp, LeaderBlockCommitOp, LeaderKeyRegisterOp, StackStxOp, TransferStxOp,
};
use crate::chainstate::burn::{BlockSnapshot, SortitionHash};
use crate::chainstate::coordinator::{BlockEventDispatcher, Error};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{
    PoxVersions, RawRewardSetEntry, RewardSet, BOOT_TEST_POX_4_AGG_KEY_CONTRACT,
    BOOT_TEST_POX_4_AGG_KEY_FNAME, POX_4_NAME, SIGNERS_MAX_LIST_SIZE, SIGNERS_NAME, SIGNERS_PK_LEN,
    SIGNERS_UPDATE_STATE, SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{
    ChainstateTx, ClarityTx, DBConfig as ChainstateConfig, MinerPaymentSchedule,
    MinerPaymentTxFees, MinerRewardInfo, StacksBlockHeaderTypes, StacksChainState, StacksDBTx,
    StacksEpochReceipt, StacksHeaderInfo,
};
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction,
    TenureChangeCause, TenureChangeError, TenureChangePayload, TransactionPayload,
    MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity::vm::clarity::{ClarityConnection, TransactionConnection};
use crate::clarity_vm::clarity::{
    ClarityInstance, ClarityTransactionConnection, PreCommitClarityBlock,
};
use crate::clarity_vm::database::SortitionDBRef;
use crate::core::BOOT_BLOCK_HASH;
use crate::net::stackerdb::StackerDBConfig;
use crate::net::Error as net_error;
use crate::util_lib::boot;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, u64_to_sql, DBConn, Error as DBError,
    FromRow,
};
use crate::{chainstate, monitoring};

pub struct NakamotoSigners();

pub struct SignerCalculation {
    pub reward_set: RewardSet,
    pub events: Vec<StacksTransactionEvent>,
}

pub struct AggregateKeyVoteParams {
    pub signer_index: u64,
    pub aggregate_key: Vec<u8>,
    pub voting_round: u64,
    pub reward_cycle: u64,
}

impl RawRewardSetEntry {
    pub fn from_pox_4_tuple(is_mainnet: bool, tuple: TupleData) -> Result<Self, ChainstateError> {
        let mut tuple_data = tuple.data_map;

        let pox_addr_tuple = tuple_data
            .remove("pox-addr")
            .expect("FATAL: no `pox-addr` in return value from (get-reward-set-pox-address)");

        let reward_address = PoxAddress::try_from_pox_tuple(is_mainnet, &pox_addr_tuple)
            .unwrap_or_else(|| panic!("FATAL: not a valid PoX address: {pox_addr_tuple}"));

        let total_ustx = tuple_data
            .remove("total-ustx")
            .expect(
                "FATAL: no 'total-ustx' in return value from (pox-4.get-reward-set-pox-address)",
            )
            .expect_u128()
            .expect("FATAL: total-ustx is not a u128");

        let stacker = tuple_data
            .remove("stacker")
            .expect("FATAL: no 'stacker' in return value from (pox-4.get-reward-set-pox-address)")
            .expect_optional()?
            .map(|value| value.expect_principal())
            .transpose()?;

        let signer = tuple_data
            .remove("signer")
            .expect("FATAL: no 'signer' in return value from (pox-4.get-reward-set-pox-address)")
            .expect_buff(SIGNERS_PK_LEN)?;

        // (buff 33) only enforces max size, not min size, so we need to do a len check
        let pk_bytes = if signer.len() == SIGNERS_PK_LEN {
            let mut bytes = [0; SIGNERS_PK_LEN];
            bytes.copy_from_slice(signer.as_slice());
            bytes
        } else {
            [0; SIGNERS_PK_LEN]
        };

        debug!(
            "Parsed PoX reward address";
            "stacked_ustx" => total_ustx,
            "reward_address" => %reward_address,
            "stacker" => ?stacker,
            "signer" => to_hex(&signer),
        );

        Ok(Self {
            reward_address,
            amount_stacked: total_ustx,
            stacker,
            signer: Some(pk_bytes),
        })
    }
}

impl NakamotoSigners {
    fn get_reward_slots(
        clarity: &mut ClarityTransactionConnection,
        reward_cycle: u64,
        pox_contract: &str,
    ) -> Result<Vec<RawRewardSetEntry>, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        if !matches!(
            PoxVersions::lookup_by_name(pox_contract),
            Some(PoxVersions::Pox4)
        ) {
            error!("Invoked Nakamoto reward-set fetch on non-pox-4 contract");
            return Err(ChainstateError::DefunctPoxContract);
        }
        let pox_contract = &boot_code_id(pox_contract, is_mainnet);

        let list_length = clarity
            .eval_method_read_only(
                pox_contract,
                "get-reward-set-size",
                &[SymbolicExpression::atom_value(Value::UInt(
                    reward_cycle.into(),
                ))],
            )?
            .expect_u128()?;

        let mut slots = vec![];
        for index in 0..list_length {
            let tuple = clarity
                .eval_method_read_only(
                    pox_contract,
                    "get-reward-set-pox-address",
                    &[
                        SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
                        SymbolicExpression::atom_value(Value::UInt(index)),
                    ],
                )?
                .expect_optional()?
                .unwrap_or_else(|| {
                    panic!(
                        "FATAL: missing PoX address in slot {} out of {} in reward cycle {}",
                        index, list_length, reward_cycle
                    )
                })
                .expect_tuple()?;

            let entry = RawRewardSetEntry::from_pox_4_tuple(is_mainnet, tuple)?;

            slots.push(entry)
        }

        Ok(slots)
    }

    /// Compute the reward set for the next reward cycle, store it, and write it to the .signers
    /// contract.  `reward_cycle` is the _current_ reward cycle.
    pub fn handle_signer_stackerdb_update(
        clarity: &mut ClarityTransactionConnection,
        pox_constants: &PoxConstants,
        reward_cycle: u64,
        pox_contract: &str,
        coinbase_height: u64,
    ) -> Result<SignerCalculation, ChainstateError> {
        let is_mainnet = clarity.is_mainnet();
        let sender_addr = PrincipalData::from(boot::boot_code_addr(is_mainnet));
        let signers_contract = &boot_code_id(SIGNERS_NAME, is_mainnet);

        let liquid_ustx = clarity.with_clarity_db_readonly(|db| db.get_total_liquid_ustx())?;
        let reward_slots = Self::get_reward_slots(clarity, reward_cycle, pox_contract)?;
        let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
            &pox_constants,
            &reward_slots[..],
            liquid_ustx,
        );
        let reward_set =
            StacksChainState::make_reward_set(threshold, reward_slots, StacksEpochId::Epoch30);

        test_debug!("Reward set for cycle {}: {:?}", &reward_cycle, &reward_set);
        let stackerdb_list = if participation == 0 {
            vec![]
        } else {
            reward_set
                .signers
                .as_ref()
                .ok_or(ChainstateError::PoxNoRewardCycle)?
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    Value::Tuple(
                        TupleData::from_data(vec![
                            (
                                "signer".into(),
                                Value::Principal(PrincipalData::from(signing_address)),
                            ),
                            ("num-slots".into(), Value::UInt(1))
                        ])
                            .expect(
                                "BUG: Failed to construct `{ signer: principal, num-slots: u64 }` tuple",
                            ),
                    )
                })
                .collect()
        };

        let signers_list = if participation == 0 {
            vec![]
        } else {
            reward_set
                .signers
                .as_ref()
                .ok_or(ChainstateError::PoxNoRewardCycle)?
                .iter()
                .map(|signer| {
                    let signer_hash = Hash160::from_data(&signer.signing_key);
                    let signing_address = StacksAddress::p2pkh_from_hash(is_mainnet, signer_hash);
                    Value::Tuple(
                        TupleData::from_data(vec![
                            (
                                "signer".into(),
                                Value::Principal(PrincipalData::from(signing_address)),
                            ),
                            ("weight".into(), Value::UInt(signer.weight.into())),
                        ])
                        .expect(
                            "BUG: Failed to construct `{ signer: principal, weight: uint }` tuple",
                        ),
                    )
                })
                .collect()
        };

        if signers_list.len() > SIGNERS_MAX_LIST_SIZE {
            panic!(
                "FATAL: signers list returned by reward set calculations longer than maximum ({} > {})",
                signers_list.len(),
                SIGNERS_MAX_LIST_SIZE,
            );
        }

        let set_stackerdb_args = [
            SymbolicExpression::atom_value(Value::cons_list_unsanitized(stackerdb_list).expect(
                "BUG: Failed to construct `(list 4000 { signer: principal, num-slots: u64 })` list",
            )),
            SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
            SymbolicExpression::atom_value(Value::UInt(coinbase_height.into())),
        ];

        let set_signers_args = [
            SymbolicExpression::atom_value(Value::UInt(reward_cycle.into())),
            SymbolicExpression::atom_value(Value::cons_list_unsanitized(signers_list).expect(
                "BUG: Failed to construct `(list 4000 { signer: principal, weight: uint })` list",
            )),
        ];

        let (value, _, events, _) = clarity
            .with_abort_callback(
                |vm_env| {
                    vm_env.execute_in_env(sender_addr.clone(), None, None, |env| {
                        env.execute_contract_allow_private(
                            &signers_contract,
                            "stackerdb-set-signer-slots",
                            &set_stackerdb_args,
                            false,
                        )?;
                        env.execute_contract_allow_private(
                            &signers_contract,
                            "set-signers",
                            &set_signers_args,
                            false,
                        )
                    })
                },
                |_, _| false,
            )
            .expect("FATAL: failed to update signer stackerdb");

        if let Value::Response(ref data) = value {
            if !data.committed {
                error!(
                    "Error while updating .signers contract";
                    "reward_cycle" => reward_cycle,
                    "cc_response" => %value,
                );
                panic!();
            }
        }

        Ok(SignerCalculation { events, reward_set })
    }

    /// If this block is mined in the prepare phase, based on its tenure's `burn_tip_height`.  If
    /// so, and if we haven't done so yet, then compute the PoX reward set, store it, and update
    /// the .signers contract.  The stored PoX reward set is the reward set for the next reward
    /// cycle, and will be used by the Nakamoto chains coordinator to validate its block-commits
    /// and block signatures.
    pub fn check_and_handle_prepare_phase_start(
        clarity_tx: &mut ClarityTx,
        first_block_height: u64,
        pox_constants: &PoxConstants,
        burn_tip_height: u64,
        coinbase_height: u64,
    ) -> Result<Option<SignerCalculation>, ChainstateError> {
        let current_epoch = clarity_tx.get_epoch();
        if current_epoch < StacksEpochId::Epoch25 {
            // before Epoch-2.5, no need for special handling
            return Ok(None);
        }
        // now, determine if we are in a prepare phase, and we are the first
        //  block in this prepare phase in our fork
        if !pox_constants.is_in_prepare_phase(first_block_height, burn_tip_height) {
            // if we're not in a prepare phase, don't need to do anything
            return Ok(None);
        }

        let Some(cycle_of_prepare_phase) =
            pox_constants.reward_cycle_of_prepare_phase(first_block_height, burn_tip_height)
        else {
            // if we're not in a prepare phase, don't need to do anything
            return Ok(None);
        };

        let active_pox_contract = pox_constants.active_pox_contract(burn_tip_height);
        if !matches!(
            PoxVersions::lookup_by_name(active_pox_contract),
            Some(PoxVersions::Pox4)
        ) {
            debug!(
                "Active PoX contract is not PoX-4, skipping .signers updates until PoX-4 is active"
            );
            return Ok(None);
        }

        let signers_contract = &boot_code_id(SIGNERS_NAME, clarity_tx.config.mainnet);

        // are we the first block in the prepare phase in our fork?
        let needs_update: Result<_, ChainstateError>  = clarity_tx.connection().with_clarity_db_readonly(|clarity_db| {
            if !clarity_db.has_contract(signers_contract) {
                // if there's no signers contract, no need to update anything.
                return Ok(false)
            }
            let Ok(value) = clarity_db.lookup_variable_unknown_descriptor(
                signers_contract,
                SIGNERS_UPDATE_STATE,
                &current_epoch,
            ) else {
                error!("FATAL: Failed to read `{SIGNERS_UPDATE_STATE}` variable from .signers contract");
                panic!();
            };
            let cycle_number = value.expect_u128()?;
            // if the cycle_number is less than `cycle_of_prepare_phase`, we need to update
            //  the .signers state.
            Ok(cycle_number < cycle_of_prepare_phase.into())
        });

        if !needs_update? {
            debug!("Current cycle has already been setup in .signers or .signers is not initialized yet");
            return Ok(None);
        }

        info!(
            "Performing .signers state update";
            "burn_height" => burn_tip_height,
            "for_cycle" => cycle_of_prepare_phase,
            "coinbase_height" => coinbase_height,
            "signers_contract" => %signers_contract,
        );

        clarity_tx
            .connection()
            .as_free_transaction(|clarity| {
                Self::handle_signer_stackerdb_update(
                    clarity,
                    &pox_constants,
                    cycle_of_prepare_phase,
                    active_pox_contract,
                    coinbase_height,
                )
            })
            .map(Some)
    }

    /// Make the contract name for a signers DB contract
    pub fn make_signers_db_name(reward_cycle: u64, message_id: u32) -> String {
        format!("{}-{}-{}", &SIGNERS_NAME, reward_cycle % 2, message_id)
    }

    /// Make the contract ID for a signers DB contract
    pub fn make_signers_db_contract_id(
        reward_cycle: u64,
        message_id: u32,
        mainnet: bool,
    ) -> QualifiedContractIdentifier {
        let name = Self::make_signers_db_name(reward_cycle, message_id);
        boot_code_id(&name, mainnet)
    }

    /// Get the signer addresses and corresponding weights for a given reward cycle
    pub fn get_signers_weights(
        chainstate: &mut StacksChainState,
        sortdb: &SortitionDB,
        block_id: &StacksBlockId,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, u64>, ChainstateError> {
        let signers_opt = chainstate
            .eval_boot_code_read_only(
                sortdb,
                block_id,
                SIGNERS_NAME,
                &format!("(get-signers u{})", reward_cycle),
            )?
            .expect_optional()?;
        let mut signers = HashMap::new();
        if let Some(signers_list) = signers_opt {
            for signer in signers_list.expect_list()? {
                let signer_tuple = signer.expect_tuple()?;
                let principal_data = signer_tuple.get("signer")?.clone().expect_principal()?;
                let signer_address = if let PrincipalData::Standard(signer) = principal_data {
                    signer.into()
                } else {
                    panic!(
                        "FATAL: Signer returned from get-signers is not a standard principal: {:?}",
                        principal_data
                    );
                };
                let weight = u64::try_from(signer_tuple.get("weight")?.to_owned().expect_u128()?)
                    .expect("FATAL: Signer weight greater than a u64::MAX");
                signers.insert(signer_address, weight);
            }
        }
        if signers.is_empty() {
            error!(
                "No signers found for reward cycle";
                "reward_cycle" => reward_cycle,
            );
            return Err(ChainstateError::NoRegisteredSigners(reward_cycle));
        }
        Ok(signers)
    }

    /// Verify that the transaction is a valid vote for the aggregate public key
    /// Note: it does not verify the function arguments, only that the transaction is validly formed
    /// and has a valid nonce from an expected address
    pub fn valid_vote_transaction(
        account_nonces: &HashMap<StacksAddress, u64>,
        transaction: &StacksTransaction,
        is_mainnet: bool,
    ) -> bool {
        let origin_address = transaction.origin_address();
        let origin_nonce = transaction.get_origin_nonce();
        let Some(account_nonce) = account_nonces.get(&origin_address) else {
            debug!("valid_vote_transaction: Unrecognized origin address ({origin_address}).",);
            return false;
        };
        if transaction.is_mainnet() != is_mainnet {
            debug!("valid_vote_transaction: Received a transaction for an unexpected network.",);
            return false;
        }
        if origin_nonce < *account_nonce {
            debug!("valid_vote_transaction: Received a transaction with an outdated nonce ({origin_nonce} < {account_nonce}).");
            return false;
        }
        Self::parse_vote_for_aggregate_public_key(transaction).is_some()
    }

    pub fn parse_vote_for_aggregate_public_key(
        transaction: &StacksTransaction,
    ) -> Option<AggregateKeyVoteParams> {
        let TransactionPayload::ContractCall(payload) = &transaction.payload else {
            // Not a contract call so not a special cased vote for aggregate public key transaction
            return None;
        };
        if payload.contract_identifier()
            != boot_code_id(SIGNERS_VOTING_NAME, transaction.is_mainnet())
            || payload.function_name != SIGNERS_VOTING_FUNCTION_NAME.into()
        {
            // This is not a special cased transaction.
            return None;
        }
        if payload.function_args.len() != 4 {
            return None;
        }
        let signer_index_value = payload.function_args.first()?;
        let signer_index = u64::try_from(signer_index_value.clone().expect_u128().ok()?).ok()?;
        let aggregate_key_value = payload.function_args.get(1)?;
        let aggregate_key = aggregate_key_value.clone().expect_buff(33).ok()?;
        let round_value = payload.function_args.get(2)?;
        let voting_round = u64::try_from(round_value.clone().expect_u128().ok()?).ok()?;
        let reward_cycle =
            u64::try_from(payload.function_args.get(3)?.clone().expect_u128().ok()?).ok()?;
        Some(AggregateKeyVoteParams {
            signer_index,
            aggregate_key,
            voting_round,
            reward_cycle,
        })
    }

    /// Update the map of filtered valid transactions, selecting one per address based first on lowest nonce, then txid
    pub fn update_filtered_transactions(
        filtered_transactions: &mut HashMap<StacksAddress, StacksTransaction>,
        account_nonces: &HashMap<StacksAddress, u64>,
        mainnet: bool,
        transactions: Vec<StacksTransaction>,
    ) {
        for transaction in transactions {
            if NakamotoSigners::valid_vote_transaction(&account_nonces, &transaction, mainnet) {
                let origin_address = transaction.origin_address();
                let origin_nonce = transaction.get_origin_nonce();
                if let Some(entry) = filtered_transactions.get_mut(&origin_address) {
                    let entry_nonce = entry.get_origin_nonce();
                    if entry_nonce > origin_nonce
                        || (entry_nonce == origin_nonce && entry.txid() > transaction.txid())
                    {
                        *entry = transaction;
                    }
                } else {
                    filtered_transactions.insert(origin_address, transaction);
                }
            }
        }
    }
}
