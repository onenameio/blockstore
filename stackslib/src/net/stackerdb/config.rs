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

/// This file implements the interface to the StackerDB smart contract for loading the DB's config.
/// The smart contract must conform to this trait:
///
/// ```clarity,ignore
/// ;; Any StackerDB smart contract must conform to this trait.
/// (define-trait stackerdb-trait
///
///     ;; Get the list of (signer, num-slots) that make up this DB
///     (define-public (stackerdb-get-signer-slots) (response (list 4096 { signer: principal, num-slots: uint }) uint))
///
///     ;; Get the control metadata for this DB
///     (define-public (stackerdb-get-config)
///         (response {
///             chunk-size: uint,
///             write-freq: uint,
///             max-writes: uint,
///             max-neighbors: uint,
///             hint-replicas: (list 128 { addr: (list 16 uint), port: uint, public-key-hash: (buff 20) })
///         },
///         uint))
/// )
/// ```
use std::collections::{HashMap, HashSet};
use std::mem;

use clarity::vm::analysis::ContractAnalysis;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::database::BurnStateDB;
use clarity::vm::types::{
    BufferLength, FixedFunction, FunctionType, ListTypeData, PrincipalData,
    QualifiedContractIdentifier, SequenceData, SequenceSubtype, StandardPrincipalData,
    TupleTypeSignature, TypeSignature, Value as ClarityValue,
};
use clarity::vm::ClarityName;
use lazy_static::lazy_static;
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Hash160;

use super::{STACKERDB_MAX_PAGE_COUNT, STACKERDB_PAGE_LIST_MAX, STACKERDB_SLOTS_FUNCTION};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::nakamoto::NakamotoChainState;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as chainstate_error;
use crate::clarity_vm::clarity::{ClarityReadOnlyConnection, Error as clarity_error};
use crate::net::stackerdb::{
    StackerDBConfig, StackerDBs, STACKERDB_CONFIG_FUNCTION, STACKERDB_INV_MAX,
    STACKERDB_MAX_CHUNK_SIZE,
};
use crate::net::{Error as NetError, NeighborAddress};

const MAX_HINT_REPLICAS: u32 = 128;

lazy_static! {
    pub static ref REQUIRED_FUNCTIONS: [(ClarityName, Vec<TypeSignature>, TypeSignature); 2] = [
        (
            STACKERDB_SLOTS_FUNCTION.into(),
            vec![],
            TypeSignature::new_response(
                ListTypeData::new_list(
                    TupleTypeSignature::try_from(vec![
                        ("signer".into(), TypeSignature::PrincipalType),
                        ("num-slots".into(), TypeSignature::UIntType)
                    ])
                    .expect("FATAL: failed to construct signer list type")
                    .into(),
                    STACKERDB_PAGE_LIST_MAX
                )
                .expect("FATAL: could not construct signer list type")
                .into(),
                TypeSignature::UIntType
            ).expect("FATAL: failed to construct response with signer slots"),
        ),
        (
            STACKERDB_CONFIG_FUNCTION.into(),
            vec![],
            TypeSignature::new_response(
                TypeSignature::TupleType(
                    TupleTypeSignature::try_from(vec![
                        ("chunk-size".into(), TypeSignature::UIntType),
                        ("write-freq".into(), TypeSignature::UIntType),
                        ("max-writes".into(), TypeSignature::UIntType),
                        ("max-neighbors".into(), TypeSignature::UIntType),
                        ("hint-replicas".into(), ListTypeData::new_list(
                            TypeSignature::TupleType(
                                TupleTypeSignature::try_from(vec![
                                    ("addr".into(), ListTypeData::new_list(TypeSignature::UIntType, 16)
                                        .expect("FATAL: invalid IP address list")
                                        .into()),
                                    ("port".into(), TypeSignature::UIntType),
                                    ("public-key-hash".into(),
                                        // can't use BUFF_20 here because it's also in a
                                        // lazy_static! block
                                        TypeSignature::SequenceType(SequenceSubtype::BufferType(BufferLength::try_from(20u32).expect("FATAL: could not create (buff 20)"))))
                                ])
                                .expect("FATAL: unable to construct hint-replicas type")
                                ),
                            MAX_HINT_REPLICAS)
                            .expect("FATAL: failed to construct hint-replicas list type")
                            .into())
                    ]).expect("FATAL: unable to construct config type")),
                TypeSignature::UIntType
            ).expect("FATAL: unable to construct config response type")
        )
    ];
}

impl StackerDBConfig {
    /// Check that a smart contract is consistent with being a StackerDB controller.
    /// Returns Ok(..) if the contract is valid
    /// Returns Err(reason) if the contract is invalid.  A human-readable reason will be given.
    fn is_contract_valid(epoch: &StacksEpochId, analysis: ContractAnalysis) -> Result<(), String> {
        for (name, expected_args, expected_return) in REQUIRED_FUNCTIONS.iter() {
            let func = if let Some(f) = analysis.read_only_function_types.get(name) {
                f
            } else if let Some(f) = analysis.public_function_types.get(name) {
                f
            } else {
                let reason = format!("Contract is missing function '{name}'");
                return Err(reason);
            };

            let FunctionType::Fixed(func) = func else {
                return Err(format!("Function '{name}' must be a fixed function"));
            };

            if func.args.len() != expected_args.len() {
                let reason = format!(
                    "Function '{name}' has an invalid signature: it must have {} args (got {})",
                    expected_args.len(),
                    func.args.len(),
                );
                return Err(reason);
            }
            for (actual_arg, expected_arg) in func.args.iter().zip(expected_args.iter()) {
                if !actual_arg
                    .signature
                    .admits_type(epoch, expected_arg)
                    .unwrap_or(false)
                {
                    return Err(format!("Function '{name}' has an invalid argument type: expected {expected_arg}, got {actual_arg}"));
                }
            }

            if !expected_return
                .admits_type(epoch, &func.returns)
                .unwrap_or(false)
            {
                return Err(format!("Function '{name}' has an invalid return type: expected {expected_return}, got {}", &func.returns));
            }
        }
        Ok(())
    }

    fn parse_slot_entry(
        entry: ClarityValue,
        contract_id: &QualifiedContractIdentifier,
    ) -> Result<(StacksAddress, u32), String> {
        let ClarityValue::Tuple(slot_data) = entry else {
            let reason = format!(
                "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned non-tuple slot entry",
            );
            return Err(reason);
        };

        let Ok(ClarityValue::Principal(signer_principal)) = slot_data.get("signer") else {
            let reason = format!(
                "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned tuple without `signer` entry of type `principal`",
            );
            return Err(reason);
        };

        let Ok(ClarityValue::UInt(num_slots)) = slot_data.get("num-slots") else {
            let reason = format!(
                "StackerDB fn `{contract_id}.{STACKERDB_SLOTS_FUNCTION}` returned tuple without `num-slots` entry of type `uint`",
            );
            return Err(reason);
        };

        let num_slots = u32::try_from(*num_slots)
            .map_err(|_| format!("Contract `{contract_id}` set too many slots for one signer (max = {STACKERDB_INV_MAX})"))?;
        if num_slots > STACKERDB_INV_MAX {
            return Err(format!("Contract `{contract_id}` set too many slots for one signer (max = {STACKERDB_INV_MAX})"));
        }

        let PrincipalData::Standard(standard_principal) = signer_principal else {
            return Err(format!(
                "StackerDB contract `{contract_id}` set a contract principal as a writer, which is not supported"
            ));
        };
        let addr = StacksAddress::from(standard_principal.clone());
        Ok((addr, num_slots))
    }

    fn eval_signer_slots(
        chainstate: &mut StacksChainState,
        burn_dbconn: &dyn BurnStateDB,
        contract_id: &QualifiedContractIdentifier,
        tip: &StacksBlockId,
    ) -> Result<Vec<(StacksAddress, u32)>, NetError> {
        let value = chainstate.eval_read_only(
            burn_dbconn,
            tip,
            contract_id,
            &format!("({STACKERDB_SLOTS_FUNCTION})"),
        )?;

        let result = value.expect_result()?;
        let slot_list = match result {
            Err(err_val) => {
                let err_code = err_val.expect_u128()?;
                let reason = format!(
                    "Contract {} failed to run `stackerdb-get-signer-slots`: error u{}",
                    contract_id, &err_code
                );
                warn!("{}", &reason);
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }
            Ok(ok_val) => ok_val.expect_list()?,
        };

        let mut total_num_slots = 0u32;
        let mut ret = vec![];
        for slot_value in slot_list.into_iter() {
            let (addr, num_slots) =
                Self::parse_slot_entry(slot_value, contract_id).map_err(|e| {
                    warn!("Failed to parse StackerDB slot entry: {}", &e);
                    NetError::InvalidStackerDBContract(contract_id.clone(), e)
                })?;

            if num_slots > STACKERDB_INV_MAX {
                let reason = format!(
                    "Contract {} stipulated more than maximum number of slots for one signer ({})",
                    contract_id, STACKERDB_INV_MAX
                );
                warn!("{}", &reason);
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }

            total_num_slots =
                total_num_slots
                    .checked_add(num_slots)
                    .ok_or(NetError::OverflowError(format!(
                        "Contract {} stipulates more than u32::MAX slots",
                        &contract_id
                    )))?;

            if total_num_slots > STACKERDB_INV_MAX {
                let reason = format!(
                    "Contract {contract_id} stipulated more than the maximum number of slots"
                );
                warn!("{reason}");
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }

            ret.push((addr, num_slots));
        }
        Ok(ret)
    }

    /// Evaluate contract-given hint-replicas
    fn eval_hint_replicas(
        contract_id: &QualifiedContractIdentifier,
        hint_replicas_list: Vec<ClarityValue>,
    ) -> Result<Vec<NeighborAddress>, NetError> {
        let mut hint_replicas = vec![];
        for hint_replica_value in hint_replicas_list.into_iter() {
            let hint_replica_data = hint_replica_value.expect_tuple()?;

            let addr_byte_list = hint_replica_data
                .get("addr")
                .expect("FATAL: missing 'addr'")
                .clone()
                .expect_list()?;
            let port = hint_replica_data
                .get("port")
                .expect("FATAL: missing 'port'")
                .clone()
                .expect_u128()?;
            let pubkey_hash_bytes = hint_replica_data
                .get("public-key-hash")
                .expect("FATAL: missing 'public-key-hash")
                .clone()
                .expect_buff_padded(20, 0)?;

            let mut addr_bytes = vec![];
            for byte_val in addr_byte_list.into_iter() {
                let byte = byte_val.expect_u128()?;
                if byte > (u8::MAX as u128) {
                    let reason = format!(
                        "Contract {} stipulates an addr byte above u8::MAX",
                        contract_id
                    );
                    warn!("{}", &reason);
                    return Err(NetError::InvalidStackerDBContract(
                        contract_id.clone(),
                        reason,
                    ));
                }
                addr_bytes.push(byte as u8);
            }
            if addr_bytes.len() != 16 {
                let reason = format!(
                    "Contract {} did not stipulate a full 16-octet IP address",
                    contract_id
                );
                warn!("{}", &reason);
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }

            if port < 1024 || port > u128::from(u16::MAX - 1) {
                let reason = format!(
                    "Contract {} stipulates a port lower than 1024 or above u16::MAX - 1",
                    contract_id
                );
                warn!("{}", &reason);
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }
            // NOTE: port is now known to be in range [1024, 65535]

            let mut pubkey_hash_slice = [0u8; 20];
            pubkey_hash_slice.copy_from_slice(&pubkey_hash_bytes[0..20]);

            let peer_addr = PeerAddress::from_slice(&addr_bytes).expect("FATAL: not 16 bytes");
            if peer_addr.is_in_private_range() {
                debug!(
                    "Ignoring private IP address '{}' in hint-replicas",
                    &peer_addr.to_socketaddr(port as u16)
                );
                continue;
            }

            let naddr = NeighborAddress {
                addrbytes: peer_addr,
                port: port as u16,
                public_key_hash: Hash160(pubkey_hash_slice),
            };
            hint_replicas.push(naddr);
        }
        Ok(hint_replicas)
    }

    /// Evaluate the contract to get its config
    fn eval_config(
        chainstate: &mut StacksChainState,
        burn_dbconn: &dyn BurnStateDB,
        contract_id: &QualifiedContractIdentifier,
        tip: &StacksBlockId,
        signers: Vec<(StacksAddress, u32)>,
        local_max_neighbors: u64,
        local_hint_replicas: Option<Vec<NeighborAddress>>,
    ) -> Result<StackerDBConfig, NetError> {
        let value =
            chainstate.eval_read_only(burn_dbconn, tip, contract_id, "(stackerdb-get-config)")?;

        let result = value.expect_result()?;
        let config_tuple = match result {
            Err(err_val) => {
                let err_code = err_val.expect_u128()?;
                let reason = format!(
                    "Contract {} failed to run `stackerdb-get-config`: err u{}",
                    contract_id, &err_code
                );
                warn!("{}", &reason);
                return Err(NetError::InvalidStackerDBContract(
                    contract_id.clone(),
                    reason,
                ));
            }
            Ok(ok_val) => ok_val.expect_tuple()?,
        };

        let chunk_size = config_tuple
            .get("chunk-size")
            .expect("FATAL: missing 'chunk-size'")
            .clone()
            .expect_u128()?;

        if chunk_size > STACKERDB_MAX_CHUNK_SIZE as u128 {
            let reason = format!(
                "Contract {} stipulates a chunk size beyond STACKERDB_MAX_CHUNK_SIZE",
                contract_id
            );
            warn!("{}", &reason);
            return Err(NetError::InvalidStackerDBContract(
                contract_id.clone(),
                reason,
            ));
        }

        let write_freq = config_tuple
            .get("write-freq")
            .expect("FATAL: missing 'write-freq'")
            .clone()
            .expect_u128()?;
        if write_freq > u64::MAX as u128 {
            let reason = format!(
                "Contract {} stipulates a write frequency beyond u64::MAX",
                contract_id
            );
            warn!("{}", &reason);
            return Err(NetError::InvalidStackerDBContract(
                contract_id.clone(),
                reason,
            ));
        }

        let max_writes = config_tuple
            .get("max-writes")
            .expect("FATAL: missing 'max-writes'")
            .clone()
            .expect_u128()?;
        if max_writes > u32::MAX as u128 {
            let reason = format!(
                "Contract {} stipulates a max-write bound beyond u32::MAX",
                contract_id
            );
            warn!("{}", &reason);
            return Err(NetError::InvalidStackerDBContract(
                contract_id.clone(),
                reason,
            ));
        }

        let mut max_neighbors = config_tuple
            .get("max-neighbors")
            .expect("FATAL: missing 'max-neighbors'")
            .clone()
            .expect_u128()?;

        if max_neighbors > usize::MAX as u128 {
            let reason = format!(
                "Contract {} stipulates a maximum number of neighbors beyond usize::MAX",
                contract_id
            );
            warn!("{}", &reason);
            return Err(NetError::InvalidStackerDBContract(
                contract_id.clone(),
                reason,
            ));
        }

        if max_neighbors > u128::from(local_max_neighbors) {
            debug!(
                "Contract {} stipulates a maximum number of neighbors ({}) beyond locally-configured maximum {}; defaulting to locally-configured maximum",
                contract_id,
                max_neighbors,
                local_max_neighbors,
            );
            max_neighbors = u128::from(local_max_neighbors);
        }

        let hint_replicas = if let Some(replicas) = local_hint_replicas {
            replicas.clone()
        } else {
            let hint_replicas_list = config_tuple
                .get("hint-replicas")
                .expect("FATAL: missing 'hint-replicas'")
                .clone()
                .expect_list()?;

            Self::eval_hint_replicas(contract_id, hint_replicas_list)?
        };

        Ok(StackerDBConfig {
            chunk_size: chunk_size as u64,
            signers,
            write_freq: write_freq as u64,
            max_writes: max_writes as u32,
            hint_replicas,
            max_neighbors: max_neighbors as usize,
        })
    }

    /// Load up the DB config from the controlling smart contract as of the current Stacks chain
    /// tip
    pub fn from_smart_contract(
        chainstate: &mut StacksChainState,
        sortition_db: &SortitionDB,
        contract_id: &QualifiedContractIdentifier,
        max_neighbors: u64,
        local_hint_replicas: Option<Vec<NeighborAddress>>,
    ) -> Result<StackerDBConfig, NetError> {
        let chain_tip =
            NakamotoChainState::get_canonical_block_header(chainstate.db(), sortition_db)?
                .ok_or(NetError::NoSuchStackerDB(contract_id.clone()))?;

        let burn_tip = SortitionDB::get_block_snapshot_consensus(
            sortition_db.conn(),
            &chain_tip.consensus_hash,
        )?
        .expect("FATAL: missing snapshot for Stacks block");

        let chain_tip_hash = StacksBlockId::new(
            &chain_tip.consensus_hash,
            &chain_tip.anchored_header.block_hash(),
        );
        let cur_epoch = SortitionDB::get_stacks_epoch(sortition_db.conn(), burn_tip.block_height)?
            .expect("FATAL: no epoch defined");

        let dbconn = sortition_db.index_handle_at_block(chainstate, &chain_tip_hash)?;

        // check the target contract
        let res = chainstate.with_read_only_clarity_tx(&dbconn, &chain_tip_hash, |clarity_tx| {
            // determine if this contract exists and conforms to this trait
            clarity_tx.with_clarity_db_readonly(|db| {
                // contract must exist or this errors out
                let analysis = db
                    .load_contract_analysis(contract_id)?
                    .ok_or(NetError::NoSuchStackerDB(contract_id.clone()))?;

                // contract must be consistent with StackerDB control interface
                if let Err(invalid_reason) = Self::is_contract_valid(&cur_epoch.epoch_id, analysis)
                {
                    let reason = format!(
                        "Contract {} does not conform to StackerDB trait: {}",
                        contract_id, invalid_reason
                    );
                    warn!("{}", &reason);
                    return Err(NetError::InvalidStackerDBContract(
                        contract_id.clone(),
                        reason,
                    ));
                }

                Ok(())
            })
        });

        if res.is_none() {
            let reason = format!(
                "Could not evaluate contract {} at {}",
                contract_id, &chain_tip_hash
            );
            warn!("{}", &reason);
            return Err(NetError::InvalidStackerDBContract(
                contract_id.clone(),
                reason,
            ));
        } else if let Some(Err(e)) = res {
            if contract_id.is_boot() {
                debug!(
                    "Could not use contract {} for StackerDB: {:?}",
                    contract_id, &e
                );
            } else {
                warn!(
                    "Could not use contract {} for StackerDB: {:?}",
                    contract_id, &e
                );
            }
            return Err(e);
        }

        // evaluate the contract for these two functions
        let signers = Self::eval_signer_slots(chainstate, &dbconn, contract_id, &chain_tip_hash)?;
        let config = Self::eval_config(
            chainstate,
            &dbconn,
            contract_id,
            &chain_tip_hash,
            signers,
            max_neighbors,
            local_hint_replicas,
        )?;
        Ok(config)
    }
}
