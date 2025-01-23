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

use std::io;
use std::io::prelude::*;
use std::io::{Read, Write};

use clarity::vm::representations::{ClarityName, ContractName};
use clarity::vm::types::serialization::SerializationError as clarity_serialization_error;
use clarity::vm::types::{QualifiedContractIdentifier, StandardPrincipalData};
use clarity::vm::{ClarityVersion, SymbolicExpression, SymbolicExpressionType, Value};
use stacks_common::codec::{read_next, write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{to_hex, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;

use crate::burnchains::Txid;
use crate::chainstate::stacks::{TransactionPayloadID, *};
use crate::codec::Error as CodecError;
use crate::core::*;
use crate::net::Error as net_error;
use crate::util_lib::boot::boot_code_addr;

impl StacksMessageCodec for TransactionContractCall {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.function_name)?;
        write_next(fd, &self.function_args)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionContractCall, codec_error> {
        let address: StacksAddress = read_next(fd)?;
        let contract_name: ContractName = read_next(fd)?;
        let function_name: ClarityName = read_next(fd)?;
        let function_args: Vec<Value> = {
            let mut bound_read = BoundReader::from_reader(fd, u64::from(MAX_TRANSACTION_LEN));
            read_next(&mut bound_read)
        }?;

        // function name must be valid Clarity variable
        if !StacksString::from(function_name.clone()).is_clarity_variable() {
            warn!("Invalid function name -- not a clarity variable");
            return Err(codec_error::DeserializeError(
                "Failed to parse transaction: invalid function name -- not a Clarity variable"
                    .to_string(),
            ));
        }

        Ok(TransactionContractCall {
            address,
            contract_name,
            function_name,
            function_args,
        })
    }
}

impl TransactionContractCall {
    pub fn to_clarity_contract_id(&self) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(
            StandardPrincipalData::from(self.address.clone()),
            self.contract_name.clone(),
        )
    }
}

impl fmt::Display for TransactionContractCall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let formatted_args = self
            .function_args
            .iter()
            .map(|v| format!("{}", v))
            .collect::<Vec<String>>()
            .join(", ");
        write!(
            f,
            "{}.{}::{}({})",
            self.address, self.contract_name, self.function_name, formatted_args
        )
    }
}

impl StacksMessageCodec for TransactionSmartContract {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.name)?;
        write_next(fd, &self.code_body)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionSmartContract, codec_error> {
        let name: ContractName = read_next(fd)?;
        let code_body: StacksString = read_next(fd)?;
        Ok(TransactionSmartContract { name, code_body })
    }
}

fn ClarityVersion_consensus_serialize<W: Write>(
    version: &ClarityVersion,
    fd: &mut W,
) -> Result<(), codec_error> {
    match *version {
        ClarityVersion::Clarity1 => write_next(fd, &1u8)?,
        ClarityVersion::Clarity2 => write_next(fd, &2u8)?,
        ClarityVersion::Clarity3 => write_next(fd, &3u8)?,
    }
    Ok(())
}

fn ClarityVersion_consensus_deserialize<R: Read>(
    fd: &mut R,
) -> Result<ClarityVersion, codec_error> {
    let version_byte: u8 = read_next(fd)?;
    match version_byte {
        1u8 => Ok(ClarityVersion::Clarity1),
        2u8 => Ok(ClarityVersion::Clarity2),
        3u8 => Ok(ClarityVersion::Clarity3),
        _ => Err(codec_error::DeserializeError(format!(
            "Unrecognized ClarityVersion byte {}",
            &version_byte
        ))),
    }
}

impl StacksMessageCodec for TenureChangeCause {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        let byte = (*self) as u8;
        write_next(fd, &byte)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TenureChangeCause, codec_error> {
        let byte: u8 = read_next(fd)?;
        TenureChangeCause::try_from(byte).map_err(|_| {
            codec_error::DeserializeError(format!("Unrecognized TenureChangeCause byte {byte}"))
        })
    }
}

impl StacksMessageCodec for TenureChangePayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.tenure_consensus_hash)?;
        write_next(fd, &self.prev_tenure_consensus_hash)?;
        write_next(fd, &self.burn_view_consensus_hash)?;
        write_next(fd, &self.previous_tenure_end)?;
        write_next(fd, &self.previous_tenure_blocks)?;
        write_next(fd, &self.cause)?;
        write_next(fd, &self.pubkey_hash)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Self, codec_error> {
        Ok(Self {
            tenure_consensus_hash: read_next(fd)?,
            prev_tenure_consensus_hash: read_next(fd)?,
            burn_view_consensus_hash: read_next(fd)?,
            previous_tenure_end: read_next(fd)?,
            previous_tenure_blocks: read_next(fd)?,
            cause: read_next(fd)?,
            pubkey_hash: read_next(fd)?,
        })
    }
}

impl StacksMessageCodec for TransactionPayload {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match self {
            TransactionPayload::TokenTransfer(address, amount, memo) => {
                write_next(fd, &(TransactionPayloadID::TokenTransfer as u8))?;
                write_next(fd, address)?;
                write_next(fd, amount)?;
                write_next(fd, memo)?;
            }
            TransactionPayload::ContractCall(cc) => {
                write_next(fd, &(TransactionPayloadID::ContractCall as u8))?;
                cc.consensus_serialize(fd)?;
            }
            TransactionPayload::SmartContract(sc, version_opt) => {
                if let Some(version) = version_opt {
                    // caller requests a specific Clarity version
                    write_next(fd, &(TransactionPayloadID::VersionedSmartContract as u8))?;
                    ClarityVersion_consensus_serialize(&version, fd)?;
                    sc.consensus_serialize(fd)?;
                } else {
                    // caller requests to use whatever the current clarity version is
                    write_next(fd, &(TransactionPayloadID::SmartContract as u8))?;
                    sc.consensus_serialize(fd)?;
                }
            }
            TransactionPayload::PoisonMicroblock(h1, h2) => {
                write_next(fd, &(TransactionPayloadID::PoisonMicroblock as u8))?;
                h1.consensus_serialize(fd)?;
                h2.consensus_serialize(fd)?;
            }
            TransactionPayload::Coinbase(buf, recipient_opt, vrf_opt) => {
                match (recipient_opt, vrf_opt) {
                    (None, None) => {
                        // stacks 2.05 and earlier only use this path
                        write_next(fd, &(TransactionPayloadID::Coinbase as u8))?;
                        write_next(fd, buf)?;
                    }
                    (Some(recipient), None) => {
                        write_next(fd, &(TransactionPayloadID::CoinbaseToAltRecipient as u8))?;
                        write_next(fd, buf)?;
                        write_next(fd, &Value::Principal(recipient.clone()))?;
                    }
                    (None, Some(vrf_proof)) => {
                        // nakamoto coinbase
                        // encode principal as (optional principal)
                        write_next(fd, &(TransactionPayloadID::NakamotoCoinbase as u8))?;
                        write_next(fd, buf)?;
                        write_next(fd, &Value::none())?;
                        write_next(fd, vrf_proof)?;
                    }
                    (Some(recipient), Some(vrf_proof)) => {
                        write_next(fd, &(TransactionPayloadID::NakamotoCoinbase as u8))?;
                        write_next(fd, buf)?;
                        write_next(
                            fd,
                            &Value::some(Value::Principal(recipient.clone())).expect(
                                "FATAL: failed to encode recipient principal as `optional`",
                            ),
                        )?;
                        write_next(fd, vrf_proof)?;
                    }
                }
            }
            TransactionPayload::TenureChange(tc) => {
                write_next(fd, &(TransactionPayloadID::TenureChange as u8))?;
                tc.consensus_serialize(fd)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionPayload, codec_error> {
        let type_id_u8 = read_next(fd)?;
        let type_id = TransactionPayloadID::from_u8(type_id_u8).ok_or_else(|| {
            codec_error::DeserializeError(format!(
                "Failed to parse transaction -- unknown payload ID {type_id_u8}"
            ))
        })?;
        let payload = match type_id {
            TransactionPayloadID::TokenTransfer => {
                let principal = read_next(fd)?;
                let amount = read_next(fd)?;
                let memo = read_next(fd)?;
                TransactionPayload::TokenTransfer(principal, amount, memo)
            }
            TransactionPayloadID::ContractCall => {
                let payload: TransactionContractCall = read_next(fd)?;
                TransactionPayload::ContractCall(payload)
            }
            TransactionPayloadID::SmartContract => {
                let payload: TransactionSmartContract = read_next(fd)?;
                TransactionPayload::SmartContract(payload, None)
            }
            TransactionPayloadID::VersionedSmartContract => {
                let version = ClarityVersion_consensus_deserialize(fd)?;
                let payload: TransactionSmartContract = read_next(fd)?;
                TransactionPayload::SmartContract(payload, Some(version))
            }
            TransactionPayloadID::PoisonMicroblock => {
                let h1: StacksMicroblockHeader = read_next(fd)?;
                let h2: StacksMicroblockHeader = read_next(fd)?;

                // must differ in some field
                if h1 == h2 {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction -- microblock headers match".to_string(),
                    ));
                }

                // must have the same sequence number or same block parent
                if h1.sequence != h2.sequence && h1.prev_block != h2.prev_block {
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction -- microblock headers do not identify a fork"
                            .to_string(),
                    ));
                }

                TransactionPayload::PoisonMicroblock(h1, h2)
            }
            TransactionPayloadID::Coinbase => {
                let payload: CoinbasePayload = read_next(fd)?;
                TransactionPayload::Coinbase(payload, None, None)
            }
            TransactionPayloadID::CoinbaseToAltRecipient => {
                let payload: CoinbasePayload = read_next(fd)?;
                let principal_value: Value = read_next(fd)?;
                let recipient = match principal_value {
                    Value::Principal(recipient_principal) => recipient_principal,
                    _ => {
                        return Err(codec_error::DeserializeError("Failed to parse coinbase transaction -- did not receive a recipient principal value".to_string()));
                    }
                };

                TransactionPayload::Coinbase(payload, Some(recipient), None)
            }
            // TODO: gate this!
            TransactionPayloadID::NakamotoCoinbase => {
                let payload: CoinbasePayload = read_next(fd)?;
                let principal_value_opt: Value = read_next(fd)?;
                let recipient_opt = if let Value::Optional(optional_data) = principal_value_opt {
                    if let Some(principal_value) = optional_data.data {
                        if let Value::Principal(recipient_principal) = *principal_value {
                            Some(recipient_principal)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    return Err(codec_error::DeserializeError("Failed to parse nakamoto coinbase transaction -- did not receive an optional recipient principal value".to_string()));
                };
                let vrf_proof: VRFProof = read_next(fd)?;
                TransactionPayload::Coinbase(payload, recipient_opt, Some(vrf_proof))
            }
            TransactionPayloadID::TenureChange => {
                let payload: TenureChangePayload = read_next(fd)?;
                TransactionPayload::TenureChange(payload)
            }
        };

        Ok(payload)
    }
}

impl<'a, H> FromIterator<&'a StacksTransaction> for MerkleTree<H>
where
    H: MerkleHashFunc + Clone + PartialEq + fmt::Debug,
{
    fn from_iter<T: IntoIterator<Item = &'a StacksTransaction>>(iter: T) -> Self {
        let txid_vec: Vec<_> = iter
            .into_iter()
            .map(|x| x.txid().as_bytes().to_vec())
            .collect();
        MerkleTree::new(&txid_vec)
    }
}

impl TransactionPayload {
    pub fn new_contract_call(
        contract_address: StacksAddress,
        contract_name: &str,
        function_name: &str,
        args: Vec<Value>,
    ) -> Option<TransactionPayload> {
        let contract_name_str = match ContractName::try_from(contract_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                test_debug!("Not a clarity name: '{}'", contract_name);
                return None;
            }
        };

        let function_name_str = match ClarityName::try_from(function_name.to_string()) {
            Ok(s) => s,
            Err(_) => {
                test_debug!("Not a clarity name: '{}'", contract_name);
                return None;
            }
        };

        Some(TransactionPayload::ContractCall(TransactionContractCall {
            address: contract_address,
            contract_name: contract_name_str,
            function_name: function_name_str,
            function_args: args,
        }))
    }

    pub fn new_smart_contract(
        name: &str,
        contract: &str,
        version_opt: Option<ClarityVersion>,
    ) -> Option<TransactionPayload> {
        match (
            ContractName::try_from(name.to_string()),
            StacksString::from_str(contract),
        ) {
            (Ok(s_name), Some(s_body)) => Some(TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: s_name,
                    code_body: s_body,
                },
                version_opt,
            )),
            (_, _) => None,
        }
    }
}

impl StacksMessageCodec for AssetInfo {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &self.contract_address)?;
        write_next(fd, &self.contract_name)?;
        write_next(fd, &self.asset_name)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<AssetInfo, codec_error> {
        let contract_address: StacksAddress = read_next(fd)?;
        let contract_name: ContractName = read_next(fd)?;
        let asset_name: ClarityName = read_next(fd)?;
        Ok(AssetInfo {
            contract_address,
            contract_name,
            asset_name,
        })
    }
}

impl StacksMessageCodec for PostConditionPrincipal {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            PostConditionPrincipal::Origin => {
                write_next(fd, &(PostConditionPrincipalID::Origin as u8))?;
            }
            PostConditionPrincipal::Standard(ref address) => {
                write_next(fd, &(PostConditionPrincipalID::Standard as u8))?;
                write_next(fd, address)?;
            }
            PostConditionPrincipal::Contract(ref address, ref contract_name) => {
                write_next(fd, &(PostConditionPrincipalID::Contract as u8))?;
                write_next(fd, address)?;
                write_next(fd, contract_name)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PostConditionPrincipal, codec_error> {
        let principal_id: u8 = read_next(fd)?;
        let principal = match principal_id {
            x if x == PostConditionPrincipalID::Origin as u8 => PostConditionPrincipal::Origin,
            x if x == PostConditionPrincipalID::Standard as u8 => {
                let addr: StacksAddress = read_next(fd)?;
                PostConditionPrincipal::Standard(addr)
            }
            x if x == PostConditionPrincipalID::Contract as u8 => {
                let addr: StacksAddress = read_next(fd)?;
                let contract_name: ContractName = read_next(fd)?;
                PostConditionPrincipal::Contract(addr, contract_name)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: unknown post condition principal ID {}",
                    principal_id
                )));
            }
        };
        Ok(principal)
    }
}

impl StacksMessageCodec for TransactionPostCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionPostCondition::STX(ref principal, ref fungible_condition, ref amount) => {
                write_next(fd, &(AssetInfoID::STX as u8))?;
                write_next(fd, principal)?;
                write_next(fd, &(*fungible_condition as u8))?;
                write_next(fd, amount)?;
            }
            TransactionPostCondition::Fungible(
                ref principal,
                ref asset_info,
                ref fungible_condition,
                ref amount,
            ) => {
                write_next(fd, &(AssetInfoID::FungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, &(*fungible_condition as u8))?;
                write_next(fd, amount)?;
            }
            TransactionPostCondition::Nonfungible(
                ref principal,
                ref asset_info,
                ref asset_value,
                ref nonfungible_condition,
            ) => {
                write_next(fd, &(AssetInfoID::NonfungibleAsset as u8))?;
                write_next(fd, principal)?;
                write_next(fd, asset_info)?;
                write_next(fd, asset_value)?;
                write_next(fd, &(*nonfungible_condition as u8))?;
            }
        };
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionPostCondition, codec_error> {
        let asset_info_id: u8 = read_next(fd)?;
        let postcond = match asset_info_id {
            x if x == AssetInfoID::STX as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;
                let amount: u64 = read_next(fd)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8).ok_or(
                    codec_error::DeserializeError(format!(
                    "Failed to parse transaction: Failed to parse STX fungible condition code {}",
                    condition_u8
                )),
                )?;

                TransactionPostCondition::STX(principal, condition_code, amount)
            }
            x if x == AssetInfoID::FungibleAsset as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let asset: AssetInfo = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;
                let amount: u64 = read_next(fd)?;

                let condition_code = FungibleConditionCode::from_u8(condition_u8).ok_or(
                    codec_error::DeserializeError(format!(
                    "Failed to parse transaction: Failed to parse FungibleAsset condition code {}",
                    condition_u8
                )),
                )?;

                TransactionPostCondition::Fungible(principal, asset, condition_code, amount)
            }
            x if x == AssetInfoID::NonfungibleAsset as u8 => {
                let principal: PostConditionPrincipal = read_next(fd)?;
                let asset: AssetInfo = read_next(fd)?;
                let asset_value: Value = read_next(fd)?;
                let condition_u8: u8 = read_next(fd)?;

                let condition_code = NonfungibleConditionCode::from_u8(condition_u8)
                    .ok_or(codec_error::DeserializeError(format!("Failed to parse transaction: Failed to parse NonfungibleAsset condition code {}", condition_u8)))?;

                TransactionPostCondition::Nonfungible(principal, asset, asset_value, condition_code)
            }
            _ => {
                return Err(codec_error::DeserializeError(format!(
                    "Failed to aprse transaction: unknown asset info ID {}",
                    asset_info_id
                )));
            }
        };

        Ok(postcond)
    }
}

impl StacksTransaction {
    pub fn tx_len(&self) -> u64 {
        let mut tx_bytes = vec![];
        self.consensus_serialize(&mut tx_bytes)
            .expect("BUG: Failed to serialize a transaction object");
        u64::try_from(tx_bytes.len()).expect("tx len exceeds 2^64 bytes")
    }

    pub fn consensus_deserialize_with_len<R: Read>(
        fd: &mut R,
    ) -> Result<(StacksTransaction, u64), codec_error> {
        let mut bound_read = BoundReader::from_reader(fd, MAX_TRANSACTION_LEN.into());
        let fd = &mut bound_read;

        let version_u8: u8 = read_next(fd)?;
        let chain_id: u32 = read_next(fd)?;
        let auth: TransactionAuth = read_next(fd)?;
        let anchor_mode_u8: u8 = read_next(fd)?;
        let post_condition_mode_u8: u8 = read_next(fd)?;
        let post_conditions: Vec<TransactionPostCondition> = read_next(fd)?;

        let payload: TransactionPayload = read_next(fd)?;

        let version = if (version_u8 & 0x80) == 0 {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let anchor_mode = match anchor_mode_u8 {
            x if x == TransactionAnchorMode::OffChainOnly as u8 => {
                TransactionAnchorMode::OffChainOnly
            }
            x if x == TransactionAnchorMode::OnChainOnly as u8 => {
                TransactionAnchorMode::OnChainOnly
            }
            x if x == TransactionAnchorMode::Any as u8 => TransactionAnchorMode::Any,
            _ => {
                warn!("Invalid tx: invalid anchor mode");
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: invalid anchor mode {}",
                    anchor_mode_u8
                )));
            }
        };

        // if the payload is a proof of a poisoned microblock stream, or is a coinbase, then this _must_ be anchored.
        // Otherwise, if the offending leader is the next leader, they can just orphan their proof
        // of malfeasance.
        match payload {
            TransactionPayload::PoisonMicroblock(_, _) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    warn!("Invalid tx: invalid anchor mode for poison microblock");
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction: invalid anchor mode for PoisonMicroblock"
                            .to_string(),
                    ));
                }
            }
            TransactionPayload::Coinbase(..) => {
                if anchor_mode != TransactionAnchorMode::OnChainOnly {
                    warn!("Invalid tx: invalid anchor mode for coinbase");
                    return Err(codec_error::DeserializeError(
                        "Failed to parse transaction: invalid anchor mode for Coinbase".to_string(),
                    ));
                }
            }
            _ => {}
        }

        let post_condition_mode = match post_condition_mode_u8 {
            x if x == TransactionPostConditionMode::Allow as u8 => {
                TransactionPostConditionMode::Allow
            }
            x if x == TransactionPostConditionMode::Deny as u8 => {
                TransactionPostConditionMode::Deny
            }
            _ => {
                warn!("Invalid tx: invalid post condition mode");
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction: invalid post-condition mode {}",
                    post_condition_mode_u8
                )));
            }
        };
        let tx = StacksTransaction {
            version,
            chain_id,
            auth,
            anchor_mode,
            post_condition_mode,
            post_conditions,
            payload,
        };

        Ok((tx, fd.num_read()))
    }

    /// Try to convert to a coinbase payload
    pub fn try_as_coinbase(
        &self,
    ) -> Option<(&CoinbasePayload, Option<&PrincipalData>, Option<&VRFProof>)> {
        match &self.payload {
            TransactionPayload::Coinbase(payload, recipient_opt, vrf_proof_opt) => {
                Some((payload, recipient_opt.as_ref(), vrf_proof_opt.as_ref()))
            }
            _ => None,
        }
    }

    /// Try to convert to a tenure change payload
    pub fn try_as_tenure_change(&self) -> Option<&TenureChangePayload> {
        match &self.payload {
            TransactionPayload::TenureChange(tc_payload) => Some(tc_payload),
            _ => None,
        }
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.version as u8))?;
        write_next(fd, &self.chain_id)?;
        write_next(fd, &self.auth)?;
        write_next(fd, &(self.anchor_mode as u8))?;
        write_next(fd, &(self.post_condition_mode as u8))?;
        write_next(fd, &self.post_conditions)?;
        write_next(fd, &self.payload)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksTransaction, codec_error> {
        StacksTransaction::consensus_deserialize_with_len(fd).map(|(result, _)| result)
    }
}

impl From<TransactionSmartContract> for TransactionPayload {
    fn from(value: TransactionSmartContract) -> Self {
        TransactionPayload::SmartContract(value, None)
    }
}

impl From<TransactionContractCall> for TransactionPayload {
    fn from(value: TransactionContractCall) -> Self {
        TransactionPayload::ContractCall(value)
    }
}

impl StacksTransaction {
    /// Create a new, unsigned transaction and an empty STX fee with no post-conditions.
    pub fn new(
        version: TransactionVersion,
        auth: TransactionAuth,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let anchor_mode = match payload {
            TransactionPayload::Coinbase(..) => TransactionAnchorMode::OnChainOnly,
            TransactionPayload::PoisonMicroblock(_, _) => TransactionAnchorMode::OnChainOnly,
            _ => TransactionAnchorMode::Any,
        };

        StacksTransaction {
            version,
            chain_id: 0,
            auth,
            anchor_mode,
            post_condition_mode: TransactionPostConditionMode::Deny,
            post_conditions: vec![],
            payload,
        }
    }

    /// Get fee rate
    pub fn get_tx_fee(&self) -> u64 {
        self.auth.get_tx_fee()
    }

    /// Set fee rate
    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        self.auth.set_tx_fee(tx_fee);
    }

    /// Get origin nonce
    pub fn get_origin_nonce(&self) -> u64 {
        self.auth.get_origin_nonce()
    }

    /// get sponsor nonce
    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        self.auth.get_sponsor_nonce()
    }

    /// set origin nonce
    pub fn set_origin_nonce(&mut self, n: u64) {
        self.auth.set_origin_nonce(n);
    }

    /// set sponsor nonce
    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), Error> {
        self.auth.set_sponsor_nonce(n)
    }

    /// Set anchor mode
    pub fn set_anchor_mode(&mut self, anchor_mode: TransactionAnchorMode) {
        self.anchor_mode = anchor_mode;
    }

    /// Set post-condition mode
    pub fn set_post_condition_mode(&mut self, postcond_mode: TransactionPostConditionMode) {
        self.post_condition_mode = postcond_mode;
    }

    /// Add a post-condition
    pub fn add_post_condition(&mut self, post_condition: TransactionPostCondition) {
        self.post_conditions.push(post_condition);
    }

    /// a txid of a stacks transaction is its sha512/256 hash
    pub fn txid(&self) -> Txid {
        let mut bytes = vec![];
        self.consensus_serialize(&mut bytes)
            .expect("BUG: failed to serialize to a vec");
        Txid::from_stacks_tx(&bytes)
    }

    /// Get a mutable reference to the internal auth structure
    pub fn borrow_auth(&mut self) -> &mut TransactionAuth {
        &mut self.auth
    }

    /// Get an immutable reference to the internal auth structure
    pub fn auth(&self) -> &TransactionAuth {
        &self.auth
    }

    /// begin signing the transaction.
    /// If this is a sponsored transaction, then the origin only commits to knowing that it is
    /// sponsored.  It does _not_ commit to the sponsored fields, so set them all to sentinel
    /// values.
    /// Return the initial sighash.
    fn sign_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// begin verifying a transaction.
    /// return the initial sighash
    fn verify_begin(&self) -> Txid {
        let mut tx = self.clone();
        tx.auth = tx.auth.into_initial_sighash_auth();
        tx.txid()
    }

    /// Sign a sighash and append the signature and public key to the given spending condition.
    /// Returns the next sighash
    fn sign_and_append(
        condition: &mut TransactionSpendingCondition,
        cur_sighash: &Txid,
        auth_flag: &TransactionAuthFlags,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, net_error> {
        let (next_sig, next_sighash) = TransactionSpendingCondition::next_signature(
            cur_sighash,
            auth_flag,
            condition.tx_fee(),
            condition.nonce(),
            privk,
        )?;
        match condition {
            TransactionSpendingCondition::Singlesig(ref mut cond) => {
                cond.set_signature(next_sig);
                Ok(next_sighash)
            }
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_signature(
                    if privk.compress_public() {
                        TransactionPublicKeyEncoding::Compressed
                    } else {
                        TransactionPublicKeyEncoding::Uncompressed
                    },
                    next_sig,
                );
                Ok(next_sighash)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                cond.push_signature(
                    if privk.compress_public() {
                        TransactionPublicKeyEncoding::Compressed
                    } else {
                        TransactionPublicKeyEncoding::Uncompressed
                    },
                    next_sig,
                );
                Ok(*cur_sighash)
            }
        }
    }

    /// Pop the last auth field
    fn pop_auth_field(
        condition: &mut TransactionSpendingCondition,
    ) -> Option<TransactionAuthField> {
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => cond.pop_auth_field(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                cond.pop_auth_field()
            }
            TransactionSpendingCondition::Singlesig(ref mut cond) => cond.pop_signature(),
        }
    }

    /// Append a public key to a multisig condition
    fn append_pubkey(
        condition: &mut TransactionSpendingCondition,
        pubkey: &StacksPublicKey,
    ) -> Result<(), net_error> {
        match condition {
            TransactionSpendingCondition::Multisig(ref mut cond) => {
                cond.push_public_key(pubkey.clone());
                Ok(())
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                cond.push_public_key(pubkey.clone());
                Ok(())
            }
            _ => Err(net_error::SigningError(
                "Not a multisig condition".to_string(),
            )),
        }
    }

    /// Append the next signature from the origin account authorization.
    /// Return the next sighash.
    pub fn sign_next_origin(
        &mut self,
        cur_sighash: &Txid,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, net_error> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(ref mut origin_condition)
            | TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::sign_and_append(
                    origin_condition,
                    cur_sighash,
                    &TransactionAuthFlags::AuthStandard,
                    privk,
                )?
            }
        };
        Ok(next_sighash)
    }

    /// Append the next public key to the origin account authorization.
    pub fn append_next_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        match self.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            }
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::append_pubkey(origin_condition, pubk)
            }
        }
    }

    /// Append the next signature from the sponsoring account.
    /// Return the next sighash
    pub fn sign_next_sponsor(
        &mut self,
        cur_sighash: &Txid,
        privk: &StacksPrivateKey,
    ) -> Result<Txid, net_error> {
        let next_sighash = match self.auth {
            TransactionAuth::Standard(_) => {
                // invalid
                return Err(net_error::SigningError(
                    "Cannot sign standard authorization with a sponsoring private key".to_string(),
                ));
            }
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::sign_and_append(
                    sponsor_condition,
                    cur_sighash,
                    &TransactionAuthFlags::AuthSponsored,
                    privk,
                )?
            }
        };
        Ok(next_sighash)
    }

    /// Append the next public key to the sponsor account authorization.
    pub fn append_next_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        match self.auth {
            TransactionAuth::Standard(_) => Err(net_error::SigningError(
                "Cannot appned a public key to the sponsor of a standard auth condition"
                    .to_string(),
            )),
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::append_pubkey(sponsor_condition, pubk)
            }
        }
    }

    /// Verify this transaction's signatures
    pub fn verify(&self) -> Result<(), net_error> {
        self.auth.verify(&self.verify_begin())
    }

    /// Verify the transaction's origin signatures only.
    /// Used by sponsors to get the next sig-hash to sign.
    pub fn verify_origin(&self) -> Result<Txid, net_error> {
        self.auth.verify_origin(&self.verify_begin())
    }

    /// Get the origin account's address
    pub fn origin_address(&self) -> StacksAddress {
        match (&self.version, &self.auth) {
            (TransactionVersion::Mainnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_mainnet()
            }
            (TransactionVersion::Testnet, TransactionAuth::Standard(origin_condition)) => {
                origin_condition.address_testnet()
            }
            (
                TransactionVersion::Mainnet,
                TransactionAuth::Sponsored(origin_condition, _unused),
            ) => origin_condition.address_mainnet(),
            (
                TransactionVersion::Testnet,
                TransactionAuth::Sponsored(origin_condition, _unused),
            ) => origin_condition.address_testnet(),
        }
    }

    /// Get the sponsor account's address, if this transaction is sponsored
    pub fn sponsor_address(&self) -> Option<StacksAddress> {
        match (&self.version, &self.auth) {
            (TransactionVersion::Mainnet, TransactionAuth::Standard(_unused)) => None,
            (TransactionVersion::Testnet, TransactionAuth::Standard(_unused)) => None,
            (
                TransactionVersion::Mainnet,
                TransactionAuth::Sponsored(_unused, sponsor_condition),
            ) => Some(sponsor_condition.address_mainnet()),
            (
                TransactionVersion::Testnet,
                TransactionAuth::Sponsored(_unused, sponsor_condition),
            ) => Some(sponsor_condition.address_testnet()),
        }
    }

    /// Get a copy of the origin spending condition
    pub fn get_origin(&self) -> TransactionSpendingCondition {
        self.auth.origin().clone()
    }

    /// Get a copy of the sending condition that will pay the tx fee
    pub fn get_payer(&self) -> TransactionSpendingCondition {
        match self.auth.sponsor() {
            Some(ref tsc) => (*tsc).clone(),
            None => self.auth.origin().clone(),
        }
    }

    /// Is this a mainnet transaction?  false means 'testnet'
    pub fn is_mainnet(&self) -> bool {
        match self.version {
            TransactionVersion::Mainnet => true,
            _ => false,
        }
    }

    /// Is this a phantom transaction?
    pub fn is_phantom(&self) -> bool {
        let boot_address = boot_code_addr(self.is_mainnet()).into();
        if let TransactionPayload::TokenTransfer(address, amount, _) = &self.payload {
            *address == boot_address && *amount == 0
        } else {
            false
        }
    }
}

impl StacksTransactionSigner {
    pub fn new(tx: &StacksTransaction) -> StacksTransactionSigner {
        StacksTransactionSigner {
            tx: tx.clone(),
            sighash: tx.sign_begin(),
            origin_done: false,
            check_oversign: true,
            check_overlap: true,
        }
    }

    pub fn new_sponsor(
        tx: &StacksTransaction,
        spending_condition: TransactionSpendingCondition,
    ) -> Result<StacksTransactionSigner, Error> {
        if !tx.auth.is_sponsored() {
            return Err(Error::IncompatibleSpendingConditionError);
        }
        let mut new_tx = tx.clone();
        new_tx.auth.set_sponsor(spending_condition)?;
        let origin_sighash = new_tx.verify_origin().map_err(Error::NetError)?;

        Ok(StacksTransactionSigner {
            tx: new_tx,
            sighash: origin_sighash,
            origin_done: true,
            check_oversign: true,
            check_overlap: true,
        })
    }

    pub fn resume(&mut self, tx: &StacksTransaction) {
        self.tx = tx.clone()
    }

    pub fn disable_checks(&mut self) {
        self.check_oversign = false;
        self.check_overlap = false;
    }

    pub fn sign_origin(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't sign another origin private key since we started signing sponsors
            return Err(net_error::SigningError(
                "Cannot sign origin after sponsor key".to_string(),
            ));
        }

        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                if self.check_oversign
                    && origin_condition.num_signatures() >= origin_condition.signatures_required()
                {
                    return Err(net_error::SigningError(
                        "Origin would have too many signatures".to_string(),
                    ));
                }
            }
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                if self.check_oversign
                    && origin_condition.num_signatures() >= origin_condition.signatures_required()
                {
                    return Err(net_error::SigningError(
                        "Origin would have too many signatures".to_string(),
                    ));
                }
            }
        }

        let next_sighash = self.tx.sign_next_origin(&self.sighash, privk)?;
        self.sighash = next_sighash;
        Ok(())
    }

    pub fn append_origin(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        if self.check_overlap && self.origin_done {
            // can't append another origin key
            return Err(net_error::SigningError(
                "Cannot append public key to origin after sponsor key".to_string(),
            ));
        }

        self.tx.append_next_origin(pubk)
    }

    pub fn sign_sponsor(&mut self, privk: &StacksPrivateKey) -> Result<(), net_error> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref sponsor_condition) => {
                if self.check_oversign
                    && sponsor_condition.num_signatures() >= sponsor_condition.signatures_required()
                {
                    return Err(net_error::SigningError(
                        "Sponsor would have too many signatures".to_string(),
                    ));
                }
            }
            _ => {}
        }

        let next_sighash = self.tx.sign_next_sponsor(&self.sighash, privk)?;
        self.sighash = next_sighash;
        self.origin_done = true;
        Ok(())
    }

    pub fn append_sponsor(&mut self, pubk: &StacksPublicKey) -> Result<(), net_error> {
        self.tx.append_next_sponsor(pubk)
    }

    pub fn pop_origin_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Standard(ref mut origin_condition) => {
                StacksTransaction::pop_auth_field(origin_condition)
            }
            TransactionAuth::Sponsored(ref mut origin_condition, _) => {
                StacksTransaction::pop_auth_field(origin_condition)
            }
        }
    }

    pub fn pop_sponsor_auth_field(&mut self) -> Option<TransactionAuthField> {
        match self.tx.auth {
            TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                StacksTransaction::pop_auth_field(sponsor_condition)
            }
            _ => None,
        }
    }

    pub fn complete(&self) -> bool {
        match self.tx.auth {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsored_condition) => {
                origin_condition.num_signatures() >= origin_condition.signatures_required()
                    && sponsored_condition.num_signatures()
                        >= sponsored_condition.signatures_required()
                    && (self.origin_done || !self.check_overlap)
            }
        }
    }

    pub fn get_tx_incomplete(&self) -> StacksTransaction {
        self.tx.clone()
    }

    pub fn get_tx(&self) -> Option<StacksTransaction> {
        if self.complete() {
            Some(self.tx.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use clarity::vm::representations::{ClarityName, ContractName};
    use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
    use stacks_common::util::hash::*;
    use stacks_common::util::log;
    use stacks_common::util::retry::{BoundReader, LogReader};

    use super::*;
    use crate::chainstate::stacks::test::codec_all_transactions;
    use crate::chainstate::stacks::{
        StacksPublicKey as PubKey, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, *,
    };
    use crate::net::codec::test::check_codec_and_corruption;
    use crate::net::codec::*;
    use crate::net::*;

    impl StacksTransaction {
        /// Sign a sighash without appending the signature and public key
        /// to the given spending condition.
        /// Returns the resulting signature
        fn sign_no_append_origin(
            &self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, net_error> {
            let next_sig = match self.auth {
                TransactionAuth::Standard(ref origin_condition)
                | TransactionAuth::Sponsored(ref origin_condition, _) => {
                    let (next_sig, _next_sighash) = TransactionSpendingCondition::next_signature(
                        cur_sighash,
                        &TransactionAuthFlags::AuthStandard,
                        origin_condition.tx_fee(),
                        origin_condition.nonce(),
                        privk,
                    )?;
                    next_sig
                }
            };
            Ok(next_sig)
        }

        /// Appends a signature and public key to the spending condition.
        fn append_origin_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        ) -> Result<(), net_error> {
            match self.auth {
                TransactionAuth::Standard(ref mut origin_condition)
                | TransactionAuth::Sponsored(ref mut origin_condition, _) => match origin_condition
                {
                    TransactionSpendingCondition::Singlesig(ref mut cond) => {
                        cond.set_signature(signature);
                    }
                    TransactionSpendingCondition::Multisig(ref mut cond) => {
                        cond.push_signature(key_encoding, signature);
                    }
                    TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                        cond.push_signature(key_encoding, signature);
                    }
                },
            };
            Ok(())
        }

        /// Sign a sighash as a sponsor without appending the signature and public key
        /// to the given spending condition.
        /// Returns the resulting signature
        fn sign_no_append_sponsor(
            &mut self,
            cur_sighash: &Txid,
            privk: &StacksPrivateKey,
        ) -> Result<MessageSignature, net_error> {
            let next_sig = match self.auth {
                TransactionAuth::Standard(_) => {
                    return Err(net_error::SigningError(
                        "Cannot sign standard authorization with a sponsoring private key"
                            .to_string(),
                    ));
                }
                TransactionAuth::Sponsored(_, ref mut sponsor_condition) => {
                    let (next_sig, _next_sighash) = TransactionSpendingCondition::next_signature(
                        cur_sighash,
                        &TransactionAuthFlags::AuthSponsored,
                        sponsor_condition.tx_fee(),
                        sponsor_condition.nonce(),
                        privk,
                    )?;
                    next_sig
                }
            };
            Ok(next_sig)
        }

        /// Appends a sponsor signature and public key to the spending condition.
        pub fn append_sponsor_signature(
            &mut self,
            signature: MessageSignature,
            key_encoding: TransactionPublicKeyEncoding,
        ) -> Result<(), net_error> {
            match self.auth {
                TransactionAuth::Standard(_) => Err(net_error::SigningError(
                    "Cannot appned a public key to the sponsor of a standard auth condition"
                        .to_string(),
                )),
                TransactionAuth::Sponsored(_, ref mut sponsor_condition) => match sponsor_condition
                {
                    TransactionSpendingCondition::Singlesig(ref mut cond) => {
                        Ok(cond.set_signature(signature))
                    }
                    TransactionSpendingCondition::Multisig(ref mut cond) => {
                        Ok(cond.push_signature(key_encoding, signature))
                    }
                    TransactionSpendingCondition::OrderIndependentMultisig(ref mut cond) => {
                        Ok(cond.push_signature(key_encoding, signature))
                    }
                },
            }
        }
    }

    fn corrupt_auth_field(
        corrupt_auth_fields: &TransactionAuth,
        i: usize,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let mut new_corrupt_auth_fields = corrupt_auth_fields.clone();
        match new_corrupt_auth_fields {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(_) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(_) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsor_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            let mut sig_bytes = data.signature.as_bytes().to_vec();
                            sig_bytes[1] ^= 1u8; // this breaks the `r` parameter
                            data.signature = MessageSignature::from_raw(&sig_bytes);
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                },
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            let corrupt_field = match data.fields[i] {
                                TransactionAuthField::PublicKey(ref pubkey) => {
                                    TransactionAuthField::PublicKey(StacksPublicKey::from_hex("0270790e675116a63a75008832d82ad93e4332882ab0797b0f156de9d739160a0b").unwrap())
                                }
                                TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                                    let mut sig_bytes = sig.as_bytes().to_vec();
                                    sig_bytes[1] ^= 1u8;    // this breaks the `r` paramter
                                    let corrupt_sig = MessageSignature::from_raw(&sig_bytes);
                                    TransactionAuthField::Signature(*key_encoding, corrupt_sig)
                                }
                            };
                            data.fields[i] = corrupt_field
                        }
                    }
                }
            }
        };
        new_corrupt_auth_fields
    }

    fn find_signature(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::Signature(..)) {
                        j = f;
                        break;
                    };
                }
                j
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::Signature(..)) {
                        j = f;
                        break;
                    };
                }
                j
            }
        }
    }

    fn find_public_key(spend: &TransactionSpendingCondition) -> usize {
        match spend {
            TransactionSpendingCondition::Singlesig(_) => 0,
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::PublicKey(_)) {
                        j = f;
                        break;
                    };
                }
                j
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut j = 0;
                for f in 0..data.fields.len() {
                    if matches!(data.fields[f], TransactionAuthField::PublicKey(_)) {
                        j = f;
                        break;
                    };
                }
                j
            }
        }
    }

    fn corrupt_auth_field_signature(
        corrupt_auth_fields: &TransactionAuth,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_signature(spend)
                } else {
                    0
                }
            }
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_signature(sponsor_spend)
                } else if corrupt_origin {
                    find_signature(origin_spend)
                } else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    fn corrupt_auth_field_public_key(
        corrupt_auth_fields: &TransactionAuth,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) -> TransactionAuth {
        let i = match corrupt_auth_fields {
            TransactionAuth::Standard(ref spend) => {
                if corrupt_origin {
                    find_public_key(spend)
                } else {
                    0
                }
            }
            TransactionAuth::Sponsored(ref origin_spend, ref sponsor_spend) => {
                if corrupt_sponsor {
                    find_public_key(sponsor_spend)
                } else if corrupt_origin {
                    find_public_key(origin_spend)
                } else {
                    0
                }
            }
        };
        corrupt_auth_field(corrupt_auth_fields, i, corrupt_origin, corrupt_sponsor)
    }

    // verify that we can verify signatures over a transaction.
    // also verify that we can corrupt any field and fail to verify the transaction.
    // corruption tests should obviously fail -- the initial sighash changes if any of the
    // serialized data changes.
    fn test_signature_and_corruption(
        signed_tx: &StacksTransaction,
        corrupt_origin: bool,
        corrupt_sponsor: bool,
    ) {
        // signature is well-formed otherwise
        signed_tx.verify().unwrap();

        // mess with the auth hash code
        let mut corrupt_tx_hash_mode = signed_tx.clone();
        let mut corrupt_auth_hash_mode = corrupt_tx_hash_mode.auth().clone();
        match corrupt_auth_hash_mode {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == SinglesigHashMode::P2PKH {
                                SinglesigHashMode::P2WPKH
                            } else {
                                SinglesigHashMode::P2PKH
                            };
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.hash_mode = if data.hash_mode == MultisigHashMode::P2SH {
                                MultisigHashMode::P2WSH
                            } else {
                                MultisigHashMode::P2SH
                            };
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.hash_mode =
                                if data.hash_mode == OrderIndependentMultisigHashMode::P2SH {
                                    OrderIndependentMultisigHashMode::P2WSH
                                } else {
                                    OrderIndependentMultisigHashMode::P2SH
                                };
                        }
                    }
                }
            }
        };
        corrupt_tx_hash_mode.auth = corrupt_auth_hash_mode;
        assert!(corrupt_tx_hash_mode.txid() != signed_tx.txid());

        // mess with the auth nonce
        let mut corrupt_tx_nonce = signed_tx.clone();
        let mut corrupt_auth_nonce = corrupt_tx_nonce.auth().clone();
        match corrupt_auth_nonce {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    };
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            data.nonce += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            data.nonce += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_nonce.auth = corrupt_auth_nonce;
        assert!(corrupt_tx_nonce.txid() != signed_tx.txid());

        // corrupt a signature
        let mut corrupt_tx_signature = signed_tx.clone();
        let corrupt_auth_signature = corrupt_tx_signature.auth.clone();
        corrupt_tx_signature.auth =
            corrupt_auth_field_signature(&corrupt_auth_signature, corrupt_origin, corrupt_sponsor);

        assert!(corrupt_tx_signature.txid() != signed_tx.txid());

        // corrupt a public key
        let mut corrupt_tx_public_key = signed_tx.clone();
        let corrupt_auth_public_key = corrupt_tx_public_key.auth.clone();
        corrupt_tx_public_key.auth = corrupt_auth_field_public_key(
            &corrupt_auth_public_key,
            corrupt_origin,
            corrupt_sponsor,
        );

        assert!(corrupt_tx_public_key.txid() != signed_tx.txid());

        // mess with the auth num-signatures required, if applicable
        let mut corrupt_tx_signatures_required = signed_tx.clone();
        let mut corrupt_auth_signatures_required = corrupt_tx_signatures_required.auth().clone();
        let mut is_multisig_origin = false;
        let mut is_multisig_sponsor = false;
        match corrupt_auth_signatures_required {
            TransactionAuth::Standard(ref mut origin_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    };
                }
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsored_condition) => {
                if corrupt_origin {
                    match origin_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_origin = true;
                            data.signatures_required += 1;
                        }
                    }
                }
                if corrupt_sponsor {
                    match sponsored_condition {
                        TransactionSpendingCondition::Singlesig(ref mut data) => {}
                        TransactionSpendingCondition::Multisig(ref mut data) => {
                            is_multisig_sponsor = true;
                            data.signatures_required += 1;
                        }
                        TransactionSpendingCondition::OrderIndependentMultisig(ref mut data) => {
                            is_multisig_sponsor = true;
                            data.signatures_required += 1;
                        }
                    }
                }
            }
        };
        corrupt_tx_signatures_required.auth = corrupt_auth_signatures_required;
        if is_multisig_origin || is_multisig_sponsor {
            assert!(corrupt_tx_signatures_required.txid() != signed_tx.txid());
        }

        // mess with transaction version
        let mut corrupt_tx_version = signed_tx.clone();
        corrupt_tx_version.version = if corrupt_tx_version.version == TransactionVersion::Mainnet {
            TransactionVersion::Testnet
        } else {
            TransactionVersion::Mainnet
        };

        assert!(corrupt_tx_version.txid() != signed_tx.txid());

        // mess with chain ID
        let mut corrupt_tx_chain_id = signed_tx.clone();
        corrupt_tx_chain_id.chain_id = signed_tx.chain_id + 1;
        assert!(corrupt_tx_chain_id.txid() != signed_tx.txid());

        // mess with transaction fee
        let mut corrupt_tx_fee = signed_tx.clone();
        corrupt_tx_fee.set_tx_fee(corrupt_tx_fee.get_tx_fee() + 1);
        assert!(corrupt_tx_fee.txid() != signed_tx.txid());

        // mess with anchor mode
        let mut corrupt_tx_anchor_mode = signed_tx.clone();
        corrupt_tx_anchor_mode.anchor_mode =
            if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OffChainOnly {
                TransactionAnchorMode::OnChainOnly
            } else if corrupt_tx_anchor_mode.anchor_mode == TransactionAnchorMode::OnChainOnly {
                TransactionAnchorMode::Any
            } else {
                TransactionAnchorMode::OffChainOnly
            };

        assert!(corrupt_tx_anchor_mode.txid() != signed_tx.txid());

        // mess with post conditions
        let mut corrupt_tx_post_conditions = signed_tx.clone();
        corrupt_tx_post_conditions
            .post_conditions
            .push(TransactionPostCondition::STX(
                PostConditionPrincipal::Origin,
                FungibleConditionCode::SentGt,
                0,
            ));

        let mut corrupt_tx_post_condition_mode = signed_tx.clone();
        corrupt_tx_post_condition_mode.post_condition_mode = if corrupt_tx_post_condition_mode
            .post_condition_mode
            == TransactionPostConditionMode::Allow
        {
            TransactionPostConditionMode::Deny
        } else {
            TransactionPostConditionMode::Allow
        };

        // mess with payload
        let mut corrupt_tx_payload = signed_tx.clone();
        corrupt_tx_payload.payload = match corrupt_tx_payload.payload {
            TransactionPayload::TokenTransfer(ref addr, ref amount, ref memo) => {
                TransactionPayload::TokenTransfer(addr.clone(), amount + 1, memo.clone())
            }
            TransactionPayload::ContractCall(_) => TransactionPayload::SmartContract(
                TransactionSmartContract {
                    name: ContractName::try_from("corrupt-name").unwrap(),
                    code_body: StacksString::from_str("corrupt body").unwrap(),
                },
                None,
            ),
            TransactionPayload::SmartContract(..) => {
                TransactionPayload::ContractCall(TransactionContractCall {
                    address: StacksAddress {
                        version: 1,
                        bytes: Hash160([0xff; 20]),
                    },
                    contract_name: ContractName::try_from("hello-world").unwrap(),
                    function_name: ClarityName::try_from("hello-function").unwrap(),
                    function_args: vec![Value::Int(0)],
                })
            }
            TransactionPayload::PoisonMicroblock(ref h1, ref h2) => {
                let mut corrupt_h1 = h1.clone();
                let mut corrupt_h2 = h2.clone();

                corrupt_h1.sequence += 1;
                corrupt_h2.sequence += 1;
                TransactionPayload::PoisonMicroblock(corrupt_h1, corrupt_h2)
            }
            TransactionPayload::Coinbase(ref buf, ref recipient_opt, ref vrf_proof_opt) => {
                let mut corrupt_buf_bytes = buf.as_bytes().clone();
                corrupt_buf_bytes[0] = (((corrupt_buf_bytes[0] as u16) + 1) % 256) as u8;

                let corrupt_buf = CoinbasePayload(corrupt_buf_bytes);
                TransactionPayload::Coinbase(
                    corrupt_buf,
                    recipient_opt.clone(),
                    vrf_proof_opt.clone(),
                )
            }
            TransactionPayload::TenureChange(ref tc) => {
                let mut hash = tc.pubkey_hash.as_bytes().clone();
                hash[8] ^= 0x04; // Flip one bit
                let corrupt_tc = TenureChangePayload {
                    pubkey_hash: hash.into(),
                    ..tc.clone()
                };
                TransactionPayload::TenureChange(corrupt_tc)
            }
        };
        assert!(corrupt_tx_payload.txid() != signed_tx.txid());

        let mut corrupt_transactions = vec![
            corrupt_tx_hash_mode,
            corrupt_tx_nonce,
            corrupt_tx_signature.clone(), // needed below
            corrupt_tx_public_key,
            corrupt_tx_version,
            corrupt_tx_chain_id,
            corrupt_tx_fee,
            corrupt_tx_anchor_mode,
            corrupt_tx_post_condition_mode,
            corrupt_tx_post_conditions,
            corrupt_tx_payload,
        ];
        if is_multisig_origin || is_multisig_sponsor {
            corrupt_transactions.push(corrupt_tx_signatures_required.clone());
        }

        // make sure all corrupted transactions fail
        for corrupt_tx in corrupt_transactions.iter() {
            match corrupt_tx.verify() {
                Ok(_) => {
                    eprintln!("{:?}", &corrupt_tx);
                    assert!(false);
                }
                Err(e) => match e {
                    net_error::VerifyingError(msg) => {}
                    _ => assert!(false),
                },
            }
        }

        // exhaustive test -- mutate each byte
        let mut tx_bytes: Vec<u8> = vec![];
        signed_tx.consensus_serialize(&mut tx_bytes).unwrap();
        test_debug!("mutate tx: {}", to_hex(&tx_bytes));
        for i in 0..tx_bytes.len() {
            let next_byte = tx_bytes[i] as u16;
            tx_bytes[i] = ((next_byte + 1) % 0xff) as u8;

            // test_debug!("mutate byte {}", &i);
            let mut cursor = io::Cursor::new(&tx_bytes);
            let mut reader = LogReader::from_reader(&mut cursor);
            match StacksTransaction::consensus_deserialize(&mut reader) {
                Ok(corrupt_tx) => {
                    let mut corrupt_tx_bytes = vec![];
                    corrupt_tx
                        .consensus_serialize(&mut corrupt_tx_bytes)
                        .unwrap();
                    if corrupt_tx_bytes.len() < tx_bytes.len() {
                        // didn't parse fully; the block-parsing logic would reject this block.
                        tx_bytes[i] = next_byte as u8;
                        continue;
                    }
                    if corrupt_tx.verify().is_ok() && corrupt_tx != *signed_tx {
                        eprintln!("corrupt tx: {:#?}", &corrupt_tx);
                        eprintln!("signed tx:  {:#?}", &signed_tx);
                        assert!(false);
                    }
                }
                Err(_) => {}
            }
            // restore
            tx_bytes[i] = next_byte as u8;
        }
    }

    #[test]
    fn tx_stacks_transaction_payload_tokens() {
        let addr = PrincipalData::from(StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        });

        let tt_stx =
            TransactionPayload::TokenTransfer(addr.clone(), 123, TokenTransferMemo([1u8; 34]));

        // wire encodings of the same
        let mut tt_stx_bytes = vec![];
        tt_stx_bytes.push(TransactionPayloadID::TokenTransfer as u8);
        addr.consensus_serialize(&mut tt_stx_bytes).unwrap();
        tt_stx_bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123]);
        tt_stx_bytes.append(&mut vec![1u8; 34]);

        check_codec_and_corruption::<TransactionPayload>(&tt_stx, &tt_stx_bytes);

        let addr = PrincipalData::from(QualifiedContractIdentifier {
            issuer: StacksAddress {
                version: 1,
                bytes: Hash160([0xff; 20]),
            }
            .into(),
            name: "foo-contract".into(),
        });

        let tt_stx =
            TransactionPayload::TokenTransfer(addr.clone(), 123, TokenTransferMemo([1u8; 34]));

        // wire encodings of the same
        let mut tt_stx_bytes = vec![];
        tt_stx_bytes.push(TransactionPayloadID::TokenTransfer as u8);
        addr.consensus_serialize(&mut tt_stx_bytes).unwrap();
        tt_stx_bytes.append(&mut vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 123]);
        tt_stx_bytes.append(&mut vec![1u8; 34]);

        check_codec_and_corruption::<TransactionPayload>(&tt_stx, &tt_stx_bytes);
    }

    #[test]
    fn tx_stacks_transaction_payload_contracts() {
        let hello_contract_call = "hello-contract-call";
        let hello_contract_name = "hello-contract-name";
        let hello_function_name = "hello-function-name";
        let hello_contract_body = "hello contract code body";

        let contract_call = TransactionContractCall {
            address: StacksAddress {
                version: 1,
                bytes: Hash160([0xff; 20]),
            },
            contract_name: ContractName::try_from(hello_contract_name).unwrap(),
            function_name: ClarityName::try_from(hello_function_name).unwrap(),
            function_args: vec![Value::Int(0)],
        };

        let smart_contract = TransactionSmartContract {
            name: ContractName::try_from(hello_contract_name).unwrap(),
            code_body: StacksString::from_str(hello_contract_body).unwrap(),
        };

        let mut contract_call_bytes = vec![];
        contract_call
            .address
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .contract_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .function_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .function_args
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();

        let mut smart_contract_bytes = vec![];
        smart_contract
            .name
            .consensus_serialize(&mut smart_contract_bytes)
            .unwrap();
        smart_contract
            .code_body
            .consensus_serialize(&mut smart_contract_bytes)
            .unwrap();

        let mut version_1_smart_contract_bytes = vec![];
        ClarityVersion_consensus_serialize(
            &ClarityVersion::Clarity1,
            &mut version_1_smart_contract_bytes,
        )
        .unwrap();
        smart_contract
            .name
            .consensus_serialize(&mut version_1_smart_contract_bytes)
            .unwrap();
        smart_contract
            .code_body
            .consensus_serialize(&mut version_1_smart_contract_bytes)
            .unwrap();

        let mut version_2_smart_contract_bytes = vec![];
        ClarityVersion_consensus_serialize(
            &ClarityVersion::Clarity2,
            &mut version_2_smart_contract_bytes,
        )
        .unwrap();
        smart_contract
            .name
            .consensus_serialize(&mut version_2_smart_contract_bytes)
            .unwrap();
        smart_contract
            .code_body
            .consensus_serialize(&mut version_2_smart_contract_bytes)
            .unwrap();

        let mut transaction_contract_call = vec![TransactionPayloadID::ContractCall as u8];
        transaction_contract_call.append(&mut contract_call_bytes.clone());

        let mut transaction_smart_contract = vec![TransactionPayloadID::SmartContract as u8];
        transaction_smart_contract.append(&mut smart_contract_bytes.clone());

        let mut v1_smart_contract = vec![TransactionPayloadID::VersionedSmartContract as u8];
        v1_smart_contract.append(&mut version_1_smart_contract_bytes.clone());

        let mut v2_smart_contract = vec![TransactionPayloadID::VersionedSmartContract as u8];
        v2_smart_contract.append(&mut version_2_smart_contract_bytes.clone());

        check_codec_and_corruption::<TransactionContractCall>(&contract_call, &contract_call_bytes);
        check_codec_and_corruption::<TransactionSmartContract>(
            &smart_contract,
            &smart_contract_bytes,
        );
        check_codec_and_corruption::<TransactionPayload>(
            &TransactionPayload::ContractCall(contract_call.clone()),
            &transaction_contract_call,
        );
        check_codec_and_corruption::<TransactionPayload>(
            &TransactionPayload::SmartContract(smart_contract.clone(), None),
            &transaction_smart_contract,
        );
        check_codec_and_corruption::<TransactionPayload>(
            &TransactionPayload::SmartContract(
                smart_contract.clone(),
                Some(ClarityVersion::Clarity1),
            ),
            &v1_smart_contract,
        );
        check_codec_and_corruption::<TransactionPayload>(
            &TransactionPayload::SmartContract(
                smart_contract.clone(),
                Some(ClarityVersion::Clarity2),
            ),
            &v2_smart_contract,
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_coinbase() {
        let coinbase_payload =
            TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, None);
        let coinbase_payload_bytes = vec![
            // payload type ID
            TransactionPayloadID::Coinbase as u8,
            // buffer
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
        ];

        check_codec_and_corruption::<TransactionPayload>(
            &coinbase_payload,
            &coinbase_payload_bytes,
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_nakamoto_coinbase() {
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        let coinbase_payload =
            TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof));
        let coinbase_bytes = vec![
            // payload type ID
            TransactionPayloadID::NakamotoCoinbase as u8,
            // buffer
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            // no alt recipient, so Value::none
            0x09,
            // proof bytes
            0x92,
            0x75,
            0xdf,
            0x67,
            0xa6,
            0x8c,
            0x87,
            0x45,
            0xc0,
            0xff,
            0x97,
            0xb4,
            0x82,
            0x01,
            0xee,
            0x6d,
            0xb4,
            0x47,
            0xf7,
            0xc9,
            0x3b,
            0x23,
            0xae,
            0x24,
            0xcd,
            0xc2,
            0x40,
            0x0f,
            0x52,
            0xfd,
            0xb0,
            0x8a,
            0x1a,
            0x6a,
            0xc7,
            0xec,
            0x71,
            0xbf,
            0x9c,
            0x9c,
            0x76,
            0xe9,
            0x6e,
            0xe4,
            0x67,
            0x5e,
            0xbf,
            0xf6,
            0x06,
            0x25,
            0xaf,
            0x28,
            0x71,
            0x85,
            0x01,
            0x04,
            0x7b,
            0xfd,
            0x87,
            0xb8,
            0x10,
            0xc2,
            0xd2,
            0x13,
            0x9b,
            0x73,
            0xc2,
            0x3b,
            0xd6,
            0x9d,
            0xe6,
            0x63,
            0x60,
            0x95,
            0x3a,
            0x64,
            0x2c,
            0x2a,
            0x33,
            0x0a,
        ];

        check_codec_and_corruption(&coinbase_payload, &coinbase_bytes);
    }

    #[test]
    fn tx_stacks_transaction_payload_nakamoto_coinbase_alt_recipient() {
        let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
        let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

        let recipient = PrincipalData::from(QualifiedContractIdentifier {
            issuer: StacksAddress {
                version: 1,
                bytes: Hash160([0xff; 20]),
            }
            .into(),
            name: "foo-contract".into(),
        });

        let coinbase_payload =
            TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), Some(recipient), Some(proof));
        let coinbase_bytes = vec![
            // payload type ID
            TransactionPayloadID::NakamotoCoinbase as u8,
            // buffer
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            0x12,
            // have contract recipient, so Some(..)
            0x0a,
            // contract address type
            0x06,
            // address
            0x01,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            // name length
            0x0c,
            // name ('foo-contract')
            0x66,
            0x6f,
            0x6f,
            0x2d,
            0x63,
            0x6f,
            0x6e,
            0x74,
            0x72,
            0x61,
            0x63,
            0x74,
            // proof bytes
            0x92,
            0x75,
            0xdf,
            0x67,
            0xa6,
            0x8c,
            0x87,
            0x45,
            0xc0,
            0xff,
            0x97,
            0xb4,
            0x82,
            0x01,
            0xee,
            0x6d,
            0xb4,
            0x47,
            0xf7,
            0xc9,
            0x3b,
            0x23,
            0xae,
            0x24,
            0xcd,
            0xc2,
            0x40,
            0x0f,
            0x52,
            0xfd,
            0xb0,
            0x8a,
            0x1a,
            0x6a,
            0xc7,
            0xec,
            0x71,
            0xbf,
            0x9c,
            0x9c,
            0x76,
            0xe9,
            0x6e,
            0xe4,
            0x67,
            0x5e,
            0xbf,
            0xf6,
            0x06,
            0x25,
            0xaf,
            0x28,
            0x71,
            0x85,
            0x01,
            0x04,
            0x7b,
            0xfd,
            0x87,
            0xb8,
            0x10,
            0xc2,
            0xd2,
            0x13,
            0x9b,
            0x73,
            0xc2,
            0x3b,
            0xd6,
            0x9d,
            0xe6,
            0x63,
            0x60,
            0x95,
            0x3a,
            0x64,
            0x2c,
            0x2a,
            0x33,
            0x0a,
        ];

        check_codec_and_corruption(&coinbase_payload, &coinbase_bytes);
    }

    #[test]
    fn tx_stacks_transaction_payload_microblock_poison() {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };

        let header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };

        let payload = TransactionPayload::PoisonMicroblock(header_1, header_2);

        let payload_bytes = vec![
            // payload type ID
            TransactionPayloadID::PoisonMicroblock as u8,
            // header_1
            // version
            0x12,
            // sequence
            0x00,
            0x34,
            // prev block
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            // signature
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // header_2
            // version
            0x12,
            // sequence
            0x00,
            0x34,
            // prev block
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // signature
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
        ];

        check_codec_and_corruption::<TransactionPayload>(&payload, &payload_bytes);

        let payload_bytes_bad_parent = vec![
            // payload type ID
            TransactionPayloadID::PoisonMicroblock as u8,
            // header_1
            // version
            0x12,
            // sequence
            0x00,
            0x35,
            // prev block
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            0x01,
            // signature
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // header_2
            // version
            0x12,
            // sequence
            0x00,
            0x34,
            // prev block
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // signature
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
            0x03,
        ];

        assert!(
            TransactionPayload::consensus_deserialize(&mut &payload_bytes_bad_parent[..])
                .unwrap_err()
                .to_string()
                .find("microblock headers do not identify a fork")
                .is_some()
        );

        let payload_bytes_equal = vec![
            // payload type ID
            TransactionPayloadID::PoisonMicroblock as u8,
            // header_1
            // version
            0x12,
            // sequence
            0x00,
            0x34,
            // prev block
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // signature
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // header_2
            // version
            0x12,
            // sequence
            0x00,
            0x34,
            // prev block
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // tx merkle root
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            // signature
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
            0x02,
        ];

        assert!(
            TransactionPayload::consensus_deserialize(&mut &payload_bytes_equal[..])
                .unwrap_err()
                .to_string()
                .find("microblock headers match")
                .is_some()
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid() {
        let hello_contract_call = "hello-contract-call";
        let hello_contract_name = "hello-contract-name";
        let hello_function_name = "hello-function-name";

        let contract_call = TransactionContractCall {
            address: StacksAddress {
                version: 1,
                bytes: Hash160([0xff; 20]),
            },
            contract_name: ContractName::try_from(hello_contract_name).unwrap(),
            function_name: ClarityName::try_from(hello_function_name).unwrap(),
            function_args: vec![Value::Int(0)],
        };

        let mut contract_call_bytes = vec![];
        contract_call
            .address
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .contract_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .function_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call
            .function_args
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();

        let mut transaction_contract_call = vec![0xff];
        transaction_contract_call.append(&mut contract_call_bytes.clone());

        assert!(
            TransactionPayload::consensus_deserialize(&mut &transaction_contract_call[..])
                .unwrap_err()
                .to_string()
                .find("unknown payload ID")
                .is_some()
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid_contract_name() {
        // test invalid contract name
        let address = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let contract_name = "hello\x00contract-name";
        let function_name = ClarityName::try_from("hello-function-name").unwrap();
        let function_args = vec![Value::Int(0)];

        let mut contract_name_bytes = vec![contract_name.len() as u8];
        contract_name_bytes.extend_from_slice(contract_name.as_bytes());

        let mut contract_call_bytes = vec![];
        address
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call_bytes.push(contract_name.len() as u8);
        contract_call_bytes.extend_from_slice(contract_name.as_bytes());
        function_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        function_args
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();

        let mut transaction_contract_call = vec![TransactionPayloadID::ContractCall as u8];
        transaction_contract_call.append(&mut contract_call_bytes);

        assert!(
            TransactionPayload::consensus_deserialize(&mut &transaction_contract_call[..])
                .unwrap_err()
                .to_string()
                .find("Failed to parse Contract name")
                .is_some()
        );
    }

    #[test]
    fn tx_stacks_transaction_payload_invalid_function_name() {
        // test invalid contract name
        let address = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let contract_name = ContractName::try_from("hello-contract-name").unwrap();
        let hello_function_name = "hello\x00function-name";
        let mut hello_function_name_bytes = vec![hello_function_name.len() as u8];
        hello_function_name_bytes.extend_from_slice(hello_function_name.as_bytes());

        let function_args = vec![Value::Int(0)];

        let mut contract_call_bytes = vec![];
        address
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_name
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();
        contract_call_bytes.extend_from_slice(&hello_function_name_bytes);
        function_args
            .consensus_serialize(&mut contract_call_bytes)
            .unwrap();

        let mut transaction_contract_call = vec![TransactionPayloadID::ContractCall as u8];
        transaction_contract_call.append(&mut contract_call_bytes);

        assert!(
            TransactionPayload::consensus_deserialize(&mut &transaction_contract_call[..])
                .unwrap_err()
                .to_string()
                .find("Failed to parse Clarity name")
                .is_some()
        );
    }

    #[test]
    fn tx_stacks_asset() {
        let addr = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let addr_bytes = [
            // version
            0x01, // bytes
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let mut asset_name_bytes = vec![
            // length
            asset_name.len(),
        ];
        asset_name_bytes.extend_from_slice(&asset_name.to_string().as_str().as_bytes());

        let contract_name = ContractName::try_from("hello-world").unwrap();
        let mut contract_name_bytes = vec![
            // length
            contract_name.len(),
        ];
        contract_name_bytes.extend_from_slice(&contract_name.to_string().as_str().as_bytes());

        let asset_info = AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        };

        let mut asset_info_bytes = vec![];
        asset_info_bytes.extend_from_slice(&addr_bytes[..]);
        asset_info_bytes.extend_from_slice(&contract_name_bytes[..]);
        asset_info_bytes.extend_from_slice(&asset_name_bytes[..]);

        let mut actual_asset_info_bytes = vec![];
        asset_info
            .consensus_serialize(&mut actual_asset_info_bytes)
            .unwrap();
        assert_eq!(actual_asset_info_bytes, asset_info_bytes);

        assert_eq!(
            AssetInfo::consensus_deserialize(&mut &asset_info_bytes[..]).unwrap(),
            asset_info
        );
    }

    #[test]
    fn tx_stacks_postcondition() {
        let tx_post_condition_principals = vec![
            PostConditionPrincipal::Origin,
            PostConditionPrincipal::Standard(StacksAddress {
                version: 1,
                bytes: Hash160([1u8; 20]),
            }),
            PostConditionPrincipal::Contract(
                StacksAddress {
                    version: 2,
                    bytes: Hash160([2u8; 20]),
                },
                ContractName::try_from("hello-world").unwrap(),
            ),
        ];

        for tx_pcp in tx_post_condition_principals {
            let addr = StacksAddress {
                version: 1,
                bytes: Hash160([0xff; 20]),
            };
            let asset_name = ClarityName::try_from("hello-asset").unwrap();
            let contract_name = ContractName::try_from("contract-name").unwrap();

            let stx_pc =
                TransactionPostCondition::STX(tx_pcp.clone(), FungibleConditionCode::SentGt, 12345);
            let fungible_pc = TransactionPostCondition::Fungible(
                tx_pcp.clone(),
                AssetInfo {
                    contract_address: addr.clone(),
                    contract_name: contract_name.clone(),
                    asset_name: asset_name.clone(),
                },
                FungibleConditionCode::SentGt,
                23456,
            );

            let nonfungible_pc = TransactionPostCondition::Nonfungible(
                tx_pcp.clone(),
                AssetInfo {
                    contract_address: addr.clone(),
                    contract_name: contract_name.clone(),
                    asset_name: asset_name.clone(),
                },
                Value::buff_from(vec![0, 1, 2, 3]).unwrap(),
                NonfungibleConditionCode::NotSent,
            );

            let mut stx_pc_bytes = vec![];
            (AssetInfoID::STX as u8)
                .consensus_serialize(&mut stx_pc_bytes)
                .unwrap();
            tx_pcp.consensus_serialize(&mut stx_pc_bytes).unwrap();
            stx_pc_bytes.append(&mut vec![
                // condition code
                FungibleConditionCode::SentGt as u8,
                // amount
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x30,
                0x39,
            ]);

            let mut fungible_pc_bytes = vec![];
            (AssetInfoID::FungibleAsset as u8)
                .consensus_serialize(&mut fungible_pc_bytes)
                .unwrap();
            tx_pcp.consensus_serialize(&mut fungible_pc_bytes).unwrap();
            AssetInfo {
                contract_address: addr.clone(),
                contract_name: contract_name.clone(),
                asset_name: asset_name.clone(),
            }
            .consensus_serialize(&mut fungible_pc_bytes)
            .unwrap();
            fungible_pc_bytes.append(&mut vec![
                // condition code
                FungibleConditionCode::SentGt as u8,
                // amount
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x5b,
                0xa0,
            ]);

            let mut nonfungible_pc_bytes = vec![];
            (AssetInfoID::NonfungibleAsset as u8)
                .consensus_serialize(&mut nonfungible_pc_bytes)
                .unwrap();
            tx_pcp
                .consensus_serialize(&mut nonfungible_pc_bytes)
                .unwrap();
            AssetInfo {
                contract_address: addr.clone(),
                contract_name: contract_name.clone(),
                asset_name: asset_name.clone(),
            }
            .consensus_serialize(&mut nonfungible_pc_bytes)
            .unwrap();
            Value::buff_from(vec![0, 1, 2, 3])
                .unwrap()
                .consensus_serialize(&mut nonfungible_pc_bytes)
                .unwrap();
            nonfungible_pc_bytes.append(&mut vec![
                // condition code
                NonfungibleConditionCode::NotSent as u8,
            ]);

            let pcs = vec![stx_pc, fungible_pc, nonfungible_pc];
            let pc_bytes = [stx_pc_bytes, fungible_pc_bytes, nonfungible_pc_bytes];
            for i in 0..3 {
                check_codec_and_corruption::<TransactionPostCondition>(&pcs[i], &pc_bytes[i]);
            }
        }
    }

    #[test]
    fn tx_stacks_postcondition_invalid() {
        let addr = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };
        let asset_name = ClarityName::try_from("hello-asset").unwrap();
        let contract_name = ContractName::try_from("hello-world").unwrap();

        // can't parse a postcondition with an invalid condition code

        let mut stx_pc_bytes_bad_condition = vec![];
        (AssetInfoID::STX as u8)
            .consensus_serialize(&mut stx_pc_bytes_bad_condition)
            .unwrap();
        stx_pc_bytes_bad_condition.append(&mut vec![
            // principal
            PostConditionPrincipalID::Origin as u8,
            // condition code
            NonfungibleConditionCode::NotSent as u8,
            // amount
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x30,
            0x39,
        ]);

        let mut fungible_pc_bytes_bad_condition = vec![];
        (AssetInfoID::FungibleAsset as u8)
            .consensus_serialize(&mut fungible_pc_bytes_bad_condition)
            .unwrap();
        fungible_pc_bytes_bad_condition.append(&mut vec![PostConditionPrincipalID::Origin as u8]);
        AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        }
        .consensus_serialize(&mut fungible_pc_bytes_bad_condition)
        .unwrap();
        fungible_pc_bytes_bad_condition.append(&mut vec![
            // condition code
            NonfungibleConditionCode::Sent as u8,
            // amount
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x5b,
            0xa0,
        ]);

        let mut nonfungible_pc_bytes_bad_condition = vec![];
        (AssetInfoID::NonfungibleAsset as u8)
            .consensus_serialize(&mut nonfungible_pc_bytes_bad_condition)
            .unwrap();
        nonfungible_pc_bytes_bad_condition
            .append(&mut vec![PostConditionPrincipalID::Origin as u8]);
        AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        }
        .consensus_serialize(&mut nonfungible_pc_bytes_bad_condition)
        .unwrap();
        Value::buff_from(vec![0, 1, 2, 3])
            .unwrap()
            .consensus_serialize(&mut nonfungible_pc_bytes_bad_condition)
            .unwrap();
        nonfungible_pc_bytes_bad_condition.append(&mut vec![
            // condition code
            FungibleConditionCode::SentGt as u8,
        ]);

        let bad_pc_bytes = [
            stx_pc_bytes_bad_condition,
            fungible_pc_bytes_bad_condition,
            nonfungible_pc_bytes_bad_condition,
        ];
        for i in 0..3 {
            assert!(
                TransactionPostCondition::consensus_deserialize(&mut &bad_pc_bytes[i][..]).is_err()
            );
        }

        // can't parse a postcondition with an invalid principal

        let mut stx_pc_bytes_bad_principal = vec![];
        (AssetInfoID::STX as u8)
            .consensus_serialize(&mut stx_pc_bytes_bad_principal)
            .unwrap();
        stx_pc_bytes_bad_principal.append(&mut vec![
            // principal
            0xff,
            // condition code
            NonfungibleConditionCode::NotSent as u8,
            // amount
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x30,
            0x39,
        ]);

        let mut fungible_pc_bytes_bad_principal = vec![];
        (AssetInfoID::FungibleAsset as u8)
            .consensus_serialize(&mut fungible_pc_bytes_bad_principal)
            .unwrap();
        fungible_pc_bytes_bad_principal.append(&mut vec![0xff]);
        AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        }
        .consensus_serialize(&mut fungible_pc_bytes_bad_principal)
        .unwrap();
        fungible_pc_bytes_bad_principal.append(&mut vec![
            // condition code
            NonfungibleConditionCode::Sent as u8,
            // amount
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x5b,
            0xa0,
        ]);

        let mut nonfungible_pc_bytes_bad_principal = vec![];
        (AssetInfoID::NonfungibleAsset as u8)
            .consensus_serialize(&mut nonfungible_pc_bytes_bad_principal)
            .unwrap();
        nonfungible_pc_bytes_bad_principal.append(&mut vec![0xff]);
        AssetInfo {
            contract_address: addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        }
        .consensus_serialize(&mut nonfungible_pc_bytes_bad_principal)
        .unwrap();
        Value::buff_from(vec![0, 1, 2, 3])
            .unwrap()
            .consensus_serialize(&mut nonfungible_pc_bytes_bad_principal)
            .unwrap();
        nonfungible_pc_bytes_bad_principal.append(&mut vec![
            // condition code
            FungibleConditionCode::SentGt as u8,
        ]);

        let bad_pc_bytes = [
            stx_pc_bytes_bad_principal,
            fungible_pc_bytes_bad_principal,
            nonfungible_pc_bytes_bad_principal,
        ];
        for i in 0..3 {
            assert!(
                TransactionPostCondition::consensus_deserialize(&mut &bad_pc_bytes[i][..]).is_err()
            );
        }
    }

    #[test]
    fn tx_stacks_transaction_codec() {
        let all_txs = codec_all_transactions(
            &TransactionVersion::Mainnet,
            0,
            &TransactionAnchorMode::OnChainOnly,
            &TransactionPostConditionMode::Deny,
            StacksEpochId::latest(),
        );
        for tx in all_txs.iter() {
            let mut tx_bytes = vec![
                // version
                TransactionVersion::Mainnet as u8,
                // chain ID
                0x00,
                0x00,
                0x00,
                0x00,
            ];

            tx.auth.consensus_serialize(&mut tx_bytes).unwrap();
            tx_bytes.append(&mut vec![TransactionAnchorMode::OnChainOnly as u8]);
            tx_bytes.append(&mut vec![TransactionPostConditionMode::Deny as u8]);
            tx.post_conditions
                .consensus_serialize(&mut tx_bytes)
                .unwrap();
            tx.payload.consensus_serialize(&mut tx_bytes).unwrap();

            test_debug!("---------");
            test_debug!("test tx:\n{:?}", &tx);
            test_debug!("---------");
            test_debug!("text tx bytes:\n{}", &to_hex(&tx_bytes));

            check_codec_and_corruption::<StacksTransaction>(&tx, &tx_bytes);
        }
    }

    fn tx_stacks_transaction_test_txs(auth: &TransactionAuth) -> Vec<StacksTransaction> {
        let header_1 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([1u8; 32]),
            signature: MessageSignature([2u8; 65]),
        };

        let header_2 = StacksMicroblockHeader {
            version: 0x12,
            sequence: 0x34,
            prev_block: EMPTY_MICROBLOCK_PARENT_HASH.clone(),
            tx_merkle_root: Sha512Trunc256Sum([2u8; 32]),
            signature: MessageSignature([3u8; 65]),
        };

        let hello_contract_name = "hello-contract-name";
        let hello_asset_name = "hello-asset";
        let hello_token_name = "hello-token";

        let contract_name = ContractName::try_from(hello_contract_name).unwrap();
        let asset_name = ClarityName::try_from(hello_asset_name).unwrap();
        let token_name = StacksString::from_str(hello_token_name).unwrap();

        let asset_value = StacksString::from_str("asset-value").unwrap();

        let contract_addr = StacksAddress {
            version: 2,
            bytes: Hash160([0xfe; 20]),
        };

        let asset_info = AssetInfo {
            contract_address: contract_addr.clone(),
            contract_name: contract_name.clone(),
            asset_name: asset_name.clone(),
        };

        let stx_address = StacksAddress {
            version: 1,
            bytes: Hash160([0xff; 20]),
        };

        let tx_contract_call = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::new_contract_call(
                stx_address.clone(),
                "hello",
                "world",
                vec![Value::Int(1)],
            )
            .unwrap(),
        );

        let tx_smart_contract = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::new_smart_contract(
                &"name-contract".to_string(),
                &"hello smart contract".to_string(),
                None,
            )
            .unwrap(),
        );

        let tx_coinbase = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::Coinbase(CoinbasePayload([0u8; 32]), None, None),
        );

        let tx_stx = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::TokenTransfer(
                stx_address.clone().into(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        );

        let tx_poison = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::PoisonMicroblock(header_1, header_2),
        );

        let tx_tenure_change = StacksTransaction::new(
            TransactionVersion::Mainnet,
            auth.clone(),
            TransactionPayload::TenureChange(TenureChangePayload {
                tenure_consensus_hash: ConsensusHash([0x01; 20]),
                prev_tenure_consensus_hash: ConsensusHash([0x02; 20]),
                burn_view_consensus_hash: ConsensusHash([0x03; 20]),
                previous_tenure_end: StacksBlockId([0x00; 32]),
                previous_tenure_blocks: 0,
                cause: TenureChangeCause::BlockFound,
                pubkey_hash: Hash160([0x00; 20]),
            }),
        );

        let txs = vec![
            tx_contract_call,
            tx_smart_contract,
            tx_coinbase,
            tx_stx,
            tx_poison,
            tx_tenure_change,
        ];
        txs
    }

    fn check_oversign_origin_singlesig(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_origin(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => {
                    assert_eq!(&msg, "Not a multisig condition");
                }
                _ => assert!(false),
            },
        };

        // no change affected
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_sign_no_sponsor(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_sponsor(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => assert_eq!(
                    &msg,
                    "Cannot appned a public key to the sponsor of a standard auth condition"
                ),
                _ => assert!(false),
            },
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn check_oversign_sponsor_singlesig(signed_tx: &mut StacksTransaction) {
        let txid_before = signed_tx.txid();
        match signed_tx.append_next_sponsor(
            &StacksPublicKey::from_hex(
                "03442a63b6d312710b1d6b24d803120dc6f5714352ba57907863b78de55974123c",
            )
            .unwrap(),
        ) {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::SigningError(msg) => assert_eq!(&msg, "Not a multisig condition"),
                _ => assert!(false),
            },
        }
        assert_eq!(txid_before, signed_tx.txid());
    }

    fn is_order_independent_multisig(tx: &StacksTransaction) -> bool {
        let spending_condition = match &tx.auth {
            TransactionAuth::Standard(origin) => origin,
            TransactionAuth::Sponsored(_, sponsor) => sponsor,
        };
        match spending_condition {
            TransactionSpendingCondition::OrderIndependentMultisig(..) => true,
            _ => false,
        }
    }

    fn check_oversign_origin_multisig(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_origin(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    if is_order_independent_multisig(&oversigned_tx) {
                        assert!(
                            msg.contains("Signer hash does not equal hash of public key(s)"),
                            "{msg}"
                        )
                    } else {
                        assert_eq!(&msg, "Incorrect number of signatures")
                    }
                }
                _ => assert!(false),
            },
        }
    }

    fn check_oversign_origin_multisig_uncompressed(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_origin_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_origin(&privk).unwrap();
            }
            TransactionAuthField::PublicKey(_) => {
                tx_signer
                    .append_origin(&StacksPublicKey::from_private(&privk))
                    .unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
                }
                _ => assert!(false),
            },
        }
    }

    fn check_oversign_sponsor_multisig(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b01",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();
        tx_signer.sign_sponsor(&privk).unwrap();
        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    if is_order_independent_multisig(&oversigned_tx) {
                        assert!(
                            msg.contains("Signer hash does not equal hash of public key(s)"),
                            "{msg}"
                        )
                    } else {
                        assert_eq!(&msg, "Incorrect number of signatures")
                    }
                }
                _ => assert!(false),
            },
        }
    }

    fn check_oversign_sponsor_multisig_uncompressed(signed_tx: &StacksTransaction) {
        let tx = signed_tx.clone();
        let privk = StacksPrivateKey::from_hex(
            "c6ebf45dabca8cac9a25ae39ab690743b96eb2b0960066e98ba6df50d6f9293b",
        )
        .unwrap();

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.disable_checks();

        match tx_signer.pop_sponsor_auth_field().unwrap() {
            TransactionAuthField::Signature(_, _) => {
                tx_signer.sign_sponsor(&privk).unwrap();
            }
            TransactionAuthField::PublicKey(_) => {
                tx_signer
                    .append_sponsor(&StacksPublicKey::from_private(&privk))
                    .unwrap();
            }
        };

        let oversigned_tx = tx_signer.get_tx().unwrap();

        match oversigned_tx.verify() {
            Ok(_) => assert!(false),
            Err(e) => match e {
                net_error::VerifyingError(msg) => {
                    assert_eq!(&msg, "Uncompressed keys are not allowed in this hash mode");
                }
                _ => assert!(false),
            },
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap()
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(ref data)) =
                signed_tx.auth
            {
                assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                assert_eq!(data.signer, origin_address.bytes);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_sponsor = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk_diff_sponsor = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk_sponsor,
            ))
            .unwrap(), // will be replaced once the origin finishes signing
        );

        let origin_address = auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("143e543243dfcd8c02a12ad7ea371bd07bc91df9").unwrap()
            }
        );

        let sponsor_address = auth.sponsor().unwrap().address_mainnet();
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );

        let diff_sponsor_address = StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            bytes: Hash160::from_hex("a139de6733cef9e4663c4a093c1a7390a1dcc297").unwrap(),
        };

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            test_debug!("Sign origin");
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets keys, nonce, and fee after origin signs
            let origin_tx = tx_signer.get_tx_incomplete();

            let mut sponsor_auth = TransactionSpendingCondition::new_singlesig_p2pkh(
                StacksPublicKey::from_private(&privk_diff_sponsor),
            )
            .unwrap();
            sponsor_auth.set_tx_fee(456);
            sponsor_auth.set_nonce(789);

            let mut tx_sponsor_signer =
                StacksTransactionSigner::new_sponsor(&origin_tx, sponsor_auth).unwrap();

            test_debug!("Sign sponsor");
            tx_sponsor_signer.sign_sponsor(&privk_diff_sponsor).unwrap();

            // make comparable
            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_sponsor_signer.get_tx().unwrap();

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), 456);
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is a sponsor and public key is compressed.
            // auth sponsor is privk_diff_sponsor
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(
                                data.key_encoding,
                                TransactionPublicKeyEncoding::Uncompressed
                            ); // not what the origin would have seen
                            assert_eq!(data.signer, diff_sponsor_address.bytes);
                            // not what the origin would have seen
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is uncompressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(data)) =
                &signed_tx.auth
            {
                assert_eq!(
                    data.key_encoding,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.signer, origin_address.bytes);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2pkh_uncompressed() {
        let privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk_sponsored = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();

        let mut random_sponsor = StacksPrivateKey::new(); // what the origin sees
        random_sponsor.set_compress_public(true);

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(&privk_sponsored),
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("693cd53eb47d4749762d7cfaf46902bda5be5f97").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_sponsored).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is uncompressed
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(
                                data.key_encoding,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(data.signer, sponsor_address.bytes);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!()
            }
            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = auth.origin().address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();

            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2sh_mixed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.append_origin(&pubk_2).unwrap();
            tx_signer.sign_origin(&privk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2sh_mixed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("2136367c9c740e7dbed8795afdf8a6d273096718").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.append_sponsor(&pubk_2).unwrap();
            tx_signer.sign_sponsor(&privk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first & third auth fields are signatures for (un)compressed keys.
            // 2nd field is the 2nd public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                            assert_eq!(
                                data.fields[2].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wpkh() {
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(
                &privk,
            ))
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            if let TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wpkh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();

        let random_sponsor = StacksPrivateKey::new();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_singlesig_p2wpkh(
            StacksPublicKey::from_private(&privk),
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f15fa5c59d14ffcb615fa6153851cd802bb312d2").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            // try to over-sign
            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_singlesig(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 1);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and public key is compressed
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_oversign_origin_multisig_uncompressed(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new();

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);
            check_oversign_sponsor_multisig_uncompressed(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            let _ = tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_extra_signers() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            //check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 3);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            let _ = tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Uncompressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_mixed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2sh_mixed_3_out_of_9() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();
        let privk_7 = StacksPrivateKey::from_hex(
            "068856c242bfebdc57700fa598fae4e8ebb6b5f6bf932177018071489737d3ff01",
        )
        .unwrap();
        let privk_8 = StacksPrivateKey::from_hex(
            "a07a397f6b31c803f5d7f0c4620576cb03c66c12cdbdb6cd91d001d6f0052de201",
        )
        .unwrap();
        let privk_9 = StacksPrivateKey::from_hex(
            "f395129abc42c57e394dcceebeca9f51f0cb0a3f1c3a899d62e40b9340c7cc1101",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);
        let pubk_7 = StacksPublicKey::from_private(&privk_7);
        let pubk_8 = StacksPublicKey::from_private(&privk_8);
        let pubk_9 = StacksPublicKey::from_private(&privk_9);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                3,
                vec![
                    pubk_1.clone(),
                    pubk_2.clone(),
                    pubk_3.clone(),
                    pubk_4.clone(),
                    pubk_5.clone(),
                    pubk_6.clone(),
                    pubk_7.clone(),
                    pubk_8.clone(),
                    pubk_9.clone(),
                ],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("315d672961ef2583faf4107ab4ec5566014c867c").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig9 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_9)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_4);
            let _ = tx.append_next_origin(&pubk_5);
            let _ = tx.append_next_origin(&pubk_6);
            let _ = tx.append_next_origin(&pubk_7);
            let _ = tx.append_next_origin(&pubk_8);
            let _ = tx.append_origin_signature(sig9, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 3);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 9);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());
                assert!(data.fields[3].is_public_key());
                assert!(data.fields[4].is_public_key());
                assert!(data.fields[5].is_public_key());
                assert!(data.fields[6].is_public_key());
                assert!(data.fields[7].is_public_key());
                assert!(data.fields[8].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(data.fields[3].as_public_key().unwrap(), pubk_4);
                assert_eq!(data.fields[4].as_public_key().unwrap(), pubk_5);
                assert_eq!(data.fields[5].as_public_key().unwrap(), pubk_6);
                assert_eq!(data.fields[6].as_public_key().unwrap(), pubk_7);
                assert_eq!(data.fields[7].as_public_key().unwrap(), pubk_8);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[8].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_mixed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[2].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2sh_mixed_5_out_of_5() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            5,
            vec![
                pubk_1.clone(),
                pubk_2.clone(),
                pubk_3.clone(),
                pubk_4.clone(),
                pubk_5.clone(),
            ],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("fc29d14be615b0f72a66b920040c2b5b8124990b").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();
            let sig4 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_4)
                .unwrap();
            let sig5 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_5)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig4, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig5, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 5);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 5);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_signature());
                            assert!(data.fields[3].is_signature());
                            assert!(data.fields[4].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[2].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[3].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[4].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_order_independent_p2wsh_4_out_of_6() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                4,
                vec![
                    pubk_1.clone(),
                    pubk_2.clone(),
                    pubk_3.clone(),
                    pubk_4.clone(),
                    pubk_5.clone(),
                    pubk_6.clone(),
                ],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("e2a4ae14ffb0a4a0982a06d07b97d57268d2bf94").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig6 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_6)
                .unwrap();
            let sig5 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_5)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_4);
            let _ = tx.append_origin_signature(sig5, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_origin_signature(sig6, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 4);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 6);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());
                assert!(data.fields[3].is_public_key());
                assert!(data.fields[4].is_signature());
                assert!(data.fields[5].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(data.fields[3].as_public_key().unwrap(), pubk_4);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[4].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[5].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[2].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_order_independent_p2wsh_2_out_of_7() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();
        let privk_4 = StacksPrivateKey::from_hex(
            "3beb8916404874f5d5de162c95470951de5b4a7f6ec8d7a20511551821f16db501",
        )
        .unwrap();
        let privk_5 = StacksPrivateKey::from_hex(
            "601aa0939e98efec29a4dc645377c9d4acaa0b7318444ec8fd7d090d0b36d85b01",
        )
        .unwrap();
        let privk_6 = StacksPrivateKey::from_hex(
            "5a4ca3db5a3b36bc32d9f2f0894435cbc4b2b1207e95ee283616d9a0797210da01",
        )
        .unwrap();
        let privk_7 = StacksPrivateKey::from_hex(
            "068856c242bfebdc57700fa598fae4e8ebb6b5f6bf932177018071489737d3ff01",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);
        let pubk_4 = StacksPublicKey::from_private(&privk_4);
        let pubk_5 = StacksPublicKey::from_private(&privk_5);
        let pubk_6 = StacksPublicKey::from_private(&privk_6);
        let pubk_7 = StacksPublicKey::from_private(&privk_7);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
            2,
            vec![
                pubk_1.clone(),
                pubk_2.clone(),
                pubk_3.clone(),
                pubk_4.clone(),
                pubk_5.clone(),
                pubk_6.clone(),
                pubk_7.clone(),
            ],
        )
        .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("e3001c2b12f24ba279116d7001e3bd82b2b5eab4").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig7 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_7)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ = origin_tx.append_next_sponsor(&pubk_3);
            let _ = origin_tx.append_next_sponsor(&pubk_4);
            let _ = origin_tx.append_next_sponsor(&pubk_5);
            let _ = origin_tx.append_next_sponsor(&pubk_6);
            let _ =
                origin_tx.append_sponsor_signature(sig7, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 7);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_public_key());
                            assert!(data.fields[3].is_public_key());
                            assert!(data.fields[4].is_public_key());
                            assert!(data.fields[5].is_public_key());
                            assert!(data.fields[6].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[6].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                            assert_eq!(data.fields[3].as_public_key().unwrap(), pubk_4);
                            assert_eq!(data.fields[4].as_public_key().unwrap(), pubk_5);
                            assert_eq!(data.fields[5].as_public_key().unwrap(), pubk_6);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2sh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();

        assert_eq!(origin_address, order_independent_origin_address);
        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        assert_eq!(txs.len(), order_independent_txs.len());

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();
            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut order_independent_tx in order_independent_txs {
            assert_eq!(order_independent_tx.auth().origin().num_signatures(), 0);

            let order_independent_initial_sig_hash = order_independent_tx.sign_begin();
            let sig3 = order_independent_tx
                .sign_no_append_origin(&order_independent_initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = order_independent_tx
                .sign_no_append_origin(&order_independent_initial_sig_hash, &privk_2)
                .unwrap();

            let _ = order_independent_tx.append_next_origin(&pubk_1);
            let _ = order_independent_tx
                .append_origin_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = order_independent_tx
                .append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&order_independent_tx);
            check_sign_no_sponsor(&mut order_independent_tx);

            assert_eq!(order_independent_tx.auth().origin().num_signatures(), 2);

            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &order_independent_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&order_independent_tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2sh_uncompressed() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, order_independent_origin_address);

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        assert_eq!(txs.len(), order_independent_txs.len());

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();

            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for uncompressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig2 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = tx.append_next_origin(&pubk_1);
            let _ = tx.append_origin_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Uncompressed);

            check_oversign_origin_multisig(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_public_key());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[0].as_public_key().unwrap(), pubk_1);
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Uncompressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_standard_both_multisig_p2wsh() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let order_independent_origin_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap(),
        );

        let origin_address = origin_auth.origin().address_mainnet();
        let order_independent_origin_address =
            order_independent_origin_auth.origin().address_mainnet();
        assert_eq!(origin_address, order_independent_origin_address);

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&origin_auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&order_independent_origin_auth);

        for tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let mut tx_signer = StacksTransactionSigner::new(&tx);
            tx_signer.sign_origin(&privk_1).unwrap();
            tx_signer.sign_origin(&privk_2).unwrap();
            tx_signer.append_origin(&pubk_3).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_multisig(&signed_tx);
            check_oversign_origin_multisig_uncompressed(&signed_tx);
            check_sign_no_sponsor(&mut signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(TransactionSpendingCondition::Multisig(data)) =
                &signed_tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_signature());
                assert!(data.fields[2].is_public_key());

                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[1].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
            } else {
                panic!();
            }

            test_signature_and_corruption(&signed_tx, true, false);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);

            let tx_signer = StacksTransactionSigner::new(&tx);

            let initial_sig_hash = tx.sign_begin();
            let sig3 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_3)
                .unwrap();
            let sig1 = tx
                .sign_no_append_origin(&initial_sig_hash, &privk_1)
                .unwrap();

            let _ = tx.append_origin_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = tx.append_next_origin(&pubk_2);
            let _ = tx.append_origin_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            check_oversign_origin_multisig(&tx);
            check_oversign_origin_multisig_uncompressed(&tx);
            check_sign_no_sponsor(&mut tx);

            assert_eq!(tx.auth().origin().num_signatures(), 2);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            if let TransactionAuth::Standard(
                TransactionSpendingCondition::OrderIndependentMultisig(data),
            ) = &tx.auth
            {
                assert_eq!(data.signer, origin_address.bytes);
                assert_eq!(data.fields.len(), 3);
                assert!(data.fields[0].is_signature());
                assert!(data.fields[1].is_public_key());
                assert!(data.fields[2].is_signature());

                assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                assert_eq!(
                    data.fields[0].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
                assert_eq!(
                    data.fields[2].as_signature().unwrap().0,
                    TransactionPublicKeyEncoding::Compressed
                );
            } else {
                panic!();
            }

            test_signature_and_corruption(&tx, true, false);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2sh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);
        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("a23ea89d6529ac48ac766f720e480beec7f19273").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ =
                origin_tx.append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2sh_uncompressed() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d2",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_order_independent_p2sh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2sh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);

        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("73a8b4a751a678fe83e9d35ce301371bb3d397f7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig2 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_2)
                .unwrap();

            let _ = origin_tx
                .append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx
                .append_sponsor_signature(sig2, TransactionPublicKeyEncoding::Uncompressed);
            let _ = origin_tx.append_next_sponsor(&pubk_3);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Uncompressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }

    #[test]
    fn tx_stacks_transaction_sign_verify_sponsored_both_multisig_p2wsh() {
        let origin_privk = StacksPrivateKey::from_hex(
            "807bbe9e471ac976592cc35e3056592ecc0f778ee653fced3b491a122dd8d59701",
        )
        .unwrap();

        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_2 = StacksPrivateKey::from_hex(
            "2a584d899fed1d24e26b524f202763c8ab30260167429f157f1c119f550fa6af01",
        )
        .unwrap();
        let privk_3 = StacksPrivateKey::from_hex(
            "d5200dee706ee53ae98a03fba6cf4fdcc5084c30cfa9e1b3462dcdeaa3e0f1d201",
        )
        .unwrap();

        let pubk_1 = StacksPublicKey::from_private(&privk_1);
        let pubk_2 = StacksPublicKey::from_private(&privk_2);
        let pubk_3 = StacksPublicKey::from_private(&privk_3);

        let random_sponsor = StacksPrivateKey::new(); // what the origin sees

        let auth = TransactionAuth::Sponsored(
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &origin_privk,
            ))
            .unwrap(),
            TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
                &random_sponsor,
            ))
            .unwrap(),
        );

        let real_sponsor = TransactionSpendingCondition::new_multisig_p2wsh(
            2,
            vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
        )
        .unwrap();

        let real_order_independent_sponsor =
            TransactionSpendingCondition::new_multisig_order_independent_p2wsh(
                2,
                vec![pubk_1.clone(), pubk_2.clone(), pubk_3.clone()],
            )
            .unwrap();

        let origin_address = auth.origin().address_mainnet();
        let sponsor_address = real_sponsor.address_mainnet();
        let order_independent_sponsor_address = real_order_independent_sponsor.address_mainnet();

        assert_eq!(
            origin_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160::from_hex("3597aaa4bde720be93e3829aae24e76e7fcdfd3e").unwrap(),
            }
        );
        assert_eq!(sponsor_address, order_independent_sponsor_address);

        assert_eq!(
            sponsor_address,
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
                bytes: Hash160::from_hex("f5cfb61a07fb41a32197da01ce033888f0fe94a7").unwrap(),
            }
        );

        let txs = tx_stacks_transaction_test_txs(&auth);
        let order_independent_txs = tx_stacks_transaction_test_txs(&auth); // no difference

        for mut tx in txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx.auth.set_sponsor(real_sponsor.clone()).unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();
            tx_signer.resume(&origin_tx);

            tx_signer.sign_sponsor(&privk_1).unwrap();
            tx_signer.sign_sponsor(&privk_2).unwrap();
            tx_signer.append_sponsor(&pubk_3).unwrap();

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();
            let mut signed_tx = tx_signer.get_tx().unwrap();

            check_oversign_origin_singlesig(&mut signed_tx);
            check_oversign_sponsor_multisig(&signed_tx);
            check_oversign_sponsor_multisig_uncompressed(&signed_tx);

            assert_eq!(signed_tx.auth().origin().num_signatures(), 1);
            assert_eq!(signed_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and signed_tx are otherwise equal
            assert_eq!(tx.version, signed_tx.version);
            assert_eq!(tx.chain_id, signed_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), signed_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), signed_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), signed_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, signed_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, signed_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, signed_tx.post_conditions);
            assert_eq!(tx.payload, signed_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match signed_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::Multisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_signature());
                            assert!(data.fields[2].is_public_key());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[1].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[2].as_public_key().unwrap(), pubk_3);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&signed_tx, true, false);
            test_signature_and_corruption(&signed_tx, false, true);
        }

        for mut tx in order_independent_txs {
            assert_eq!(tx.auth().origin().num_signatures(), 0);
            assert_eq!(tx.auth().sponsor().unwrap().num_signatures(), 0);

            tx.set_tx_fee(123);
            tx.set_sponsor_nonce(456).unwrap();
            let mut tx_signer = StacksTransactionSigner::new(&tx);

            tx_signer.sign_origin(&origin_privk).unwrap();

            // sponsor sets and pays fee after origin signs
            let mut origin_tx = tx_signer.get_tx_incomplete();
            origin_tx
                .auth
                .set_sponsor(real_order_independent_sponsor.clone())
                .unwrap();
            origin_tx.set_tx_fee(456);
            origin_tx.set_sponsor_nonce(789).unwrap();

            let initial_sig_hash = tx_signer.sighash;
            let sig1 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_1)
                .unwrap();
            let sig3 = origin_tx
                .sign_no_append_sponsor(&initial_sig_hash, &privk_3)
                .unwrap();

            let _ =
                origin_tx.append_sponsor_signature(sig1, TransactionPublicKeyEncoding::Compressed);
            let _ = origin_tx.append_next_sponsor(&pubk_2);
            let _ =
                origin_tx.append_sponsor_signature(sig3, TransactionPublicKeyEncoding::Compressed);

            tx.set_tx_fee(456);
            tx.set_sponsor_nonce(789).unwrap();

            check_oversign_origin_singlesig(&mut origin_tx);
            check_oversign_sponsor_multisig(&origin_tx);
            check_oversign_sponsor_multisig_uncompressed(&origin_tx);

            assert_eq!(origin_tx.auth().origin().num_signatures(), 1);
            assert_eq!(origin_tx.auth().sponsor().unwrap().num_signatures(), 2);

            // tx and origin_tx are otherwise equal
            assert_eq!(tx.version, origin_tx.version);
            assert_eq!(tx.chain_id, origin_tx.chain_id);
            assert_eq!(tx.get_tx_fee(), origin_tx.get_tx_fee());
            assert_eq!(tx.get_origin_nonce(), origin_tx.get_origin_nonce());
            assert_eq!(tx.get_sponsor_nonce(), origin_tx.get_sponsor_nonce());
            assert_eq!(tx.anchor_mode, origin_tx.anchor_mode);
            assert_eq!(tx.post_condition_mode, origin_tx.post_condition_mode);
            assert_eq!(tx.post_conditions, origin_tx.post_conditions);
            assert_eq!(tx.payload, origin_tx.payload);

            // auth is standard and first two auth fields are signatures for compressed keys.
            // third field is the third public key
            match origin_tx.auth {
                TransactionAuth::Sponsored(ref origin, ref sponsor) => {
                    match origin {
                        TransactionSpendingCondition::Singlesig(ref data) => {
                            assert_eq!(data.key_encoding, TransactionPublicKeyEncoding::Compressed);
                            assert_eq!(data.signer, origin_address.bytes);
                        }
                        _ => assert!(false),
                    }
                    match sponsor {
                        TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                            assert_eq!(data.signer, sponsor_address.bytes);
                            assert_eq!(data.fields.len(), 3);
                            assert!(data.fields[0].is_signature());
                            assert!(data.fields[1].is_public_key());
                            assert!(data.fields[2].is_signature());

                            assert_eq!(
                                data.fields[0].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(
                                data.fields[2].as_signature().unwrap().0,
                                TransactionPublicKeyEncoding::Compressed
                            );
                            assert_eq!(data.fields[1].as_public_key().unwrap(), pubk_2);
                        }
                        _ => assert!(false),
                    }
                }
                _ => assert!(false),
            };

            test_signature_and_corruption(&origin_tx, true, false);
            test_signature_and_corruption(&origin_tx, false, true);
        }
    }
}
