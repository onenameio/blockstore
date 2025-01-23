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

use std::io::{Read, Write};

use stacks_common::address::AddressHashMode;
use stacks_common::codec::{write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::deps_common::bitcoin::blockdata::script::Builder;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, TrieHash, VRFSeed,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::to_hex;
use stacks_common::util::log;
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::burnchains::bitcoin::bits::parse_script;
use crate::burnchains::bitcoin::{BitcoinTxInput, BitcoinTxInputStructured};
use crate::burnchains::{
    Address, Burnchain, BurnchainBlockHeader, BurnchainTransaction, PoxConstants, PublicKey, Txid,
};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, parse_u32_from_be, parse_u64_from_be, BlockstackOperationType,
    Error as op_error, PreStxOp, StackStxOp,
};
use crate::chainstate::burn::{ConsensusHash, Opcodes};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::chainstate::stacks::{StacksPrivateKey, StacksPublicKey};
use crate::core::{StacksEpochId, POX_MAX_NUM_CYCLES};
use crate::net::Error as net_error;

// return type from parse_data below
struct ParsedData {
    stacked_ustx: u128,
    num_cycles: u8,
    signer_key: Option<StacksPublicKeyBuffer>,
    max_amount: Option<u128>,
    auth_id: Option<u32>,
}

pub static OUTPUTS_PER_COMMIT: usize = 2;

impl PreStxOp {
    #[cfg(test)]
    pub fn new(sender: &StacksAddress) -> PreStxOp {
        PreStxOp {
            output: sender.clone(),
            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreStxOp, op_error> {
        PreStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            epoch_id,
            tx,
            pox_sunset_ht,
        )
    }

    /// parse a PreStxOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        pox_sunset_ht: u64,
    ) -> Result<PreStxOp, op_error> {
        // can't be too careful...
        let num_inputs = tx.num_signers();
        let num_outputs = tx.num_recipients();

        if num_inputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                num_inputs, num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::PreStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let output = outputs[0]
            .as_ref()
            .ok_or_else(|| {
                warn!("Invalid tx: first output cannot be decoded");
                op_error::InvalidInput
            })?
            .address
            .clone()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: first output must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;

        // check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "PreStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(PreStxOp {
            output,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StackStxOp {
    #[cfg(test)]
    pub fn new(
        sender: &StacksAddress,
        reward_addr: &PoxAddress,
        stacked_ustx: u128,
        num_cycles: u8,
        signer_key: Option<StacksPublicKeyBuffer>,
        max_amount: Option<u128>,
        auth_id: Option<u32>,
    ) -> StackStxOp {
        StackStxOp {
            sender: sender.clone(),
            reward_addr: reward_addr.clone(),
            stacked_ustx,
            num_cycles,
            signer_key,
            max_amount,
            auth_id,
            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    // TODO: add tests from mutation testing results #4850
    #[cfg_attr(test, mutants::skip)]
    fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3                             19           20                  53                 69                        73
            |------|--|-----------------------------|------------|-------------------|-------------------|-------------------------|
            magic  op         uSTX to lock (u128)     cycles (u8)     signer key (optional)   max_amount (optional u128)  auth_id (optional u32)

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values ustx to lock and cycles are in big-endian order.

             parent-delta and parent-txoff will both be 0 if this block builds off of the genesis block.
        */

        if data.len() < 17 {
            // too short
            warn!(
                "StacksStxOp payload is malformed ({} bytes, expected {} or more)",
                data.len(),
                17
            );
            return None;
        }

        let stacked_ustx = parse_u128_from_be(&data[0..16]).unwrap();
        let num_cycles = data[16];

        let mut signer_key: Option<StacksPublicKeyBuffer> = None;
        let mut max_amount: Option<u128> = None;
        let mut auth_id: Option<u32> = None;

        if data.len() >= 50 {
            signer_key = Some(StacksPublicKeyBuffer::from(&data[17..50]));
        }
        if data.len() >= 66 {
            let Some(amt) = parse_u128_from_be(&data[50..66]) else {
                return None;
            };
            max_amount = Some(amt);
        }
        if data.len() >= 70 {
            let Some(id) = parse_u32_from_be(&data[66..70]) else {
                return None;
            };
            auth_id = Some(id);
        }

        Some(ParsedData {
            stacked_ustx,
            num_cycles,
            signer_key,
            max_amount,
            auth_id,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: StackStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: StackStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        StackStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            epoch_id,
            tx,
            sender,
            pox_sunset_ht,
        )
    }

    // TODO: add tests from mutation testing results #4851
    #[cfg_attr(test, mutants::skip)]
    /// parse a StackStxOp
    /// `pox_sunset_ht` is the height at which PoX *disables*
    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
        pox_sunset_ht: u64,
    ) -> Result<StackStxOp, op_error> {
        // can't be too careful...
        let num_outputs = tx.num_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs
            );
            return Err(op_error::InvalidInput);
        }

        if num_outputs == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                num_outputs,
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::StackStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = StackStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let outputs = tx.get_recipients();
        assert!(!outputs.is_empty());

        let first_output = outputs[0].as_ref().ok_or_else(|| {
            warn!("Invalid tx: failed to decode first output");
            op_error::InvalidInput
        })?;

        // coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = first_output.address.clone().coerce_hash_mode();

        // check if we've reached PoX disable
        if PoxConstants::has_pox_sunset(epoch_id) && block_height >= pox_sunset_ht {
            debug!(
                "StackStxOp broadcasted after sunset. Ignoring. txid={}",
                tx.txid()
            );
            return Err(op_error::InvalidInput);
        }

        Ok(StackStxOp {
            sender: sender.clone(),
            reward_addr,
            stacked_ustx: data.stacked_ustx,
            num_cycles: data.num_cycles,
            signer_key: data.signer_key,
            max_amount: data.max_amount,
            auth_id: data.auth_id,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }
}

impl StacksMessageCodec for PreStxOp {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::PreStx as u8))?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<PreStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl StacksMessageCodec for StackStxOp {
    /*
            0      2  3                             19           20                  53                 69                        73
            |------|--|-----------------------------|------------|-------------------|-------------------|-------------------------|
            magic  op         uSTX to lock (u128)     cycles (u8)     signer key (optional)   max_amount (optional u128)  auth_id (optional u32)
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::StackStx as u8))?;
        fd.write_all(&self.stacked_ustx.to_be_bytes())
            .map_err(codec_error::WriteError)?;
        write_next(fd, &self.num_cycles)?;

        if let Some(signer_key) = &self.signer_key {
            fd.write_all(&signer_key.as_bytes()[..])
                .map_err(codec_error::WriteError)?;
        }
        if let Some(max_amount) = &self.max_amount {
            fd.write_all(&max_amount.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        }
        if let Some(auth_id) = &self.auth_id {
            fd.write_all(&auth_id.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<StackStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

impl StackStxOp {
    pub fn check(&self) -> Result<(), op_error> {
        if self.stacked_ustx == 0 {
            warn!("Invalid StackStxOp, must have positive ustx");
            return Err(op_error::StackStxMustBePositive);
        }

        if self.num_cycles == 0 || self.num_cycles > POX_MAX_NUM_CYCLES {
            warn!(
                "Invalid StackStxOp, num_cycles = {}, but must be in (0, {}]",
                self.num_cycles, POX_MAX_NUM_CYCLES
            );
        }

        // Check to see if the signer key is valid if available
        if let Some(signer_key) = self.signer_key {
            Secp256k1PublicKey::from_slice(signer_key.as_bytes())
                .map_err(|_| op_error::StackStxInvalidKey)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_MAINNET_SINGLESIG};
    use stacks_common::deps_common::bitcoin::blockdata::opcodes;
    use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction;
    use stacks_common::deps_common::bitcoin::network::serialize::{deserialize, serialize_hex};
    use stacks_common::types::chainstate::{BlockHeaderHash, StacksAddress, VRFSeed};
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::*;
    use stacks_common::util::vrf::VRFPublicKey;

    use super::*;
    use crate::burnchains::bitcoin::address::*;
    use crate::burnchains::bitcoin::blocks::BitcoinBlockParser;
    use crate::burnchains::bitcoin::keys::BitcoinPublicKey;
    use crate::burnchains::bitcoin::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::db::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::burn::{ConsensusHash, *};
    use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
    use crate::chainstate::stacks::StacksPublicKey;
    use crate::core::StacksEpochId;

    struct OpFixture {
        txstr: String,
        opstr: String,
        result: Option<StackStxOp>,
    }

    struct CheckFixture {
        op: StackStxOp,
        res: Result<(), op_error>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex string")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    #[test]
    fn test_parse_pre_stack_stx() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::PreStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = PreStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            16843023,
        )
        .unwrap();

        assert_eq!(
            &op.output,
            &StacksAddress::from_legacy_bitcoin_address(
                &tx.outputs[0].address.clone().expect_legacy()
            )
        );
    }

    #[test]
    fn test_parse_pre_stack_stx_sunset() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::PreStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };

        // pre-2.1 this fails
        let op_err = PreStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            16843022,
        )
        .unwrap_err();

        if let op_error::InvalidInput = op_err {
        } else {
            panic!("Parsed post-sunset prestx");
        }

        // post-2.1 this succeeds
        let op = PreStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch21,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            16843022,
        )
        .unwrap();

        assert_eq!(
            &op.output,
            &StacksAddress::from_legacy_bitcoin_address(
                &tx.outputs[0].address.clone().expect_legacy()
            )
        );
    }

    #[test]
    fn test_parse_stack_stx() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = StackStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
            16843023,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &PoxAddress::Standard(
                StacksAddress::from_legacy_bitcoin_address(
                    &tx.outputs[0].address.clone().expect_legacy()
                ),
                Some(AddressHashMode::SerializeP2PKH)
            )
        );
        assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 1);
        assert_eq!(op.signer_key, Some(StacksPublicKeyBuffer([0x01; 33])));
    }

    #[test]
    fn test_parse_stack_stx_signer_key_is_none() {
        // Set the option flag for `signer_key` to None
        let data = vec![1; 17];
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::StackStx as u8,
            data,
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = StackStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
            16843023,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &PoxAddress::Standard(
                StacksAddress::from_legacy_bitcoin_address(
                    &tx.outputs[0].address.clone().expect_legacy()
                ),
                Some(AddressHashMode::SerializeP2PKH)
            )
        );
        assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 1);
        assert_eq!(op.signer_key, None);
    }

    #[test]
    fn test_parse_stack_stx_sunset() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::StackStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };

        // pre-2.1: this fails
        let op_err = StackStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
            16843022,
        )
        .unwrap_err();

        if let op_error::InvalidInput = op_err {
        } else {
            panic!("Parsed post-sunset epoch 2.05");
        }

        // post-2.1: this succeeds
        let op = StackStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch21,
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
            16843022,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &PoxAddress::Standard(
                StacksAddress::from_legacy_bitcoin_address(
                    &tx.outputs[0].address.clone().expect_legacy()
                ),
                Some(AddressHashMode::SerializeP2PKH)
            )
        );
        assert_eq!(op.stacked_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.num_cycles, 1);
    }

    #[test]
    fn test_stack_stx_op_script_len() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let reward_addr = PoxAddress::Standard(
            StacksAddress {
                version: C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
                bytes: Hash160([0x01; 20]),
            },
            None,
        );
        let op = StackStxOp {
            sender,
            reward_addr,
            stacked_ustx: 10,
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
            num_cycles: 10,
            signer_key: Some(StacksPublicKeyBuffer([0x01; 33])),
            max_amount: Some(10),
            auth_id: Some(0u32),
        };
        let op_bytes = {
            let mut bytes = [b'T', b'3'].to_vec();
            op.consensus_serialize(&mut bytes)
                .expect("Expected to be able to serialize op into bytes");
            bytes
        };
        let script = Builder::new()
            .push_opcode(opcodes::All::OP_RETURN)
            .push_slice(&op_bytes)
            .into_script();
        assert_eq!(script.len(), 75);
    }
}
