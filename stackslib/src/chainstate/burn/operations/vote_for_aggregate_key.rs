// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use stacks_common::codec::{write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::deps_common::bitcoin::blockdata::script::Builder;
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::bitcoin::bits::parse_script;
use crate::burnchains::bitcoin::{BitcoinTxInput, BitcoinTxInputStructured};
use crate::burnchains::{BurnchainBlockHeader, BurnchainTransaction, Txid};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, parse_u16_from_be, parse_u32_from_be, parse_u64_from_be,
    BlockstackOperationType, Error as op_error, PreStxOp, VoteForAggregateKeyOp,
};
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::address::PoxAddress;

struct ParsedData {
    signer_index: u16,
    aggregate_key: StacksPublicKeyBuffer,
    round: u32,
    reward_cycle: u64,
}

impl VoteForAggregateKeyOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<VoteForAggregateKeyOp, op_error> {
        VoteForAggregateKeyOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
           Wire format:

           0     2    3           5              38     42           50
           |-----|----|-----------|--------------|------|------------|
           magic  op  signer_index aggregate_key  round  reward_cycle

           Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */

        if data.len() != 47 {
            warn!(
                "Vote for aggregate key operation data has an invalid length ({} bytes)",
                data.len()
            );
            return None;
        }

        let signer_index =
            parse_u16_from_be(&data[0..2]).expect("Failed to parse signer index from tx");
        let aggregate_key = StacksPublicKeyBuffer::from(&data[2..35]);

        let round = parse_u32_from_be(&data[35..39]).expect("Failed to parse round from tx");
        let reward_cycle =
            parse_u64_from_be(&data[39..47]).expect("Failed to parse reward cycle from tx");

        Some(ParsedData {
            signer_index,
            aggregate_key,
            round,
            reward_cycle,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: VoteForAggregateKey must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: VoteForAggregateKey must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn get_sender_pubkey(tx: &BurnchainTransaction) -> Result<Secp256k1PublicKey, op_error> {
        match tx {
            BurnchainTransaction::Bitcoin(ref btc) => match btc.inputs.get(0) {
                Some(BitcoinTxInput::Raw(input)) => {
                    let script_sig = Builder::from(input.scriptSig.clone()).into_script();
                    let structured_input = BitcoinTxInputStructured::from_bitcoin_p2pkh_script_sig(
                        &parse_script(&script_sig),
                        input.tx_ref,
                    )
                    .ok_or(op_error::InvalidInput)?;
                    structured_input
                        .keys
                        .get(0)
                        .cloned()
                        .ok_or(op_error::InvalidInput)
                }
                Some(BitcoinTxInput::Structured(input)) => {
                    input.keys.get(0).cloned().ok_or(op_error::InvalidInput)
                }
                _ => Err(op_error::InvalidInput),
            },
        }
    }

    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<VoteForAggregateKeyOp, op_error> {
        let outputs = tx.get_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::VoteForAggregateKey as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = VoteForAggregateKeyOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let signer_key = VoteForAggregateKeyOp::get_sender_pubkey(tx)?;

        Ok(VoteForAggregateKeyOp {
            sender: sender.clone(),
            signer_index: data.signer_index,
            aggregate_key: data.aggregate_key,
            round: data.round,
            reward_cycle: data.reward_cycle,
            signer_key: signer_key.to_bytes_compressed().as_slice().into(),
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    /// Check the payload of a vote-for-aggregate-key burn op.
    /// Both `signer_key` and `aggregate_key` are checked for validity against
    /// `Secp256k1PublicKey` from `stacks_common`
    pub fn check(&self) -> Result<(), op_error> {
        // Check to see if the aggregate key is valid
        let aggregate_key_bytes = self.aggregate_key.as_bytes();
        Secp256k1PublicKey::from_slice(aggregate_key_bytes)
            .map_err(|_| op_error::VoteForAggregateKeyInvalidKey)?;

        // Check to see if the signer key is valid
        let signer_key_bytes = self.signer_key.as_bytes();
        Secp256k1PublicKey::from_slice(signer_key_bytes)
            .map_err(|_| op_error::VoteForAggregateKeyInvalidKey)?;

        Ok(())
    }
}

impl StacksMessageCodec for VoteForAggregateKeyOp {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        /*
           Wire format:

           0     2    3           5              38     42           50
           |-----|----|-----------|--------------|------|------------|
           magic  op  signer_index aggregate_key  round  reward_cycle
        */

        write_next(fd, &(Opcodes::VoteForAggregateKey as u8))?;
        fd.write_all(&self.signer_index.to_be_bytes())
            .map_err(codec_error::WriteError)?;
        fd.write_all(self.aggregate_key.as_bytes())
            .map_err(codec_error::WriteError)?;
        fd.write_all(&self.round.to_be_bytes())
            .map_err(codec_error::WriteError)?;
        fd.write_all(&self.reward_cycle.to_be_bytes())
            .map_err(codec_error::WriteError)?;

        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<Self, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::deps_common::bitcoin::blockdata::script::Builder;
    use stacks_common::types;
    use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress};
    use stacks_common::types::{Address, StacksPublicKeyBuffer};
    use stacks_common::util::hash::*;
    use stacks_common::util::secp256k1::Secp256k1PublicKey;

    use crate::burnchains::bitcoin::address::{
        BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType,
    };
    use crate::burnchains::bitcoin::{
        BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInput,
        BitcoinTxInputRaw, BitcoinTxInputStructured, BitcoinTxOutput,
    };
    use crate::burnchains::{BurnchainTransaction, Txid};
    use crate::chainstate::burn::operations::{Error as op_error, VoteForAggregateKeyOp};
    use crate::chainstate::burn::Opcodes;
    use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};

    #[test]
    fn test_parse_vote_tx_signer_key() {
        let aggregate_key = StacksPublicKeyBuffer([0x01; 33]);
        let signer_key = StacksPublicKeyBuffer([0x02; 33]);
        let signer_pubkey = Secp256k1PublicKey::from_slice(signer_key.as_bytes()).unwrap();
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::VoteForAggregateKey as u8,
            data: vec![1; 47],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![signer_pubkey],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
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

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let vote_op = VoteForAggregateKeyOp::parse_from_tx(
            1000,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx),
            &sender,
        )
        .expect("Failed to parse vote tx");

        assert_eq!(&vote_op.sender, &sender);
        assert_eq!(&vote_op.signer_key, &signer_key);
    }

    #[test]
    fn test_vote_tx_data() {
        let round: u32 = 24;
        let signer_index: u16 = 12;
        let aggregate_key = StacksPublicKeyBuffer([0x01; 33]);
        let signer_key = StacksPublicKeyBuffer([0x02; 33]);
        let reward_cycle: u64 = 10;

        let mut data: Vec<u8> = vec![];

        data.extend_from_slice(&signer_index.to_be_bytes());
        data.extend_from_slice(aggregate_key.as_bytes());
        data.extend_from_slice(&round.to_be_bytes());
        data.extend_from_slice(&reward_cycle.to_be_bytes());

        let signer_key = StacksPublicKeyBuffer([0x02; 33]);
        let signer_pubkey = Secp256k1PublicKey::from_slice(signer_key.as_bytes()).unwrap();
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::VoteForAggregateKey as u8,
            data: data.clone(),
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![signer_pubkey],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
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

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let vote_op = VoteForAggregateKeyOp::parse_from_tx(
            1000,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx),
            &sender,
        )
        .expect("Failed to parse vote tx");

        debug!("Vote op test data: {:?}", to_hex(data.as_slice()));

        assert_eq!(vote_op.signer_index, signer_index);
        assert_eq!(&vote_op.aggregate_key, &aggregate_key);
        assert_eq!(vote_op.round, round);
        assert_eq!(vote_op.reward_cycle, reward_cycle);
    }

    #[test]
    fn test_raw_input_signer_key() {
        let aggregate_key = StacksPublicKeyBuffer([0x01; 33]);
        let signer_key = Secp256k1PublicKey::from_hex("040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap();
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::VoteForAggregateKey as u8,
            data: vec![1; 47],
            data_amt: 0,
            inputs: vec![BitcoinTxInput::Raw(BitcoinTxInputRaw {
                scriptSig: hex_bytes("483045022100be57031bf2c095945ba2876e97b3f86ee051643a29b908f22ed45ccf58620103022061e056e5f48c5a51c66604a1ca28e4bfaabab1478424c9bbb396cc6afe5c222e0141040fadbbcea0ff3b05f03195b41cd991d7a0af8bd38559943aec99cbdaf0b22cc806b9a4f07579934774cc0c155e781d45c989f94336765e88a66d91cfb9f060b0").unwrap(),
                witness: vec![],
                tx_ref: (Txid([0; 32]), 0),
            })],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                }),
            }],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let vote_op = VoteForAggregateKeyOp::parse_from_tx(
            1000,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx),
            &sender,
        )
        .expect("Failed to parse vote tx");

        assert_eq!(&vote_op.sender, &sender);
        assert_eq!(
            &vote_op.signer_key,
            &signer_key.to_bytes_compressed().as_slice().into()
        );
    }

    #[test]
    fn test_key_validation() {
        let sender_addr = "ST2QKZ4FKHAH1NQKYKYAYZPY440FEPK7GZ1R5HBP2";
        let sender = StacksAddress::from_string(sender_addr).unwrap();
        let op = VoteForAggregateKeyOp {
            sender,
            reward_cycle: 10,
            round: 1,
            signer_index: 12,
            signer_key: StacksPublicKeyBuffer([0x00; 33]),
            aggregate_key: StacksPublicKeyBuffer([0x00; 33]),
            txid: Txid([10u8; 32]),
            vtxindex: 10,
            block_height: 10,
            burn_header_hash: BurnchainHeaderHash([0x10; 32]),
        };

        match op.check() {
            Ok(_) => panic!("Invalid key should not pass validation"),
            Err(op_error::VoteForAggregateKeyInvalidKey) => (),
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
