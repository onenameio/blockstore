use std::io::{Read, Write};

use stacks_common::codec::{write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress};

use crate::burnchains::{BurnchainBlockHeader, BurnchainTransaction, Txid};
use crate::chainstate::burn::operations::{
    parse_u128_from_be, parse_u32_from_be, parse_u64_from_be, BlockstackOperationType,
    DelegateStxOp, Error as op_error, PreStxOp,
};
use crate::chainstate::burn::Opcodes;
use crate::chainstate::stacks::address::PoxAddress;

struct ParsedData {
    delegated_ustx: u128,
    until_burn_height: Option<u64>,
    reward_addr_index: Option<u32>,
}

impl DelegateStxOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<DelegateStxOp, op_error> {
        DelegateStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
            Wire format:

            0      2  3                  19       24             33
            |------|--|------------------|--------|--------------|
             magic  op delegated ustx       ^       until burn height
                                    reward addr output index

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
             "reward address output index" is encoded as follows: the first byte is an option marker
               - if it is set to 1, the parse function attempts to parse the next 4 bytes as a u32,
                  and this value determines which index in the btc op outputs corresponds to the
                  reward address
               - if it is set to 0, the value is interpreteted as None
             "until burn height" is encoded as follows: the first byte is an option marker
               - if it is set to 1, the parse function attempts to parse the next 8 bytes as a u64
               - if it is set to 0, the value is interpreteted as None

        */
        // magic + op are omitted
        if data.len() < 22 {
            // too short to have required data
            warn!("DELEGATE_STX payload is malformed ({} bytes)", data.len());
            return None;
        }

        let delegated_ustx = parse_u128_from_be(&data[0..16]).unwrap();

        // `reward_addr_index` is type Option<u32>.
        // The first byte of it marks whether it is none or some (0 = none, 1 = some)
        // If the first byte is 1, then the next 4 bytes are parsed as a u32
        let reward_addr_index = {
            if data[16] == 1 {
                let index = parse_u32_from_be(&data[17..21]).unwrap();
                Some(index)
            } else if data[16] == 0 {
                None
            } else {
                warn!("DELEGATE_STX payload is malformed (invalid byte value for reward_addr_index option flag)");
                return None;
            }
        };

        // `until_burn_height` is type Option<u64>.
        // The first byte of it marks whether it is none or some (0 = none, 1 = some)
        // If the first byte is 1, then the next 8 bytes are parsed
        let until_burn_height = {
            if data[21] == 1 {
                if data.len() < 30 {
                    // too short to have required data
                    warn!("DELEGATE_STX payload is malformed ({} bytes)", data.len());
                    return None;
                }
                let burn_height = parse_u64_from_be(&data[22..30]).unwrap();
                Some(burn_height)
            } else if data[21] == 0 {
                None
            } else {
                warn!("DELEGATE_STX payload is malformed (invalid byte value for until_burn_height option flag)");
                return None;
            }
        };

        Some(ParsedData {
            delegated_ustx,
            until_burn_height,
            reward_addr_index,
        })
    }

    pub fn get_sender_txid(tx: &BurnchainTransaction) -> Result<&Txid, op_error> {
        match tx.get_input_tx_ref(0) {
            Some((ref txid, vout)) => {
                if *vout != 1 {
                    warn!("Invalid tx: DelegateStxOp must spend the second output of the PreStxOp");
                    Err(op_error::InvalidInput)
                } else {
                    Ok(txid)
                }
            }
            None => {
                warn!("Invalid tx: DelegateStxOp must have at least one input");
                Err(op_error::InvalidInput)
            }
        }
    }

    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<DelegateStxOp, op_error> {
        let outputs = tx.get_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.is_empty() {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::DelegateStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = DelegateStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let delegate_to = outputs
            .get(0)
            .ok_or(op_error::InvalidInput)?
            .as_ref()
            .ok_or(op_error::InvalidInput)?
            .clone()
            .address
            .coerce_hash_mode()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: output 1 must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;

        // coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = if let Some(index) = data.reward_addr_index {
            if outputs.len() > index as usize {
                Some((
                    index,
                    outputs
                        .get(index as usize)
                        .expect("Index should be in bounds.")
                        .as_ref()
                        .ok_or(op_error::InvalidInput)?
                        .clone()
                        .address
                        .coerce_hash_mode(),
                ))
            } else {
                None
            }
        } else {
            None
        };

        Ok(DelegateStxOp {
            sender: sender.clone(),
            reward_addr,
            delegate_to,
            delegated_ustx: data.delegated_ustx,
            until_burn_height: data.until_burn_height,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    pub fn check(&self) -> Result<(), op_error> {
        if self.delegated_ustx == 0 {
            warn!("Invalid DelegateStxOp, must have positive ustx");
            return Err(op_error::DelegateStxMustBePositive);
        }

        Ok(())
    }
}

impl StacksMessageCodec for DelegateStxOp {
    /*
             Wire format:

            0      2  3                  19       24             33
            |------|--|------------------|--------|--------------|
             magic  op delegated ustx       ^       until burn height
                                    reward addr output index

    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::DelegateStx as u8))?;
        fd.write_all(&self.delegated_ustx.to_be_bytes())
            .map_err(codec_error::WriteError)?;

        if let Some((index, _)) = self.reward_addr {
            fd.write_all(&1_u8.to_be_bytes())
                .map_err(codec_error::WriteError)?;
            fd.write_all(&index.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        } else {
            fd.write_all(&0_u8.to_be_bytes())
                .map_err(codec_error::WriteError)?;
            fd.write_all(&0_u32.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        }

        if let Some(height) = self.until_burn_height {
            fd.write_all(&1_u8.to_be_bytes())
                .map_err(codec_error::WriteError)?;
            fd.write_all(&height.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        } else {
            fd.write_all(&0_u8.to_be_bytes())
                .map_err(codec_error::WriteError)?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<DelegateStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::address::AddressHashMode;
    use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksAddress};
    use stacks_common::util::hash::*;

    use crate::burnchains::bitcoin::address::{
        BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType,
    };
    use crate::burnchains::bitcoin::{
        BitcoinInputType, BitcoinNetworkType, BitcoinTransaction, BitcoinTxInput,
        BitcoinTxInputStructured, BitcoinTxOutput,
    };
    use crate::burnchains::{BurnchainTransaction, Txid};
    use crate::chainstate::burn::operations::{DelegateStxOp, Error as op_error};
    use crate::chainstate::burn::Opcodes;
    use crate::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};

    // Parse a DelegateStx op in which the height is set to None.
    #[test]
    fn test_parse_delegate_stx_height_is_none() {
        let mut data = vec![1; 22];
        // Set the reward addr to be the 2nd output
        for i in 17..=19 {
            data[i] = 0;
        }
        // Set the 21th byte to none, which signifies that `until_burn_height` is None.
        data[21] = 0;
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
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
                        bytes: Hash160([3; 20]),
                    }
                    .into(),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([4; 20]),
                    }
                    .into(),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &Some((
                1,
                PoxAddress::Standard(
                    StacksAddress::from_legacy_bitcoin_address(
                        &tx.outputs[1].address.clone().expect_legacy()
                    ),
                    Some(AddressHashMode::SerializeP2PKH)
                )
            ))
        );
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.delegate_to, StacksAddress::new(22, Hash160([2u8; 20])));
        assert_eq!(op.until_burn_height, None);
    }

    // Parse a DelegateStx op in which the reward pox address is None.
    #[test]
    fn test_parse_delegate_stx_pox_addr_is_none() {
        // Set the option flag for `reward_addr_index` to None.
        let mut data = vec![1; 80];
        data[16] = 0;
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
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
                    address: LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }
                    .into(),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([4; 20]),
                    }
                    .into(),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(&op.reward_addr, &None);
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.delegate_to, StacksAddress::new(22, Hash160([2u8; 20])));
        assert_eq!(op.until_burn_height, Some(u64::from_be_bytes([1; 8])));
    }

    // Fail to parse a DelegateStx op that has a too-short data field.
    #[test]
    fn test_parse_delegate_stx_too_short() {
        // Data is shorter than length 22.
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
            data: vec![1; 20],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                }
                .into(),
            }],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let err = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap_err();
        assert!(match err {
            op_error::ParseError => true,
            _ => false,
        });

        // Data is length 17. The 16th byte is set to 1, which signals that until_burn_height
        // is Some(u64), so the deserialize function expects another 8 bytes
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
            data: vec![1; 17],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                }
                .into(),
            }],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let err = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap_err();
        assert!(match err {
            op_error::ParseError => true,
            _ => false,
        });
    }

    // This test sets the op code to the op code of the StackStx
    // operation. Thus, attempting to parse the tx as a DelegateStx
    // operation will fail.
    #[test]
    fn test_parse_delegate_stx_wrong_op_code() {
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
            outputs: vec![BitcoinTxOutput {
                units: 10,
                address: LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([2; 20]),
                }
                .into(),
            }],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let err = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap_err();

        assert!(match err {
            op_error::InvalidInput => true,
            _ => false,
        });
    }

    // This test constructs a tx with zero outputs, which causes
    // an error during parsing, since the parser expects at least
    // one output.
    #[test]
    fn test_parse_delegate_stx_zero_outputs() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let err = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap_err();

        assert!(match err {
            op_error::InvalidInput => true,
            _ => false,
        });
    }

    // Parse a normal DelegateStx op in which the reward_addr is set to output index 2.
    #[test]
    fn test_parse_delegate_stx() {
        let mut data = vec![1; 80];
        // Perform these modifications in order for the reward_addr_index to be 2.
        data[17] = 0;
        data[18] = 0;
        data[19] = 0;
        data[20] = 2;

        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
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
                        bytes: Hash160([3; 20]),
                    }
                    .into(),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([4; 20]),
                    }
                    .into(),
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &Some((
                2,
                PoxAddress::Standard(
                    StacksAddress::from_legacy_bitcoin_address(
                        &tx.outputs[2].address.clone().expect_legacy()
                    ),
                    Some(AddressHashMode::SerializeP2PKH)
                )
            ))
        );
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.delegate_to, StacksAddress::new(22, Hash160([2u8; 20])));
        assert_eq!(op.until_burn_height, Some(u64::from_be_bytes([1; 8])));
    }
}
