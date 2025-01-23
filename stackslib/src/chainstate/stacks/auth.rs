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

use stacks_common::address::{public_keys_to_address_hash, AddressHashMode};
use stacks_common::codec::{
    read_next, write_next, Error as codec_error, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::types::chainstate::StacksAddress;
use stacks_common::types::{StacksEpochId, StacksPublicKeyBuffer};
use stacks_common::util::hash::{to_hex, Hash160, Sha512Trunc256Sum};
use stacks_common::util::retry::{BoundReader, RetryReader};
use stacks_common::util::secp256k1::{MessageSignature, MESSAGE_SIGNATURE_ENCODED_SIZE};

use crate::burnchains::{PrivateKey, PublicKey, Txid};
use crate::chainstate::stacks::{
    Error, MultisigHashMode, MultisigSpendingCondition, OrderIndependentMultisigHashMode,
    OrderIndependentMultisigSpendingCondition, SinglesigHashMode, SinglesigSpendingCondition,
    StacksPrivateKey, StacksPublicKey, TransactionAuth, TransactionAuthField,
    TransactionAuthFieldID, TransactionAuthFlags, TransactionPublicKeyEncoding,
    TransactionSpendingCondition, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::net::{Error as net_error, STACKS_PUBLIC_KEY_ENCODED_SIZE};

impl StacksMessageCodec for TransactionAuthField {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionAuthField::PublicKey(ref pubk) => {
                let field_id = if pubk.compressed() {
                    TransactionAuthFieldID::PublicKeyCompressed
                } else {
                    TransactionAuthFieldID::PublicKeyUncompressed
                };

                let pubkey_buf = StacksPublicKeyBuffer::from_public_key(pubk);

                write_next(fd, &(field_id as u8))?;
                write_next(fd, &pubkey_buf)?;
            }
            TransactionAuthField::Signature(ref key_encoding, ref sig) => {
                let field_id = if *key_encoding == TransactionPublicKeyEncoding::Compressed {
                    TransactionAuthFieldID::SignatureCompressed
                } else {
                    TransactionAuthFieldID::SignatureUncompressed
                };

                write_next(fd, &(field_id as u8))?;
                write_next(fd, sig)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionAuthField, codec_error> {
        let field_id: u8 = read_next(fd)?;
        let field = match field_id {
            x if x == TransactionAuthFieldID::PublicKeyCompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| codec_error::DeserializeError(e.into()))?;
                pubkey.set_compressed(true);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::PublicKeyUncompressed as u8 => {
                let pubkey_buf: StacksPublicKeyBuffer = read_next(fd)?;
                let mut pubkey = pubkey_buf
                    .to_public_key()
                    .map_err(|e| codec_error::DeserializeError(e.into()))?;
                pubkey.set_compressed(false);

                TransactionAuthField::PublicKey(pubkey)
            }
            x if x == TransactionAuthFieldID::SignatureCompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, sig)
            }
            x if x == TransactionAuthFieldID::SignatureUncompressed as u8 => {
                let sig: MessageSignature = read_next(fd)?;
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, sig)
            }
            _ => {
                test_debug!("Failed to deserialize auth field ID {}", field_id);
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse auth field: unkonwn auth field ID {}",
                    field_id
                )));
            }
        };
        Ok(field)
    }
}

impl StacksMessageCodec for MultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<MultisigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = MultisigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        let signatures_required: u16 = read_next(fd)?;

        // read and decode _exactly_ num_signatures signature buffers
        let mut num_sigs_given: u16 = 0;
        let mut have_uncompressed = false;
        for f in fields.iter() {
            match *f {
                TransactionAuthField::Signature(ref key_encoding, _) => {
                    num_sigs_given =
                        num_sigs_given
                            .checked_add(1)
                            .ok_or(codec_error::DeserializeError(
                                "Failed to parse multisig spending condition: too many signatures"
                                    .to_string(),
                            ))?;
                    if *key_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }
                }
                TransactionAuthField::PublicKey(ref pubk) => {
                    if !pubk.compressed() {
                        have_uncompressed = true;
                    }
                }
            };
        }

        // must be given the right number of signatures
        if num_sigs_given != signatures_required {
            test_debug!(
                "Failed to deserialize multisig spending condition: got {} sigs, expected {}",
                num_sigs_given,
                signatures_required
            );
            return Err(codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: got {} sigs, expected {}",
                num_sigs_given, signatures_required
            )));
        }

        // must all be compressed if we're using P2WSH
        if have_uncompressed && hash_mode == MultisigHashMode::P2WSH {
            test_debug!(
                "Failed to deserialize multisig spending condition: expected compressed keys only"
            );
            return Err(codec_error::DeserializeError(
                "Failed to parse multisig spending condition: expected compressed keys only"
                    .to_string(),
            ));
        }

        Ok(MultisigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            fields,
            signatures_required,
        })
    }
}

impl MultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: StacksPublicKey) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            bytes: self.signer.clone(),
        }
    }

    pub fn address_testnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_TESTNET_MULTISIG,
            bytes: self.signer.clone(),
        }
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, net_error> {
        let mut pubkeys = vec![];
        let mut cur_sighash = initial_sighash.clone();
        let mut num_sigs: u16 = 0;
        let mut have_uncompressed = false;
        for field in self.fields.iter() {
            let pubkey = match field {
                TransactionAuthField::PublicKey(ref pubkey) => {
                    if !pubkey.compressed() {
                        have_uncompressed = true;
                    }
                    pubkey.clone()
                }
                TransactionAuthField::Signature(ref pubkey_encoding, ref sigbuf) => {
                    if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }

                    let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(
                        &cur_sighash,
                        cond_code,
                        self.tx_fee,
                        self.nonce,
                        pubkey_encoding,
                        sigbuf,
                    )?;
                    cur_sighash = next_sighash;
                    num_sigs = num_sigs
                        .checked_add(1)
                        .ok_or(net_error::VerifyingError("Too many signatures".to_string()))?;
                    pubkey
                }
            };
            pubkeys.push(pubkey);
        }

        if num_sigs != self.signatures_required {
            return Err(net_error::VerifyingError(
                "Incorrect number of signatures".to_string(),
            ));
        }

        if have_uncompressed && self.hash_mode == MultisigHashMode::P2WSH {
            return Err(net_error::VerifyingError(
                "Uncompressed keys are not allowed in this hash mode".to_string(),
            ));
        }

        let addr_bytes = match StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            self.signatures_required as usize,
            &pubkeys,
        ) {
            Some(a) => a.bytes,
            None => {
                return Err(net_error::VerifyingError(
                    "Failed to generate address from public keys".to_string(),
                ));
            }
        };

        if addr_bytes != self.signer {
            return Err(net_error::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                addr_bytes, self.signer
            )));
        }

        Ok(cur_sighash)
    }
}

impl StacksMessageCodec for OrderIndependentMultisigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &self.fields)?;
        write_next(fd, &self.signatures_required)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<OrderIndependentMultisigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse multisig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;
        let fields: Vec<TransactionAuthField> = {
            let mut bound_read = BoundReader::from_reader(fd, MAX_MESSAGE_LEN as u64);
            read_next(&mut bound_read)
        }?;

        let signatures_required: u16 = read_next(fd)?;

        // read and decode _exactly_ num_signatures signature buffers
        let mut num_sigs_given: u16 = 0;
        let mut have_uncompressed = false;
        for f in fields.iter() {
            match *f {
                TransactionAuthField::Signature(ref key_encoding, _) => {
                    num_sigs_given =
                        num_sigs_given
                            .checked_add(1)
                            .ok_or(codec_error::DeserializeError(
                                "Failed to parse order independent multisig spending condition: too many signatures"
                                    .to_string(),
                            ))?;
                    if *key_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }
                }
                TransactionAuthField::PublicKey(ref pubk) => {
                    if !pubk.compressed() {
                        have_uncompressed = true;
                    }
                }
            };
        }

        // must be given the right number of signatures
        if num_sigs_given < signatures_required {
            let msg = format!(
                "Failed to deserialize order independent multisig spending condition: got {num_sigs_given} sigs, expected at least {signatures_required}"
            );
            test_debug!("{msg}");
            return Err(codec_error::DeserializeError(msg));
        }

        // must all be compressed if we're using P2WSH
        if have_uncompressed && hash_mode == OrderIndependentMultisigHashMode::P2WSH {
            let msg = "Failed to deserialize order independent multisig spending condition: expected compressed keys only".to_string();
            test_debug!("{msg}");
            return Err(codec_error::DeserializeError(msg));
        }

        Ok(OrderIndependentMultisigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            fields,
            signatures_required,
        })
    }
}

impl OrderIndependentMultisigSpendingCondition {
    pub fn push_signature(
        &mut self,
        key_encoding: TransactionPublicKeyEncoding,
        signature: MessageSignature,
    ) {
        self.fields
            .push(TransactionAuthField::Signature(key_encoding, signature));
    }

    pub fn push_public_key(&mut self, public_key: StacksPublicKey) {
        self.fields
            .push(TransactionAuthField::PublicKey(public_key));
    }

    pub fn pop_auth_field(&mut self) -> Option<TransactionAuthField> {
        self.fields.pop()
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_MAINNET_MULTISIG,
            bytes: self.signer.clone(),
        }
    }

    pub fn address_testnet(&self) -> StacksAddress {
        StacksAddress {
            version: C32_ADDRESS_VERSION_TESTNET_MULTISIG,
            bytes: self.signer.clone(),
        }
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, net_error> {
        let mut pubkeys = vec![];
        let mut num_sigs: u16 = 0;
        let mut have_uncompressed = false;
        for field in self.fields.iter() {
            let pubkey = match field {
                TransactionAuthField::PublicKey(ref pubkey) => {
                    if !pubkey.compressed() {
                        have_uncompressed = true;
                    }
                    pubkey.clone()
                }
                TransactionAuthField::Signature(ref pubkey_encoding, ref sigbuf) => {
                    if *pubkey_encoding == TransactionPublicKeyEncoding::Uncompressed {
                        have_uncompressed = true;
                    }

                    let (pubkey, _next_sighash) = TransactionSpendingCondition::next_verification(
                        &initial_sighash,
                        cond_code,
                        self.tx_fee,
                        self.nonce,
                        pubkey_encoding,
                        sigbuf,
                    )?;
                    num_sigs = num_sigs
                        .checked_add(1)
                        .ok_or(net_error::VerifyingError("Too many signatures".to_string()))?;
                    pubkey
                }
            };
            pubkeys.push(pubkey);
        }

        if num_sigs < self.signatures_required {
            return Err(net_error::VerifyingError(format!(
                "Not enough signatures. Got {num_sigs}, expected at least {req}",
                req = self.signatures_required
            )));
        }

        if have_uncompressed && self.hash_mode == OrderIndependentMultisigHashMode::P2WSH {
            return Err(net_error::VerifyingError(
                "Uncompressed keys are not allowed in this hash mode".to_string(),
            ));
        }

        let addr_bytes = match StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            self.signatures_required as usize,
            &pubkeys,
        ) {
            Some(a) => a.bytes,
            None => {
                return Err(net_error::VerifyingError(
                    "Failed to generate address from public keys".to_string(),
                ));
            }
        };

        if addr_bytes != self.signer {
            return Err(net_error::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                addr_bytes, self.signer
            )));
        }

        Ok(initial_sighash.clone())
    }
}

impl StacksMessageCodec for SinglesigSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(self.hash_mode.clone() as u8))?;
        write_next(fd, &self.signer)?;
        write_next(fd, &self.nonce)?;
        write_next(fd, &self.tx_fee)?;
        write_next(fd, &(self.key_encoding.clone() as u8))?;
        write_next(fd, &self.signature)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<SinglesigSpendingCondition, codec_error> {
        let hash_mode_u8: u8 = read_next(fd)?;
        let hash_mode = SinglesigHashMode::from_u8(hash_mode_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse singlesig spending condition: unknown hash mode {}",
                hash_mode_u8
            )),
        )?;

        let signer: Hash160 = read_next(fd)?;
        let nonce: u64 = read_next(fd)?;
        let tx_fee: u64 = read_next(fd)?;

        let key_encoding_u8: u8 = read_next(fd)?;
        let key_encoding = TransactionPublicKeyEncoding::from_u8(key_encoding_u8).ok_or(
            codec_error::DeserializeError(format!(
                "Failed to parse singlesig spending condition: unknown key encoding {}",
                key_encoding_u8
            )),
        )?;

        let signature: MessageSignature = read_next(fd)?;

        // sanity check -- must be compressed if we're using p2wpkh
        if hash_mode == SinglesigHashMode::P2WPKH
            && key_encoding != TransactionPublicKeyEncoding::Compressed
        {
            test_debug!("Incompatible hashing mode and key encoding");
            return Err(codec_error::DeserializeError("Failed to parse singlesig spending condition: incomaptible hash mode and key encoding".to_string()));
        }

        Ok(SinglesigSpendingCondition {
            signer,
            nonce,
            tx_fee,
            hash_mode,
            key_encoding,
            signature,
        })
    }
}

impl SinglesigSpendingCondition {
    pub fn set_signature(&mut self, signature: MessageSignature) {
        self.signature = signature;
    }

    pub fn pop_signature(&mut self) -> Option<TransactionAuthField> {
        if self.signature == MessageSignature::empty() {
            return None;
        }

        let ret = self.signature.clone();
        self.signature = MessageSignature::empty();

        return Some(TransactionAuthField::Signature(
            self.key_encoding.clone(),
            ret,
        ));
    }

    pub fn address_mainnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_MAINNET_MULTISIG,
        };
        StacksAddress {
            version,
            bytes: self.signer.clone(),
        }
    }

    pub fn address_testnet(&self) -> StacksAddress {
        let version = match self.hash_mode {
            SinglesigHashMode::P2PKH => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            SinglesigHashMode::P2WPKH => C32_ADDRESS_VERSION_TESTNET_MULTISIG,
        };
        StacksAddress {
            version,
            bytes: self.signer.clone(),
        }
    }

    /// Authenticate a spending condition against an initial sighash.
    /// In doing so, recover all public keys and verify that they hash to the signer
    /// via the given hash mode.
    /// Returns the final sighash
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, net_error> {
        let (pubkey, next_sighash) = TransactionSpendingCondition::next_verification(
            initial_sighash,
            cond_code,
            self.tx_fee,
            self.nonce,
            &self.key_encoding,
            &self.signature,
        )?;
        let addr_bytes = match StacksAddress::from_public_keys(
            0,
            &self.hash_mode.to_address_hash_mode(),
            1,
            &vec![pubkey],
        ) {
            Some(a) => a.bytes,
            None => {
                return Err(net_error::VerifyingError(
                    "Failed to generate address from public key".to_string(),
                ));
            }
        };

        if addr_bytes != self.signer {
            return Err(net_error::VerifyingError(format!(
                "Signer hash does not equal hash of public key(s): {} != {}",
                &addr_bytes, &self.signer
            )));
        }

        Ok(next_sighash)
    }
}

impl StacksMessageCodec for TransactionSpendingCondition {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                data.consensus_serialize(fd)?;
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                data.consensus_serialize(fd)?;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.consensus_serialize(fd)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(
        fd: &mut R,
    ) -> Result<TransactionSpendingCondition, codec_error> {
        // peek the hash mode byte
        let hash_mode_u8: u8 = read_next(fd)?;
        let peek_buf = [hash_mode_u8];
        let mut rrd = peek_buf.chain(fd);
        let cond = {
            if SinglesigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond = SinglesigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::Singlesig(cond)
            } else if MultisigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond = MultisigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::Multisig(cond)
            } else if OrderIndependentMultisigHashMode::from_u8(hash_mode_u8).is_some() {
                let cond =
                    OrderIndependentMultisigSpendingCondition::consensus_deserialize(&mut rrd)?;
                TransactionSpendingCondition::OrderIndependentMultisig(cond)
            } else {
                test_debug!("Invalid address hash mode {}", hash_mode_u8);
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse spending condition: invalid hash mode {}",
                    hash_mode_u8
                )));
            }
        };

        Ok(cond)
    }
}

impl TransactionSpendingCondition {
    pub fn new_singlesig_p2pkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let key_encoding = if pubkey.compressed() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };
        let signer_addr =
            StacksAddress::from_public_keys(0, &AddressHashMode::SerializeP2PKH, 1, &vec![pubkey])?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding,
                signature: MessageSignature::empty(),
            },
        ))
    }

    pub fn new_singlesig_p2wpkh(pubkey: StacksPublicKey) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WPKH,
            1,
            &vec![pubkey],
        )?;

        Some(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature::empty(),
            },
        ))
    }

    pub fn new_multisig_p2sh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_order_independent_p2sh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2SH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_order_independent_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::OrderIndependentMultisig(
            OrderIndependentMultisigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    pub fn new_multisig_p2wsh(
        num_sigs: u16,
        pubkeys: Vec<StacksPublicKey>,
    ) -> Option<TransactionSpendingCondition> {
        let signer_addr = StacksAddress::from_public_keys(
            0,
            &AddressHashMode::SerializeP2WSH,
            usize::from(num_sigs),
            &pubkeys,
        )?;

        Some(TransactionSpendingCondition::Multisig(
            MultisigSpendingCondition {
                signer: signer_addr.bytes,
                nonce: 0,
                tx_fee: 0,
                hash_mode: MultisigHashMode::P2WSH,
                fields: vec![],
                signatures_required: num_sigs,
            },
        ))
    }

    /// When committing to the fact that a transaction is sponsored, the origin doesn't know
    /// anything else.  Instead, it commits to this sentinel value as its sponsor.
    /// It is intractable to calculate a private key that could generate this.
    pub fn new_initial_sighash() -> TransactionSpendingCondition {
        TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
            signer: Hash160([0u8; 20]),
            nonce: 0,
            tx_fee: 0,
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            signature: MessageSignature::empty(),
        })
    }

    pub fn num_signatures(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                if data.signature != MessageSignature::empty() {
                    1
                } else {
                    0
                }
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                let mut num_sigs: u16 = 0;
                for field in data.fields.iter() {
                    if field.is_signature() {
                        num_sigs = num_sigs
                            .checked_add(1)
                            .expect("Unreasonable amount of signatures"); // something is seriously wrong if this fails
                    }
                }
                num_sigs
            }
        }
    }

    pub fn signatures_required(&self) -> u16 {
        match *self {
            TransactionSpendingCondition::Singlesig(_) => 1,
            TransactionSpendingCondition::Multisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.signatures_required
            }
        }
    }

    pub fn nonce(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.nonce,
            TransactionSpendingCondition::Multisig(ref data) => data.nonce,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.nonce,
        }
    }

    pub fn tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.tx_fee,
            TransactionSpendingCondition::Multisig(ref data) => data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => data.tx_fee,
        }
    }

    pub fn set_nonce(&mut self, n: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.nonce = n;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.nonce = n;
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = tx_fee;
            }
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionSpendingCondition::Singlesig(ref singlesig_data) => singlesig_data.tx_fee,
            TransactionSpendingCondition::Multisig(ref multisig_data) => multisig_data.tx_fee,
            TransactionSpendingCondition::OrderIndependentMultisig(ref multisig_data) => {
                multisig_data.tx_fee
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_mainnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_mainnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_mainnet()
            }
        }
    }

    /// Get the mainnet account address of the spending condition
    pub fn address_testnet(&self) -> StacksAddress {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::Multisig(ref data) => data.address_testnet(),
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.address_testnet()
            }
        }
    }

    /// Get the address for an account, given the network flag
    pub fn get_address(&self, mainnet: bool) -> StacksAddress {
        if mainnet {
            self.address_mainnet()
        } else {
            self.address_testnet()
        }
    }

    /// Clear fee rate, nonces, signatures, and public keys
    pub fn clear(&mut self) {
        match *self {
            TransactionSpendingCondition::Singlesig(ref mut singlesig_data) => {
                singlesig_data.tx_fee = 0;
                singlesig_data.nonce = 0;
                singlesig_data.signature = MessageSignature::empty();
            }
            TransactionSpendingCondition::Multisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref mut multisig_data) => {
                multisig_data.tx_fee = 0;
                multisig_data.nonce = 0;
                multisig_data.fields.clear();
            }
        }
    }

    pub fn make_sighash_presign(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
    ) -> Txid {
        // new hash combines the previous hash and all the new data this signature will add.  This
        // includes:
        // * the previous hash
        // * the auth flag
        // * the fee rate (big-endian 8-byte number)
        // * nonce (big-endian 8-byte number)
        let new_tx_hash_bits_len = 32 + 1 + 8 + 8;
        let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);

        new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
        new_tx_hash_bits.extend_from_slice(&[*cond_code as u8]);
        new_tx_hash_bits.extend_from_slice(&tx_fee.to_be_bytes());
        new_tx_hash_bits.extend_from_slice(&nonce.to_be_bytes());

        assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

        let next_sighash = Txid::from_sighash_bytes(&new_tx_hash_bits);
        next_sighash
    }

    pub fn make_sighash_postsign(
        cur_sighash: &Txid,
        pubkey: &StacksPublicKey,
        sig: &MessageSignature,
    ) -> Txid {
        // new hash combines the previous hash and all the new data this signature will add.  This
        // includes:
        // * the public key compression flag
        // * the signature
        let new_tx_hash_bits_len = 32 + 1 + MESSAGE_SIGNATURE_ENCODED_SIZE;
        let mut new_tx_hash_bits = Vec::with_capacity(new_tx_hash_bits_len as usize);
        let pubkey_encoding = if pubkey.compressed() {
            TransactionPublicKeyEncoding::Compressed
        } else {
            TransactionPublicKeyEncoding::Uncompressed
        };

        new_tx_hash_bits.extend_from_slice(cur_sighash.as_bytes());
        new_tx_hash_bits.extend_from_slice(&[pubkey_encoding as u8]);
        new_tx_hash_bits.extend_from_slice(sig.as_bytes());

        assert!(new_tx_hash_bits.len() == new_tx_hash_bits_len as usize);

        let next_sighash = Txid::from_sighash_bytes(&new_tx_hash_bits);
        next_sighash
    }

    /// Linear-complexity signing algorithm -- we sign a rolling hash over all data committed to by
    /// the previous signer (instead of naively re-serializing the transaction each time), as well
    /// as over new data provided by this key (excluding its own public key or signature, which
    /// are authenticated by the spending condition's key hash).
    /// Calculates and returns the next signature and sighash, which the subsequent private key
    /// must sign.
    pub fn next_signature(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        privk: &StacksPrivateKey,
    ) -> Result<(MessageSignature, Txid), net_error> {
        let sighash_presign = TransactionSpendingCondition::make_sighash_presign(
            cur_sighash,
            cond_code,
            tx_fee,
            nonce,
        );

        // sign the current hash
        let sig = privk
            .sign(sighash_presign.as_bytes())
            .map_err(|se| net_error::SigningError(se.to_string()))?;

        let pubk = StacksPublicKey::from_private(privk);
        let next_sighash =
            TransactionSpendingCondition::make_sighash_postsign(&sighash_presign, &pubk, &sig);

        Ok((sig, next_sighash))
    }

    /// Linear-complexity verifying algorithm -- we verify a rolling hash over all data committed
    /// to by order of signers (instead of re-serializing the tranasction each time).
    /// Calculates the next sighash and public key, which the next verifier must verify.
    /// Used by StacksTransaction::verify*
    pub fn next_verification(
        cur_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
        tx_fee: u64,
        nonce: u64,
        key_encoding: &TransactionPublicKeyEncoding,
        sig: &MessageSignature,
    ) -> Result<(StacksPublicKey, Txid), net_error> {
        let sighash_presign = TransactionSpendingCondition::make_sighash_presign(
            cur_sighash,
            cond_code,
            tx_fee,
            nonce,
        );

        // verify the current signature
        let mut pubk = StacksPublicKey::recover_to_pubkey(sighash_presign.as_bytes(), sig)
            .map_err(|ve| net_error::VerifyingError(ve.to_string()))?;

        match key_encoding {
            TransactionPublicKeyEncoding::Compressed => pubk.set_compressed(true),
            TransactionPublicKeyEncoding::Uncompressed => pubk.set_compressed(false),
        };

        // what's the next sighash going to be?
        let next_sighash =
            TransactionSpendingCondition::make_sighash_postsign(&sighash_presign, &pubk, sig);
        Ok((pubk, next_sighash))
    }

    /// Verify all signatures
    pub fn verify(
        &self,
        initial_sighash: &Txid,
        cond_code: &TransactionAuthFlags,
    ) -> Result<Txid, net_error> {
        match *self {
            TransactionSpendingCondition::Singlesig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
            TransactionSpendingCondition::Multisig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
            TransactionSpendingCondition::OrderIndependentMultisig(ref data) => {
                data.verify(initial_sighash, cond_code)
            }
        }
    }

    /// Checks if this TransactionSpendingCondition is supported in the passed epoch
    /// OrderIndependent multisig is not supported before epoch 3.0
    pub fn is_supported_in_epoch(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            TransactionSpendingCondition::Singlesig(..)
            | TransactionSpendingCondition::Multisig(..) => true,
            TransactionSpendingCondition::OrderIndependentMultisig(..) => {
                epoch_id >= StacksEpochId::Epoch30
            }
        }
    }
}

impl StacksMessageCodec for TransactionAuth {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthStandard as u8))?;
                write_next(fd, origin_condition)?;
            }
            TransactionAuth::Sponsored(ref origin_condition, ref sponsor_condition) => {
                write_next(fd, &(TransactionAuthFlags::AuthSponsored as u8))?;
                write_next(fd, origin_condition)?;
                write_next(fd, sponsor_condition)?;
            }
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TransactionAuth, codec_error> {
        let type_id: u8 = read_next(fd)?;
        let auth = match type_id {
            x if x == TransactionAuthFlags::AuthStandard as u8 => {
                let origin_auth: TransactionSpendingCondition = read_next(fd)?;
                TransactionAuth::Standard(origin_auth)
            }
            x if x == TransactionAuthFlags::AuthSponsored as u8 => {
                let origin_auth: TransactionSpendingCondition = read_next(fd)?;
                let sponsor_auth: TransactionSpendingCondition = read_next(fd)?;
                TransactionAuth::Sponsored(origin_auth, sponsor_auth)
            }
            _ => {
                test_debug!("Unrecognized transaction auth flags {:?}", type_id);
                return Err(codec_error::DeserializeError(format!(
                    "Failed to parse transaction authorization: unrecognized auth flags {}",
                    type_id
                )));
            }
        };
        Ok(auth)
    }
}

impl TransactionAuth {
    pub fn from_p2pkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(
            privk,
        )) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_p2sh(privks: &[StacksPrivateKey], num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2sh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_order_independent_p2sh(
        privks: &[StacksPrivateKey],
        num_sigs: u16,
    ) -> Option<TransactionAuth> {
        let pubks = privks.iter().map(StacksPublicKey::from_private).collect();

        TransactionSpendingCondition::new_multisig_order_independent_p2sh(num_sigs, pubks)
            .map(TransactionAuth::Standard)
    }

    pub fn from_order_independent_p2wsh(
        privks: &[StacksPrivateKey],
        num_sigs: u16,
    ) -> Option<TransactionAuth> {
        let pubks = privks.iter().map(StacksPublicKey::from_private).collect();

        TransactionSpendingCondition::new_multisig_order_independent_p2wsh(num_sigs, pubks)
            .map(TransactionAuth::Standard)
    }

    pub fn from_p2wpkh(privk: &StacksPrivateKey) -> Option<TransactionAuth> {
        match TransactionSpendingCondition::new_singlesig_p2wpkh(StacksPublicKey::from_private(
            privk,
        )) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    pub fn from_p2wsh(privks: &[StacksPrivateKey], num_sigs: u16) -> Option<TransactionAuth> {
        let mut pubks = vec![];
        for privk in privks.iter() {
            pubks.push(StacksPublicKey::from_private(privk));
        }

        match TransactionSpendingCondition::new_multisig_p2wsh(num_sigs, pubks) {
            Some(auth) => Some(TransactionAuth::Standard(auth)),
            None => None,
        }
    }

    /// merge two standard auths into a sponsored auth.
    /// build them with the above helper methods
    pub fn into_sponsored(self, sponsor_auth: TransactionAuth) -> Option<TransactionAuth> {
        match (self, sponsor_auth) {
            (TransactionAuth::Standard(sc), TransactionAuth::Standard(sp)) => {
                Some(TransactionAuth::Sponsored(sc, sp))
            }
            (_, _) => None,
        }
    }

    /// Directly set the sponsor spending condition
    pub fn set_sponsor(
        &mut self,
        sponsor_spending_cond: TransactionSpendingCondition,
    ) -> Result<(), Error> {
        match *self {
            TransactionAuth::Sponsored(_, ref mut ssc) => {
                *ssc = sponsor_spending_cond;
                Ok(())
            }
            _ => Err(Error::IncompatibleSpendingConditionError),
        }
    }

    pub fn is_standard(&self) -> bool {
        match *self {
            TransactionAuth::Standard(_) => true,
            _ => false,
        }
    }

    pub fn is_sponsored(&self) -> bool {
        match *self {
            TransactionAuth::Sponsored(_, _) => true,
            _ => false,
        }
    }

    /// When beginning to sign a sponsored transaction, the origin account will not commit to any
    /// information about the sponsor (only that it is sponsored).  It does so by using sentinel
    /// sponsored account information.
    pub fn into_initial_sighash_auth(self) -> TransactionAuth {
        match self {
            TransactionAuth::Standard(mut origin) => {
                origin.clear();
                TransactionAuth::Standard(origin)
            }
            TransactionAuth::Sponsored(mut origin, _) => {
                origin.clear();
                TransactionAuth::Sponsored(
                    origin,
                    TransactionSpendingCondition::new_initial_sighash(),
                )
            }
        }
    }

    pub fn origin(&self) -> &TransactionSpendingCondition {
        match *self {
            TransactionAuth::Standard(ref s) => s,
            TransactionAuth::Sponsored(ref s, _) => s,
        }
    }

    pub fn get_origin_nonce(&self) -> u64 {
        self.origin().nonce()
    }

    pub fn set_origin_nonce(&mut self, n: u64) {
        match *self {
            TransactionAuth::Standard(ref mut s) => s.set_nonce(n),
            TransactionAuth::Sponsored(ref mut s, _) => s.set_nonce(n),
        }
    }

    pub fn sponsor(&self) -> Option<&TransactionSpendingCondition> {
        match *self {
            TransactionAuth::Standard(_) => None,
            TransactionAuth::Sponsored(_, ref s) => Some(s),
        }
    }

    pub fn get_sponsor_nonce(&self) -> Option<u64> {
        match self.sponsor() {
            None => None,
            Some(s) => Some(s.nonce()),
        }
    }

    pub fn set_sponsor_nonce(&mut self, n: u64) -> Result<(), Error> {
        match *self {
            TransactionAuth::Standard(_) => Err(Error::IncompatibleSpendingConditionError),
            TransactionAuth::Sponsored(_, ref mut s) => {
                s.set_nonce(n);
                Ok(())
            }
        }
    }

    pub fn set_tx_fee(&mut self, tx_fee: u64) {
        match *self {
            TransactionAuth::Standard(ref mut s) => s.set_tx_fee(tx_fee),
            TransactionAuth::Sponsored(_, ref mut s) => s.set_tx_fee(tx_fee),
        }
    }

    pub fn get_tx_fee(&self) -> u64 {
        match *self {
            TransactionAuth::Standard(ref s) => s.get_tx_fee(),
            TransactionAuth::Sponsored(_, ref s) => s.get_tx_fee(),
        }
    }

    pub fn verify_origin(&self, initial_sighash: &Txid) -> Result<Txid, net_error> {
        match *self {
            TransactionAuth::Standard(ref origin_condition) => {
                origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)
            }
            TransactionAuth::Sponsored(ref origin_condition, _) => {
                origin_condition.verify(initial_sighash, &TransactionAuthFlags::AuthStandard)
            }
        }
    }

    pub fn verify(&self, initial_sighash: &Txid) -> Result<(), net_error> {
        let origin_sighash = self.verify_origin(initial_sighash)?;
        match *self {
            TransactionAuth::Standard(_) => Ok(()),
            TransactionAuth::Sponsored(_, ref sponsor_condition) => sponsor_condition
                .verify(&origin_sighash, &TransactionAuthFlags::AuthSponsored)
                .map(|_sigh| ()),
        }
    }

    /// Clear out all transaction auth fields, nonces, and fee rates from the spending condition(s).
    pub fn clear(&mut self) {
        match *self {
            TransactionAuth::Standard(ref mut origin_condition) => {
                origin_condition.clear();
            }
            TransactionAuth::Sponsored(ref mut origin_condition, ref mut sponsor_condition) => {
                origin_condition.clear();
                sponsor_condition.clear();
            }
        }
    }

    /// Checks if this TransactionAuth is supported in the passed epoch
    /// OrderIndependent multisig is not supported before epoch 3.0
    pub fn is_supported_in_epoch(&self, epoch_id: StacksEpochId) -> bool {
        match self {
            TransactionAuth::Standard(origin) => origin.is_supported_in_epoch(epoch_id),
            TransactionAuth::Sponsored(origin, sponsor) => {
                origin.is_supported_in_epoch(epoch_id) && sponsor.is_supported_in_epoch(epoch_id)
            }
        }
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod test {
    use stacks_common::types::StacksEpochId::Epoch30;
    use super::*;
    use crate::chainstate::stacks::{StacksPublicKey as PubKey, *};
    use crate::net::codec::test::check_codec_and_corruption;
    use crate::net::codec::*;
    use crate::net::*;

    #[test]
    fn tx_stacks_spending_condition_p2pkh() {
        // p2pkh
        let spending_condition_p2pkh_uncompressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Uncompressed,
            nonce: 123,
            tx_fee: 456,
            signature: MessageSignature::from_raw(&[0xff; 65]),
        };

        let spending_condition_p2pkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding,
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        let spending_condition_p2pkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2PKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            tx_fee: 456,
            signature: MessageSignature::from_raw(&[0xfe; 65]),
        };

        let spending_condition_p2pkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
        ];

        let spending_conditions = [
            spending_condition_p2pkh_compressed,
            spending_condition_p2pkh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_p2pkh_compressed_bytes,
            spending_condition_p2pkh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<SinglesigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2sh() {
        // p2sh
        let spending_condition_p2sh_uncompressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 123,
            tx_fee: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
            ],
            signatures_required: 2
        };

        let spending_condition_p2sh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (uncompressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures required
            0x00, 0x02,
        ];

        let spending_condition_p2sh_compressed = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2SH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xff; 65]),
                ),
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xfe; 65]),
                ),
                TransactionAuthField::PublicKey(
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                    )
                    .unwrap(),
                ),
            ],
            signatures_required: 2,
        };

        let spending_condition_p2sh_compressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        let spending_conditions = [
            spending_condition_p2sh_compressed,
            spending_condition_p2sh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_p2sh_compressed_bytes,
            spending_condition_p2sh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<MultisigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_order_independent_p2sh() {
        // order independent p2sh
        let spending_condition_order_independent_p2sh_uncompressed = OrderIndependentMultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: OrderIndependentMultisigHashMode::P2SH,
            nonce: 123,
            tx_fee: 456,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
            ],
            signatures_required: 2
        };

        let spending_condition_order_independent_p2sh_uncompressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            // field #3: key (uncompressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures required
            0x00, 0x02,
        ];

        let spending_condition_order_independent_p2sh_compressed = OrderIndependentMultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: OrderIndependentMultisigHashMode::P2SH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xff; 65]),
                ),
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xfe; 65]),
                ),
                TransactionAuthField::PublicKey(
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                    )
                        .unwrap(),
                ),
            ],
            signatures_required: 2,
        };

        let spending_condition_order_independent_p2sh_compressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        let spending_conditions = [
            spending_condition_order_independent_p2sh_compressed,
            spending_condition_order_independent_p2sh_uncompressed,
        ];
        let spending_conditions_bytes = [
            spending_condition_order_independent_p2sh_compressed_bytes,
            spending_condition_order_independent_p2sh_uncompressed_bytes,
        ];

        for i in 0..spending_conditions.len() {
            check_codec_and_corruption::<OrderIndependentMultisigSpendingCondition>(
                &spending_conditions[i],
                &spending_conditions_bytes[i],
            );
        }
    }

    #[test]
    fn tx_stacks_spending_condition_p2wpkh() {
        let spending_condition_p2wpkh_compressed = SinglesigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: SinglesigHashMode::P2WPKH,
            key_encoding: TransactionPublicKeyEncoding::Compressed,
            nonce: 345,
            tx_fee: 567,
            signature: MessageSignature::from_raw(&[0xfe; 65]),
        };

        let spending_condition_p2wpkh_compressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
        ];

        check_codec_and_corruption::<SinglesigSpendingCondition>(
            &spending_condition_p2wpkh_compressed,
            &spending_condition_p2wpkh_compressed_bytes,
        );
    }

    #[test]
    fn tx_stacks_spending_condition_p2wsh() {
        let spending_condition_p2wsh = MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xff; 65]),
                ),
                TransactionAuthField::Signature(
                    TransactionPublicKeyEncoding::Compressed,
                    MessageSignature::from_raw(&[0xfe; 65]),
                ),
                TransactionAuthField::PublicKey(
                    PubKey::from_hex(
                        "03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77",
                    )
                    .unwrap(),
                ),
            ],
            signatures_required: 2,
        };

        let spending_condition_p2wsh_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x02,
        ];

        check_codec_and_corruption::<MultisigSpendingCondition>(
            &spending_condition_p2wsh,
            &spending_condition_p2wsh_bytes,
        );
    }

    #[test]
    fn tx_stacks_auth() {
        // same spending conditions above
        let spending_conditions = vec![
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                nonce: 123,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xff; 65])
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2PKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 345,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xff; 65])
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("04ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c771f112f919b00a6c6c5f51f7c63e1762fe9fac9b66ec75a053db7f51f4a52712b").unwrap()),
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 123,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2SH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            }),
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                nonce: 345,
                tx_fee: 567,
                signature: MessageSignature::from_raw(&[0xfe; 65]),
            }),
            TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: MultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::PublicKey(PubKey::from_hex("03ef2340518b5867b23598a9cf74611f8b98064f7d55cdb8c107c67b5efcbc5c77").unwrap())
                ],
                signatures_required: 2
            }),
            TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: OrderIndependentMultisigHashMode::P2WSH,
                nonce: 456,
                tx_fee: 567,
                fields: vec![
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xff; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfe; 65])),
                    TransactionAuthField::Signature(TransactionPublicKeyEncoding::Compressed, MessageSignature::from_raw(&[0xfd; 65])),
                ],
                signatures_required: 1
            })
        ];

        for i in 0..spending_conditions.len() {
            let mut spending_condition_bytes = vec![];
            spending_conditions[i]
                .consensus_serialize(&mut spending_condition_bytes)
                .unwrap();

            let mut spending_condition_2_bytes = vec![];
            spending_conditions[(i + 1) % spending_conditions.len()]
                .consensus_serialize(&mut spending_condition_2_bytes)
                .unwrap();

            let auth_standard = TransactionAuth::Standard(spending_conditions[i].clone());
            let mut auth_standard_bytes = vec![TransactionAuthFlags::AuthStandard as u8];
            auth_standard_bytes.append(&mut spending_condition_bytes.clone());

            let auth_sponsored = TransactionAuth::Sponsored(
                spending_conditions[i].clone(),
                spending_conditions[(i + 1) % spending_conditions.len()].clone(),
            );
            let mut auth_sponsored_bytes = vec![TransactionAuthFlags::AuthSponsored as u8];
            auth_sponsored_bytes.append(&mut spending_condition_bytes.clone());
            auth_sponsored_bytes.append(&mut spending_condition_2_bytes.clone());

            check_codec_and_corruption::<TransactionAuth>(&auth_standard, &auth_standard_bytes);
            check_codec_and_corruption::<TransactionAuth>(&auth_sponsored, &auth_sponsored_bytes);
        }
    }

    #[test]
    fn tx_stacks_invalid_spending_conditions() {
        let bad_hash_mode_bytes = [
            // singlesig
            // hash mode
            0xff,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        let bad_hash_mode_multisig_bytes = [
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        let bad_hash_mode_order_independent_multisig_bytes = [
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // key encoding,
            TransactionPublicKeyEncoding::Compressed as u8,
            // signature
            0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd,
        ];

        // this will parse into a singlesig spending condition, but data will still remain.
        // the reason it parses is because the public keys length field encodes a valid 2-byte
        // prefix of a public key, and the parser will lump it into a public key
        let bad_hash_mode_singlesig_bytes_parseable = [
            // hash mode
            SinglesigHashMode::P2PKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce (embeds key encoding and part of the parsed nonce)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields (embed part of the signature)
            0x00, 0x00, 0x00, 0x01,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // number of signatures
            0x00, 0x01,
        ];

        // wrong number of public keys (too many signatures)
        let bad_public_key_count_bytes = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x01,
        ];

        // wrong number of public keys (not enough signatures)
        let bad_public_key_count_bytes_2 = vec![
            // hash mode
            MultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x03,
        ];

        // wrong number of public keys (not enough signatures)
        let bad_public_key_count_bytes_3 = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2SH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // fields length
            0x00, 0x00, 0x00, 0x03,
            // field #1: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // field #1: signature
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // field #2: signature
            TransactionAuthFieldID::SignatureCompressed as u8,
            // filed #2: signature
            0x02, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // field #3: public key
            TransactionAuthFieldID::PublicKeyCompressed as u8,
            // field #3: key (compressed)
            0x03, 0xef, 0x23, 0x40, 0x51, 0x8b, 0x58, 0x67, 0xb2, 0x35, 0x98, 0xa9, 0xcf, 0x74, 0x61, 0x1f, 0x8b, 0x98, 0x06, 0x4f, 0x7d, 0x55, 0xcd, 0xb8, 0xc1, 0x07, 0xc6, 0x7b, 0x5e, 0xfc, 0xbc, 0x5c, 0x77,
            // number of signatures
            0x00, 0x03,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_p2wpkh_uncompressed =
            TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
                signer: Hash160([0x11; 20]),
                hash_mode: SinglesigHashMode::P2WPKH,
                nonce: 123,
                tx_fee: 567,
                key_encoding: TransactionPublicKeyEncoding::Uncompressed,
                signature: MessageSignature::from_raw(&[0xff; 65]),
            });

        let bad_p2wpkh_uncompressed_bytes = vec![
            // hash mode
            SinglesigHashMode::P2WPKH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // public key uncompressed
            TransactionPublicKeyEncoding::Uncompressed as u8,
            // signature
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_p2wsh_uncompressed = TransactionSpendingCondition::Multisig(MultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: MultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04b7e10dd2c02dec648880ea346ece86a7820c4fa5114fb500b2645f6c972092dbe2334a653db0ab8d8ccffa6c35d3919e4cf8da3aeedafc7b9eb8235d0f2e7fdc").unwrap()),
            ],
            signatures_required: 2
        });

        let bad_p2wsh_uncompressed_bytes = vec![
            // hash mode
            MultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields
            0x00, 0x00, 0x00, 0x03,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            0x02, 0xb7, 0xe1, 0x0d, 0xd2, 0xc0, 0x2d, 0xec, 0x64, 0x88, 0x80, 0xea, 0x34, 0x6e, 0xce, 0x86, 0xa7, 0x82, 0x0c, 0x4f, 0xa5, 0x11, 0x4f, 0xb5, 0x00, 0xb2, 0x64, 0x5f, 0x6c, 0x97, 0x20, 0x92, 0xdb,
            // signatures
            0x00, 0x02,
        ];

        // hashing mode doesn't allow uncompressed keys
        let bad_order_independent_p2wsh_uncompressed = TransactionSpendingCondition::OrderIndependentMultisig(OrderIndependentMultisigSpendingCondition {
            signer: Hash160([0x11; 20]),
            hash_mode: OrderIndependentMultisigHashMode::P2WSH,
            nonce: 456,
            tx_fee: 567,
            fields: vec![
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xff; 65])),
                TransactionAuthField::Signature(TransactionPublicKeyEncoding::Uncompressed, MessageSignature::from_raw(&[0xfe; 65])),
                TransactionAuthField::PublicKey(PubKey::from_hex("04b7e10dd2c02dec648880ea346ece86a7820c4fa5114fb500b2645f6c972092dbe2334a653db0ab8d8ccffa6c35d3919e4cf8da3aeedafc7b9eb8235d0f2e7fdc").unwrap()),
            ],
            signatures_required: 2
        });

        let bad_order_independent_p2wsh_uncompressed_bytes = vec![
            // hash mode
            OrderIndependentMultisigHashMode::P2WSH as u8,
            // signer
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            // nonce
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
            // fee rate
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x37,
            // number of fields
            0x00, 0x00, 0x00, 0x03,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            // signature
            TransactionAuthFieldID::SignatureUncompressed as u8,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            // key
            TransactionAuthFieldID::PublicKeyUncompressed as u8,
            0x02, 0xb7, 0xe1, 0x0d, 0xd2, 0xc0, 0x2d, 0xec, 0x64, 0x88, 0x80, 0xea, 0x34, 0x6e, 0xce, 0x86, 0xa7, 0x82, 0x0c, 0x4f, 0xa5, 0x11, 0x4f, 0xb5, 0x00, 0xb2, 0x64, 0x5f, 0x6c, 0x97, 0x20, 0x92, 0xdb,
            // signatures
            0x00, 0x02,
        ];

        // we can serialize the invalid p2wpkh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_p2wpkh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_p2wpkh_uncompressed_bytes);

        // we can serialize the invalid p2wsh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_p2wsh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_p2wsh_uncompressed_bytes);

        // we can serialize the invalid p2wsh uncompressed condition, but we can't deserialize it
        let mut actual_bytes = vec![];
        bad_order_independent_p2wsh_uncompressed
            .consensus_serialize(&mut actual_bytes)
            .unwrap();
        assert_eq!(actual_bytes, bad_order_independent_p2wsh_uncompressed_bytes);

        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes_2[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_public_key_count_bytes_3[..]
        )
        .is_err());
        assert!(
            TransactionSpendingCondition::consensus_deserialize(&mut &bad_hash_mode_bytes[..])
                .is_err()
        );
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_multisig_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_order_independent_multisig_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_p2wpkh_uncompressed_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_p2wsh_uncompressed_bytes[..]
        )
        .is_err());
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_order_independent_p2wsh_uncompressed_bytes[..]
        )
        .is_err());

        // corrupt but will parse with trailing bits
        assert!(TransactionSpendingCondition::consensus_deserialize(
            &mut &bad_hash_mode_singlesig_bytes_parseable[..]
        )
        .is_ok());
    }

    #[test]
    fn tx_stacks_signature() {
        let cur_sighash = Txid([0u8; 32]);
        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let privk_uncompressed = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e0",
        )
        .unwrap();

        let keys = [
            privk.clone(),
            privk.clone(),
            privk_uncompressed.clone(),
            privk_uncompressed.clone(),
        ];

        let key_modes = [
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Compressed,
            TransactionPublicKeyEncoding::Uncompressed,
            TransactionPublicKeyEncoding::Uncompressed,
        ];

        let auth_flags = [
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
            TransactionAuthFlags::AuthStandard,
            TransactionAuthFlags::AuthSponsored,
        ];

        let tx_fees = [123, 456, 123, 456];

        let nonces: Vec<u64> = vec![1, 2, 3, 4];

        for i in 0..4 {
            let (sig, next_sighash) = TransactionSpendingCondition::next_signature(
                &cur_sighash,
                &auth_flags[i],
                tx_fees[i],
                nonces[i],
                &keys[i],
            )
            .unwrap();

            let mut expected_sighash_bytes = vec![];

            expected_sighash_bytes.clear();
            expected_sighash_bytes.extend_from_slice(cur_sighash.as_bytes());
            expected_sighash_bytes.extend_from_slice(&[auth_flags[i] as u8]);
            expected_sighash_bytes.extend_from_slice(&tx_fees[i].to_be_bytes());
            expected_sighash_bytes.extend_from_slice(&nonces[i].to_be_bytes());
            let expected_sighash_presign = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

            expected_sighash_bytes.clear();
            expected_sighash_bytes.extend_from_slice(expected_sighash_presign.as_bytes());
            expected_sighash_bytes.extend_from_slice(&[key_modes[i] as u8]);
            expected_sighash_bytes.extend_from_slice(sig.as_bytes());
            let expected_sighash_postsign = Txid::from_sighash_bytes(&expected_sighash_bytes[..]);

            assert_eq!(next_sighash, expected_sighash_postsign);

            let key_encoding = if keys[i].compress_public() {
                TransactionPublicKeyEncoding::Compressed
            } else {
                TransactionPublicKeyEncoding::Uncompressed
            };

            let (next_pubkey, verified_next_sighash) =
                TransactionSpendingCondition::next_verification(
                    &cur_sighash,
                    &auth_flags[i],
                    tx_fees[i],
                    nonces[i],
                    &key_encoding,
                    &sig,
                )
                .unwrap();

            assert_eq!(verified_next_sighash, expected_sighash_postsign);
            assert_eq!(next_pubkey, StacksPublicKey::from_private(&keys[i]));
        }
    }

    fn tx_auth_check_all_epochs(
        auth: TransactionAuth,
        activation_epoch_id: Option<StacksEpochId>,
    ) {
        let epoch_list = [
            StacksEpochId::Epoch10,
            StacksEpochId::Epoch20,
            StacksEpochId::Epoch2_05,
            StacksEpochId::Epoch21,
            StacksEpochId::Epoch22,
            StacksEpochId::Epoch23,
            StacksEpochId::Epoch24,
            StacksEpochId::Epoch25,
            StacksEpochId::Epoch30,
        ];

        for epoch_id in epoch_list.iter() {
            if activation_epoch_id.is_none() {
                assert_eq!(auth.is_supported_in_epoch(*epoch_id), true);
            } else if activation_epoch_id.unwrap() > *epoch_id {
                assert_eq!(auth.is_supported_in_epoch(*epoch_id), false);
            } else {
                assert_eq!(auth.is_supported_in_epoch(*epoch_id), true);
            }
        }
    }

    #[test]
    fn tx_auth_is_supported_in_epoch() {
        let privk_1 = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        ).unwrap();

        let privk_2 = StacksPrivateKey::from_hex(
            "7e3af4db6af6b3c67e2c6c6d7d5983b519f4d9b3a6e00580ae96dcace3bde8bc01",
        ).unwrap();

        let auth_p2pkh = TransactionAuth::from_p2pkh(&privk_1).unwrap();
        let auth_sponsored_p2pkh = auth_p2pkh.clone().into_sponsored(
            TransactionAuth::from_p2pkh(&privk_2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_p2pkh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2pkh, None);

        let auth_p2wpkh = TransactionAuth::from_p2wpkh(&privk_1).unwrap();
        let auth_sponsored_p2wpkh = auth_p2wpkh.clone().into_sponsored(
            TransactionAuth::from_p2wpkh(&privk_2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_p2wpkh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2wpkh, None);

        let auth_p2sh = TransactionAuth::from_p2sh(&[privk_1, privk_2], 2).unwrap();
        let auth_sponsored_p2sh = auth_p2sh.clone().into_sponsored(
            TransactionAuth::from_p2sh(&[privk_1, privk_2], 2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_p2sh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2sh, None);

        let auth_p2wsh = TransactionAuth::from_p2wsh(&[privk_1, privk_2], 2).unwrap();
        let auth_sponsored_p2wsh = auth_p2wsh.clone().into_sponsored(
            TransactionAuth::from_p2wsh(&[privk_1, privk_2], 2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_p2wsh, None);
        tx_auth_check_all_epochs(auth_sponsored_p2wsh, None);

        let auth_order_independent_p2sh = TransactionAuth::from_order_independent_p2sh(&[privk_1, privk_2], 2).unwrap();
        let auth_sponsored_order_independent_p2sh = auth_order_independent_p2sh.clone().into_sponsored(
            TransactionAuth::from_order_independent_p2sh(&[privk_1, privk_2], 2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_order_independent_p2sh, Some(StacksEpochId::Epoch30));
        tx_auth_check_all_epochs(auth_sponsored_order_independent_p2sh, Some(StacksEpochId::Epoch30));

        let auth_order_independent_p2wsh = TransactionAuth::from_order_independent_p2wsh(&[privk_1, privk_2], 2).unwrap();
        let auth_sponsored_order_independent_p2wsh = auth_order_independent_p2wsh.clone().into_sponsored(
            TransactionAuth::from_order_independent_p2wsh(&[privk_1, privk_2], 2).unwrap()
        ).unwrap();

        tx_auth_check_all_epochs(auth_order_independent_p2wsh, Some(StacksEpochId::Epoch30));
        tx_auth_check_all_epochs(auth_sponsored_order_independent_p2wsh, Some(StacksEpochId::Epoch30));
    }
}
