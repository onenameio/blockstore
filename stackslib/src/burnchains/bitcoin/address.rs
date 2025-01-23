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

use stacks_common::address::b58 as base58;
use stacks_common::address::c32::c32_address;
use stacks_common::deps_common::bech32;
use stacks_common::deps_common::bech32::{u5, FromBase32, ToBase32};
use stacks_common::deps_common::bitcoin::blockdata::opcodes::All as BtcOp;
use stacks_common::deps_common::bitcoin::blockdata::script::Builder as BtcScriptBuilder;
use stacks_common::deps_common::bitcoin::blockdata::transaction::TxOut;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160};
use stacks_common::util::log;

use crate::burnchains::bitcoin::{BitcoinNetworkType, Error as btc_error};
use crate::burnchains::Address;
use crate::chainstate::stacks::{
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum LegacyBitcoinAddressType {
    PublicKeyHash,
    ScriptHash,
}

/// Legacy Bitcoin address
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct LegacyBitcoinAddress {
    pub addrtype: LegacyBitcoinAddressType,
    pub network_id: BitcoinNetworkType,
    pub bytes: Hash160,
}

/// Segwit address.  The bool member is "mainnet" (to determine the hrp)
/// New in 2.1
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum SegwitBitcoinAddress {
    P2WPKH(bool, [u8; 20]),
    P2WSH(bool, [u8; 32]),
    P2TR(bool, [u8; 32]),
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum BitcoinAddress {
    Legacy(LegacyBitcoinAddress),
    Segwit(SegwitBitcoinAddress),
}

impl From<LegacyBitcoinAddress> for BitcoinAddress {
    fn from(addr: LegacyBitcoinAddress) -> BitcoinAddress {
        BitcoinAddress::Legacy(addr)
    }
}

impl From<SegwitBitcoinAddress> for BitcoinAddress {
    fn from(addr: SegwitBitcoinAddress) -> BitcoinAddress {
        BitcoinAddress::Segwit(addr)
    }
}

// legacy address versions
pub const ADDRESS_VERSION_MAINNET_SINGLESIG: u8 = 0;
pub const ADDRESS_VERSION_MAINNET_MULTISIG: u8 = 5;
pub const ADDRESS_VERSION_TESTNET_SINGLESIG: u8 = 111;
pub const ADDRESS_VERSION_TESTNET_MULTISIG: u8 = 196;

// segwit hrps
pub const SEGWIT_MAINNET_HRP: &str = "bc";
pub const SEGWIT_TESTNET_HRP: &str = "tb";

// segwit witnes versions
pub const SEGWIT_V0: u8 = 0;
pub const SEGWIT_V1: u8 = 1;

pub fn legacy_address_type_to_version_byte(
    addrtype: LegacyBitcoinAddressType,
    network_id: BitcoinNetworkType,
) -> u8 {
    match (addrtype, network_id) {
        (LegacyBitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_SINGLESIG
        }
        (LegacyBitcoinAddressType::ScriptHash, BitcoinNetworkType::Mainnet) => {
            ADDRESS_VERSION_MAINNET_MULTISIG
        }
        (LegacyBitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Testnet)
        | (LegacyBitcoinAddressType::PublicKeyHash, BitcoinNetworkType::Regtest) => {
            ADDRESS_VERSION_TESTNET_SINGLESIG
        }
        (LegacyBitcoinAddressType::ScriptHash, BitcoinNetworkType::Testnet)
        | (LegacyBitcoinAddressType::ScriptHash, BitcoinNetworkType::Regtest) => {
            ADDRESS_VERSION_TESTNET_MULTISIG
        }
    }
}

pub fn legacy_version_byte_to_address_type(
    version: u8,
) -> Option<(LegacyBitcoinAddressType, BitcoinNetworkType)> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some((
            LegacyBitcoinAddressType::PublicKeyHash,
            BitcoinNetworkType::Mainnet,
        )),
        ADDRESS_VERSION_MAINNET_MULTISIG => Some((
            LegacyBitcoinAddressType::ScriptHash,
            BitcoinNetworkType::Mainnet,
        )),
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some((
            LegacyBitcoinAddressType::PublicKeyHash,
            BitcoinNetworkType::Testnet,
        )),
        ADDRESS_VERSION_TESTNET_MULTISIG => Some((
            LegacyBitcoinAddressType::ScriptHash,
            BitcoinNetworkType::Testnet,
        )),
        _ => None,
    }
}

/// Convert bitcoin address byte to stacks address byte.
/// Only works for legacy Bitcoin addresess.
pub fn to_c32_version_byte(version: u8) -> Option<u8> {
    match version {
        ADDRESS_VERSION_MAINNET_SINGLESIG => Some(C32_ADDRESS_VERSION_MAINNET_SINGLESIG),
        ADDRESS_VERSION_MAINNET_MULTISIG => Some(C32_ADDRESS_VERSION_MAINNET_MULTISIG),
        ADDRESS_VERSION_TESTNET_SINGLESIG => Some(C32_ADDRESS_VERSION_TESTNET_SINGLESIG),
        ADDRESS_VERSION_TESTNET_MULTISIG => Some(C32_ADDRESS_VERSION_TESTNET_MULTISIG),
        _ => None,
    }
}

/// Convert stacks address byte to bitcoin address byte
pub fn to_b58_version_byte(version: u8) -> Option<u8> {
    match version {
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG => Some(ADDRESS_VERSION_MAINNET_SINGLESIG),
        C32_ADDRESS_VERSION_MAINNET_MULTISIG => Some(ADDRESS_VERSION_MAINNET_MULTISIG),
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG => Some(ADDRESS_VERSION_TESTNET_SINGLESIG),
        C32_ADDRESS_VERSION_TESTNET_MULTISIG => Some(ADDRESS_VERSION_TESTNET_MULTISIG),
        _ => None,
    }
}

/// Get the HRP for a segwit address based on whether or not we're in mainnet
pub fn segwit_hrp(mainnet: bool) -> &'static str {
    if mainnet {
        SEGWIT_MAINNET_HRP
    } else {
        SEGWIT_TESTNET_HRP
    }
}

impl LegacyBitcoinAddress {
    fn to_versioned_bytes(&self) -> [u8; 21] {
        let mut ret = [0; 21];
        let addrtype = self.addrtype;
        let network_id = self.network_id;
        let version_byte = legacy_address_type_to_version_byte(addrtype, network_id);

        ret[0] = version_byte;
        for i in 0..20 {
            ret[i + 1] = self.bytes[i];
        }
        return ret;
    }

    pub fn to_b58(&self) -> String {
        let versioned_bytes = self.to_versioned_bytes();
        base58::check_encode_slice(&versioned_bytes)
    }

    pub fn to_p2pkh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_DUP)
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUALVERIFY)
            .push_opcode(BtcOp::OP_CHECKSIG)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    pub fn to_p2sh_tx_out(bytes: &Hash160, value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_HASH160)
            .push_slice(&bytes.0)
            .push_opcode(BtcOp::OP_EQUAL)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Instantiate a legacy address from a b58check string
    /// Note that the network type will be 'testnet' if there is a testnet or regtest version byte
    pub fn from_b58(addrb58: &str) -> Result<LegacyBitcoinAddress, btc_error> {
        let bytes = base58::from_check(addrb58).map_err(|_e| btc_error::InvalidByteSequence)?;

        if bytes.len() != 21 {
            test_debug!("Invalid address: {} bytes", bytes.len());
            return Err(btc_error::InvalidByteSequence);
        }

        let version = bytes[0];

        let (addrtype, network_id) = match legacy_version_byte_to_address_type(version) {
            Some(x) => x,
            None => {
                test_debug!("Invalid address: unrecognized version {}", version);
                return Err(btc_error::InvalidByteSequence);
            }
        };

        let mut payload_bytes = [0; 20];
        let b = &bytes[1..21];
        payload_bytes.copy_from_slice(b);

        Ok(LegacyBitcoinAddress {
            network_id,
            addrtype,
            bytes: Hash160(payload_bytes),
        })
    }
}

impl SegwitBitcoinAddress {
    pub fn witness_version(&self) -> u8 {
        match *self {
            SegwitBitcoinAddress::P2WPKH(..) | SegwitBitcoinAddress::P2WSH(..) => SEGWIT_V0,
            SegwitBitcoinAddress::P2TR(..) => SEGWIT_V1,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.bytes_ref().to_vec()
    }

    pub fn bytes_ref(&self) -> &[u8] {
        match *self {
            SegwitBitcoinAddress::P2WPKH(_, ref bytes) => bytes,
            SegwitBitcoinAddress::P2WSH(_, ref bytes) => bytes,
            SegwitBitcoinAddress::P2TR(_, ref bytes) => bytes,
        }
    }

    pub fn to_versioned_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_bytes();
        let version = self.witness_version();
        let mut version_bytes = Vec::with_capacity(1 + bytes.len());
        version_bytes.push(version);
        version_bytes.append(&mut bytes);
        version_bytes
    }

    pub fn is_mainnet(&self) -> bool {
        match *self {
            SegwitBitcoinAddress::P2WPKH(ref mainnet, _) => *mainnet,
            SegwitBitcoinAddress::P2WSH(ref mainnet, _) => *mainnet,
            SegwitBitcoinAddress::P2TR(ref mainnet, _) => *mainnet,
        }
    }

    pub fn bech32_variant(&self) -> bech32::Variant {
        match self.witness_version() {
            SEGWIT_V0 => bech32::Variant::Bech32,
            _ => bech32::Variant::Bech32m,
        }
    }

    pub fn to_bech32_hrp(&self, hrp: &str) -> String {
        let bytes = self.to_bytes();
        let mut bytes_u5: Vec<u5> = vec![u5::try_from_u8(self.witness_version())
            .expect("FATAL: bad witness version does not fit into a u5")];
        bytes_u5.extend_from_slice(&bytes.to_base32());
        let addr = bech32::encode(&hrp, bytes_u5, self.bech32_variant())
            .expect("FATAL: could not encode segwit address");
        addr
    }

    pub fn to_bech32(&self) -> String {
        let hrp = segwit_hrp(self.is_mainnet());
        self.to_bech32_hrp(hrp)
    }

    pub fn from_bech32(s: &str) -> Option<SegwitBitcoinAddress> {
        let (hrp, quintets, variant) = bech32::decode(s)
            .map_err(|e| {
                test_debug!("Failed to decode '{}': {:?}", s, &e);
                e
            })
            .ok()?;

        let mainnet = if hrp == SEGWIT_MAINNET_HRP {
            Some(true)
        } else if hrp == SEGWIT_TESTNET_HRP {
            Some(false)
        } else {
            test_debug!("Unrecognized hrp '{:?}'", &hrp);
            None
        }?;

        if quintets.is_empty() || quintets.len() > 65 {
            test_debug!("Invalid prog length: {}", quintets.len());
            return None;
        }

        let version: u8 = quintets[0].into();
        let mut prog = Vec::with_capacity(quintets.len());
        prog.append(&mut quintets[1..].to_vec());

        let bytes = Vec::from_base32(&prog)
            .map_err(|e| {
                test_debug!("Failed to decode quintets: {:?}", &e);
                e
            })
            .ok()?;

        match (variant, version, bytes.len()) {
            (bech32::Variant::Bech32, SEGWIT_V0, 20) => {
                let mut bytes_20 = [0u8; 20];
                bytes_20.copy_from_slice(&bytes[0..20]);
                Some(SegwitBitcoinAddress::P2WPKH(mainnet, bytes_20))
            }
            (bech32::Variant::Bech32, SEGWIT_V0, 32) => {
                let mut bytes_32 = [0u8; 32];
                bytes_32.copy_from_slice(&bytes[0..32]);
                Some(SegwitBitcoinAddress::P2WSH(mainnet, bytes_32))
            }
            (bech32::Variant::Bech32m, SEGWIT_V1, 32) => {
                let mut bytes_32 = [0u8; 32];
                bytes_32.copy_from_slice(&bytes[0..32]);
                Some(SegwitBitcoinAddress::P2TR(mainnet, bytes_32))
            }
            (_, _, _) => {
                test_debug!(
                    "Unrecognized segwit address {}: ({:?}, {}, [u8; {}])",
                    s,
                    &variant,
                    version,
                    bytes.len()
                );
                None
            }
        }
    }

    pub fn to_p2wpkh_tx_out(bytes: &[u8; 20], value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_PUSHBYTES_0)
            .push_slice(bytes)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    pub fn to_p2wsh_tx_out(bytes: &[u8; 32], value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_PUSHBYTES_0)
            .push_slice(bytes)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    pub fn to_p2tr_tx_out(bytes: &[u8; 32], value: u64) -> TxOut {
        let script_pubkey = BtcScriptBuilder::new()
            .push_opcode(BtcOp::OP_PUSHNUM_1)
            .push_slice(bytes)
            .into_script();
        TxOut {
            value,
            script_pubkey,
        }
    }

    pub fn is_p2wpkh(&self) -> bool {
        if let SegwitBitcoinAddress::P2WPKH(..) = self {
            true
        } else {
            false
        }
    }

    pub fn is_p2wsh(&self) -> bool {
        if let SegwitBitcoinAddress::P2WSH(..) = self {
            true
        } else {
            false
        }
    }

    pub fn is_p2tr(&self) -> bool {
        if let SegwitBitcoinAddress::P2TR(..) = self {
            true
        } else {
            false
        }
    }
}

impl BitcoinAddress {
    /// Make a legacy bitcoin address from legacy address parts
    pub fn from_bytes_legacy(
        network_id: BitcoinNetworkType,
        addrtype: LegacyBitcoinAddressType,
        bytes: &[u8],
    ) -> Result<BitcoinAddress, btc_error> {
        if bytes.len() != 20 {
            return Err(btc_error::InvalidByteSequence);
        }

        let mut my_bytes = [0; 20];
        let b = &bytes[..bytes.len()];
        my_bytes.copy_from_slice(b);

        Ok(BitcoinAddress::Legacy(LegacyBitcoinAddress {
            network_id,
            addrtype,
            bytes: Hash160(my_bytes),
        }))
    }

    /// Make a segwit p2wpkh bitcoin address from parts
    pub fn from_bytes_segwit_p2wpkh(
        network_id: BitcoinNetworkType,
        bytes: &[u8],
    ) -> Result<BitcoinAddress, btc_error> {
        if bytes.len() != 20 {
            return Err(btc_error::InvalidByteSequence);
        }

        let mut my_bytes = [0; 20];
        let b = &bytes[..bytes.len()];
        my_bytes.copy_from_slice(b);

        let mainnet = network_id == BitcoinNetworkType::Mainnet;
        Ok(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(
            mainnet, my_bytes,
        )))
    }

    /// Instantiate an address from a scriptpubkey
    /// If we don't recognize it, then return None.
    /// WARNING: cannot differentiate between p2sh and segwit-p2sh
    pub fn from_scriptpubkey(
        network_id: BitcoinNetworkType,
        scriptpubkey: &[u8],
    ) -> Option<BitcoinAddress> {
        if scriptpubkey.len() == 25
            && scriptpubkey[0..3] == [0x76, 0xa9, 0x14]
            && scriptpubkey[23..25] == [0x88, 0xac]
        {
            // p2pkh
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[3..23];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                network_id,
                addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                bytes: Hash160(my_bytes),
            }))
        } else if scriptpubkey.len() == 23
            && scriptpubkey[0..2] == [0xa9, 0x14]
            && scriptpubkey[22] == 0x87
        {
            // p2sh (or maybe segwit-p2sh)
            let mut my_bytes = [0; 20];
            let b = &scriptpubkey[2..22];
            my_bytes.copy_from_slice(b);

            Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                network_id,
                addrtype: LegacyBitcoinAddressType::ScriptHash,
                bytes: Hash160(my_bytes),
            }))
        } else if scriptpubkey.len() == 22
            && scriptpubkey[0..2] == [BtcOp::OP_PUSHBYTES_0 as u8, 0x14]
        {
            // segwit p2wpkh
            let mut witness_program = [0u8; 20];
            witness_program.copy_from_slice(&scriptpubkey[2..22]);

            let mainnet = network_id == BitcoinNetworkType::Mainnet;
            Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(
                mainnet,
                witness_program,
            )))
        } else if scriptpubkey.len() == 34
            && scriptpubkey[0..2] == [BtcOp::OP_PUSHBYTES_0 as u8, 0x20]
        {
            // segwit p2wsh
            let mut witness_program = [0u8; 32];
            witness_program.copy_from_slice(&scriptpubkey[2..34]);

            let mainnet = network_id == BitcoinNetworkType::Mainnet;
            Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                mainnet,
                witness_program,
            )))
        } else if scriptpubkey.len() == 34
            && scriptpubkey[0..2] == [BtcOp::OP_PUSHNUM_1 as u8, 0x20]
        {
            // segwit p2tr
            let mut witness_program = [0u8; 32];
            witness_program.copy_from_slice(&scriptpubkey[2..34]);

            let mainnet = network_id == BitcoinNetworkType::Mainnet;
            Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                mainnet,
                witness_program,
            )))
        } else {
            None
        }
    }

    pub fn is_segwit_p2wpkh(&self) -> bool {
        if let BitcoinAddress::Segwit(ref swaddr) = self {
            return swaddr.is_p2wpkh();
        }
        return false;
    }

    pub fn is_segwit_p2wsh(&self) -> bool {
        if let BitcoinAddress::Segwit(ref swaddr) = self {
            return swaddr.is_p2wsh();
        }
        return false;
    }

    pub fn is_segwit_p2tr(&self) -> bool {
        if let BitcoinAddress::Segwit(ref swaddr) = self {
            return swaddr.is_p2tr();
        }
        return false;
    }

    #[cfg(test)]
    pub fn expect_legacy(self) -> LegacyBitcoinAddress {
        match self {
            BitcoinAddress::Legacy(addr) => addr,
            x => {
                panic!("Not a legacy address: {}", x);
            }
        }
    }

    #[cfg(test)]
    pub fn expect_segwit(self) -> SegwitBitcoinAddress {
        match self {
            BitcoinAddress::Segwit(addr) => addr,
            x => {
                panic!("Not a segwit address: {}", x);
            }
        }
    }

    #[cfg(test)]
    pub fn from_segwit(mainnet: bool, scriptpubkey_hex: &str) -> BitcoinAddress {
        let scriptpubkey = hex_bytes(scriptpubkey_hex).unwrap();
        BitcoinAddress::try_from_segwit(mainnet, &scriptpubkey)
            .expect("FATAL: not a segwit address")
    }

    pub fn try_from_segwit(mainnet: bool, scriptpubkey: &[u8]) -> Option<BitcoinAddress> {
        let network_id = if mainnet {
            BitcoinNetworkType::Mainnet
        } else {
            BitcoinNetworkType::Testnet
        };
        if let Some(BitcoinAddress::Segwit(sw)) =
            BitcoinAddress::from_scriptpubkey(network_id, scriptpubkey)
        {
            return Some(BitcoinAddress::Segwit(sw));
        }
        return None;
    }

    #[cfg(test)]
    pub fn from_legacy(mainnet: bool, scriptpubkey_hex: &str) -> BitcoinAddress {
        let network_id = if mainnet {
            BitcoinNetworkType::Mainnet
        } else {
            BitcoinNetworkType::Testnet
        };
        let scriptpubkey = hex_bytes(scriptpubkey_hex).unwrap();
        let addr = BitcoinAddress::from_scriptpubkey(network_id, &scriptpubkey)
            .unwrap()
            .expect_legacy();
        BitcoinAddress::Legacy(addr)
    }
}

impl Address for LegacyBitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<LegacyBitcoinAddress> {
        match LegacyBitcoinAddress::from_b58(s) {
            Ok(a) => Some(a),
            Err(_e) => None,
        }
    }

    fn is_burn(&self) -> bool {
        self.bytes == Hash160([0u8; 20])
    }
}

impl Address for SegwitBitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes()
    }

    fn from_string(s: &str) -> Option<SegwitBitcoinAddress> {
        SegwitBitcoinAddress::from_bech32(s)
    }

    fn is_burn(&self) -> bool {
        // must all be 0's
        for byte in self.to_bytes().into_iter() {
            if byte != 0 {
                return false;
            }
        }
        return true;
    }
}

impl std::fmt::Display for LegacyBitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_b58().fmt(f)
    }
}

impl std::fmt::Display for SegwitBitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_bech32().fmt(f)
    }
}

impl std::fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            BitcoinAddress::Legacy(ref legacy) => legacy.fmt(f),
            BitcoinAddress::Segwit(ref segwit) => segwit.fmt(f),
        }
    }
}

impl Address for BitcoinAddress {
    fn to_bytes(&self) -> Vec<u8> {
        match *self {
            BitcoinAddress::Legacy(ref addr) => addr.to_bytes(),
            BitcoinAddress::Segwit(ref addr) => addr.to_bytes(),
        }
    }

    fn from_string(s: &str) -> Option<BitcoinAddress> {
        if let Some(addr) = LegacyBitcoinAddress::from_string(s) {
            Some(addr.into())
        } else {
            SegwitBitcoinAddress::from_string(s).map(|addr| addr.into())
        }
    }

    fn is_burn(&self) -> bool {
        match *self {
            BitcoinAddress::Legacy(ref addr) => addr.is_burn(),
            BitcoinAddress::Segwit(ref addr) => addr.is_burn(),
        }
    }
}

#[cfg(test)]
mod tests {
    use stacks_common::types::Address;
    use stacks_common::util::hash::{hex_bytes, Hash160};
    use stacks_common::util::log;

    use super::{
        BitcoinAddress, LegacyBitcoinAddress, LegacyBitcoinAddressType, SegwitBitcoinAddress,
    };
    use crate::burnchains::bitcoin::BitcoinNetworkType;

    struct AddressFixture {
        addr: String,
        result: Option<BitcoinAddress>,
    }

    struct ScriptFixture {
        scriptpubkey: Vec<u8>,
        result: Option<BitcoinAddress>,
    }

    #[test]
    fn test_from_b58() {
        let fixtures = vec![
            AddressFixture {
                addr: "mr6nrMvvh44sR5MiX929mMXP5hqgaTr6fx".to_owned(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Testnet,
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("74178497e927ff3ff1428a241be454d393c3c91c").unwrap(),
                })),
            },
            AddressFixture {
                addr: "1B5xoFjSwAB3DUum7dxXgj3brnYsXibLbc".to_owned(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
                })),
            },
            AddressFixture {
                addr: "2Mxh5a9QxP5jgABfzATLpmFVofbzDeFRJyt".to_owned(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Testnet,
                    addrtype: LegacyBitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("3bbc6b200412398dc98c6eb49d20c6b01715c2c1").unwrap(),
                })),
            },
            AddressFixture {
                addr: "35idohuiQNndP1xR3FhNVHXgKF9YYPhWo4".to_owned(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: LegacyBitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
                })),
            },
            AddressFixture {
                // too long
                addr: "1R37rTejZ9zhAhuJcgdpSwnzqGY4AoREGYw".to_owned(),
                result: None,
            },
            AddressFixture {
                // bad checksum
                addr: "1B5xoFjSwAB3DUum7dxXgj3brnYsXibLbd".to_owned(),
                result: None,
            },
            AddressFixture {
                // unrecognized version byte
                addr: "u84Z5b4e5qhW6dBR4izgvhBZk1DmR2bhG".to_owned(),
                result: None,
            },
            AddressFixture {
                // too short
                addr: "Couv2wqrdtpEqrS1vQZZ9zb7WgUf6Z3e".to_owned(),
                result: None,
            },
        ];

        for fixture in fixtures {
            let addr_opt = LegacyBitcoinAddress::from_b58(&fixture.addr);

            match (addr_opt, fixture.result) {
                (Ok(addr), Some(res)) => assert_eq!(BitcoinAddress::Legacy(addr), res),
                (Err(_e), None) => {}
                (Ok(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
                (Err(_e), Some(_res)) => {
                    test_debug!("Failed to decode when we should have: {}", fixture.addr);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_from_bech32() {
        let fixtures = vec![
            // taken from bip-0173
            AddressFixture {
                addr: "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".to_owned(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(
                    true,
                    [
                        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
                        0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    ],
                ))),
            },
            AddressFixture {
                addr: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7".to_owned(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                    false,
                    [
                        0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20,
                        0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
                        0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62,
                    ],
                ))),
            },
            AddressFixture {
                // unrecognized witness version
                addr: "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"
                    .to_owned(),
                result: None,
            },
            AddressFixture {
                // unrecognized witness version
                addr: "BC1SW50QA3JX3S".to_owned(),
                result: None,
            },
            AddressFixture {
                // unrecognized witness version
                addr: "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj".to_owned(),
                result: None,
            },
            AddressFixture {
                addr: "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy".to_owned(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                    false,
                    [
                        0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87,
                        0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                        0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33,
                    ],
                ))),
            },
            AddressFixture {
                // bad hrp
                addr: "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty".to_owned(),
                result: None,
            },
            AddressFixture {
                // bad checksum
                addr: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5".to_owned(),
                result: None,
            },
            AddressFixture {
                // bad witness version
                addr: "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2".to_owned(),
                result: None,
            },
            AddressFixture {
                // invalid length
                addr: "bc1rw5uspcuh".to_owned(),
                result: None,
            },
            AddressFixture {
                // invalid length
                addr:
                    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90"
                        .to_owned(),
                result: None,
            },
            AddressFixture {
                // invalid length for segwit v0 witness version
                addr: "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P".to_owned(),
                result: None,
            },
            AddressFixture {
                // mixed case
                addr: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7".to_owned(),
                result: None,
            },
            AddressFixture {
                // zero-padding for more than 4 bits
                addr: "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du".to_owned(),
                result: None,
            },
            AddressFixture {
                // non-zero padding in 8-to-5 conversion
                addr: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv".to_owned(),
                result: None,
            },
            AddressFixture {
                // empty data section
                addr: "bc1gmk9yu".to_owned(),
                result: None,
            },
        ];

        for fixture in fixtures.iter() {
            test_debug!("Test '{}'", &fixture.addr);
            let addr_opt = BitcoinAddress::from_string(&fixture.addr);
            match (addr_opt, fixture.result.as_ref()) {
                (Some(addr), Some(res)) => assert_eq!(addr, *res),
                (None, None) => {}
                (None, Some(_r)) => {
                    test_debug!("Failed to decode an address when we should have");
                    assert!(false);
                }
                (Some(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
            }
            if let Some(addr) = &fixture.result {
                assert_eq!(
                    format!("{}", &addr).to_lowercase(),
                    fixture.addr.to_lowercase()
                );
            }
        }
    }

    #[test]
    fn test_from_scriptpubkey() {
        let fixtures = vec![
            ScriptFixture {
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac")
                    .unwrap()
                    .to_vec(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    bytes: Hash160::from_hex("6ea17fc39169cdd9f2414a893aa5ce0c4b4c8934").unwrap(),
                })),
            },
            ScriptFixture {
                scriptpubkey: hex_bytes("a9142c2edf39b098e05cf770e6b5a2fcedb54ee4fe0587")
                    .unwrap()
                    .to_vec(),
                result: Some(BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    network_id: BitcoinNetworkType::Mainnet,
                    addrtype: LegacyBitcoinAddressType::ScriptHash,
                    bytes: Hash160::from_hex("2c2edf39b098e05cf770e6b5a2fcedb54ee4fe05").unwrap(),
                })),
            },
            ScriptFixture {
                // doesn't start with 76 a9 14 or a9 14
                scriptpubkey: hex_bytes("002c2edf39b098e05cf770e6b5a2fcedb54ee4fe05")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                // doesn't end in 88 ac
                scriptpubkey: hex_bytes("76a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ad")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                // doesn't end in 87
                scriptpubkey: hex_bytes("a91476a9146ea17fc39169cdd9f2414a893aa5ce0c4b4c893488ac88")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                // segwit p2wpkh
                scriptpubkey: hex_bytes("0014751e76e8199196d454941c45d1b3a323f1433bd6")
                    .unwrap()
                    .to_vec(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WPKH(
                    true,
                    [
                        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
                        0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    ],
                ))),
            },
            ScriptFixture {
                // segwit p2wsh
                scriptpubkey: hex_bytes(
                    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                )
                .unwrap()
                .to_vec(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                    true,
                    [
                        0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20,
                        0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
                        0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62,
                    ],
                ))),
            },
            ScriptFixture {
                // segwit p2wsh
                scriptpubkey: hex_bytes(
                    "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
                )
                .unwrap()
                .to_vec(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2WSH(
                    true,
                    [
                        0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87,
                        0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                        0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33,
                    ],
                ))),
            },
            ScriptFixture {
                // segwit taproot
                // taken from mainnet tx 33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036
                scriptpubkey: hex_bytes(
                    "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0",
                )
                .unwrap()
                .to_vec(),
                result: Some(BitcoinAddress::Segwit(SegwitBitcoinAddress::P2TR(
                    true,
                    [
                        0x33, 0x9c, 0xe7, 0xe1, 0x65, 0xe6, 0x7d, 0x93, 0xad, 0xb3, 0xfe, 0xf8,
                        0x8a, 0x6d, 0x4b, 0xee, 0xd3, 0x3f, 0x01, 0xfa, 0x87, 0x6f, 0x05, 0xa2,
                        0x25, 0x24, 0x2b, 0x82, 0xa6, 0x31, 0xab, 0xc0,
                    ],
                ))),
            },
            ScriptFixture {
                // invalid segwit -- not 20 or 32 bytes (19 bytes)
                scriptpubkey: hex_bytes("0014751e76e8199196d454941c45d1b3a323f1433b")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- not 20 or 32 bytes (21 bytes)
                scriptpubkey: hex_bytes("0014751e76e8199196d454941c45d1b3a323f1433bdb01")
                    .unwrap()
                    .to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- not 20 or 32 bytes (31 bytes)
                scriptpubkey: hex_bytes(
                    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c63296049032",
                )
                .unwrap()
                .to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- not 20 or 32 bytes (33 bytes)
                scriptpubkey: hex_bytes(
                    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326201",
                )
                .unwrap()
                .to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- unrecognized version
                scriptpubkey: hex_bytes(
                    "0220339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0",
                )
                .unwrap()
                .to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- 0 bytes
                scriptpubkey: hex_bytes("0000").unwrap().to_vec(),
                result: None,
            },
            ScriptFixture {
                // invalid segwit -- 1 byte
                scriptpubkey: hex_bytes("000102").unwrap().to_vec(),
                result: None,
            },
        ];

        for fixture in fixtures {
            let addr_opt = BitcoinAddress::from_scriptpubkey(
                BitcoinNetworkType::Mainnet,
                &fixture.scriptpubkey,
            );

            match (addr_opt, fixture.result) {
                (Some(addr), Some(res)) => assert_eq!(addr, res),
                (None, None) => {}
                (None, Some(_r)) => {
                    test_debug!(
                        "Failed to decode an address when we should have: {:?}, {:?}",
                        &fixture.scriptpubkey,
                        &_r
                    );
                    assert!(false);
                }
                (Some(_a), None) => {
                    test_debug!("Decoded an address when we should not have");
                    assert!(false);
                }
            }
        }
    }
}
