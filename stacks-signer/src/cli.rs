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
use std::io::{self, Read};
use std::path::PathBuf;

use blockstack_lib::chainstate::stacks::address::PoxAddress;
use blockstack_lib::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;
use blockstack_lib::util_lib::signed_structured_data::{
    make_structured_data_domain, structured_data_message_hash,
};
use clap::{ArgAction, Parser, ValueEnum};
use clarity::consts::CHAIN_ID_MAINNET;
use clarity::types::chainstate::StacksPublicKey;
use clarity::types::{PrivateKey, PublicKey};
use clarity::util::hash::Sha256Sum;
use clarity::util::secp256k1::MessageSignature;
use clarity::vm::types::{QualifiedContractIdentifier, TupleData};
use clarity::vm::Value;
use libsigner::VERSION_STRING;
use serde::{Deserialize, Serialize};
use stacks_common::address::{
    b58, AddressHashMode, C32_ADDRESS_VERSION_MAINNET_MULTISIG,
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::define_u8_enum;
use stacks_common::types::chainstate::StacksPrivateKey;

extern crate alloc;

/// The CLI arguments for the stacks signer
#[derive(Parser, Debug)]
#[command(author, version, about, long_version = VERSION_STRING.as_str())]
pub struct Cli {
    /// Subcommand action to take
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands for the stacks signer binary
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Get a chunk from the stacker-db instance in hex encoding
    GetChunk(GetChunkArgs),
    /// Get the latest chunk from the stacker-db instance in hex encoding
    GetLatestChunk(GetLatestChunkArgs),
    /// List chunks from the stacker-db instance in hex encoding
    ListChunks(StackerDBArgs),
    /// Upload a chunk to the stacker-db instance
    PutChunk(PutChunkArgs),
    /// Run the signer, waiting for events from the stacker-db instance
    Run(RunSignerArgs),
    /// Generate a signature for Stacking transactions
    GenerateStackingSignature(GenerateStackingSignatureArgs),
    /// Check a configuration file and output config information
    CheckConfig(RunSignerArgs),
    /// Vote for a specified SIP with a yes or no vote
    GenerateVote(GenerateVoteArgs),
    /// Verify the vote for a specified SIP against a public key and vote info
    VerifyVote(VerifyVoteArgs),
    /// Verify signer signatures by checking stackerdb slots contain the correct data
    MonitorSigners(MonitorSignersArgs),
}

/// Basic arguments for all cyrptographic and stacker-db functionality
#[derive(Parser, Debug, Clone)]
pub struct StackerDBArgs {
    /// The Stacks node to connect to
    #[arg(long)]
    pub host: String,
    /// The stacker-db contract to use. Must be in the format of "STACKS_ADDRESS.CONTRACT_NAME"
    #[arg(short, long, value_parser = parse_contract)]
    pub contract: QualifiedContractIdentifier,
}

/// Arguments for the get-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    pub slot_version: u32,
}

/// Arguments for the get-latest-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetLatestChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the put-chunk command
pub struct PutChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The Stacks private key to use in hexademical format
    #[arg(short, long, value_parser = parse_private_key)]
    pub private_key: StacksPrivateKey,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    pub slot_version: u32,
    /// The data to upload
    #[arg(required = false, value_parser = parse_data)]
    // Note this weirdness is due to https://github.com/clap-rs/clap/discussions/4695
    // Need to specify the long name here due to invalid parsing in Clap which looks at the NAME rather than the TYPE which causes issues in how it handles Vec's.
    pub data: alloc::vec::Vec<u8>,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the Run command
pub struct RunSignerArgs {
    /// Path to config file
    #[arg(long, short, value_name = "FILE")]
    pub config: PathBuf,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the Vote command
pub struct GenerateVoteArgs {
    /// Path to signer config file
    #[arg(long, short, value_name = "FILE")]
    pub config: PathBuf,
    /// The vote info being cast
    #[clap(flatten)]
    pub vote_info: VoteInfo,
}

#[derive(Parser, Debug, Clone, Copy)]
/// Arguments for the VerifyVote command
pub struct VerifyVoteArgs {
    /// The Stacks public key to verify against
    #[arg(short, long, value_parser = parse_public_key)]
    pub public_key: StacksPublicKey,
    /// The message signature in hexadecimal format
    #[arg(short, long, value_parser = parse_message_signature)]
    pub signature: MessageSignature,
    /// The vote info being verified
    #[clap(flatten)]
    pub vote_info: VoteInfo,
}

#[derive(Parser, Debug, Clone, Copy)]
/// Information about a SIP vote
pub struct VoteInfo {
    /// The SIP number to vote on
    #[arg(long)]
    pub sip: u32,
    /// The vote to cast
    #[arg(long, value_parser = parse_vote)]
    pub vote: Vote,
}

impl VoteInfo {
    /// Get the digest to sign that authenticates this vote data
    fn digest(&self) -> Sha256Sum {
        let vote_message = TupleData::from_data(vec![
            ("sip".into(), Value::UInt(self.sip.into())),
            ("vote".into(), Value::UInt(self.vote.to_u8().into())),
        ])
        .unwrap();
        let data_domain =
            make_structured_data_domain("signer-sip-voting", "1.0.0", CHAIN_ID_MAINNET);
        structured_data_message_hash(vote_message.into(), data_domain)
    }

    /// Sign the vote data and return the signature
    pub fn sign(&self, private_key: &StacksPrivateKey) -> Result<MessageSignature, &'static str> {
        let digest = self.digest();
        private_key.sign(digest.as_bytes())
    }

    /// Verify the vote data against the provided public key and signature
    pub fn verify(
        &self,
        public_key: &StacksPublicKey,
        signature: &MessageSignature,
    ) -> Result<bool, &'static str> {
        let digest = self.digest();
        public_key.verify(digest.as_bytes(), signature)
    }
}

define_u8_enum!(
/// A given vote for a SIP
Vote {
    /// Vote yes
    Yes = 0,
    /// Vote no
    No = 1
});

impl TryFrom<&str> for Vote {
    type Error = String;
    fn try_from(input: &str) -> Result<Vote, Self::Error> {
        match input.to_lowercase().as_str() {
            "yes" => Ok(Vote::Yes),
            "no" => Ok(Vote::No),
            _ => Err(format!("Invalid vote: {}. Must be `yes` or `no`.", input)),
        }
    }
}

impl TryFrom<u8> for Vote {
    type Error = String;
    fn try_from(input: u8) -> Result<Vote, Self::Error> {
        Vote::from_u8(input).ok_or_else(|| format!("Invalid vote: {}. Must be 0 or 1.", input))
    }
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the MonitorSigners command
pub struct MonitorSignersArgs {
    /// The Stacks node to connect to
    #[arg(long)]
    pub host: String,
    /// Set the polling interval in seconds.
    #[arg(long, short, default_value = "60")]
    pub interval: u64,
    /// Max age in seconds before a signer message is considered stale.
    #[arg(long, short, default_value = "1200")]
    pub max_age: u64,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the Version command
pub struct VersionArgs {
}

#[derive(Clone, Debug, PartialEq)]
/// Wrapper around `Pox4SignatureTopic` to implement `ValueEnum`
pub struct StackingSignatureMethod(Pox4SignatureTopic);

impl StackingSignatureMethod {
    /// Get the inner `Pox4SignatureTopic`
    pub const fn topic(&self) -> &Pox4SignatureTopic {
        &self.0
    }
}

impl From<Pox4SignatureTopic> for StackingSignatureMethod {
    fn from(topic: Pox4SignatureTopic) -> Self {
        Self(topic)
    }
}

impl ValueEnum for StackingSignatureMethod {
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.0.get_name_str()))
    }

    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self(Pox4SignatureTopic::StackStx),
            Self(Pox4SignatureTopic::StackExtend),
            Self(Pox4SignatureTopic::AggregationCommit),
            Self(Pox4SignatureTopic::AggregationIncrease),
            Self(Pox4SignatureTopic::StackIncrease),
        ]
    }

    fn from_str(input: &str, _ignore_case: bool) -> Result<Self, String> {
        let topic = match input {
            "aggregation-commit" => Pox4SignatureTopic::AggregationCommit,
            "aggregation-increase" => Pox4SignatureTopic::AggregationIncrease,
            method => match Pox4SignatureTopic::lookup_by_name(method) {
                Some(topic) => topic,
                None => {
                    return Err(format!("Invalid topic: {}", input));
                }
            },
        };
        Ok(topic.into())
    }
}

#[derive(Parser, Debug, Clone, PartialEq)]
/// Arguments for the generate-stacking-signature command
pub struct GenerateStackingSignatureArgs {
    /// BTC address used to receive rewards
    #[arg(short, long, value_parser = parse_pox_addr)]
    pub pox_address: PoxAddress,
    /// The reward cycle during which this signature
    /// can be used
    #[arg(short, long)]
    pub reward_cycle: u64,
    /// Path to signer config file
    #[arg(long, short, value_name = "FILE")]
    pub config: PathBuf,
    /// Stacking method that can be used
    #[arg(long)]
    pub method: StackingSignatureMethod,
    /// Number of cycles used as a lock period.
    /// Use `1` for stack-aggregation-commit
    #[arg(long)]
    pub period: u64,
    /// The max amount of uSTX that can be used in this unique transaction
    #[arg(long)]
    pub max_amount: u128,
    /// A unique identifier to prevent re-using this authorization
    #[arg(long)]
    pub auth_id: u128,
    /// Output information in JSON format
    #[arg(long, action=ArgAction::SetTrue, required=false)]
    pub json: bool,
}

/// Parse the contract ID
fn parse_contract(contract: &str) -> Result<QualifiedContractIdentifier, String> {
    QualifiedContractIdentifier::parse(contract).map_err(|e| format!("Invalid contract: {}", e))
}

/// Parse a BTC address argument and return a `PoxAddress`.
/// This function behaves similarly to `PoxAddress::from_b58`, but also handles
/// addresses where the parsed AddressHashMode is None.
pub fn parse_pox_addr(pox_address_literal: &str) -> Result<PoxAddress, String> {
    let parsed_addr = PoxAddress::from_b58(pox_address_literal).map_or_else(
        || Err(format!("Invalid pox address: {pox_address_literal}")),
        Ok,
    );
    match parsed_addr {
        Ok(PoxAddress::Standard(addr, None)) => match addr.version() {
            C32_ADDRESS_VERSION_MAINNET_MULTISIG | C32_ADDRESS_VERSION_TESTNET_MULTISIG => Ok(
                PoxAddress::Standard(addr, Some(AddressHashMode::SerializeP2SH)),
            ),
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG | C32_ADDRESS_VERSION_TESTNET_SINGLESIG => Ok(
                PoxAddress::Standard(addr, Some(AddressHashMode::SerializeP2PKH)),
            ),
            _ => Err(format!("Invalid address version: {}", addr.version())),
        },
        _ => parsed_addr,
    }
}

/// Parse the hexadecimal Stacks private key
fn parse_private_key(private_key: &str) -> Result<StacksPrivateKey, String> {
    StacksPrivateKey::from_hex(private_key).map_err(|e| format!("Invalid private key: {}", e))
}

/// Parse the hexadecimal Stacks public key
fn parse_public_key(public_key: &str) -> Result<StacksPublicKey, String> {
    StacksPublicKey::from_hex(public_key).map_err(|e| format!("Invalid public key: {}", e))
}

/// Parse the vote
fn parse_vote(vote: &str) -> Result<Vote, String> {
    vote.try_into()
}

/// Parse the hexadecimal encoded message signature
fn parse_message_signature(signature: &str) -> Result<MessageSignature, String> {
    MessageSignature::from_hex(signature).map_err(|e| format!("Invalid message signature: {}", e))
}

/// Parse the input data
fn parse_data(data: &str) -> Result<Vec<u8>, String> {
    let encoded_data = if data == "-" {
        // Parse the data from stdin
        let mut data = String::new();
        io::stdin().read_to_string(&mut data).unwrap();
        data
    } else {
        data.to_string()
    };
    let data =
        b58::from(&encoded_data).map_err(|e| format!("Failed to decode provided data: {}", e))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::address::{PoxAddressType20, PoxAddressType32};
    use blockstack_lib::util_lib::signed_structured_data::pox4::make_pox_4_signer_key_message_hash;
    use clarity::consts::CHAIN_ID_TESTNET;
    use clarity::util::hash::Sha256Sum;

    use super::*;

    /// Helper just to ensure that a the pox address
    /// can be turned into a clarity tuple
    fn make_message_hash(pox_addr: &PoxAddress) -> Sha256Sum {
        make_pox_4_signer_key_message_hash(
            pox_addr,
            0,
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            0,
            0,
            0,
        )
    }

    fn clarity_tuple_version(pox_addr: &PoxAddress) -> u8 {
        *pox_addr
            .as_clarity_tuple()
            .expect("Failed to generate clarity tuple for pox address")
            .get("version")
            .expect("Expected version in clarity tuple")
            .clone()
            .expect_buff(1)
            .expect("Expected version to be a u128")
            .first()
            .expect("Expected version to be a uint")
    }

    #[test]
    fn test_parse_pox_addr() {
        let tr = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let pox_addr = parse_pox_addr(tr).expect("Failed to parse segwit address");
        assert_eq!(tr, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            PoxAddressType32::P2TR.to_u8()
        );
        match pox_addr {
            PoxAddress::Addr32(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType32::P2TR);
            }
            _ => panic!("Invalid parsed address"),
        }

        let legacy = "1N8GMS991YDY1E696e9SB9EsYY5ckSU7hZ";
        let pox_addr = parse_pox_addr(legacy).expect("Failed to parse legacy address");
        assert_eq!(legacy, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            AddressHashMode::SerializeP2PKH as u8
        );
        match pox_addr {
            PoxAddress::Standard(stacks_addr, hash_mode) => {
                assert_eq!(stacks_addr.version(), 22);
                assert_eq!(hash_mode, Some(AddressHashMode::SerializeP2PKH));
            }
            _ => panic!("Invalid parsed address"),
        }

        let p2sh = "33JNgVMNMC9Xm6mJG9oTVf5zWbmt5xi1Mv";
        let pox_addr = parse_pox_addr(p2sh).expect("Failed to parse legacy address");
        assert_eq!(p2sh, pox_addr.clone().to_b58());
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            AddressHashMode::SerializeP2SH as u8
        );
        make_message_hash(&pox_addr);
        match pox_addr {
            PoxAddress::Standard(stacks_addr, hash_mode) => {
                assert_eq!(stacks_addr.version(), 20);
                assert_eq!(hash_mode, Some(AddressHashMode::SerializeP2SH));
            }
            _ => panic!("Invalid parsed address"),
        }

        let testnet_p2pkh = "mnr5asd1MLSutHLL514WZXNpUNN3L98zBc";
        let pox_addr = parse_pox_addr(testnet_p2pkh).expect("Failed to parse testnet address");
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(testnet_p2pkh, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        match pox_addr {
            PoxAddress::Standard(stacks_addr, hash_mode) => {
                assert_eq!(stacks_addr.version(), C32_ADDRESS_VERSION_TESTNET_SINGLESIG);
                assert_eq!(hash_mode, Some(AddressHashMode::SerializeP2PKH));
            }
            _ => panic!("Invalid parsed address"),
        }

        let wsh = "bc1qvnpcphdctvmql5gdw6chtwvvsl6ra9gwa2nehc99np7f24juc4vqrx29cs";
        let pox_addr = parse_pox_addr(wsh).expect("Failed to parse segwit address");
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            PoxAddressType32::P2WSH.to_u8()
        );
        assert_eq!(wsh, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        match pox_addr {
            PoxAddress::Addr32(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType32::P2WSH);
            }
            _ => panic!("Invalid parsed address"),
        }

        let wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let pox_addr = parse_pox_addr(wpkh).expect("Failed to parse segwit address");
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            PoxAddressType20::P2WPKH.to_u8()
        );
        assert_eq!(wpkh, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        match pox_addr {
            PoxAddress::Addr20(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType20::P2WPKH);
            }
            _ => panic!("Invalid parsed address"),
        }

        let testnet_tr = "tb1p46cgptxsfwkqpnnj552rkae3nf6l52wxn4snp4vm6mcrz2585hwq6cdwf2";
        let pox_addr = parse_pox_addr(testnet_tr).expect("Failed to parse testnet address");
        assert_eq!(testnet_tr, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            PoxAddressType32::P2TR.to_u8()
        );
        match pox_addr {
            PoxAddress::Addr32(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType32::P2TR);
            }
            _ => panic!("Invalid parsed address"),
        }

        let testnet_segwit = "tb1q38eleudmqyg4jrm39dnudj23pv6jcjrksa437s";
        let pox_addr = parse_pox_addr(testnet_segwit).expect("Failed to parse testnet address");
        assert_eq!(testnet_segwit, pox_addr.clone().to_b58());
        make_message_hash(&pox_addr);
        assert_eq!(
            clarity_tuple_version(&pox_addr),
            PoxAddressType20::P2WPKH.to_u8()
        );
        match pox_addr {
            PoxAddress::Addr20(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType20::P2WPKH);
            }
            _ => panic!("Invalid parsed address"),
        }
    }

    #[test]
    fn test_parse_stacking_method() {
        assert_eq!(
            StackingSignatureMethod::from_str("agg-increase", true).unwrap(),
            Pox4SignatureTopic::AggregationIncrease.into()
        );
        assert_eq!(
            StackingSignatureMethod::from_str("agg-commit", true).unwrap(),
            Pox4SignatureTopic::AggregationCommit.into()
        );
        assert_eq!(
            StackingSignatureMethod::from_str("stack-increase", true).unwrap(),
            Pox4SignatureTopic::StackIncrease.into()
        );
        assert_eq!(
            StackingSignatureMethod::from_str("stack-extend", true).unwrap(),
            Pox4SignatureTopic::StackExtend.into()
        );
        assert_eq!(
            StackingSignatureMethod::from_str("stack-stx", true).unwrap(),
            Pox4SignatureTopic::StackStx.into()
        );

        // These don't exactly match the enum, but are accepted if passed as
        // CLI args

        assert_eq!(
            StackingSignatureMethod::from_str("aggregation-increase", true).unwrap(),
            Pox4SignatureTopic::AggregationIncrease.into()
        );
        assert_eq!(
            StackingSignatureMethod::from_str("aggregation-commit", true).unwrap(),
            Pox4SignatureTopic::AggregationCommit.into()
        );
    }
}
