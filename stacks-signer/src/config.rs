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

use std::fmt::{Debug, Display};
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use blockstack_lib::chainstate::stacks::TransactionVersion;
use blockstack_lib::net::connection::DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS;
use clarity::util::hash::to_hex;
use libsigner::SignerEntries;
use serde::Deserialize;
use stacks_common::address::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
use stacks_common::util::hash::Hash160;

use crate::client::SignerSlotID;

const EVENT_TIMEOUT_MS: u64 = 5000;
const BLOCK_PROPOSAL_TIMEOUT_MS: u64 = 120_000;
const BLOCK_PROPOSAL_VALIDATION_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_FIRST_PROPOSAL_BURN_BLOCK_TIMING_SECS: u64 = 60;
const DEFAULT_TENURE_LAST_BLOCK_PROPOSAL_TIMEOUT_SECS: u64 = 30;
const DEFAULT_DRY_RUN: bool = false;
const TENURE_IDLE_TIMEOUT_SECS: u64 = 120;
const DEFAULT_REORG_ATTEMPTS_ACTIVITY_TIMEOUT_MS: u64 = 200_000;
/// Default number of seconds to add to the tenure extend time, after computing the idle timeout,
/// to allow for clock skew between the signer and the miner
const DEFAULT_TENURE_IDLE_TIMEOUT_BUFFER_SECS: u64 = 2;

#[derive(thiserror::Error, Debug)]
/// An error occurred parsing the provided configuration
pub enum ConfigError {
    /// Error occurred reading config file
    #[error("{0}")]
    InvalidConfig(String),
    /// An error occurred parsing the TOML data
    #[error("{0}")]
    ParseError(String),
    /// A field was malformed
    #[error("identifier={0}, value={1}")]
    BadField(String, String),
    /// An unsupported address version
    #[error("Failed to convert private key to address: unsupported address version.")]
    UnsupportedAddressVersion,
}

#[derive(serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
/// The Stacks network to use.
pub enum Network {
    /// The mainnet network
    Mainnet,
    /// The testnet network
    Testnet,
    /// The mocknet network
    Mocknet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mainnet => write!(f, "mainnet"),
            Self::Testnet => write!(f, "testnet"),
            Self::Mocknet => write!(f, "mocknet"),
        }
    }
}

impl Network {
    /// Convert a Network enum variant to a corresponding address version
    pub const fn to_address_version(&self) -> u8 {
        match self {
            Self::Mainnet => C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
            Self::Testnet | Self::Mocknet => C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        }
    }

    /// Convert a Network enum variant to a Transaction Version
    pub const fn to_transaction_version(&self) -> TransactionVersion {
        match self {
            Self::Mainnet => TransactionVersion::Mainnet,
            Self::Testnet | Self::Mocknet => TransactionVersion::Testnet,
        }
    }

    /// Check if the network is Mainnet or not
    pub const fn is_mainnet(&self) -> bool {
        match self {
            Self::Mainnet => true,
            Self::Testnet | Self::Mocknet => false,
        }
    }
}

/// Signer config mode (whether dry-run or real)
#[derive(Debug, Clone)]
pub enum SignerConfigMode {
    /// Dry run operation: signer is not actually registered, the signer
    ///  will not submit stackerdb messages, etc.
    DryRun,
    /// Normal signer operation: if registered, the signer will submit
    /// stackerdb messages, etc.
    Normal {
        /// The signer ID assigned to this signer (may be different from signer_slot_id)
        signer_id: u32,
        /// The signer stackerdb slot id (may be different from signer_id)
        signer_slot_id: SignerSlotID,
    },
}

impl std::fmt::Display for SignerConfigMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerConfigMode::DryRun => write!(f, "Dry-Run signer"),
            SignerConfigMode::Normal { signer_id, .. } => write!(f, "signer #{signer_id}"),
        }
    }
}

/// The Configuration info needed for an individual signer per reward cycle
#[derive(Debug, Clone)]
pub struct SignerConfig {
    /// The reward cycle of the configuration
    pub reward_cycle: u64,
    /// The registered signers for this reward cycle
    pub signer_entries: SignerEntries,
    /// The signer slot ids of all signers registered for this reward cycle
    pub signer_slot_ids: Vec<SignerSlotID>,
    /// The private key for this signer
    pub stacks_private_key: StacksPrivateKey,
    /// The node host for this signer
    pub node_host: String,
    /// Whether this signer is running on mainnet or not
    pub mainnet: bool,
    /// The path to the signer's database file
    pub db_path: PathBuf,
    /// How much time must pass between the first block proposal in a tenure and the next bitcoin block
    ///  before a subsequent miner isn't allowed to reorg the tenure
    pub first_proposal_burn_block_timing: Duration,
    /// How much time to wait for a miner to propose a block following a sortition
    pub block_proposal_timeout: Duration,
    /// Time to wait for the last block of a tenure to be globally accepted or rejected
    /// before considering a new miner's block at the same height as potentially valid.
    pub tenure_last_block_proposal_timeout: Duration,
    /// How much time to wait for a block proposal validation response before marking the block invalid
    pub block_proposal_validation_timeout: Duration,
    /// How much idle time must pass before allowing a tenure extend
    pub tenure_idle_timeout: Duration,
    /// Amount of buffer time to add to the tenure extend time sent to miners to allow for
    /// clock skew
    pub tenure_idle_timeout_buffer: Duration,
    /// The maximum age of a block proposal in seconds that will be processed by the signer
    pub block_proposal_max_age_secs: u64,
    /// Time following the last block of the previous tenure's global acceptance that a signer will consider an attempt by
    /// the new miner to reorg it as valid towards miner activity
    pub reorg_attempts_activity_timeout: Duration,
    /// The running mode for the signer (dry-run or normal)
    pub signer_mode: SignerConfigMode,
}

/// The parsed configuration for the signer
#[derive(Clone)]
pub struct GlobalConfig {
    /// endpoint to the stacks node
    pub node_host: String,
    /// endpoint to the event receiver
    pub endpoint: SocketAddr,
    /// The signer's Stacks private key
    pub stacks_private_key: StacksPrivateKey,
    /// The signer's Stacks address
    pub stacks_address: StacksAddress,
    /// The network to use. One of "mainnet" or "testnet".
    pub network: Network,
    /// The time to wait for a response from the stacker-db instance
    pub event_timeout: Duration,
    /// the authorization password for the block proposal endpoint
    pub auth_password: String,
    /// The path to the signer's database file
    pub db_path: PathBuf,
    /// Metrics endpoint
    pub metrics_endpoint: Option<SocketAddr>,
    /// How much time between the first block proposal in a tenure and the next bitcoin block
    ///  must pass before a subsequent miner isn't allowed to reorg the tenure
    pub first_proposal_burn_block_timing: Duration,
    /// How much time to wait for a miner to propose a block following a sortition
    pub block_proposal_timeout: Duration,
    /// An optional custom Chain ID
    pub chain_id: Option<u32>,
    /// Time to wait for the last block of a tenure to be globally accepted or rejected
    /// before considering a new miner's block at the same height as potentially valid.
    pub tenure_last_block_proposal_timeout: Duration,
    /// How long to wait for a response from a block proposal validation response from the node
    /// before marking that block as invalid and rejecting it
    pub block_proposal_validation_timeout: Duration,
    /// How much idle time must pass before allowing a tenure extend
    pub tenure_idle_timeout: Duration,
    /// Amount of buffer time to add to the tenure extend time sent to miners to allow for
    /// clock skew
    pub tenure_idle_timeout_buffer: Duration,
    /// The maximum age of a block proposal that will be processed by the signer
    pub block_proposal_max_age_secs: u64,
    /// Time following the last block of the previous tenure's global acceptance that a signer will consider an attempt by
    /// the new miner to reorg it as valid towards miner activity
    pub reorg_attempts_activity_timeout: Duration,
    /// Is this signer binary going to be running in dry-run mode?
    pub dry_run: bool,
}

/// Internal struct for loading up the config file
#[derive(Deserialize, Debug)]
struct RawConfigFile {
    /// endpoint to stacks node
    pub node_host: String,
    /// endpoint to event receiver
    pub endpoint: String,
    /// The hex representation of the signer's Stacks private key used for communicating
    /// with the Stacks Node, including writing to the Stacker DB instance.
    pub stacks_private_key: String,
    /// The network to use. One of "mainnet" or "testnet".
    pub network: Network,
    /// The time to wait (in millisecs) for a response from the stacker-db instance
    pub event_timeout_ms: Option<u64>,
    /// The authorization password for the block proposal endpoint
    pub auth_password: String,
    /// The path to the signer's database file or :memory: for an in-memory database
    pub db_path: String,
    /// Metrics endpoint
    pub metrics_endpoint: Option<String>,
    /// How much time (in secs) must pass between the first block proposal in a tenure and the next bitcoin block
    /// before a subsequent miner isn't allowed to reorg the tenure
    pub first_proposal_burn_block_timing_secs: Option<u64>,
    /// How much time (in millisecs) to wait for a miner to propose a block following a sortition
    pub block_proposal_timeout_ms: Option<u64>,
    /// An optional custom Chain ID
    pub chain_id: Option<u32>,
    /// Time in seconds to wait for the last block of a tenure to be globally accepted or rejected
    /// before considering a new miner's block at the same height as potentially valid.
    pub tenure_last_block_proposal_timeout_secs: Option<u64>,
    /// How long to wait (in millisecs) for a response from a block proposal validation response from the node
    /// before marking that block as invalid and rejecting it
    pub block_proposal_validation_timeout_ms: Option<u64>,
    /// How much idle time (in seconds) must pass before a tenure extend is allowed
    pub tenure_idle_timeout_secs: Option<u64>,
    /// Number of seconds of buffer to add to the tenure extend time sent to miners to allow for
    /// clock skew
    pub tenure_idle_timeout_buffer_secs: Option<u64>,
    /// The maximum age of a block proposal (in secs) that will be processed by the signer.
    pub block_proposal_max_age_secs: Option<u64>,
    /// Time (in millisecs) following a block's global acceptance that a signer will consider an attempt by a miner
    /// to reorg the block as valid towards miner activity
    pub reorg_attempts_activity_timeout_ms: Option<u64>,
    /// Is this signer binary going to be running in dry-run mode?
    pub dry_run: Option<bool>,
}

impl RawConfigFile {
    /// load the config from a string
    pub fn load_from_str(data: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(data).map_err(|e| ConfigError::ParseError(format!("{e:?}")))?;
        Ok(config)
    }
    /// load the config from a file and parse it
    #[allow(dead_code)]
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        Self::try_from(&PathBuf::from(path))
    }
}

impl TryFrom<&PathBuf> for RawConfigFile {
    type Error = ConfigError;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        Self::load_from_str(&fs::read_to_string(path).map_err(|e| {
            ConfigError::InvalidConfig(format!("failed to read config file: {e:?}"))
        })?)
    }
}

impl TryFrom<RawConfigFile> for GlobalConfig {
    type Error = ConfigError;

    /// Attempt to decode the raw config file's primitive types into our types.
    /// NOTE: network access is required for this to work
    fn try_from(raw_data: RawConfigFile) -> Result<Self, Self::Error> {
        url::Url::parse(&format!("http://{}", raw_data.node_host)).map_err(|_| {
            ConfigError::BadField("node_host".to_string(), raw_data.node_host.clone())
        })?;

        let endpoint = raw_data
            .endpoint
            .to_socket_addrs()
            .map_err(|_| ConfigError::BadField("endpoint".to_string(), raw_data.endpoint.clone()))?
            .next()
            .ok_or_else(|| {
                ConfigError::BadField("endpoint".to_string(), raw_data.endpoint.clone())
            })?;

        let stacks_private_key = StacksPrivateKey::from_hex(&raw_data.stacks_private_key)
            .map_err(|e| ConfigError::BadField("stacks_private_key".to_string(), e.into()))?;
        let stacks_public_key = StacksPublicKey::from_private(&stacks_private_key);
        let signer_hash = Hash160::from_data(stacks_public_key.to_bytes_compressed().as_slice());
        let stacks_address =
            StacksAddress::p2pkh_from_hash(raw_data.network.is_mainnet(), signer_hash);
        let event_timeout =
            Duration::from_millis(raw_data.event_timeout_ms.unwrap_or(EVENT_TIMEOUT_MS));
        let first_proposal_burn_block_timing = Duration::from_secs(
            raw_data
                .first_proposal_burn_block_timing_secs
                .unwrap_or(DEFAULT_FIRST_PROPOSAL_BURN_BLOCK_TIMING_SECS),
        );
        let db_path = raw_data.db_path.into();

        let metrics_endpoint = match raw_data.metrics_endpoint {
            Some(endpoint) => Some(
                endpoint
                    .to_socket_addrs()
                    .map_err(|_| ConfigError::BadField("endpoint".to_string(), endpoint.clone()))?
                    .next()
                    .ok_or_else(|| {
                        ConfigError::BadField("endpoint".to_string(), endpoint.clone())
                    })?,
            ),
            None => None,
        };

        let block_proposal_timeout = Duration::from_millis(
            raw_data
                .block_proposal_timeout_ms
                .unwrap_or(BLOCK_PROPOSAL_TIMEOUT_MS),
        );

        let tenure_last_block_proposal_timeout = Duration::from_secs(
            raw_data
                .tenure_last_block_proposal_timeout_secs
                .unwrap_or(DEFAULT_TENURE_LAST_BLOCK_PROPOSAL_TIMEOUT_SECS),
        );

        let block_proposal_validation_timeout = Duration::from_millis(
            raw_data
                .block_proposal_validation_timeout_ms
                .unwrap_or(BLOCK_PROPOSAL_VALIDATION_TIMEOUT_MS),
        );

        let tenure_idle_timeout = Duration::from_secs(
            raw_data
                .tenure_idle_timeout_secs
                .unwrap_or(TENURE_IDLE_TIMEOUT_SECS),
        );

        let block_proposal_max_age_secs = raw_data
            .block_proposal_max_age_secs
            .unwrap_or(DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS);

        let reorg_attempts_activity_timeout = Duration::from_millis(
            raw_data
                .reorg_attempts_activity_timeout_ms
                .unwrap_or(DEFAULT_REORG_ATTEMPTS_ACTIVITY_TIMEOUT_MS),
        );

        let dry_run = raw_data.dry_run.unwrap_or(DEFAULT_DRY_RUN);

        let tenure_idle_timeout_buffer = Duration::from_secs(
            raw_data
                .tenure_idle_timeout_buffer_secs
                .unwrap_or(DEFAULT_TENURE_IDLE_TIMEOUT_BUFFER_SECS),
        );

        Ok(Self {
            node_host: raw_data.node_host,
            endpoint,
            stacks_private_key,
            stacks_address,
            network: raw_data.network,
            event_timeout,
            auth_password: raw_data.auth_password,
            db_path,
            metrics_endpoint,
            first_proposal_burn_block_timing,
            block_proposal_timeout,
            chain_id: raw_data.chain_id,
            tenure_last_block_proposal_timeout,
            block_proposal_validation_timeout,
            tenure_idle_timeout,
            block_proposal_max_age_secs,
            reorg_attempts_activity_timeout,
            dry_run,
            tenure_idle_timeout_buffer,
        })
    }
}

impl TryFrom<&PathBuf> for GlobalConfig {
    type Error = ConfigError;
    fn try_from(path: &PathBuf) -> Result<Self, ConfigError> {
        let config_file = RawConfigFile::try_from(path)?;
        Self::try_from(config_file)
    }
}

impl GlobalConfig {
    /// load the config from a string and parse it
    pub fn load_from_str(data: &str) -> Result<Self, ConfigError> {
        RawConfigFile::load_from_str(data)?.try_into()
    }

    /// load the config from a file and parse it
    pub fn load_from_file(path: &str) -> Result<Self, ConfigError> {
        Self::try_from(&PathBuf::from(path))
    }

    /// Return a string with non-sensitive configuration
    /// information for logging purposes
    pub fn config_to_log_string(&self) -> String {
        let metrics_endpoint = match &self.metrics_endpoint {
            Some(endpoint) => endpoint.to_string(),
            None => "None".to_string(),
        };
        let chain_id = format!("{:x}", self.to_chain_id());
        format!(
            r#"
Stacks node host: {node_host}
Signer endpoint: {endpoint}
Stacks address: {stacks_address}
Public key: {public_key}
Network: {network}
Chain ID: 0x{chain_id}
Database path: {db_path}
Metrics endpoint: {metrics_endpoint}
"#,
            node_host = self.node_host,
            endpoint = self.endpoint,
            stacks_address = self.stacks_address,
            public_key = to_hex(
                &StacksPublicKey::from_private(&self.stacks_private_key).to_bytes_compressed()
            ),
            network = self.network,
            db_path = self.db_path.to_str().unwrap_or_default(),
            metrics_endpoint = metrics_endpoint,
        )
    }

    /// Get the chain ID for the network
    pub fn to_chain_id(&self) -> u32 {
        self.chain_id.unwrap_or(match self.network {
            Network::Mainnet => CHAIN_ID_MAINNET,
            Network::Testnet | Network::Mocknet => CHAIN_ID_TESTNET,
        })
    }
}

impl Display for GlobalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.config_to_log_string())
    }
}

impl Debug for GlobalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.config_to_log_string())
    }
}

/// Helper function for building a signer config for each provided signer private key
#[allow(clippy::too_many_arguments)]
pub fn build_signer_config_tomls(
    stacks_private_keys: &[StacksPrivateKey],
    node_host: &str,
    timeout: Option<Duration>,
    network: &Network,
    password: &str,
    run_stamp: u16,
    mut port_start: usize,
    max_tx_fee_ustx: Option<u64>,
    tx_fee_ustx: Option<u64>,
    mut metrics_port_start: Option<usize>,
    chain_id: Option<u32>,
) -> Vec<String> {
    let mut signer_config_tomls = vec![];

    for stacks_private_key in stacks_private_keys {
        let endpoint = format!("localhost:{}", port_start);
        port_start += 1;

        let stacks_public_key = StacksPublicKey::from_private(stacks_private_key).to_hex();
        let db_dir = format!(
            "/tmp/stacks-node-tests/integrations-signers/{run_stamp}/signer_{stacks_public_key}"
        );
        let db_path = format!("{db_dir}/signerdb.sqlite");
        fs::create_dir_all(&db_dir).unwrap();

        let stacks_private_key = stacks_private_key.to_hex();
        let mut signer_config_toml = format!(
            r#"
stacks_private_key = "{stacks_private_key}"
node_host = "{node_host}"
endpoint = "{endpoint}"
network = "{network}"
auth_password = "{password}"
db_path = "{db_path}"
"#
        );

        if let Some(timeout) = timeout {
            let event_timeout_ms = timeout.as_millis();
            signer_config_toml = format!(
                r#"
{signer_config_toml}
event_timeout = {event_timeout_ms}
"#
            )
        }

        if let Some(max_tx_fee_ustx) = max_tx_fee_ustx {
            signer_config_toml = format!(
                r#"
{signer_config_toml}
max_tx_fee_ustx = {max_tx_fee_ustx}
"#
            )
        }

        if let Some(tx_fee_ustx) = tx_fee_ustx {
            signer_config_toml = format!(
                r#"
{signer_config_toml}
tx_fee_ustx = {tx_fee_ustx}
"#
            )
        }

        if let Some(metrics_port) = metrics_port_start {
            let metrics_endpoint = format!("localhost:{}", metrics_port);
            signer_config_toml = format!(
                r#"
{signer_config_toml}
metrics_endpoint = "{metrics_endpoint}"
"#
            );
            metrics_port_start = Some(metrics_port + 1);
        }

        if let Some(chain_id) = chain_id {
            signer_config_toml = format!(
                r#"
{signer_config_toml}
chain_id = {chain_id}
"#
            )
        }

        signer_config_tomls.push(signer_config_toml);
    }

    signer_config_tomls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_signer_config_tomls_should_produce_deserializable_strings() {
        let pk = StacksPrivateKey::from_hex(
            "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
        )
        .unwrap();

        let node_host = "localhost";
        let network = Network::Testnet;
        let password = "melon";

        let config_tomls = build_signer_config_tomls(
            &[pk],
            node_host,
            None,
            &network,
            password,
            rand::random(),
            3000,
            None,
            None,
            Some(4000),
            None,
        );

        let config =
            RawConfigFile::load_from_str(&config_tomls[0]).expect("Failed to parse config file");

        assert_eq!(config.auth_password, "melon");
        assert_eq!(config.metrics_endpoint, Some("localhost:4000".to_string()));
        let global_config = GlobalConfig::try_from(config).unwrap();
        assert_eq!(global_config.to_chain_id(), CHAIN_ID_TESTNET);
    }

    #[test]
    fn test_config_to_string() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let config_str = config.config_to_log_string();

        let expected_str_v4 = r#"
Stacks node host: 127.0.0.1:20443
Signer endpoint: 127.0.0.1:30000
Stacks address: ST3FPN8KBZ3YPBP0ZJGAAHTVFMQDTJCR5QPS7VTNJ
Public key: 03bc489f27da3701d9f9e577c88de5567cf4023111b7577042d55cde4d823a3505
Network: testnet
Chain ID: 0x80000000
Database path: :memory:
Metrics endpoint: 0.0.0.0:9090
Chain ID: 2147483648
"#;

        let expected_str_v6 = r#"
Stacks node host: 127.0.0.1:20443
Signer endpoint: [::1]:30000
Stacks address: ST3FPN8KBZ3YPBP0ZJGAAHTVFMQDTJCR5QPS7VTNJ
Public key: 03bc489f27da3701d9f9e577c88de5567cf4023111b7577042d55cde4d823a3505
Network: testnet
Chain ID: 0x80000000
Database path: :memory:
Metrics endpoint: 0.0.0.0:9090
"#;

        assert!(
            config_str == expected_str_v4 || config_str == expected_str_v6,
            "Config string does not match expected output. Actual:\n{}",
            config_str
        );
    }

    #[test]
    // Test the same private key twice, with and without a compression flag.
    // Ensure that the address is the same in both cases.
    fn test_stacks_addr_from_priv_key() {
        // 64 bytes, no compression flag
        let sk_hex = "2de4e77aab89c0c2570bb8bb90824f5cf2a5204a975905fee450ff9dad0fcf28";

        let expected_addr = "SP1286C62P3TAWVQV2VM2CEGTRBQZSZ6MHMS9RW05";

        let config_toml = format!(
            r#"
stacks_private_key = "{sk_hex}"
node_host = "localhost"
endpoint = "localhost:30000"
network = "mainnet"
auth_password = "abcd"
db_path = ":memory:"
            "#
        );
        let config = GlobalConfig::load_from_str(&config_toml).unwrap();
        assert_eq!(config.stacks_address.to_string(), expected_addr);

        // 65 bytes (with compression flag)
        let sk_hex = "2de4e77aab89c0c2570bb8bb90824f5cf2a5204a975905fee450ff9dad0fcf2801";

        let config_toml = format!(
            r#"
stacks_private_key = "{sk_hex}"
node_host = "localhost"
endpoint = "localhost:30000"
network = "mainnet"
auth_password = "abcd"
db_path = ":memory:"
            "#
        );
        let config = GlobalConfig::load_from_str(&config_toml).unwrap();
        assert_eq!(config.stacks_address.to_string(), expected_addr);
        assert_eq!(config.to_chain_id(), CHAIN_ID_MAINNET);
    }

    #[test]
    fn test_custom_chain_id() {
        let pk = StacksPrivateKey::from_hex(
            "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01",
        )
        .unwrap();

        let node_host = "localhost";
        let network = Network::Testnet;
        let password = "melon";
        let config_tomls = build_signer_config_tomls(
            &[pk],
            node_host,
            None,
            &network,
            password,
            rand::random(),
            3000,
            None,
            None,
            Some(4000),
            Some(0x80000100),
        );

        let config =
            RawConfigFile::load_from_str(&config_tomls[0]).expect("Failed to parse config file");
        assert_eq!(config.chain_id, Some(0x80000100));
        let global_config = GlobalConfig::try_from(config).unwrap();
        assert_eq!(global_config.to_chain_id(), 0x80000100);
    }
}
