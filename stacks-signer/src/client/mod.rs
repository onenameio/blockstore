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

/// The stacker db module for communicating with the stackerdb contract
pub(crate) mod stackerdb;
/// The stacks node client module for communicating with the stacks node
pub(crate) mod stacks_client;

use std::time::Duration;

use clarity::vm::errors::Error as ClarityError;
use clarity::vm::types::serialization::SerializationError;
use libsigner::RPCError;
use libstackerdb::Error as StackerDBError;
use slog::slog_debug;
pub use stackerdb::*;
pub use stacks_client::*;
use stacks_common::codec::Error as CodecError;
use stacks_common::debug;

/// Backoff timer initial interval in milliseconds
const BACKOFF_INITIAL_INTERVAL: u64 = 128;
/// Backoff timer max interval in milliseconds
const BACKOFF_MAX_INTERVAL: u64 = 16384;
/// Backoff timer max elapsed seconds
const BACKOFF_MAX_ELAPSED: u64 = 5;

#[derive(thiserror::Error, Debug)]
/// Client error type
pub enum ClientError {
    /// Error for when a response's format does not match the expected structure
    #[error("Unexpected response format: {0}")]
    UnexpectedResponseFormat(String),
    /// An error occurred serializing the message
    #[error("Unable to serialize stacker-db message: {0}")]
    StackerDBSerializationError(#[from] CodecError),
    /// Failed to sign stacker-db chunk
    #[error("Failed to sign stacker-db chunk: {0}")]
    FailToSign(#[from] StackerDBError),
    /// Stacker-db instance rejected the chunk
    #[error("Stacker-db rejected the chunk. Reason: {0}")]
    PutChunkRejected(String),
    /// Failed to call a read only function
    #[error("Failed to call read only function. {0}")]
    ReadOnlyFailure(String),
    /// Reqwest specific error occurred
    #[error("{0}")]
    ReqwestError(#[from] reqwest::Error),
    /// Failed to build and sign a new Stacks transaction.
    #[error("Failed to generate transaction from a transaction signer: {0}")]
    TransactionGenerationFailure(String),
    /// Stacks node client request failed
    #[error("Stacks node client request failed: {0}")]
    RequestFailure(reqwest::StatusCode),
    /// Failed to serialize a Clarity value
    #[error("Failed to serialize Clarity value: {0}")]
    ClaritySerializationError(#[from] SerializationError),
    /// Failed to parse a Clarity value
    #[error("Received a malformed clarity value: {0}")]
    MalformedClarityValue(String),
    /// Backoff retry timeout
    #[error("Backoff retry timeout occurred. Stacks node may be down.")]
    RetryTimeout,
    /// Not connected
    #[error("Not connected")]
    NotConnected,
    /// Clarity interpreter error
    #[error("Clarity interpreter error: {0}")]
    ClarityError(#[from] ClarityError),
    /// Malformed reward set
    #[error("Malformed contract data: {0}")]
    MalformedContractData(String),
    /// Stacks node does not support a feature we need
    #[error("Stacks node does not support a required feature: {0}")]
    UnsupportedStacksFeature(String),
    /// Invalid response from the stacks node
    #[error("Invalid response from the stacks node: {0}")]
    InvalidResponse(String),
    /// A successful sortition's info response should be parseable into a SortitionState
    #[error("A successful sortition's info response should be parseable into a SortitionState")]
    UnexpectedSortitionInfo,
    /// An RPC libsigner error occurred
    #[error("A libsigner RPC error occurred: {0}")]
    RPCError(#[from] RPCError),
}

/// Retry a function F with an exponential backoff and notification on transient failure
pub fn retry_with_exponential_backoff<F, E, T>(request_fn: F) -> Result<T, ClientError>
where
    F: FnMut() -> Result<T, backoff::Error<E>>,
    E: std::fmt::Debug,
{
    let notify = |err, dur| {
        debug!(
            "Failed to connect to stacks node and/or deserialize its response: {err:?}. Next attempt in {dur:?}"
        );
    };

    let backoff_timer = backoff::ExponentialBackoffBuilder::new()
        .with_initial_interval(Duration::from_millis(BACKOFF_INITIAL_INTERVAL))
        .with_max_interval(Duration::from_millis(BACKOFF_MAX_INTERVAL))
        .with_max_elapsed_time(Some(Duration::from_secs(BACKOFF_MAX_ELAPSED)))
        .build();

    backoff::retry_notify(backoff_timer, request_fn, notify).map_err(|_| ClientError::RetryTimeout)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};

    use blockstack_lib::chainstate::stacks::boot::POX_4_NAME;
    use blockstack_lib::chainstate::stacks::db::StacksBlockHeaderTypes;
    use blockstack_lib::net::api::getinfo::RPCPeerInfoData;
    use blockstack_lib::net::api::getpoxinfo::{
        RPCPoxCurrentCycleInfo, RPCPoxEpoch, RPCPoxInfoData, RPCPoxNextCycleInfo,
    };
    use blockstack_lib::util_lib::boot::boot_code_id;
    use clarity::vm::costs::ExecutionCost;
    use clarity::vm::Value as ClarityValue;
    use libsigner::SignerEntries;
    use rand::distributions::Standard;
    use rand::{thread_rng, Rng};
    use rand_core::RngCore;
    use stacks_common::types::chainstate::{
        BlockHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
    };
    use stacks_common::types::{StacksEpochId, StacksPublicKeyBuffer};
    use stacks_common::util::hash::{Hash160, Sha256Sum};

    use super::*;
    use crate::config::{GlobalConfig, SignerConfig, SignerConfigMode};

    pub struct MockServerClient {
        pub server: TcpListener,
        pub client: StacksClient,
        pub config: GlobalConfig,
    }

    impl MockServerClient {
        /// Construct a new MockServerClient on a random port
        pub fn new() -> Self {
            let mut config =
                GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
            let (server, mock_server_addr) = mock_server_random();
            config.node_host = mock_server_addr.to_string();

            let client = StacksClient::from(&config);
            Self {
                server,
                client,
                config,
            }
        }

        /// Construct a new MockServerClient on the port specified in the config
        pub fn from_config(config: GlobalConfig) -> Self {
            let server = mock_server_from_config(&config);
            let client = StacksClient::from(&config);
            Self {
                server,
                client,
                config,
            }
        }
    }

    /// Create a mock server on a random port and return the socket addr
    pub fn mock_server_random() -> (TcpListener, SocketAddr) {
        let mut mock_server_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        // Ask the OS to assign a random port to listen on by passing 0
        let server = TcpListener::bind(mock_server_addr).unwrap();

        mock_server_addr.set_port(server.local_addr().unwrap().port());
        (server, mock_server_addr)
    }

    /// Create a mock server on a same port as in the config
    pub fn mock_server_from_config(config: &GlobalConfig) -> TcpListener {
        TcpListener::bind(config.node_host.to_string()).unwrap()
    }

    /// Write a response to the mock server and return the request bytes
    pub fn write_response(mock_server: TcpListener, bytes: &[u8]) -> [u8; 1024] {
        debug!("Writing a response...");
        let mut request_bytes = [0u8; 1024];
        {
            let mut stream = mock_server.accept().unwrap().0;
            let _ = stream.read(&mut request_bytes).unwrap();
            stream.write_all(bytes).unwrap();
        }
        request_bytes
    }

    pub fn generate_random_consensus_hash() -> ConsensusHash {
        let rng = rand::thread_rng();
        let bytes: Vec<u8> = rng.sample_iter(Standard).take(20).collect();
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes);
        ConsensusHash(hash)
    }

    /// Build a response to get_pox_data_with_retry where it returns a specific reward cycle id and block height
    pub fn build_get_pox_data_response(
        reward_cycle: Option<u64>,
        prepare_phase_start_height: Option<u64>,
        epoch_25_activation_height: Option<u64>,
        epoch_30_activation_height: Option<u64>,
    ) -> (String, RPCPoxInfoData) {
        // Populate some random data!
        let epoch_25_start = epoch_25_activation_height.unwrap_or(thread_rng().next_u64());
        let epoch_30_start =
            epoch_30_activation_height.unwrap_or(epoch_25_start.saturating_add(1000));
        let current_id = reward_cycle.unwrap_or(thread_rng().next_u64());
        let next_id = current_id.saturating_add(1);
        let pox_info = RPCPoxInfoData {
            contract_id: boot_code_id(POX_4_NAME, false).to_string(),
            pox_activation_threshold_ustx: thread_rng().next_u64(),
            first_burnchain_block_height: thread_rng().next_u64(),
            current_burnchain_block_height: thread_rng().next_u64(),
            prepare_phase_block_length: thread_rng().next_u64(),
            reward_phase_block_length: thread_rng().next_u64(),
            reward_slots: thread_rng().next_u64(),
            rejection_fraction: None,
            total_liquid_supply_ustx: thread_rng().next_u64(),
            current_cycle: RPCPoxCurrentCycleInfo {
                id: current_id,
                min_threshold_ustx: thread_rng().next_u64(),
                stacked_ustx: thread_rng().next_u64(),
                is_pox_active: true,
            },
            next_cycle: RPCPoxNextCycleInfo {
                id: next_id,
                min_threshold_ustx: thread_rng().next_u64(),
                min_increment_ustx: thread_rng().next_u64(),
                stacked_ustx: thread_rng().next_u64(),
                prepare_phase_start_block_height: prepare_phase_start_height
                    .unwrap_or(thread_rng().next_u64()),
                blocks_until_prepare_phase: thread_rng().next_u32() as i64,
                reward_phase_start_block_height: thread_rng().next_u64(),
                blocks_until_reward_phase: thread_rng().next_u64(),
                ustx_until_pox_rejection: None,
            },
            min_amount_ustx: thread_rng().next_u64(),
            prepare_cycle_length: thread_rng().next_u64(),
            reward_cycle_id: current_id,
            epochs: vec![
                RPCPoxEpoch {
                    start_height: epoch_25_start,
                    end_height: epoch_30_start,
                    block_limit: ExecutionCost {
                        write_length: thread_rng().next_u64(),
                        write_count: thread_rng().next_u64(),
                        read_length: thread_rng().next_u64(),
                        read_count: thread_rng().next_u64(),
                        runtime: thread_rng().next_u64(),
                    },
                    epoch_id: StacksEpochId::Epoch25,
                    network_epoch: 0,
                },
                RPCPoxEpoch {
                    start_height: epoch_30_start,
                    end_height: epoch_30_start.saturating_add(1000),
                    block_limit: ExecutionCost {
                        write_length: thread_rng().next_u64(),
                        write_count: thread_rng().next_u64(),
                        read_length: thread_rng().next_u64(),
                        read_count: thread_rng().next_u64(),
                        runtime: thread_rng().next_u64(),
                    },
                    epoch_id: StacksEpochId::Epoch30,
                    network_epoch: 0,
                },
            ],
            reward_cycle_length: thread_rng().next_u64(),
            rejection_votes_left_required: None,
            next_reward_cycle_in: thread_rng().next_u64(),
            contract_versions: vec![],
        };
        let pox_info_json = serde_json::to_string(&pox_info).expect("Failed to serialize pox info");
        (format!("HTTP/1.1 200 Ok\n\n{pox_info_json}"), pox_info)
    }

    /// Build a response for the get_peer_info_with_retry request with a specific stacks tip height and consensus hash
    pub fn build_get_peer_info_response(
        burn_block_height: Option<u64>,
        pox_consensus_hash: Option<ConsensusHash>,
    ) -> (String, RPCPeerInfoData) {
        // Generate some random info
        let private_key = StacksPrivateKey::random();
        let public_key = StacksPublicKey::from_private(&private_key);
        let public_key_buf = StacksPublicKeyBuffer::from_public_key(&public_key);
        let public_key_hash = Hash160::from_node_public_key(&public_key);
        let stackerdb_contract_ids =
            vec![boot_code_id("fake", false), boot_code_id("fake_2", false)];
        let peer_info = RPCPeerInfoData {
            peer_version: thread_rng().next_u32(),
            pox_consensus: pox_consensus_hash.unwrap_or(generate_random_consensus_hash()),
            burn_block_height: burn_block_height.unwrap_or(thread_rng().next_u64()),
            stable_pox_consensus: generate_random_consensus_hash(),
            stable_burn_block_height: 2,
            server_version: "fake version".to_string(),
            network_id: thread_rng().next_u32(),
            parent_network_id: thread_rng().next_u32(),
            stacks_tip_height: thread_rng().next_u64(),
            stacks_tip: BlockHeaderHash([0x06; 32]),
            stacks_tip_consensus_hash: generate_random_consensus_hash(),
            unanchored_tip: None,
            unanchored_seq: Some(0),
            tenure_height: thread_rng().next_u64(),
            exit_at_block_height: None,
            is_fully_synced: false,
            genesis_chainstate_hash: Sha256Sum::zero(),
            node_public_key: Some(public_key_buf),
            node_public_key_hash: Some(public_key_hash),
            affirmations: None,
            last_pox_anchor: None,
            stackerdbs: Some(
                stackerdb_contract_ids
                    .into_iter()
                    .map(|cid| format!("{}", cid))
                    .collect(),
            ),
        };
        let peer_info_json =
            serde_json::to_string(&peer_info).expect("Failed to serialize peer info");
        (format!("HTTP/1.1 200 OK\n\n{peer_info_json}"), peer_info)
    }

    /// Build a response to a read only clarity contract call
    pub fn build_read_only_response(value: &ClarityValue) -> String {
        let hex = value
            .serialize_to_hex()
            .expect("Failed to serialize hex value");
        format!("HTTP/1.1 200 OK\n\n{{\"okay\":true,\"result\":\"{hex}\"}}")
    }

    /// Generate a signer config with the given number of signers and keys where the first signer is
    /// obtained from the provided global config
    pub fn generate_signer_config(config: &GlobalConfig, num_signers: u32) -> SignerConfig {
        assert!(
            num_signers > 0,
            "Cannot generate 0 signers...Specify at least 1 signer."
        );

        let weight_per_signer = 100 / num_signers;
        let mut remaining_weight = 100 % num_signers;

        let reward_cycle = thread_rng().next_u64();

        let mut signer_pk_to_id = HashMap::new();
        let mut signer_id_to_pk = HashMap::new();
        let mut signer_addr_to_id = HashMap::new();
        let mut signer_pks = Vec::new();
        let mut signer_slot_ids = Vec::new();
        let mut signer_id_to_addr = BTreeMap::new();
        let mut signer_addr_to_weight = HashMap::new();
        let mut signer_addresses = Vec::new();

        for signer_id in 0..num_signers {
            let private_key = if signer_id == 0 {
                config.stacks_private_key
            } else {
                StacksPrivateKey::random()
            };
            let public_key = StacksPublicKey::from_private(&private_key);

            signer_id_to_pk.insert(signer_id, public_key);
            signer_pk_to_id.insert(public_key, signer_id);
            let address = StacksAddress::p2pkh(false, &public_key);
            signer_addr_to_id.insert(address, signer_id);
            signer_pks.push(public_key);
            signer_slot_ids.push(SignerSlotID(signer_id));
            signer_id_to_addr.insert(signer_id, address);
            signer_addr_to_weight.insert(address, weight_per_signer + remaining_weight);
            signer_addresses.push(address);
            remaining_weight = 0; // The first signer gets the extra weight if there is any. All other signers only get the weight_per_signer
        }
        SignerConfig {
            reward_cycle,
            signer_mode: SignerConfigMode::Normal {
                signer_id: 0,
                signer_slot_id: SignerSlotID(rand::thread_rng().gen_range(0..num_signers)), // Give a random signer slot id between 0 and num_signers
            },
            signer_entries: SignerEntries {
                signer_addr_to_id,
                signer_id_to_pk,
                signer_pk_to_id,
                signer_pks,
                signer_id_to_addr,
                signer_addr_to_weight,
                signer_addresses,
            },
            signer_slot_ids,
            stacks_private_key: config.stacks_private_key,
            node_host: config.node_host.to_string(),
            mainnet: config.network.is_mainnet(),
            db_path: config.db_path.clone(),
            first_proposal_burn_block_timing: config.first_proposal_burn_block_timing,
            block_proposal_timeout: config.block_proposal_timeout,
            tenure_last_block_proposal_timeout: config.tenure_last_block_proposal_timeout,
            block_proposal_validation_timeout: config.block_proposal_validation_timeout,
            tenure_idle_timeout: config.tenure_idle_timeout,
            tenure_idle_timeout_buffer: config.tenure_idle_timeout_buffer,
            block_proposal_max_age_secs: config.block_proposal_max_age_secs,
            reorg_attempts_activity_timeout: config.reorg_attempts_activity_timeout,
        }
    }

    pub fn build_get_tenure_tip_response(header_types: &StacksBlockHeaderTypes) -> String {
        let response_json =
            serde_json::to_string(header_types).expect("Failed to serialize tenure tip info");
        format!("HTTP/1.1 200 OK\n\n{response_json}")
    }

    pub fn build_get_last_set_cycle_response(cycle: u64) -> String {
        let clarity_value = ClarityValue::okay(ClarityValue::UInt(cycle as u128)).unwrap();
        build_read_only_response(&clarity_value)
    }
}
