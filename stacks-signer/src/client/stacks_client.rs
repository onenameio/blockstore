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
use std::collections::{HashMap, VecDeque};
use std::fmt::Display;
use std::time::{Duration, Instant};

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use blockstack_lib::chainstate::stacks::boot::{NakamotoSignerEntry, SIGNERS_NAME};
use blockstack_lib::chainstate::stacks::db::StacksBlockHeaderTypes;
use blockstack_lib::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSpendingCondition, TransactionVersion,
};
use blockstack_lib::net::api::callreadonly::CallReadOnlyResponse;
use blockstack_lib::net::api::get_tenures_fork_info::{
    TenureForkingInfo, RPC_TENURE_FORKING_INFO_PATH,
};
use blockstack_lib::net::api::getaccount::AccountEntryResponse;
use blockstack_lib::net::api::getpoxinfo::RPCPoxInfoData;
use blockstack_lib::net::api::getsortition::{SortitionInfo, RPC_SORTITION_INFO_PATH};
use blockstack_lib::net::api::getstackers::GetStackersResponse;
use blockstack_lib::net::api::postblock::StacksBlockAcceptedData;
use blockstack_lib::net::api::postblock_proposal::NakamotoBlockProposal;
use blockstack_lib::net::api::postblock_v3;
use blockstack_lib::util_lib::boot::boot_code_id;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::{ClarityName, ContractName, Value as ClarityValue};
use libsigner::v0::messages::PeerInfo;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;
use serde_json::json;
use slog::{slog_debug, slog_warn};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::StacksEpochId;
use stacks_common::{debug, warn};

use super::SignerSlotID;
use crate::client::{retry_with_exponential_backoff, ClientError};
use crate::config::GlobalConfig;
use crate::runloop::RewardCycleInfo;

/// The Stacks signer client used to communicate with the stacks node
#[derive(Clone, Debug)]
pub struct StacksClient {
    /// The stacks address of the signer
    stacks_address: StacksAddress,
    /// The private key used in all stacks node communications
    stacks_private_key: StacksPrivateKey,
    /// The stacks node HTTP base endpoint
    http_origin: String,
    /// The types of transactions
    tx_version: TransactionVersion,
    /// The chain we are interacting with
    chain_id: u32,
    /// Whether we are mainnet or not
    pub mainnet: bool,
    /// The Client used to make HTTP connects
    stacks_node_client: reqwest::blocking::Client,
    /// the auth password for the stacks node
    auth_password: String,
}

#[derive(Deserialize)]
struct GetStackersErrorResp {
    err_msg: String,
}

/// Result from fetching current and last sortition:
///  two sortition infos
pub struct CurrentAndLastSortition {
    /// the latest winning sortition in the current burnchain fork
    pub current_sortition: SortitionInfo,
    /// the last winning sortition prior to `current_sortition`, if there was one
    pub last_sortition: Option<SortitionInfo>,
}

impl From<&GlobalConfig> for StacksClient {
    fn from(config: &GlobalConfig) -> Self {
        Self {
            stacks_private_key: config.stacks_private_key,
            stacks_address: config.stacks_address,
            http_origin: format!("http://{}", config.node_host),
            tx_version: config.network.to_transaction_version(),
            chain_id: config.to_chain_id(),
            stacks_node_client: reqwest::blocking::Client::new(),
            mainnet: config.network.is_mainnet(),
            auth_password: config.auth_password.clone(),
        }
    }
}

impl StacksClient {
    /// Create a new signer StacksClient with the provided private key, stacks node host endpoint, version, and auth password
    pub fn new(
        stacks_private_key: StacksPrivateKey,
        node_host: String,
        auth_password: String,
        mainnet: bool,
        chain_id: u32,
    ) -> Self {
        let pubkey = StacksPublicKey::from_private(&stacks_private_key);
        let tx_version = if mainnet {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let stacks_address = StacksAddress::p2pkh(mainnet, &pubkey);
        Self {
            stacks_private_key,
            stacks_address,
            http_origin: format!("http://{}", node_host),
            tx_version,
            chain_id,
            stacks_node_client: reqwest::blocking::Client::new(),
            mainnet,
            auth_password,
        }
    }

    /// Create a new signer StacksClient and attempt to connect to the stacks node to determine the version
    pub fn try_from_host(
        stacks_private_key: StacksPrivateKey,
        node_host: String,
        auth_password: String,
    ) -> Result<Self, ClientError> {
        let mut stacks_client = Self::new(
            stacks_private_key,
            node_host,
            auth_password,
            true,
            CHAIN_ID_MAINNET,
        );
        let pubkey = StacksPublicKey::from_private(&stacks_private_key);
        let info = stacks_client.get_peer_info()?;
        if info.network_id == CHAIN_ID_MAINNET {
            stacks_client.mainnet = true;
            stacks_client.chain_id = CHAIN_ID_MAINNET;
            stacks_client.tx_version = TransactionVersion::Mainnet;
        } else {
            stacks_client.mainnet = false;
            stacks_client.chain_id = info.network_id;
            stacks_client.tx_version = TransactionVersion::Testnet;
        }
        stacks_client.stacks_address = StacksAddress::p2pkh(stacks_client.mainnet, &pubkey);
        Ok(stacks_client)
    }

    /// Get our signer address
    pub const fn get_signer_address(&self) -> &StacksAddress {
        &self.stacks_address
    }

    /// Get the stacks tip header of the tenure given its consensus hash
    pub fn get_tenure_tip(
        &self,
        consensus_hash: &ConsensusHash,
    ) -> Result<StacksBlockHeaderTypes, ClientError> {
        debug!("StacksClient: Getting tenure tip";
            "consensus_hash" => %consensus_hash,
        );
        let send_request = || {
            self.stacks_node_client
                .get(self.tenure_tip_path(consensus_hash))
                .send()
                .map_err(|e| {
                    warn!("Signer failed to request latest sortition"; "err" => ?e);
                    e
                })
        };
        let response = send_request()?;
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let sortition_info = response.json()?;
        Ok(sortition_info)
    }

    /// Get the last set reward cycle stored within the stackerdb contract
    pub fn get_last_set_cycle(&self) -> Result<u128, ClientError> {
        debug!("StacksClient: Getting last set cycle");
        let signer_stackerdb_contract_id = boot_code_id(SIGNERS_NAME, self.mainnet);
        let function_name_str = "get-last-set-cycle";
        let function_name = ClarityName::from(function_name_str);
        let value = self.read_only_contract_call(
            &signer_stackerdb_contract_id.issuer.clone().into(),
            &signer_stackerdb_contract_id.name,
            &function_name,
            &[],
        )?;
        Ok(value.expect_result_ok()?.expect_u128()?)
    }

    /// Retrieve the signer slots stored within the stackerdb contract
    pub fn get_stackerdb_signer_slots(
        &self,
        stackerdb_contract: &QualifiedContractIdentifier,
        page: u32,
    ) -> Result<Vec<(StacksAddress, u128)>, ClientError> {
        debug!("StacksClient: Getting signer slots";
            "stackerdb_contract" => %stackerdb_contract,
            "page" => page,
        );
        let function_name_str = "stackerdb-get-signer-slots-page";
        let function_name = ClarityName::from(function_name_str);
        let function_args = &[ClarityValue::UInt(page.into())];
        let value = self.read_only_contract_call(
            &stackerdb_contract.issuer.clone().into(),
            &stackerdb_contract.name,
            &function_name,
            function_args,
        )?;
        self.parse_signer_slots(value)
    }

    /// Helper function  that attempts to deserialize a clarity hext string as a list of signer slots and their associated number of signer slots
    fn parse_signer_slots(
        &self,
        value: ClarityValue,
    ) -> Result<Vec<(StacksAddress, u128)>, ClientError> {
        debug!("Parsing signer slots...");
        let value = value.expect_result_ok()?;
        let values = value.expect_list()?;
        let mut signer_slots = Vec::with_capacity(values.len());
        for value in values {
            let tuple_data = value.expect_tuple()?;
            let principal_data = tuple_data.get("signer")?.clone().expect_principal()?;
            let signer = if let PrincipalData::Standard(signer) = principal_data {
                signer.into()
            } else {
                panic!("BUG: Signers stackerdb contract is corrupted");
            };
            let num_slots = tuple_data.get("num-slots")?.clone().expect_u128()?;
            signer_slots.push((signer, num_slots));
        }
        Ok(signer_slots)
    }

    /// Get the stackerdb signer slots for a specific reward cycle
    pub fn get_parsed_signer_slots(
        &self,
        reward_cycle: u64,
    ) -> Result<HashMap<StacksAddress, SignerSlotID>, ClientError> {
        debug!("StacksClient: Getting parsed signer slots";
            "reward_cycle" => reward_cycle,
        );
        let signer_set =
            u32::try_from(reward_cycle % 2).expect("FATAL: reward_cycle % 2 exceeds u32::MAX");
        let signer_stackerdb_contract_id = boot_code_id(SIGNERS_NAME, self.mainnet);
        // Get the signer writers from the stacker-db to find the signer slot id
        let stackerdb_signer_slots =
            self.get_stackerdb_signer_slots(&signer_stackerdb_contract_id, signer_set)?;
        Ok(stackerdb_signer_slots
            .into_iter()
            .enumerate()
            .map(|(index, (address, _))| {
                (
                    address,
                    SignerSlotID(
                        u32::try_from(index).expect("FATAL: number of signers exceeds u32::MAX"),
                    ),
                )
            })
            .collect())
    }

    /// Determine the stacks node current epoch
    pub fn get_node_epoch(&self) -> Result<StacksEpochId, ClientError> {
        debug!("StacksClient: Getting node epoch");
        let pox_info = self.get_pox_data()?;
        let burn_block_height = self.get_burn_block_height()?;

        let epoch_25 = pox_info
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch25)
            .ok_or(ClientError::UnsupportedStacksFeature(
                "/v2/pox must report epochs".into(),
            ))?;

        let epoch_30 = pox_info
            .epochs
            .iter()
            .find(|epoch| epoch.epoch_id == StacksEpochId::Epoch30)
            .ok_or(ClientError::UnsupportedStacksFeature(
                "/v2/pox mut report epochs".into(),
            ))?;

        if burn_block_height < epoch_25.start_height {
            Ok(StacksEpochId::Epoch24)
        } else if burn_block_height < epoch_30.start_height {
            Ok(StacksEpochId::Epoch25)
        } else {
            Ok(StacksEpochId::Epoch30)
        }
    }

    /// Submit the block proposal to the stacks node. The block will be validated and returned via the HTTP endpoint for Block events.
    pub fn submit_block_for_validation(&self, block: NakamotoBlock) -> Result<(), ClientError> {
        debug!("StacksClient: Submitting block for validation";
            "signer_sighash" => %block.header.signer_signature_hash(),
            "block_id" => %block.header.block_id(),
            "block_height" => %block.header.chain_length,
        );
        let block_proposal = NakamotoBlockProposal {
            block,
            chain_id: self.chain_id,
        };
        let timer = crate::monitoring::actions::new_rpc_call_timer(
            &self.block_proposal_path(),
            &self.http_origin,
        );
        let send_request = || {
            self.stacks_node_client
                .post(self.block_proposal_path())
                .header("Content-Type", "application/json")
                .header(AUTHORIZATION, self.auth_password.clone())
                .json(&block_proposal)
                .send()
                .map_err(backoff::Error::transient)
        };

        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        Ok(())
    }

    /// Get information about the tenures between `chosen_parent` and `last_sortition`
    pub fn get_tenure_forking_info(
        &self,
        chosen_parent: &ConsensusHash,
        last_sortition: &ConsensusHash,
    ) -> Result<Vec<TenureForkingInfo>, ClientError> {
        debug!("StacksClient: Getting tenure forking info";
            "chosen_parent" => %chosen_parent,
            "last_sortition" => %last_sortition,
        );
        let mut tenures: VecDeque<TenureForkingInfo> =
            self.get_tenure_forking_info_step(chosen_parent, last_sortition)?;
        if tenures.is_empty() {
            return Ok(vec![]);
        }
        while tenures.back().map(|x| &x.consensus_hash) != Some(chosen_parent) {
            let new_start = tenures.back().ok_or_else(|| {
                ClientError::InvalidResponse(
                    "Should have tenure data in forking info response".into(),
                )
            })?;
            let mut next_results =
                self.get_tenure_forking_info_step(chosen_parent, &new_start.consensus_hash)?;
            if next_results.pop_front().is_none() {
                return Err(ClientError::InvalidResponse(
                    "Could not fetch forking info all the way back to the requested chosen_parent"
                        .into(),
                ));
            }
            if next_results.is_empty() {
                return Err(ClientError::InvalidResponse(
                    "Could not fetch forking info all the way back to the requested chosen_parent"
                        .into(),
                ));
            }
            tenures.extend(next_results.into_iter());
        }

        Ok(tenures.into_iter().collect())
    }

    fn get_tenure_forking_info_step(
        &self,
        chosen_parent: &ConsensusHash,
        last_sortition: &ConsensusHash,
    ) -> Result<VecDeque<TenureForkingInfo>, ClientError> {
        debug!("StacksClient: Getting tenure forking info";
            "chosen_parent" => %chosen_parent,
            "last_sortition" => %last_sortition,
        );
        let path = self.tenure_forking_info_path(chosen_parent, last_sortition);
        // Use a separate metrics path to allow the same metric for different start and stop hashes
        let metrics_path = format!(
            "{}{RPC_TENURE_FORKING_INFO_PATH}/:start/:stop",
            self.http_origin
        );
        let timer =
            crate::monitoring::actions::new_rpc_call_timer(&metrics_path, &self.http_origin);
        let send_request = || {
            self.stacks_node_client
                .get(&path)
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let tenures = response.json()?;

        Ok(tenures)
    }

    /// Get the current winning sortition and the last winning sortition
    pub fn get_current_and_last_sortition(&self) -> Result<CurrentAndLastSortition, ClientError> {
        debug!("StacksClient: Getting current and prior sortition");
        let path = format!("{}/latest_and_last", self.sortition_info_path());
        let timer = crate::monitoring::actions::new_rpc_call_timer(&path, &self.http_origin);
        let send_request = || {
            self.stacks_node_client.get(&path).send().map_err(|e| {
                warn!("Signer failed to request latest sortition"; "err" => ?e);
                e
            })
        };
        let response = send_request()?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let mut info_list: VecDeque<SortitionInfo> = response.json()?;
        let Some(current_sortition) = info_list.pop_front() else {
            return Err(ClientError::UnexpectedResponseFormat(
                "Empty SortitionInfo returned".into(),
            ));
        };
        if !current_sortition.was_sortition {
            return Err(ClientError::UnexpectedResponseFormat(
                "'Current' SortitionInfo returned which was not a winning sortition".into(),
            ));
        }
        let last_sortition = if current_sortition.last_sortition_ch.is_some() {
            let Some(last_sortition) = info_list.pop_back() else {
                return Err(ClientError::UnexpectedResponseFormat("'Current' SortitionInfo has `last_sortition_ch` field, but corresponding data not returned".into()));
            };
            Some(last_sortition)
        } else {
            None
        };
        Ok(CurrentAndLastSortition {
            current_sortition,
            last_sortition,
        })
    }

    /// Get the current peer info data from the stacks node
    pub fn get_peer_info(&self) -> Result<PeerInfo, ClientError> {
        debug!("StacksClient: Getting peer info");
        let timer = crate::monitoring::actions::new_rpc_call_timer(
            &self.core_info_path(),
            &self.http_origin,
        );
        let send_request = || {
            self.stacks_node_client
                .get(self.core_info_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let peer_info_data = response.json::<PeerInfo>()?;
        Ok(peer_info_data)
    }

    /// Get the reward set signers from the stacks node for the given reward cycle
    pub fn get_reward_set_signers(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<Vec<NakamotoSignerEntry>>, ClientError> {
        debug!("StacksClient: Getting reward set signers";
            "reward_cycle" => reward_cycle,
        );
        let timer = crate::monitoring::actions::new_rpc_call_timer(
            &format!("{}/v3/stacker_set/:reward_cycle", self.http_origin),
            &self.http_origin,
        );
        let send_request = || {
            let response = self
                .stacks_node_client
                .get(self.reward_set_path(reward_cycle))
                .send()
                .map_err(|e| backoff::Error::transient(e.into()))?;
            let status = response.status();
            if status.is_success() {
                return response.json().map_err(|e| {
                    warn!("Failed to parse the GetStackers response: {e}");
                    backoff::Error::permanent(e.into())
                });
            }
            let error_data = response.json::<GetStackersErrorResp>().map_err(|e| {
                warn!("Failed to parse the GetStackers error response: {e}");
                backoff::Error::permanent(e.into())
            })?;

            warn!("Got error response ({status}): {}", error_data.err_msg);
            Err(backoff::Error::permanent(ClientError::RequestFailure(
                status,
            )))
        };
        let stackers_response =
            retry_with_exponential_backoff::<_, ClientError, GetStackersResponse>(send_request)?;
        timer.stop_and_record();
        Ok(stackers_response.stacker_set.signers)
    }

    /// Retrieve the current pox data from the stacks node
    pub fn get_pox_data(&self) -> Result<RPCPoxInfoData, ClientError> {
        debug!("StacksClient: Getting pox data");
        let timer =
            crate::monitoring::actions::new_rpc_call_timer(&self.pox_path(), &self.http_origin);
        let send_request = || {
            self.stacks_node_client
                .get(self.pox_path())
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let pox_info_data = response.json::<RPCPoxInfoData>()?;
        Ok(pox_info_data)
    }

    /// Helper function to retrieve the burn tip height from the stacks node
    fn get_burn_block_height(&self) -> Result<u64, ClientError> {
        debug!("StacksClient: Getting burn block height");
        self.get_peer_info().map(|info| info.burn_block_height)
    }

    /// Get the current reward cycle info from the stacks node
    pub fn get_current_reward_cycle_info(&self) -> Result<RewardCycleInfo, ClientError> {
        debug!("StacksClient: Getting current reward cycle info");
        let pox_data = self.get_pox_data()?;
        let blocks_mined = pox_data
            .current_burnchain_block_height
            .saturating_sub(pox_data.first_burnchain_block_height);
        let reward_cycle_length = pox_data
            .reward_phase_block_length
            .saturating_add(pox_data.prepare_phase_block_length);
        let reward_cycle = blocks_mined / reward_cycle_length;
        Ok(RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length: pox_data.prepare_phase_block_length,
            first_burnchain_block_height: pox_data.first_burnchain_block_height,
            last_burnchain_block_height: pox_data.current_burnchain_block_height,
        })
    }

    /// Helper function to retrieve the account info from the stacks node for a specific address
    pub fn get_account_entry(
        &self,
        address: &StacksAddress,
    ) -> Result<AccountEntryResponse, ClientError> {
        debug!("StacksClient: Getting account info";
            "address" => %address,
        );
        let timer_label = format!("{}/v2/accounts/:principal", self.http_origin);
        let timer = crate::monitoring::actions::new_rpc_call_timer(&timer_label, &self.http_origin);
        let send_request = || {
            self.stacks_node_client
                .get(self.accounts_path(address))
                .send()
                .map_err(backoff::Error::transient)
        };
        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let account_entry = response.json::<AccountEntryResponse>()?;
        Ok(account_entry)
    }

    /// Post a block to the stacks-node, retry forever on errors.
    ///
    /// In tests, this panics if the retry takes longer than 30 seconds.
    pub fn post_block_until_ok<F: Display>(&self, log_fmt: &F, block: &NakamotoBlock) -> bool {
        debug!("StacksClient: Posting block to stacks node";
            "signer_sighash" => %block.header.signer_signature_hash(),
            "block_id" => %block.header.block_id(),
            "block_height" => %block.header.chain_length,
        );
        let start_time = Instant::now();
        loop {
            match self.post_block(block) {
                Ok(block_push_result) => {
                    debug!("{log_fmt}: Block pushed to stacks node: {block_push_result:?}");
                    return block_push_result;
                }
                Err(e) => {
                    if cfg!(any(test, feature = "testing"))
                        && start_time.elapsed() > Duration::from_secs(30)
                    {
                        panic!(
                            "{log_fmt}: Timed out in test while pushing block to stacks node: {e}"
                        );
                    }
                    warn!("{log_fmt}: Failed to push block to stacks node: {e}. Retrying...");
                }
            };
        }
    }

    /// Try to post a completed nakamoto block to our connected stacks-node
    /// Returns `true` if the block was accepted or `false` if the block
    ///   was rejected.
    pub fn post_block(&self, block: &NakamotoBlock) -> Result<bool, ClientError> {
        debug!("StacksClient: Posting block to the stacks node";
            "signer_sighash" => %block.header.signer_signature_hash(),
            "block_id" => %block.header.block_id(),
            "block_height" => %block.header.chain_length,
        );
        let path = format!("{}{}?broadcast=1", self.http_origin, postblock_v3::PATH);
        let timer = crate::monitoring::actions::new_rpc_call_timer(&path, &self.http_origin);
        let send_request = || {
            self.stacks_node_client
                .post(&path)
                .header("Content-Type", "application/octet-stream")
                .header(AUTHORIZATION, self.auth_password.clone())
                .body(block.serialize_to_vec())
                .send()
                .map_err(|e| {
                    debug!("Failed to submit block to the Stacks node: {e:?}");
                    backoff::Error::transient(e)
                })
        };
        let response = retry_with_exponential_backoff(send_request)?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let post_block_resp = response.json::<StacksBlockAcceptedData>()?;
        Ok(post_block_resp.accepted)
    }

    /// Makes a read only contract call to a stacks contract
    pub fn read_only_contract_call(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
        function_args: &[ClarityValue],
    ) -> Result<ClarityValue, ClientError> {
        debug!(
            "StacksClient: Calling read-only function {function_name} with args {function_args:?}"
        );
        let args = function_args
            .iter()
            .filter_map(|arg| arg.serialize_to_hex().ok())
            .collect::<Vec<String>>();
        if args.len() != function_args.len() {
            return Err(ClientError::ReadOnlyFailure(
                "Failed to serialize Clarity function arguments".into(),
            ));
        }

        let body =
            json!({"sender": self.stacks_address.to_string(), "arguments": args}).to_string();
        let path = self.read_only_path(contract_addr, contract_name, function_name);
        let timer_label = format!(
            "{}/v2/contracts/call-read/:principal/{contract_name}/{function_name}",
            self.http_origin
        );
        let timer = crate::monitoring::actions::new_rpc_call_timer(&timer_label, &self.http_origin);
        let response = self
            .stacks_node_client
            .post(path)
            .header("Content-Type", "application/json")
            .body(body)
            .send()?;
        timer.stop_and_record();
        if !response.status().is_success() {
            return Err(ClientError::RequestFailure(response.status()));
        }
        let call_read_only_response = response.json::<CallReadOnlyResponse>()?;
        if !call_read_only_response.okay {
            return Err(ClientError::ReadOnlyFailure(format!(
                "{function_name}: {}",
                call_read_only_response
                    .cause
                    .unwrap_or_else(|| "unknown".to_string())
            )));
        }
        let hex = call_read_only_response.result.unwrap_or_default();
        let value = ClarityValue::try_deserialize_hex_untyped(&hex)?;
        Ok(value)
    }

    fn pox_path(&self) -> String {
        format!("{}/v2/pox", self.http_origin)
    }

    fn read_only_path(
        &self,
        contract_addr: &StacksAddress,
        contract_name: &ContractName,
        function_name: &ClarityName,
    ) -> String {
        format!(
            "{}/v2/contracts/call-read/{contract_addr}/{contract_name}/{function_name}",
            self.http_origin
        )
    }

    fn block_proposal_path(&self) -> String {
        format!("{}/v3/block_proposal", self.http_origin)
    }

    fn sortition_info_path(&self) -> String {
        format!("{}{RPC_SORTITION_INFO_PATH}", self.http_origin)
    }

    fn tenure_forking_info_path(&self, start: &ConsensusHash, stop: &ConsensusHash) -> String {
        format!(
            "{}{RPC_TENURE_FORKING_INFO_PATH}/{}/{}",
            self.http_origin,
            start.to_hex(),
            stop.to_hex()
        )
    }

    fn core_info_path(&self) -> String {
        format!("{}/v2/info", self.http_origin)
    }

    fn accounts_path(&self, stacks_address: &StacksAddress) -> String {
        format!("{}/v2/accounts/{stacks_address}?proof=0", self.http_origin)
    }

    fn reward_set_path(&self, reward_cycle: u64) -> String {
        format!("{}/v3/stacker_set/{reward_cycle}", self.http_origin)
    }

    fn tenure_tip_path(&self, consensus_hash: &ConsensusHash) -> String {
        format!("{}/v3/tenures/tip/{}", self.http_origin, consensus_hash)
    }

    /// Helper function to create a stacks transaction for a modifying contract call
    #[allow(clippy::too_many_arguments)]
    pub fn build_unsigned_contract_call_transaction(
        contract_addr: &StacksAddress,
        contract_name: ContractName,
        function_name: ClarityName,
        function_args: &[ClarityValue],
        stacks_private_key: &StacksPrivateKey,
        tx_version: TransactionVersion,
        chain_id: u32,
        nonce: u64,
    ) -> Result<StacksTransaction, ClientError> {
        let tx_payload = TransactionPayload::ContractCall(TransactionContractCall {
            address: *contract_addr,
            contract_name,
            function_name,
            function_args: function_args.to_vec(),
        });
        let public_key = StacksPublicKey::from_private(stacks_private_key);
        let tx_auth = TransactionAuth::Standard(
            TransactionSpendingCondition::new_singlesig_p2pkh(public_key).ok_or(
                ClientError::TransactionGenerationFailure(format!(
                    "Failed to create spending condition from public key: {}",
                    public_key.to_hex()
                )),
            )?,
        );

        let mut unsigned_tx = StacksTransaction::new(tx_version, tx_auth, tx_payload);
        unsigned_tx.set_origin_nonce(nonce);

        unsigned_tx.anchor_mode = TransactionAnchorMode::Any;
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = chain_id;
        Ok(unsigned_tx)
    }

    /// Sign an unsigned transaction
    pub fn sign_transaction(
        &self,
        unsigned_tx: StacksTransaction,
    ) -> Result<StacksTransaction, ClientError> {
        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer
            .sign_origin(&self.stacks_private_key)
            .map_err(|e| ClientError::TransactionGenerationFailure(e.to_string()))?;

        tx_signer
            .get_tx()
            .ok_or(ClientError::TransactionGenerationFailure(
                "Failed to generate transaction from a transaction signer".to_string(),
            ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::thread::spawn;

    use blockstack_lib::burnchains::Address;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
    use blockstack_lib::chainstate::stacks::address::PoxAddress;
    use blockstack_lib::chainstate::stacks::boot::{
        NakamotoSignerEntry, PoxStartCycleInfo, RewardSet,
    };
    use clarity::types::chainstate::{StacksBlockId, TrieHash};
    use clarity::util::hash::Sha512Trunc256Sum;
    use clarity::util::secp256k1::MessageSignature;
    use clarity::vm::types::{
        ListData, ListTypeData, ResponseData, SequenceData, TupleData, TupleTypeSignature,
        TypeSignature,
    };
    use rand::thread_rng;
    use rand_core::RngCore;
    use stacks_common::bitvec::BitVec;
    use stacks_common::consts::SIGNER_SLOTS_PER_USER;

    use super::*;
    use crate::client::tests::{
        build_get_last_set_cycle_response, build_get_peer_info_response,
        build_get_pox_data_response, build_get_tenure_tip_response, build_read_only_response,
        write_response, MockServerClient,
    };

    #[test]
    fn read_only_contract_call_200_success() {
        let mock = MockServerClient::new();
        let value = ClarityValue::UInt(10_u128);
        let response = build_read_only_response(&value);
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, response.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_with_function_args_200_success() {
        let mock = MockServerClient::new();
        let value = ClarityValue::UInt(10_u128);
        let response = build_read_only_response(&value);
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[ClarityValue::UInt(10_u128)],
            )
        });
        write_response(mock.server, response.as_bytes());
        let result = h.join().unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn read_only_contract_call_200_failure() {
        let mock = MockServerClient::new();
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n{\"okay\":false,\"cause\":\"Some reason\"}",
        );
        let result = h.join().unwrap();
        assert!(matches!(result, Err(ClientError::ReadOnlyFailure(_))));
    }

    #[test]
    fn read_only_contract_call_400_failure() {
        let mock = MockServerClient::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, b"HTTP/1.1 400 Bad Request\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(
                reqwest::StatusCode::BAD_REQUEST
            ))
        ));
    }

    #[test]
    fn read_only_contract_call_404_failure() {
        let mock = MockServerClient::new();
        // Simulate a 400 Bad Request response
        let h = spawn(move || {
            mock.client.read_only_contract_call(
                &mock.client.stacks_address,
                &ContractName::from("contract-name"),
                &ClarityName::from("function-name"),
                &[],
            )
        });
        write_response(mock.server, b"HTTP/1.1 404 Not Found\n\n");
        let result = h.join().unwrap();
        assert!(matches!(
            result,
            Err(ClientError::RequestFailure(reqwest::StatusCode::NOT_FOUND))
        ));
    }

    #[test]
    fn valid_reward_cycle_should_succeed() {
        let mock = MockServerClient::new();
        let (pox_data_response, pox_data) = build_get_pox_data_response(None, None, None, None);
        let h = spawn(move || mock.client.get_current_reward_cycle_info());
        write_response(mock.server, pox_data_response.as_bytes());
        let current_cycle_info = h.join().unwrap().unwrap();
        let blocks_mined = pox_data
            .current_burnchain_block_height
            .saturating_sub(pox_data.first_burnchain_block_height);
        let reward_cycle_length = pox_data
            .reward_phase_block_length
            .saturating_add(pox_data.prepare_phase_block_length);
        let id = blocks_mined / reward_cycle_length;
        assert_eq!(current_cycle_info.reward_cycle, id);
    }

    #[test]
    fn invalid_reward_cycle_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_current_reward_cycle_info());
        write_response(
            mock.server,
            b"HTTP/1.1 200 Ok\n\n{\"current_cycle\":{\"id\":\"fake id\", \"is_pox_active\":false}}",
        );
        let res = h.join().unwrap();
        assert!(matches!(res, Err(ClientError::ReqwestError(_))));
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_succeed() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_burn_block_height());
        let (response, peer_info) = build_get_peer_info_response(None, None);
        write_response(mock.server, response.as_bytes());
        let burn_block_height = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(burn_block_height, peer_info.burn_block_height);
    }

    #[test]
    fn core_info_call_for_burn_block_height_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_burn_block_height());
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn parse_valid_signer_slots_should_succeed() {
        let mock = MockServerClient::new();

        let signers = [
            "ST20SA6BAK9YFKGVWP4Z1XNMTFF04FA2E0M8YRNNQ",
            "ST1JGAHRH8VEFE8QGB04H261Z52ZF62MAH40CD6ZN",
            "STEQZ3HS6VJXMQSJK0PC8ZSHTZFSZCDKHA7R60XT",
            "ST96T6M18C9WJMQ39HW41B7CJ88Y2WKZQ1CK330M",
            "ST1SQ9TKBPEFJX39X6D6P5EFK0AMQFQHKK9R0MJFC",
        ];

        let tuple_type_signature: TupleTypeSignature = [
            (ClarityName::from("num_slots"), TypeSignature::UIntType),
            (ClarityName::from("signer"), TypeSignature::PrincipalType),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>()
        .try_into()
        .unwrap();

        let list_data: Vec<_> = signers
            .into_iter()
            .map(|signer| {
                let principal_data = StacksAddress::from_string(signer).unwrap().into();

                let data_map = [
                    ("num-slots".into(), ClarityValue::UInt(13)),
                    (
                        "signer".into(),
                        ClarityValue::Principal(PrincipalData::Standard(principal_data)),
                    ),
                ]
                .into_iter()
                .collect();

                ClarityValue::Tuple(TupleData {
                    type_signature: tuple_type_signature.clone(),
                    data_map,
                })
            })
            .collect();

        let list_type_signature =
            ListTypeData::new_list(TypeSignature::TupleType(tuple_type_signature), 5).unwrap();

        let sequence = ClarityValue::Sequence(SequenceData::List(ListData {
            data: list_data,
            type_signature: list_type_signature,
        }));

        let value = ClarityValue::Response(ResponseData {
            committed: true,
            data: Box::new(sequence),
        });

        let signer_slots = mock.client.parse_signer_slots(value).unwrap();
        assert_eq!(signer_slots.len(), 5);
        signer_slots
            .into_iter()
            .for_each(|(_address, slots)| assert_eq!(slots, SIGNER_SLOTS_PER_USER as u128));
    }

    #[test]
    fn get_node_epoch_should_succeed() {
        let mock = MockServerClient::new();
        // The burn block height is one BEHIND the activation height of 2.5, therefore is 2.4
        let burn_block_height: u64 = 100;
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_add(1)),
            None,
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch24);

        // The burn block height is the same as the activation height of 2.5, therefore is 2.5
        let pox_response = build_get_pox_data_response(None, None, Some(burn_block_height), None).0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch25);

        // The burn block height is the AFTER as the activation height of 2.5 but BEFORE the activation height of 3.0, therefore is 2.5
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height.saturating_add(1)),
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch25);

        // The burn block height is the AFTER as the activation height of 2.5 and the SAME as the activation height of 3.0, therefore is 3.0
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height),
        )
        .0;
        let peer_response = build_get_peer_info_response(Some(burn_block_height), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch30);

        // The burn block height is the AFTER as the activation height of 2.5 and AFTER the activation height of 3.0, therefore is 3.0
        let pox_response = build_get_pox_data_response(
            None,
            None,
            Some(burn_block_height.saturating_sub(1)),
            Some(burn_block_height),
        )
        .0;
        let peer_response =
            build_get_peer_info_response(Some(burn_block_height.saturating_add(1)), None).0;
        let mock = MockServerClient::from_config(mock.config);
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(mock.server, pox_response.as_bytes());
        let mock = MockServerClient::from_config(mock.config);
        write_response(mock.server, peer_response.as_bytes());
        let epoch = h.join().unwrap().expect("Failed to deserialize response");
        assert_eq!(epoch, StacksEpochId::Epoch30);
    }

    #[test]
    fn get_node_epoch_should_fail() {
        let mock = MockServerClient::new();
        let h = spawn(move || mock.client.get_node_epoch());
        write_response(
            mock.server,
            b"HTTP/1.1 200 OK\n\n4e99f99bc4a05437abb8c7d0c306618f45b203196498e2ebe287f10497124958",
        );
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn submit_block_for_validation_should_succeed() {
        let mock = MockServerClient::new();
        let header = NakamotoBlockHeader::empty();
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let h = spawn(move || mock.client.submit_block_for_validation(block));
        write_response(mock.server, b"HTTP/1.1 200 OK\n\n");
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn submit_block_for_validation_should_fail() {
        let mock = MockServerClient::new();
        let header = NakamotoBlockHeader::empty();
        let block = NakamotoBlock {
            header,
            txs: vec![],
        };
        let h = spawn(move || mock.client.submit_block_for_validation(block));
        write_response(mock.server, b"HTTP/1.1 404 Not Found\n\n");
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn get_peer_info_should_succeed() {
        let mock = MockServerClient::new();
        let (response, peer_info) = build_get_peer_info_response(None, None);
        let h = spawn(move || mock.client.get_peer_info());
        write_response(mock.server, response.as_bytes());
        let reduced_peer_info = h.join().unwrap().unwrap();
        assert_eq!(
            reduced_peer_info.burn_block_height,
            peer_info.burn_block_height
        );
        assert_eq!(reduced_peer_info.pox_consensus, peer_info.pox_consensus);
        assert_eq!(
            reduced_peer_info.stacks_tip_consensus_hash,
            peer_info.stacks_tip_consensus_hash
        );
        assert_eq!(reduced_peer_info.stacks_tip, peer_info.stacks_tip);
        assert_eq!(reduced_peer_info.server_version, peer_info.server_version);
    }

    #[test]
    fn get_reward_set_should_succeed() {
        let mock = MockServerClient::new();
        let private_key = StacksPrivateKey::new();
        let public_key = StacksPublicKey::from_private(&private_key);
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(&public_key.to_bytes_compressed());
        let stacker_set = RewardSet {
            rewarded_addresses: vec![PoxAddress::standard_burn_address(false)],
            start_cycle_state: PoxStartCycleInfo {
                missed_reward_slots: vec![],
            },
            signers: Some(vec![NakamotoSignerEntry {
                signing_key: bytes,
                stacked_amt: rand::thread_rng().next_u64() as u128,
                weight: 1,
            }]),
            pox_ustx_threshold: None,
        };
        let stackers_response = GetStackersResponse {
            stacker_set: stacker_set.clone(),
        };

        let stackers_response_json = serde_json::to_string(&stackers_response)
            .expect("Failed to serialize get stacker response");
        let response = format!("HTTP/1.1 200 OK\n\n{stackers_response_json}");
        let h = spawn(move || mock.client.get_reward_set_signers(0));
        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), stacker_set.signers);
    }

    #[test]
    fn get_tenure_tip_should_succeed() {
        let mock = MockServerClient::new();
        let consensus_hash = ConsensusHash([15; 20]);
        let header = StacksBlockHeaderTypes::Nakamoto(NakamotoBlockHeader {
            version: 1,
            chain_length: 10,
            burn_spent: 10,
            consensus_hash: ConsensusHash([15; 20]),
            parent_block_id: StacksBlockId([0; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 3,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
        });
        let response = build_get_tenure_tip_response(&header);
        let h = spawn(move || mock.client.get_tenure_tip(&consensus_hash));
        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), header);
    }

    #[test]
    fn get_last_set_cycle_should_succeed() {
        let mock = MockServerClient::new();
        let reward_cycle = thread_rng().next_u64();
        let response = build_get_last_set_cycle_response(reward_cycle);
        let h = spawn(move || mock.client.get_last_set_cycle());
        write_response(mock.server, response.as_bytes());
        assert_eq!(h.join().unwrap().unwrap(), reward_cycle as u128);
    }

    #[test]
    fn get_chain_id_from_config() {
        let mock = MockServerClient::from_config(
            GlobalConfig::load_from_file("./src/tests/conf/signer-custom-chain-id.toml").unwrap(),
        );
        assert_eq!(mock.client.chain_id, 0x80000100);
    }
}
