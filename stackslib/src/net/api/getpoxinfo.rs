// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::types::{PrincipalData, StandardPrincipalData};
use clarity::vm::ClarityVersion;
use regex::{Captures, Regex};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::Sha256Sum;

use crate::burnchains::Burnchain;
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::stacks::boot::{POX_1_NAME, POX_2_NAME, POX_3_NAME, POX_4_NAME};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::Error as ChainError;
use crate::core::mempool::MemPoolDB;
use crate::core::StacksEpoch;
use crate::net::http::{
    parse_json, Error, HttpNotFound, HttpRequest, HttpRequestContents, HttpRequestPreamble,
    HttpResponse, HttpResponseContents, HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler, StacksHttp,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState, TipRequest};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::Error as DBError;

#[derive(Clone)]
pub struct RPCPoxInfoRequestHandler {}
impl RPCPoxInfoRequestHandler {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPoxCurrentCycleInfo {
    pub id: u64,
    pub min_threshold_ustx: u64,
    pub stacked_ustx: u64,
    pub is_pox_active: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPoxNextCycleInfo {
    pub id: u64,
    pub min_threshold_ustx: u64,
    pub min_increment_ustx: u64,
    pub stacked_ustx: u64,
    pub prepare_phase_start_block_height: u64,
    pub blocks_until_prepare_phase: i64,
    pub reward_phase_start_block_height: u64,
    pub blocks_until_reward_phase: u64,
    pub ustx_until_pox_rejection: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPoxContractVersion {
    pub contract_id: String,
    pub activation_burnchain_block_height: u64,
    pub first_reward_cycle_id: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPoxEpoch {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: ExecutionCost,
    pub network_epoch: u8,
}

impl From<StacksEpoch> for RPCPoxEpoch {
    fn from(epoch: StacksEpoch) -> Self {
        Self {
            epoch_id: epoch.epoch_id,
            start_height: epoch.start_height,
            end_height: epoch.end_height,
            block_limit: epoch.block_limit,
            network_epoch: epoch.network_epoch,
        }
    }
}

/// The data we return on GET /v2/pox
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RPCPoxInfoData {
    pub contract_id: String,
    pub pox_activation_threshold_ustx: u64,
    pub first_burnchain_block_height: u64,
    pub current_burnchain_block_height: u64,
    pub prepare_phase_block_length: u64,
    pub reward_phase_block_length: u64,
    pub reward_slots: u64,
    pub rejection_fraction: Option<u64>,
    pub total_liquid_supply_ustx: u64,
    pub current_cycle: RPCPoxCurrentCycleInfo,
    pub next_cycle: RPCPoxNextCycleInfo,
    pub epochs: Vec<RPCPoxEpoch>,

    // below are included for backwards-compatibility
    pub min_amount_ustx: u64,
    pub prepare_cycle_length: u64,
    pub reward_cycle_id: u64,
    pub reward_cycle_length: u64,
    pub rejection_votes_left_required: Option<u64>,
    pub next_reward_cycle_in: u64,

    // Information specific to each PoX contract version
    pub contract_versions: Vec<RPCPoxContractVersion>,
}

impl RPCPoxInfoData {
    pub fn from_db(
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState,
        tip: &StacksBlockId,
        burnchain: &Burnchain,
    ) -> Result<RPCPoxInfoData, NetError> {
        let mainnet = chainstate.mainnet;
        let chain_id = chainstate.chain_id;
        let current_burn_height =
            SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?.block_height;

        let pox_contract_name = burnchain
            .pox_constants
            .active_pox_contract(current_burn_height);

        let contract_identifier = boot_code_id(pox_contract_name, mainnet);
        let function = "get-pox-info";
        let cost_track = LimitedCostTracker::new_free();
        let sender = PrincipalData::Standard(StandardPrincipalData::transient());

        debug!(
            "Active PoX contract is '{}' (current_burn_height = {}, v1_unlock_height = {}",
            &contract_identifier, current_burn_height, burnchain.pox_constants.v1_unlock_height
        );

        // Note: should always be 0 unless somehow configured to start later
        let pox_1_first_cycle = burnchain
            .block_height_to_reward_cycle(burnchain.first_block_height)
            .ok_or(NetError::ChainstateError(
                "PoX-1 first reward cycle begins before first burn block height".to_string(),
            ))?;

        let pox_2_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(burnchain.pox_constants.v1_unlock_height))
            .ok_or(NetError::ChainstateError(
                "PoX-2 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let pox_3_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(
                burnchain.pox_constants.pox_3_activation_height,
            ))
            .ok_or(NetError::ChainstateError(
                "PoX-3 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let pox_4_first_cycle = burnchain
            .block_height_to_reward_cycle(u64::from(
                burnchain.pox_constants.pox_4_activation_height,
            ))
            .ok_or(NetError::ChainstateError(
                "PoX-4 first reward cycle begins before first burn block height".to_string(),
            ))?
            + 1;

        let data = chainstate
            .maybe_read_only_clarity_tx(
                &sortdb.index_handle_at_block(chainstate, tip)?,
                tip,
                |clarity_tx| {
                    clarity_tx.with_readonly_clarity_env(
                        mainnet,
                        chain_id,
                        ClarityVersion::Clarity2,
                        sender,
                        None,
                        cost_track,
                        |env| env.execute_contract(&contract_identifier, function, &[], true),
                    )
                },
            )
            .map_err(|_| NetError::NotFoundError)?;

        let res = match data {
            Some(Ok(res)) => res.expect_result_ok()?.expect_tuple()?,
            _ => return Err(NetError::DBError(DBError::NotFoundError)),
        };

        let first_burnchain_block_height = res
            .get("first-burnchain-block-height")
            .unwrap_or_else(|_| panic!("FATAL: no 'first-burnchain-block-height'"))
            .to_owned()
            .expect_u128()? as u64;

        let min_stacking_increment_ustx = res
            .get("min-amount-ustx")
            .unwrap_or_else(|_| panic!("FATAL: no 'min-amount-ustx'"))
            .to_owned()
            .expect_u128()? as u64;

        let prepare_cycle_length = res
            .get("prepare-cycle-length")
            .unwrap_or_else(|_| panic!("FATAL: no 'prepare-cycle-length'"))
            .to_owned()
            .expect_u128()? as u64;

        let reward_cycle_length = res
            .get("reward-cycle-length")
            .unwrap_or_else(|_| panic!("FATAL: no 'reward-cycle-length'"))
            .to_owned()
            .expect_u128()? as u64;

        let total_liquid_supply_ustx = res
            .get("total-liquid-supply-ustx")
            .unwrap_or_else(|_| panic!("FATAL: no 'total-liquid-supply-ustx'"))
            .to_owned()
            .expect_u128()? as u64;

        let has_rejection_data = pox_contract_name == POX_1_NAME
            || pox_contract_name == POX_2_NAME
            || pox_contract_name == POX_3_NAME;

        let (rejection_fraction, rejection_votes_left_required) = if has_rejection_data {
            let rejection_fraction = res
                .get("rejection-fraction")
                .unwrap_or_else(|_| panic!("FATAL: no 'rejection-fraction'"))
                .to_owned()
                .expect_u128()? as u64;

            let current_rejection_votes = res
                .get("current-rejection-votes")
                .unwrap_or_else(|_| panic!("FATAL: no 'current-rejection-votes'"))
                .to_owned()
                .expect_u128()? as u64;

            let total_required = (total_liquid_supply_ustx as u128 / 100)
                .checked_mul(rejection_fraction as u128)
                .ok_or_else(|| NetError::DBError(DBError::Overflow))?
                as u64;

            let votes_left = total_required.saturating_sub(current_rejection_votes);
            (Some(rejection_fraction), Some(votes_left))
        } else {
            (None, None)
        };

        let burnchain_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())?;

        let pox_consts = &burnchain.pox_constants;

        if prepare_cycle_length != pox_consts.prepare_length as u64 {
            error!(
                "PoX Constants in config mismatched with PoX contract constants: {} != {}",
                prepare_cycle_length, pox_consts.prepare_length
            );
            return Err(NetError::DBError(DBError::Corruption));
        }

        if reward_cycle_length != pox_consts.reward_cycle_length as u64 {
            error!(
                "PoX Constants in config mismatched with PoX contract constants: {} != {}",
                reward_cycle_length, pox_consts.reward_cycle_length
            );
            return Err(NetError::DBError(DBError::Corruption));
        }

        // Manually calculate `reward_cycle_id` so that clients don't get an "off by one" view at
        //  reward cycle boundaries (because if the reward cycle is loaded from clarity, its
        //  evaluated in the last mined Stacks block, not the most recent burn block).
        let reward_cycle_id = burnchain
            .block_height_to_reward_cycle(burnchain_tip.block_height)
            .ok_or_else(|| {
                NetError::ChainstateError("Current burn block height is before stacks start".into())
            })?;
        let effective_height = burnchain_tip.block_height - first_burnchain_block_height;

        let next_reward_cycle_in = reward_cycle_length - (effective_height % reward_cycle_length);

        let next_rewards_start = burnchain_tip.block_height + next_reward_cycle_in;
        let next_prepare_phase_start = next_rewards_start - prepare_cycle_length;

        let next_prepare_phase_in = i64::try_from(next_prepare_phase_start)
            .map_err(|_| NetError::ChainstateError("Burn block height overflowed i64".into()))?
            - i64::try_from(burnchain_tip.block_height).map_err(|_| {
                NetError::ChainstateError("Burn block height overflowed i64".into())
            })?;

        let cur_block_pox_contract = pox_consts.active_pox_contract(burnchain_tip.block_height);
        let cur_cycle_pox_contract =
            pox_consts.active_pox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id));
        let next_cycle_pox_contract = pox_consts
            .active_pox_contract(burnchain.reward_cycle_to_block_height(reward_cycle_id + 1));

        let cur_cycle_stacked_ustx = chainstate.get_total_ustx_stacked(
            &sortdb,
            tip,
            reward_cycle_id as u128,
            cur_cycle_pox_contract,
        )?;
        let next_cycle_stacked_ustx =
            // next_cycle_pox_contract might not be instantiated yet
            match chainstate.get_total_ustx_stacked(
                &sortdb,
                tip,
                reward_cycle_id as u128 + 1,
                next_cycle_pox_contract,
            ) {
                Ok(ustx) => ustx,
                Err(ChainError::ClarityError(_)) => {
                    // contract not instantiated yet
                    0
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

        let reward_slots = pox_consts.reward_slots() as u64;

        let cur_cycle_threshold = StacksChainState::get_threshold_from_participation(
            total_liquid_supply_ustx as u128,
            cur_cycle_stacked_ustx,
            reward_slots as u128,
        ) as u64;

        let next_threshold = StacksChainState::get_threshold_from_participation(
            total_liquid_supply_ustx as u128,
            next_cycle_stacked_ustx,
            reward_slots as u128,
        ) as u64;

        let pox_activation_threshold_ustx = (total_liquid_supply_ustx as u128)
            .checked_mul(pox_consts.pox_participation_threshold_pct as u128)
            .map(|x| x / 100)
            .ok_or_else(|| NetError::DBError(DBError::Overflow))?
            as u64;

        let cur_cycle_pox_active = sortdb.is_pox_active(burnchain, &burnchain_tip)?;
        let epochs: Vec<_> = SortitionDB::get_stacks_epochs(sortdb.conn())?
            .into_iter()
            .map(RPCPoxEpoch::from)
            .collect();

        Ok(RPCPoxInfoData {
            contract_id: boot_code_id(cur_block_pox_contract, chainstate.mainnet).to_string(),
            pox_activation_threshold_ustx,
            first_burnchain_block_height,
            current_burnchain_block_height: burnchain_tip.block_height,
            prepare_phase_block_length: prepare_cycle_length,
            reward_phase_block_length: reward_cycle_length - prepare_cycle_length,
            reward_slots,
            rejection_fraction,
            total_liquid_supply_ustx,
            current_cycle: RPCPoxCurrentCycleInfo {
                id: reward_cycle_id,
                min_threshold_ustx: cur_cycle_threshold,
                stacked_ustx: cur_cycle_stacked_ustx as u64,
                is_pox_active: cur_cycle_pox_active,
            },
            next_cycle: RPCPoxNextCycleInfo {
                id: reward_cycle_id + 1,
                min_threshold_ustx: next_threshold,
                min_increment_ustx: min_stacking_increment_ustx,
                stacked_ustx: next_cycle_stacked_ustx as u64,
                prepare_phase_start_block_height: next_prepare_phase_start,
                blocks_until_prepare_phase: next_prepare_phase_in,
                reward_phase_start_block_height: next_rewards_start,
                blocks_until_reward_phase: next_reward_cycle_in,
                ustx_until_pox_rejection: rejection_votes_left_required,
            },
            epochs,
            min_amount_ustx: next_threshold,
            prepare_cycle_length,
            reward_cycle_id,
            reward_cycle_length,
            rejection_votes_left_required,
            next_reward_cycle_in,
            contract_versions: vec![
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_1_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain.first_block_height,
                    first_reward_cycle_id: pox_1_first_cycle,
                },
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_2_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain.pox_constants.v1_unlock_height
                        as u64,
                    first_reward_cycle_id: pox_2_first_cycle,
                },
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_3_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain
                        .pox_constants
                        .pox_3_activation_height
                        as u64,
                    first_reward_cycle_id: pox_3_first_cycle,
                },
                RPCPoxContractVersion {
                    contract_id: boot_code_id(POX_4_NAME, chainstate.mainnet).to_string(),
                    activation_burnchain_block_height: burnchain
                        .pox_constants
                        .pox_4_activation_height
                        as u64,
                    first_reward_cycle_id: pox_4_first_cycle,
                },
            ],
        })
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCPoxInfoRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v2/pox$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/pox"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body for GetPoxInfo".to_string(),
            ));
        }

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCPoxInfoRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {}

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let tip = match node.load_stacks_chain_tip(&preamble, &contents) {
            Ok(tip) => tip,
            Err(error_resp) => {
                return error_resp.try_into_contents().map_err(NetError::from);
            }
        };

        let pox_info_res =
            node.with_node_state(|network, sortdb, chainstate, _mempool, _rpc_args| {
                RPCPoxInfoData::from_db(sortdb, chainstate, &tip, network.get_burnchain())
            });

        let pox_info = match pox_info_res {
            Ok(pox_info) => pox_info,
            Err(NetError::NotFoundError) | Err(NetError::DBError(DBError::NotFoundError)) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpNotFound::new("No such chain tip".into()),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
            Err(e) => {
                return StacksHttpResponse::new_error(
                    &preamble,
                    &HttpServerError::new(format!("Failed to load PoX info: {:?}", &e)),
                )
                .try_into_contents()
                .map_err(NetError::from);
            }
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&pox_info)?;
        Ok((preamble, body))
    }
}

impl HttpResponse for RPCPoxInfoRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let pox_info: RPCPoxInfoData = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(pox_info)?)
    }
}

impl StacksHttpRequest {
    /// Make a new getinfo request to this endpoint
    pub fn new_getpoxinfo(host: PeerHost, tip_req: TipRequest) -> StacksHttpRequest {
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v2/pox".into(),
            HttpRequestContents::new().for_tip(tip_req),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_rpc_get_pox_info(self) -> Result<RPCPoxInfoData, NetError> {
        let contents = self.get_http_payload_ok()?;
        let response_json: serde_json::Value = contents.try_into()?;
        let pox_info: RPCPoxInfoData = serde_json::from_value(response_json)
            .map_err(|_e| Error::DecodeError("Failed to decode JSON".to_string()))?;
        Ok(pox_info)
    }
}
