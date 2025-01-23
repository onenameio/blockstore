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

use lazy_static::lazy_static;
use prometheus::{
    gather, histogram_opts, opts, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, Encoder, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, TextEncoder,
};

lazy_static! {
    pub static ref STACKS_TIP_HEIGHT_GAUGE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stacks_node_height",
        "The current height of the Stacks node"
    ))
    .unwrap();
    pub static ref BLOCK_VALIDATION_RESPONSES: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_block_validation_responses",
        "The number of block validation responses. `response_type` is either 'accepted' or 'rejected'",
        &["response_type"]
    )
    .unwrap();
    pub static ref BLOCK_RESPONSES_SENT: IntCounterVec = register_int_counter_vec!(
        "stacks_signer_block_responses_sent",
        "The number of block responses sent. `response_type` is either 'accepted' or 'rejected'",
        &["response_type"]
    )
    .unwrap();
    pub static ref BLOCK_PROPOSALS_RECEIVED: IntCounter = register_int_counter!(opts!(
        "stacks_signer_block_proposals_received",
        "The number of block proposals received by the signer"
    ))
    .unwrap();
    pub static ref CURRENT_REWARD_CYCLE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_current_reward_cycle",
        "The current reward cycle"
    )).unwrap();
    pub static ref SIGNER_STX_BALANCE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_stx_balance",
        "The current STX balance of the signer"
    )).unwrap();
    pub static ref SIGNER_NONCE: IntGauge = register_int_gauge!(opts!(
        "stacks_signer_nonce",
        "The current nonce of the signer"
    )).unwrap();

    pub static ref SIGNER_RPC_CALL_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_node_rpc_call_latencies_histogram",
        "Time (seconds) measuring round-trip RPC call latency to the Stacks node"
        // Will use DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0] by default
    ), &["path"]).unwrap();

    pub static ref SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_block_validation_latencies_histogram",
        "Time (seconds) measuring block validation time reported by the Stacks node",
        vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0]
    ), &[]).unwrap();

    pub static ref SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM: HistogramVec = register_histogram_vec!(histogram_opts!(
        "stacks_signer_block_response_latencies_histogram",
        "Time (seconds) measuring end-to-end time to respond to a block",
        vec![0.005, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0]
    ), &[]).unwrap();
}

pub fn gather_metrics_string() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    let metrics_families = gather();
    encoder.encode(&metrics_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
