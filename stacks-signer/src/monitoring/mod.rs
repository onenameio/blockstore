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

#[cfg(feature = "monitoring_prom")]
mod prometheus;

#[cfg(feature = "monitoring_prom")]
mod server;

/// Actions for updating metrics
#[cfg(feature = "monitoring_prom")]
pub mod actions {
    use ::prometheus::HistogramTimer;
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use slog::slog_error;
    use stacks_common::error;

    use crate::config::GlobalConfig;
    use crate::monitoring::prometheus::*;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(height: i64) {
        STACKS_TIP_HEIGHT_GAUGE.set(height);
    }

    /// Update the current reward cycle
    pub fn update_reward_cycle(reward_cycle: i64) {
        CURRENT_REWARD_CYCLE.set(reward_cycle);
    }

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_VALIDATION_RESPONSES
            .with_label_values(&[label_value])
            .inc();
    }

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(accepted: bool) {
        let label_value = if accepted { "accepted" } else { "rejected" };
        BLOCK_RESPONSES_SENT.with_label_values(&[label_value]).inc();
    }

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {
        BLOCK_PROPOSALS_RECEIVED.inc();
    }

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(balance: i64) {
        SIGNER_STX_BALANCE.set(balance);
    }

    /// Update the signer nonce metric
    pub fn update_signer_nonce(nonce: u64) {
        SIGNER_NONCE.set(nonce as i64);
    }

    /// Start a new RPC call timer.
    /// The `origin` parameter is the base path of the RPC call, e.g. `http://node.com`.
    /// The `origin` parameter is removed from `full_path` when storing in prometheus.
    pub fn new_rpc_call_timer(full_path: &str, origin: &str) -> HistogramTimer {
        let path = super::remove_origin_from_path(full_path, origin);
        let histogram = SIGNER_RPC_CALL_LATENCIES_HISTOGRAM.with_label_values(&[&path]);
        histogram.start_timer()
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(block: &NakamotoBlock) {
        use clarity::util::get_epoch_time_ms;

        let diff =
            get_epoch_time_ms().saturating_sub(block.header.timestamp.saturating_mul(1000).into());
        SIGNER_BLOCK_RESPONSE_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(diff as f64 / 1000.0);
    }

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(latency_ms: u64) {
        SIGNER_BLOCK_VALIDATION_LATENCIES_HISTOGRAM
            .with_label_values(&[])
            .observe(latency_ms as f64 / 1000.0);
    }

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_none() {
            return Ok(());
        }
        let _ = std::thread::Builder::new()
            .name("signer_metrics".to_string())
            .spawn(move || {
                if let Err(monitoring_err) = super::server::MonitoringServer::start(&config) {
                    error!("Monitoring: Error in metrics server: {:?}", monitoring_err);
                }
            });
        Ok(())
    }
}

/// No-op actions for updating metrics
#[cfg(not(feature = "monitoring_prom"))]
pub mod actions {
    use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
    use slog::slog_info;
    use stacks_common::info;

    use crate::GlobalConfig;

    /// Update stacks tip height gauge
    pub fn update_stacks_tip_height(_height: i64) {}

    /// Update the current reward cycle
    pub fn update_reward_cycle(_reward_cycle: i64) {}

    /// Increment the block validation responses counter
    pub fn increment_block_validation_responses(_accepted: bool) {}

    /// Increment the block responses sent counter
    pub fn increment_block_responses_sent(_accepted: bool) {}

    /// Increment the number of block proposals received
    pub fn increment_block_proposals_received() {}

    /// Update the stx balance of the signer
    pub fn update_signer_stx_balance(_balance: i64) {}

    /// Update the signer nonce metric
    pub fn update_signer_nonce(_nonce: u64) {}

    /// NoOp timer uses for monitoring when the monitoring feature is not enabled.
    pub struct NoOpTimer;
    impl NoOpTimer {
        /// NoOp method to stop recording when the monitoring feature is not enabled.
        pub fn stop_and_record(&self) {}
    }

    /// Stop and record the no-op timer.
    pub fn new_rpc_call_timer(_full_path: &str, _origin: &str) -> NoOpTimer {
        NoOpTimer
    }

    /// Record the time taken to issue a block response for
    /// a given block. The block's timestamp is used to calculate the latency.
    ///
    /// Call this right after broadcasting a BlockResponse
    pub fn record_block_response_latency(_block: &NakamotoBlock) {}

    /// Record the time taken to validate a block, as reported by the Stacks node.
    pub fn record_block_validation_latency(_latency_ms: u64) {}

    /// Start serving monitoring metrics.
    /// This will only serve the metrics if the `monitoring_prom` feature is enabled.
    pub fn start_serving_monitoring_metrics(config: GlobalConfig) -> Result<(), String> {
        if config.metrics_endpoint.is_some() {
            info!("`metrics_endpoint` is configured for the signer, but the monitoring_prom feature is not enabled. Not starting monitoring metrics server.");
        }
        Ok(())
    }
}

// Allow dead code because this is only used in the `monitoring_prom` feature
// but we want to run it in a test
#[allow(dead_code)]
/// Remove the origin from the full path to avoid duplicate metrics for different origins
fn remove_origin_from_path(full_path: &str, origin: &str) -> String {
    full_path.replace(origin, "")
}

#[test]
fn test_remove_origin_from_path() {
    let full_path = "http://localhost:20443/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");

    let full_path = "/v2/info";
    let origin = "http://localhost:20443";
    let path = remove_origin_from_path(full_path, origin);
    assert_eq!(path, "/v2/info");
}
