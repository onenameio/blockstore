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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use stacks::burnchains::{Burnchain, Error as burnchain_error};
use stacks_common::util::{get_epoch_time_secs, sleep_ms};

use crate::burnchains::BurnchainTip;
use crate::Config;

#[derive(Clone)]
pub struct PoxSyncWatchdogComms {
    /// how many passes in the p2p state machine have taken place since startup?
    p2p_state_passes: Arc<AtomicU64>,
    /// how many times have we done an inv sync?
    inv_sync_passes: Arc<AtomicU64>,
    /// how many times have we done a download pass?
    download_passes: Arc<AtomicU64>,
    /// What's our last IBD status?
    last_ibd: Arc<AtomicBool>,
    /// Should keep running?
    should_keep_running: Arc<AtomicBool>,
}

impl PoxSyncWatchdogComms {
    pub fn new(should_keep_running: Arc<AtomicBool>) -> PoxSyncWatchdogComms {
        PoxSyncWatchdogComms {
            p2p_state_passes: Arc::new(AtomicU64::new(0)),
            inv_sync_passes: Arc::new(AtomicU64::new(0)),
            download_passes: Arc::new(AtomicU64::new(0)),
            last_ibd: Arc::new(AtomicBool::new(true)),
            should_keep_running,
        }
    }

    pub fn get_p2p_state_passes(&self) -> u64 {
        self.p2p_state_passes.load(Ordering::SeqCst)
    }

    pub fn get_inv_sync_passes(&self) -> u64 {
        self.inv_sync_passes.load(Ordering::SeqCst)
    }

    pub fn get_download_passes(&self) -> u64 {
        self.download_passes.load(Ordering::SeqCst)
    }

    pub fn get_ibd(&self) -> bool {
        self.last_ibd.load(Ordering::SeqCst)
    }

    fn interruptable_sleep(&self, secs: u64) -> Result<(), burnchain_error> {
        let deadline = secs + get_epoch_time_secs();
        while get_epoch_time_secs() < deadline {
            sleep_ms(1000);
            if !self.should_keep_running() {
                return Err(burnchain_error::CoordinatorClosed);
            }
        }
        Ok(())
    }

    pub fn should_keep_running(&self) -> bool {
        self.should_keep_running.load(Ordering::SeqCst)
    }

    pub fn notify_p2p_state_pass(&mut self) {
        self.p2p_state_passes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn notify_inv_sync_pass(&mut self) {
        self.inv_sync_passes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn notify_download_pass(&mut self) {
        self.download_passes.fetch_add(1, Ordering::SeqCst);
    }

    pub fn set_ibd(&mut self, value: bool) {
        self.last_ibd.store(value, Ordering::SeqCst);
    }
}

/// Monitor the state of the Stacks blockchain as the peer network and relay threads download and
/// proces Stacks blocks.  Don't allow the node to process the next PoX reward cycle's sortitions
/// unless it's reasonably sure that it has processed all Stacks blocks for this reward cycle.
/// This struct monitors the Stacks chainstate to make this determination.
pub struct PoxSyncWatchdog {
    /// time between burnchain syncs in steady state
    steady_state_burnchain_sync_interval: u64,
    /// handle to relayer thread that informs the watchdog when the P2P state-machine does stuff
    relayer_comms: PoxSyncWatchdogComms,
    /// should this sync watchdog always download? used in integration tests.
    unconditionally_download: bool,
}

impl PoxSyncWatchdog {
    pub fn new(
        config: &Config,
        watchdog_comms: PoxSyncWatchdogComms,
    ) -> Result<PoxSyncWatchdog, String> {
        let burnchain_poll_time = config.burnchain.poll_time_secs;
        let unconditionally_download = config.node.pox_sync_sample_secs == 0;

        Ok(PoxSyncWatchdog {
            unconditionally_download,
            steady_state_burnchain_sync_interval: burnchain_poll_time,
            relayer_comms: watchdog_comms,
        })
    }

    pub fn make_comms_handle(&self) -> PoxSyncWatchdogComms {
        self.relayer_comms.clone()
    }

    /// Are we in the initial burnchain block download? i.e. is the burn tip snapshot far enough away
    /// from the burnchain height that we should be eagerly downloading snapshots?
    fn infer_initial_burnchain_block_download(
        burnchain: &Burnchain,
        last_processed_height: u64,
        burnchain_height: u64,
    ) -> bool {
        let ibd =
            last_processed_height + (burnchain.stable_confirmations as u64) < burnchain_height;
        if ibd {
            debug!(
                "PoX watchdog: {last_processed_height} + {} < {burnchain_height}, so initial block download",
                burnchain.stable_confirmations
            );
        } else {
            debug!(
                "PoX watchdog: {last_processed_height} + {} >= {burnchain_height}, so steady-state",
                burnchain.stable_confirmations
            );
        }
        ibd
    }

    /// This code path is only used for Epoch 2.5 and earlier.
    ///
    /// Wait to poll the burnchain for its height, and compute the maximum height up to which we
    /// should process sortitions.
    ///
    /// This code used to be much more elaborate, and would use a set of heuristics to determine
    /// whether or not there could be an outstanding PoX anchor block to try waiting for before
    /// attempting to process sortitions without it.  However, we now know for a fact that in epoch
    /// 2.5 and earlier, in both mainnet and testnet, there are no missing anchor blocks, so this
    /// code instead just sleeps for `[burnchain].poll_time_secs` and computes the burn block height of
    /// the start of the first reward cycle for which we don't yet have an anchor block.
    ///
    /// Return (still-in-ibd?, maximum-burnchain-sync-height) on success.
    pub fn pox_sync_wait(
        &mut self,
        burnchain: &Burnchain,
        burnchain_tip: &BurnchainTip, // this is the highest burnchain snapshot we've sync'ed to
        burnchain_height: u64,        // this is the absolute burnchain block height
    ) -> Result<(bool, u64), burnchain_error> {
        let burnchain_rc = burnchain
            .block_height_to_reward_cycle(burnchain_height)
            .expect("FATAL: burnchain height is before system start");

        let sortition_rc = burnchain
            .block_height_to_reward_cycle(burnchain_tip.block_snapshot.block_height)
            .expect("FATAL: sortition height is before system start");

        let ibbd = PoxSyncWatchdog::infer_initial_burnchain_block_download(
            burnchain,
            burnchain_tip.block_snapshot.block_height,
            burnchain_height,
        );

        let max_sync_height = if sortition_rc < burnchain_rc {
            burnchain
                .reward_cycle_to_block_height(sortition_rc + 1)
                .min(burnchain_height)
        } else {
            burnchain_tip
                .block_snapshot
                .block_height
                .max(burnchain_height)
        };

        if !self.unconditionally_download {
            self.relayer_comms
                .interruptable_sleep(self.steady_state_burnchain_sync_interval)?;
        }

        Ok((ibbd, max_sync_height))
    }
}
