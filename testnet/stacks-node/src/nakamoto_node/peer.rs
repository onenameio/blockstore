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
use std::net::SocketAddr;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::time::Duration;

use stacks::burnchains::db::BurnchainHeaderReader;
use stacks::burnchains::PoxConstants;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::signal_mining_blocked;
use stacks::core::mempool::MemPoolDB;
use stacks::cost_estimates::metrics::{CostMetric, UnitMetric};
use stacks::cost_estimates::{CostEstimator, FeeEstimator, UnitEstimator};
use stacks::net::dns::{DNSClient, DNSResolver};
use stacks::net::p2p::PeerNetwork;
use stacks::net::RPCHandlerArgs;
use stacks_common::util::hash::Sha256Sum;

use crate::burnchains::make_bitcoin_indexer;
use crate::nakamoto_node::relayer::RelayerDirective;
use crate::neon_node::open_chainstate_with_faults;
use crate::run_loop::nakamoto::{Globals, RunLoop};
use crate::{Config, EventDispatcher};

/// Thread that runs the network state machine, handling both p2p and http requests.
pub struct PeerThread {
    /// Node config
    config: Config,
    /// instance of the peer network. Made optional in order to trick the borrow checker.
    net: PeerNetwork,
    /// handle to global inter-thread comms
    globals: Globals,
    /// how long to wait for network messages on each poll, in millis
    poll_timeout: u64,
    /// handle to the sortition DB
    sortdb: SortitionDB,
    /// handle to the chainstate DB
    chainstate: StacksChainState,
    /// handle to the mempool DB
    mempool: MemPoolDB,
    /// Buffered network result relayer command.
    /// P2P network results are consolidated into a single directive.
    results_with_data: Option<RelayerDirective>,
    /// total number of p2p state-machine passes so far. Used to signal when to download the next
    /// reward cycle of blocks
    num_p2p_state_machine_passes: u64,
    /// total number of inventory state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_inv_sync_passes: u64,
    /// total number of download state-machine passes so far. Used to signal when to download the
    /// next reward cycle of blocks.
    num_download_passes: u64,
    /// last burnchain block seen in the PeerNetwork's chain view since the last run
    last_burn_block_height: u64,
}

impl PeerThread {
    /// Main loop of the p2p thread.
    /// Runs in a separate thread.
    /// Continuously receives, until told otherwise.
    pub fn main(mut self, event_dispatcher: EventDispatcher) {
        debug!("p2p thread ID is {:?}", thread::current().id());
        let should_keep_running = self.globals.should_keep_running.clone();
        let (mut dns_resolver, mut dns_client) = DNSResolver::new(10);

        // spawn a daemon thread that runs the DNS resolver.
        // It will die when the rest of the system dies.
        {
            let _jh = thread::Builder::new()
                .name("dns-resolver".to_string())
                .spawn(move || {
                    debug!("DNS resolver thread ID is {:?}", thread::current().id());
                    dns_resolver.thread_main();
                })
                .unwrap();
        }

        // NOTE: these must be instantiated in the thread context, since it can't be safely sent
        // between threads
        let fee_estimator_opt = self.config.make_fee_estimator();
        let cost_estimator = self
            .config
            .make_cost_estimator()
            .unwrap_or_else(|| Box::new(UnitEstimator));
        let cost_metric = self
            .config
            .make_cost_metric()
            .unwrap_or_else(|| Box::new(UnitMetric));

        let indexer = make_bitcoin_indexer(&self.config, Some(should_keep_running));

        // receive until we can't reach the receiver thread
        loop {
            if !self.globals.keep_running() {
                break;
            }
            if !self.run_one_pass(
                &indexer,
                Some(&mut dns_client),
                &event_dispatcher,
                &cost_estimator,
                &cost_metric,
                fee_estimator_opt.as_ref(),
            ) {
                break;
            }
        }

        // kill miner
        signal_mining_blocked(self.globals.get_miner_status());

        // set termination flag so other threads die
        self.globals.signal_stop();

        // thread exited, so signal to the relayer thread to die.
        while let Err(TrySendError::Full(_)) =
            self.globals.relay_send.try_send(RelayerDirective::Exit)
        {
            warn!("Failed to direct relayer thread to exit, sleeping and trying again");
            thread::sleep(Duration::from_secs(5));
        }
        info!("P2P thread exit!");
    }

    /// Instantiate the p2p thread.
    /// Binds the addresses in the config (which may panic if the port is blocked).
    /// This is so the node will crash "early" before any new threads start if there's going to be
    /// a bind error anyway.
    pub fn new(runloop: &RunLoop, net: PeerNetwork) -> PeerThread {
        Self::new_all(
            runloop.get_globals(),
            runloop.config(),
            runloop.get_burnchain().pox_constants,
            net,
        )
    }

    fn new_all(
        globals: Globals,
        config: &Config,
        pox_constants: PoxConstants,
        mut net: PeerNetwork,
    ) -> Self {
        let config = config.clone();
        let mempool = config
            .connect_mempool_db()
            .expect("FATAL: database failure opening mempool");
        let burn_db_path = config.get_burn_db_file_path();

        let sortdb = SortitionDB::open(&burn_db_path, false, pox_constants)
            .expect("FATAL: could not open sortition DB");

        let chainstate =
            open_chainstate_with_faults(&config).expect("FATAL: could not open chainstate DB");

        let p2p_sock: SocketAddr = config
            .node
            .p2p_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.p2p_bind));
        let rpc_sock = config
            .node
            .rpc_bind
            .parse()
            .unwrap_or_else(|_| panic!("Failed to parse socket: {}", &config.node.rpc_bind));

        let did_bind = net
            .try_bind(&p2p_sock, &rpc_sock)
            .expect("BUG: PeerNetwork could not bind");

        if !did_bind {
            info!("`PeerNetwork::bind()` skipped, already bound");
        }

        let poll_timeout = config.get_poll_time();
        PeerThread {
            config,
            net,
            globals,
            poll_timeout,
            sortdb,
            chainstate,
            mempool,
            results_with_data: None,
            num_p2p_state_machine_passes: 0,
            num_inv_sync_passes: 0,
            num_download_passes: 0,
            last_burn_block_height: 0,
        }
    }

    /// Check if the StackerDB config needs to be updated (by looking
    ///  at the signal in `self.globals`), and if so, refresh the
    ///  StackerDB config
    fn refresh_stackerdb(&mut self) {
        if !self.globals.coord_comms.need_stackerdb_update() {
            return;
        }

        if let Err(e) = self
            .net
            .refresh_stacker_db_configs(&self.sortdb, &mut self.chainstate)
        {
            warn!("Failed to update StackerDB configs: {e}");
        }

        self.globals.coord_comms.set_stackerdb_update(false);
    }

    /// Run one pass of the p2p/http state machine
    /// Return true if we should continue running passes; false if not
    #[allow(clippy::borrowed_box)]
    pub(crate) fn run_one_pass<B: BurnchainHeaderReader>(
        &mut self,
        indexer: &B,
        dns_client_opt: Option<&mut DNSClient>,
        event_dispatcher: &EventDispatcher,
        cost_estimator: &Box<dyn CostEstimator>,
        cost_metric: &Box<dyn CostMetric>,
        fee_estimator: Option<&Box<dyn FeeEstimator>>,
    ) -> bool {
        // initial block download?
        let ibd = self.globals.in_initial_block_download();
        let download_backpressure = self
            .results_with_data
            .as_ref()
            .map(|res| {
                if let RelayerDirective::HandleNetResult(netres) = &res {
                    netres.has_block_data_to_store()
                } else {
                    false
                }
            })
            .unwrap_or(false);

        let poll_ms = if !download_backpressure && self.net.has_more_downloads() {
            // keep getting those blocks -- drive the downloader state-machine
            debug!(
                "P2P: backpressure: {download_backpressure}, more downloads: {}",
                self.net.has_more_downloads()
            );
            1
        } else {
            self.poll_timeout
        };

        self.refresh_stackerdb();

        // do one pass
        let p2p_res = {
            // NOTE: handler_args must be created such that it outlives the inner net.run() call and
            // doesn't ref anything within p2p_thread.
            let handler_args = RPCHandlerArgs {
                exit_at_block_height: self.config.burnchain.process_exit_at_block_height,
                genesis_chainstate_hash: Sha256Sum::from_hex(stx_genesis::GENESIS_CHAINSTATE_HASH)
                    .unwrap(),
                event_observer: Some(event_dispatcher),
                cost_estimator: Some(cost_estimator.as_ref()),
                cost_metric: Some(cost_metric.as_ref()),
                fee_estimator: fee_estimator.map(|boxed_estimator| boxed_estimator.as_ref()),
                coord_comms: Some(&self.globals.coord_comms),
            };
            self.net.run(
                indexer,
                &self.sortdb,
                &mut self.chainstate,
                &mut self.mempool,
                dns_client_opt,
                download_backpressure,
                ibd,
                poll_ms,
                &handler_args,
            )
        };
        match p2p_res {
            Ok(network_result) => {
                if self.num_p2p_state_machine_passes < network_result.num_state_machine_passes {
                    // p2p state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_p2p_state_pass();
                    self.num_p2p_state_machine_passes = network_result.num_state_machine_passes;
                }

                if self.num_inv_sync_passes < network_result.num_inv_sync_passes {
                    // inv-sync state-machine did a full pass. Notify anyone listening.
                    self.globals.sync_comms.notify_inv_sync_pass();
                    self.num_inv_sync_passes = network_result.num_inv_sync_passes;
                }

                if self.num_download_passes < network_result.num_download_passes {
                    // download state-machine did a full pass.  Notify anyone listening.
                    self.globals.sync_comms.notify_download_pass();
                    self.num_download_passes = network_result.num_download_passes;
                }

                self.last_burn_block_height = network_result.burn_height;
                if let Some(res) = self.results_with_data.take() {
                    if let RelayerDirective::HandleNetResult(netres) = res {
                        let new_res = netres.update(network_result);
                        self.results_with_data = Some(RelayerDirective::HandleNetResult(new_res));
                    }
                } else {
                    self.results_with_data =
                        Some(RelayerDirective::HandleNetResult(network_result));
                }

                self.globals.raise_initiative(
                    "PeerThread::run_one_pass() with data-bearing network result".to_string(),
                );
            }
            Err(e) => {
                // this is only reachable if the network is not instantiated correctly --
                // i.e. you didn't connect it
                panic!("P2P: Failed to process network dispatch: {e:?}");
            }
        };

        if let Some(next_result) = self.results_with_data.take() {
            // have blocks, microblocks, and/or transactions (don't care about anything else),
            // or a directive to mine microblocks
            self.globals.raise_initiative(
                "PeerThread::run_one_pass() with backlogged network results".to_string(),
            );
            if let Err(e) = self.globals.relay_send.try_send(next_result) {
                debug!(
                    "P2P: {:?}: download backpressure detected",
                    &self.net.local_peer,
                );
                match e {
                    TrySendError::Full(directive) => {
                        // don't lose this data -- just try it again
                        self.results_with_data = Some(directive);
                    }
                    TrySendError::Disconnected(_) => {
                        info!("P2P: Relayer hang up with p2p channel");
                        self.globals.signal_stop();
                        return false;
                    }
                }
            } else {
                debug!("P2P: Dispatched result to Relayer!",);
            }
        }

        true
    }
}
