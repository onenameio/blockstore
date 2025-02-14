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
use std::fmt::Debug;
use std::sync::mpsc::Sender;
use std::time::Duration;

use clarity::codec::StacksMessageCodec;
use hashbrown::HashMap;
use libsigner::{SignerEntries, SignerEvent, SignerRunLoop};
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::{debug, error, info, warn};

use crate::chainstate::SortitionsView;
use crate::client::{retry_with_exponential_backoff, ClientError, StacksClient};
use crate::config::{GlobalConfig, SignerConfig, SignerConfigMode};
#[cfg(any(test, feature = "testing"))]
use crate::v0::tests::TEST_SKIP_SIGNER_CLEANUP;
use crate::Signer as SignerTrait;

#[derive(thiserror::Error, Debug)]
/// Configuration error type
pub enum ConfigurationError {
    /// Error occurred while fetching data from the stacks node
    #[error("{0}")]
    ClientError(#[from] ClientError),
    /// The stackerdb signer config is not yet updated
    #[error("The stackerdb config is not yet updated")]
    StackerDBNotUpdated,
    /// The signer binary is configured as dry-run, but is also registered for this cycle
    #[error("The signer binary is configured as dry-run, but is also registered for this cycle")]
    DryRunStackerIsRegistered,
}

/// The internal signer state info
#[derive(PartialEq, Clone, Debug)]
pub struct StateInfo {
    /// the runloop state
    pub runloop_state: State,
    /// the current reward cycle info
    pub reward_cycle_info: Option<RewardCycleInfo>,
    /// The current running signers reward cycles
    pub running_signers: Vec<u64>,
}

/// The signer result that can be sent across threads
pub enum SignerResult {
    /// The signer has received a status check
    StatusCheck(StateInfo),
}

impl From<StateInfo> for SignerResult {
    fn from(state_info: StateInfo) -> Self {
        SignerResult::StatusCheck(state_info)
    }
}

/// The runloop state
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum State {
    /// The runloop is uninitialized
    Uninitialized,
    /// The runloop has no registered signers
    NoRegisteredSigners,
    /// The runloop has registered signers
    RegisteredSigners,
}

/// The current reward cycle info
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct RewardCycleInfo {
    /// The current reward cycle
    pub reward_cycle: u64,
    /// The total reward cycle length
    pub reward_cycle_length: u64,
    /// The prepare phase length
    pub prepare_phase_block_length: u64,
    /// The first burn block height
    pub first_burnchain_block_height: u64,
    /// The burnchain block height of the last query
    pub last_burnchain_block_height: u64,
}

impl RewardCycleInfo {
    /// Check if the provided burnchain block height is part of the reward cycle
    pub const fn is_in_reward_cycle(&self, burnchain_block_height: u64) -> bool {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        let reward_cycle = blocks_mined / self.reward_cycle_length;
        self.reward_cycle == reward_cycle
    }

    /// Get the reward cycle for a specific burnchain block height
    pub const fn get_reward_cycle(&self, burnchain_block_height: u64) -> u64 {
        let blocks_mined = burnchain_block_height.saturating_sub(self.first_burnchain_block_height);
        blocks_mined / self.reward_cycle_length
    }

    /// Check if the provided burnchain block height is in the prepare phase of the next cycle
    pub fn is_in_next_prepare_phase(&self, burnchain_block_height: u64) -> bool {
        let effective_height = burnchain_block_height - self.first_burnchain_block_height;
        let reward_index = effective_height % self.reward_cycle_length;

        reward_index >= (self.reward_cycle_length - self.prepare_phase_block_length)
            && self.get_reward_cycle(burnchain_block_height) == self.reward_cycle
    }
}

/// The configuration state for a reward cycle.
/// Allows us to track if we've registered a signer for a cycle or not
///  and to differentiate between being unregistered and simply not configured
pub enum ConfiguredSigner<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Signer is registered for the cycle and ready to process messages
    RegisteredSigner(Signer),
    /// The signer runloop isn't registered for this cycle (i.e., we've checked the
    ///   the signer set and we're not in it)
    NotRegistered {
        /// the cycle number we're not registered for
        cycle: u64,
        /// Phantom data for the message codec
        _phantom_state: std::marker::PhantomData<T>,
    },
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> std::fmt::Display
    for ConfiguredSigner<Signer, T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegisteredSigner(s) => write!(f, "{s}"),
            Self::NotRegistered { cycle, .. } => write!(f, "NotRegistered in Cycle #{cycle}"),
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    ConfiguredSigner<Signer, T>
{
    /// Create a `NotRegistered` instance of the enum (so that callers do not need
    ///  to supply phantom_state data).
    pub fn not_registered(cycle: u64) -> Self {
        Self::NotRegistered {
            cycle,
            _phantom_state: std::marker::PhantomData,
        }
    }

    /// The reward cycle this signer is configured for
    pub fn reward_cycle(&self) -> u64 {
        match self {
            ConfiguredSigner::RegisteredSigner(s) => s.reward_cycle(),
            ConfiguredSigner::NotRegistered { cycle, .. } => *cycle,
        }
    }
}

/// The runloop for the stacks signer
pub struct RunLoop<Signer, T>
where
    Signer: SignerTrait<T>,
    T: StacksMessageCodec + Clone + Send + Debug,
{
    /// Configuration info
    pub config: GlobalConfig,
    /// The stacks node client
    pub stacks_client: StacksClient,
    /// The internal signer for an odd or even reward cycle
    /// Keyed by reward cycle % 2
    pub stacks_signers: HashMap<u64, ConfiguredSigner<Signer, T>>,
    /// The state of the runloop
    pub state: State,
    /// The current reward cycle info. Only None if the runloop is uninitialized
    pub current_reward_cycle_info: Option<RewardCycleInfo>,
    /// Cache sortitin data from `stacks-node`
    pub sortition_state: Option<SortitionsView>,
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug> RunLoop<Signer, T> {
    /// Create a new signer runloop from the provided configuration
    pub fn new(config: GlobalConfig) -> Self {
        let stacks_client = StacksClient::from(&config);
        Self {
            config,
            stacks_client,
            stacks_signers: HashMap::with_capacity(2),
            state: State::Uninitialized,
            current_reward_cycle_info: None,
            sortition_state: None,
        }
    }
    /// Get the registered signers for a specific reward cycle
    /// Returns None if no signers are registered or its not Nakamoto cycle
    pub fn get_parsed_reward_set(
        &self,
        reward_cycle: u64,
    ) -> Result<Option<SignerEntries>, ClientError> {
        debug!("Getting registered signers for reward cycle {reward_cycle}...");
        let Some(signers) = self.stacks_client.get_reward_set_signers(reward_cycle)? else {
            warn!("No reward set signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        };
        if signers.is_empty() {
            warn!("No registered signers found for reward cycle {reward_cycle}.");
            return Ok(None);
        }
        let entries = SignerEntries::parse(self.config.network.is_mainnet(), &signers).unwrap();
        Ok(Some(entries))
    }

    /// Get a signer configuration for a specific reward cycle from the stacks node
    fn get_signer_config(
        &mut self,
        reward_cycle: u64,
    ) -> Result<Option<SignerConfig>, ConfigurationError> {
        // We can only register for a reward cycle if a reward set exists.
        let signer_entries = match self.get_parsed_reward_set(reward_cycle) {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!("Error while fetching reward set {reward_cycle}: {e:?}");
                return Err(e.into());
            }
        };

        // Ensure that the stackerdb has been updated for the reward cycle before proceeding
        let last_calculated_reward_cycle =
            self.stacks_client.get_last_set_cycle().map_err(|e| {
                warn!(
                    "Failed to fetch last calculated stackerdb cycle from stacks-node";
                    "reward_cycle" => reward_cycle,
                    "err" => ?e
                );
                ConfigurationError::StackerDBNotUpdated
            })?;
        if last_calculated_reward_cycle < reward_cycle as u128 {
            warn!(
                "Stackerdb has not been updated for reward cycle {reward_cycle}. Last calculated reward cycle is {last_calculated_reward_cycle}."
            );
            return Err(ConfigurationError::StackerDBNotUpdated);
        }

        let signer_slot_ids = self
            .stacks_client
            .get_parsed_signer_slots(reward_cycle)
            .map_err(|e| {
                warn!("Error while fetching stackerdb slots {reward_cycle}: {e:?}");
                e
            })?;

        let dry_run = self.config.dry_run;
        let current_addr = self.stacks_client.get_signer_address();

        let signer_config_mode = if !dry_run {
            let Some(signer_slot_id) = signer_slot_ids.get(current_addr) else {
                warn!(
                    "Signer {current_addr} was not found in stacker db. Must not be registered for this reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            let Some(signer_id) = signer_entries.signer_addr_to_id.get(current_addr) else {
                warn!(
                    "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            info!(
                "Signer #{signer_id} ({current_addr}) is registered for reward cycle {reward_cycle}."
            );
            SignerConfigMode::Normal {
                signer_slot_id: *signer_slot_id,
                signer_id: *signer_id,
            }
        } else {
            if signer_slot_ids.contains_key(current_addr) {
                error!(
                    "Signer is configured for dry-run, but the signer address {current_addr} was found in stacker db."
                );
                return Err(ConfigurationError::DryRunStackerIsRegistered);
            };
            if signer_entries.signer_addr_to_id.contains_key(current_addr) {
                warn!(
                    "Signer {current_addr} was found in stacker db but not the reward set for reward cycle {reward_cycle}."
                );
                return Ok(None);
            };
            SignerConfigMode::DryRun
        };
        Ok(Some(SignerConfig {
            reward_cycle,
            signer_mode: signer_config_mode,
            signer_entries,
            signer_slot_ids: signer_slot_ids.into_values().collect(),
            first_proposal_burn_block_timing: self.config.first_proposal_burn_block_timing,
            stacks_private_key: self.config.stacks_private_key,
            node_host: self.config.node_host.to_string(),
            mainnet: self.config.network.is_mainnet(),
            db_path: self.config.db_path.clone(),
            block_proposal_timeout: self.config.block_proposal_timeout,
            tenure_last_block_proposal_timeout: self.config.tenure_last_block_proposal_timeout,
            block_proposal_validation_timeout: self.config.block_proposal_validation_timeout,
            tenure_idle_timeout: self.config.tenure_idle_timeout,
            tenure_idle_timeout_buffer: self.config.tenure_idle_timeout_buffer,
            block_proposal_max_age_secs: self.config.block_proposal_max_age_secs,
            reorg_attempts_activity_timeout: self.config.reorg_attempts_activity_timeout,
        }))
    }

    /// Refresh signer configuration for a specific reward cycle
    fn refresh_signer_config(&mut self, reward_cycle: u64) {
        let reward_index = reward_cycle % 2;
        let new_signer_config = match self.get_signer_config(reward_cycle) {
            Ok(Some(new_signer_config)) => {
                let signer_mode = new_signer_config.signer_mode.clone();
                let new_signer = Signer::new(new_signer_config);
                info!("{new_signer} Signer is registered for reward cycle {reward_cycle} as {signer_mode}. Initialized signer state.");
                ConfiguredSigner::RegisteredSigner(new_signer)
            }
            Ok(None) => {
                warn!("Signer is not registered for reward cycle {reward_cycle}");
                ConfiguredSigner::not_registered(reward_cycle)
            }
            Err(e) => {
                warn!("Failed to get the reward set info: {e}. Will try again later.");
                return;
            }
        };

        self.stacks_signers.insert(reward_index, new_signer_config);
    }

    fn initialize_runloop(&mut self) -> Result<(), ClientError> {
        debug!("Initializing signer runloop...");
        let reward_cycle_info = retry_with_exponential_backoff(|| {
            self.stacks_client
                .get_current_reward_cycle_info()
                .map_err(backoff::Error::transient)
        })?;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        self.refresh_signer_config(current_reward_cycle);
        // We should only attempt to initialize the next reward cycle signer if we are in the prepare phase of the next reward cycle
        if reward_cycle_info.is_in_next_prepare_phase(reward_cycle_info.last_burnchain_block_height)
        {
            self.refresh_signer_config(current_reward_cycle.saturating_add(1));
        }
        self.current_reward_cycle_info = Some(reward_cycle_info);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn refresh_runloop(&mut self, ev_burn_block_height: u64) -> Result<(), ClientError> {
        let current_burn_block_height = std::cmp::max(
            self.stacks_client.get_peer_info()?.burn_block_height,
            ev_burn_block_height,
        );
        let reward_cycle_info = self
            .current_reward_cycle_info
            .as_mut()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.");
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let block_reward_cycle = reward_cycle_info.get_reward_cycle(current_burn_block_height);

        // First ensure we refresh our view of the current reward cycle information
        if block_reward_cycle != current_reward_cycle {
            let new_reward_cycle_info = RewardCycleInfo {
                reward_cycle: block_reward_cycle,
                reward_cycle_length: reward_cycle_info.reward_cycle_length,
                prepare_phase_block_length: reward_cycle_info.prepare_phase_block_length,
                first_burnchain_block_height: reward_cycle_info.first_burnchain_block_height,
                last_burnchain_block_height: current_burn_block_height,
            };
            *reward_cycle_info = new_reward_cycle_info;
        }
        let reward_cycle_before_refresh = current_reward_cycle;
        let current_reward_cycle = reward_cycle_info.reward_cycle;
        let is_in_next_prepare_phase =
            reward_cycle_info.is_in_next_prepare_phase(current_burn_block_height);
        let next_reward_cycle = current_reward_cycle.saturating_add(1);

        info!(
            "Refreshing runloop with new burn block event";
            "latest_node_burn_ht" => current_burn_block_height,
            "event_ht" =>  ev_burn_block_height,
            "reward_cycle_before_refresh" => reward_cycle_before_refresh,
            "current_reward_cycle" => current_reward_cycle,
            "configured_for_current" => Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle),
            "registered_for_current" => Self::is_registered_for_cycle(&self.stacks_signers, current_reward_cycle),
            "configured_for_next" => Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle),
            "registered_for_next" => Self::is_registered_for_cycle(&self.stacks_signers, next_reward_cycle),
            "is_in_next_prepare_phase" => is_in_next_prepare_phase,
        );

        // Check if we need to refresh the signers:
        //   need to refresh the current signer if we are not configured for the current reward cycle
        //   need to refresh the next signer if we're not configured for the next reward cycle, and we're in the prepare phase
        if !Self::is_configured_for_cycle(&self.stacks_signers, current_reward_cycle) {
            self.refresh_signer_config(current_reward_cycle);
        }
        if is_in_next_prepare_phase
            && !Self::is_configured_for_cycle(&self.stacks_signers, next_reward_cycle)
        {
            self.refresh_signer_config(next_reward_cycle);
        }

        self.cleanup_stale_signers(current_reward_cycle);
        if self.stacks_signers.is_empty() {
            self.state = State::NoRegisteredSigners;
        } else {
            self.state = State::RegisteredSigners;
        }
        Ok(())
    }

    fn is_configured_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
    }

    fn is_registered_for_cycle(
        stacks_signers: &HashMap<u64, ConfiguredSigner<Signer, T>>,
        reward_cycle: u64,
    ) -> bool {
        let Some(signer) = stacks_signers.get(&(reward_cycle % 2)) else {
            return false;
        };
        signer.reward_cycle() == reward_cycle
            && matches!(signer, ConfiguredSigner::RegisteredSigner(_))
    }

    fn cleanup_stale_signers(&mut self, current_reward_cycle: u64) {
        #[cfg(any(test, feature = "testing"))]
        if TEST_SKIP_SIGNER_CLEANUP.get() {
            warn!("Skipping signer cleanup due to testing directive.");
            return;
        }
        let mut to_delete = Vec::new();
        for (idx, signer) in &mut self.stacks_signers {
            let reward_cycle = signer.reward_cycle();
            if reward_cycle >= current_reward_cycle {
                // We are either the current or a future reward cycle, so we are not stale.
                continue;
            }
            if let ConfiguredSigner::RegisteredSigner(signer) = signer {
                if !signer.has_unprocessed_blocks() {
                    debug!("{signer}: Signer's tenure has completed.");
                    to_delete.push(*idx);
                }
            }
        }
        for idx in to_delete {
            self.stacks_signers.remove(&idx);
        }
    }
}

impl<Signer: SignerTrait<T>, T: StacksMessageCodec + Clone + Send + Debug>
    SignerRunLoop<Vec<SignerResult>, T> for RunLoop<Signer, T>
{
    fn set_event_timeout(&mut self, timeout: Duration) {
        self.config.event_timeout = timeout;
    }

    fn get_event_timeout(&self) -> Duration {
        self.config.event_timeout
    }

    fn run_one_pass(
        &mut self,
        event: Option<SignerEvent<T>>,
        res: &Sender<Vec<SignerResult>>,
    ) -> Option<Vec<SignerResult>> {
        debug!(
            "Running one pass for the signer. state={:?}, event={event:?}",
            self.state
        );
        // This is the only event that we respond to from the outer signer runloop
        if let Some(SignerEvent::StatusCheck) = event {
            info!("Signer status check requested: {:?}.", self.state);
            if let Err(e) = res.send(vec![StateInfo {
                runloop_state: self.state,
                reward_cycle_info: self.current_reward_cycle_info,
                running_signers: self
                    .stacks_signers
                    .values()
                    .map(|s| s.reward_cycle())
                    .collect(),
            }
            .into()])
            {
                error!("Failed to send status check result: {e}.");
            }
        }

        if self.state == State::Uninitialized {
            if let Err(e) = self.initialize_runloop() {
                error!("Failed to initialize signer runloop: {e}.");
                if let Some(event) = event {
                    warn!("Ignoring event: {event:?}");
                }
                return None;
            }
        } else if let Some(SignerEvent::NewBurnBlock { burn_height, .. }) = event {
            if let Err(e) = self.refresh_runloop(burn_height) {
                error!("Failed to refresh signer runloop: {e}.");
                warn!("Signer may have an outdated view of the network.");
            }
        }
        let current_reward_cycle = self
            .current_reward_cycle_info
            .as_ref()
            .expect("FATAL: cannot be an initialized signer with no reward cycle info.")
            .reward_cycle;
        for configured_signer in self.stacks_signers.values_mut() {
            let ConfiguredSigner::RegisteredSigner(ref mut signer) = configured_signer else {
                debug!("{configured_signer}: Not configured for cycle, ignoring events for cycle");
                continue;
            };

            signer.process_event(
                &self.stacks_client,
                &mut self.sortition_state,
                event.as_ref(),
                res,
                current_reward_cycle,
            );
        }
        if self.state == State::NoRegisteredSigners && event.is_some() {
            let next_reward_cycle = current_reward_cycle.saturating_add(1);
            info!("Signer is not registered for the current reward cycle ({current_reward_cycle}). Reward set is not yet determined or signer is not registered for the upcoming reward cycle ({next_reward_cycle}).");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::boot::NakamotoSignerEntry;
    use libsigner::SignerEntries;
    use rand::{thread_rng, Rng, RngCore};
    use stacks_common::types::chainstate::{StacksPrivateKey, StacksPublicKey};

    use super::RewardCycleInfo;

    #[test]
    fn parse_nakamoto_signer_entries_test() {
        let nmb_signers = 10;
        let weight = 10;
        let mut signer_entries = Vec::with_capacity(nmb_signers);
        for _ in 0..nmb_signers {
            let key =
                StacksPublicKey::from_private(&StacksPrivateKey::random()).to_bytes_compressed();
            let mut signing_key = [0u8; 33];
            signing_key.copy_from_slice(&key);
            signer_entries.push(NakamotoSignerEntry {
                signing_key,
                stacked_amt: 0,
                weight,
            });
        }

        let parsed_entries = SignerEntries::parse(false, &signer_entries).unwrap();
        assert_eq!(parsed_entries.signer_id_to_pk.len(), nmb_signers);
        let mut signer_ids = parsed_entries
            .signer_id_to_pk
            .into_keys()
            .collect::<Vec<_>>();
        signer_ids.sort();
        assert_eq!(
            signer_ids,
            (0..nmb_signers).map(|id| id as u32).collect::<Vec<_>>()
        );
    }

    #[test]
    fn is_in_reward_cycle_info() {
        let rand_byte: u8 = std::cmp::max(1, thread_rng().gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height));
        assert!(reward_cycle_info.is_in_reward_cycle(last_burnchain_block_height));
        assert!(!reward_cycle_info
            .is_in_reward_cycle(first_burnchain_block_height.wrapping_add(reward_cycle_length)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_length)
                .wrapping_sub(1)
        ));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height.wrapping_add(reward_cycle_phase_block_length)
        ));
        assert!(reward_cycle_info.is_in_reward_cycle(first_burnchain_block_height.wrapping_add(1)));

        assert!(reward_cycle_info.is_in_reward_cycle(
            first_burnchain_block_height
                .wrapping_add(reward_cycle_phase_block_length)
                .wrapping_add(1)
        ));
    }

    #[test]
    fn is_in_next_prepare_phase() {
        let reward_cycle_info = RewardCycleInfo {
            reward_cycle: 5,
            reward_cycle_length: 10,
            prepare_phase_block_length: 5,
            first_burnchain_block_height: 0,
            last_burnchain_block_height: 50,
        };

        assert!(!reward_cycle_info.is_in_next_prepare_phase(49));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(50));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(51));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(52));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(53));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(54));
        assert!(reward_cycle_info.is_in_next_prepare_phase(55));
        assert!(reward_cycle_info.is_in_next_prepare_phase(56));
        assert!(reward_cycle_info.is_in_next_prepare_phase(57));
        assert!(reward_cycle_info.is_in_next_prepare_phase(58));
        assert!(reward_cycle_info.is_in_next_prepare_phase(59));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(60));
        assert!(!reward_cycle_info.is_in_next_prepare_phase(61));

        let rand_byte: u8 = std::cmp::max(1, thread_rng().gen());
        let prepare_phase_block_length = rand_byte as u64;
        // Ensure the reward cycle is not close to u64 Max to prevent overflow when adding prepare phase len
        let reward_cycle_length = (std::cmp::max(
            prepare_phase_block_length.wrapping_add(1),
            thread_rng().next_u32() as u64,
        ))
        .wrapping_add(prepare_phase_block_length);
        let reward_cycle_phase_block_length =
            reward_cycle_length.wrapping_sub(prepare_phase_block_length);
        let first_burnchain_block_height = std::cmp::max(1u8, thread_rng().gen()) as u64;
        let last_burnchain_block_height = thread_rng().gen_range(
            first_burnchain_block_height
                ..first_burnchain_block_height
                    .wrapping_add(reward_cycle_length)
                    .wrapping_sub(prepare_phase_block_length),
        );
        let blocks_mined = last_burnchain_block_height.wrapping_sub(first_burnchain_block_height);
        let reward_cycle = blocks_mined / reward_cycle_length;

        let reward_cycle_info = RewardCycleInfo {
            reward_cycle,
            reward_cycle_length,
            prepare_phase_block_length,
            first_burnchain_block_height,
            last_burnchain_block_height,
        };

        for i in 0..reward_cycle_length {
            if i < reward_cycle_phase_block_length {
                assert!(!reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            } else {
                assert!(reward_cycle_info
                    .is_in_next_prepare_phase(first_burnchain_block_height.wrapping_add(i)));
            }
        }
    }
}
