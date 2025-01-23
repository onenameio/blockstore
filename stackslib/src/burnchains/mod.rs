// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::marker::PhantomData;
use std::{error, fmt, io};

use rusqlite::Error as sqlite_error;
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, PoxId, StacksAddress, TrieHash,
};
pub use stacks_common::types::{Address, PrivateKey, PublicKey};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use self::bitcoin::indexer::{
    BITCOIN_MAINNET as BITCOIN_NETWORK_ID_MAINNET, BITCOIN_MAINNET_NAME,
    BITCOIN_REGTEST as BITCOIN_NETWORK_ID_REGTEST, BITCOIN_REGTEST_NAME,
    BITCOIN_TESTNET as BITCOIN_NETWORK_ID_TESTNET, BITCOIN_TESTNET_NAME,
};
use self::bitcoin::{
    BitcoinBlock, BitcoinInputType, BitcoinTransaction, BitcoinTxInput, BitcoinTxOutput,
    Error as btc_error,
};
use crate::chainstate::burn::distribution::BurnSamplePoint;
use crate::chainstate::burn::operations::leader_block_commit::{
    MissedBlockCommit, OUTPUTS_PER_COMMIT,
};
use crate::chainstate::burn::operations::{
    BlockstackOperationType, Error as op_error, LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::{POX_1_NAME, POX_2_NAME, POX_3_NAME, POX_4_NAME};
use crate::chainstate::stacks::StacksPublicKey;
use crate::core::*;
use crate::net::neighbors::MAX_NEIGHBOR_BLOCK_DELAY;
use crate::util_lib::db::Error as db_error;

/// This module contains drivers and types for all burn chains we support.
pub mod affirmation;
pub mod bitcoin;
pub mod burnchain;
pub mod db;
pub mod indexer;

#[cfg(test)]
pub mod tests;

pub struct Txid(pub [u8; 32]);
impl_array_newtype!(Txid, u8, 32);
impl_array_hexstring_fmt!(Txid);
impl_byte_array_newtype!(Txid, u8, 32);
impl_byte_array_message_codec!(Txid, 32);
impl_byte_array_serde!(Txid);
pub const TXID_ENCODED_SIZE: u32 = 32;

pub const MAGIC_BYTES_LENGTH: usize = 2;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MagicBytes([u8; MAGIC_BYTES_LENGTH]);
impl_array_newtype!(MagicBytes, u8, MAGIC_BYTES_LENGTH);
impl MagicBytes {
    pub fn default() -> MagicBytes {
        BLOCKSTACK_MAGIC_MAINNET
    }
}

pub const BLOCKSTACK_MAGIC_MAINNET: MagicBytes = MagicBytes([105, 100]); // 'id'

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainParameters {
    chain_name: String,
    network_name: String,
    network_id: u32,
    stable_confirmations: u32,
    consensus_hash_lifetime: u32,
    pub first_block_height: u64,
    pub first_block_hash: BurnchainHeaderHash,
    pub first_block_timestamp: u32,
    pub initial_reward_start_block: u64,
}

impl BurnchainParameters {
    pub fn from_params(chain: &str, network: &str) -> Option<BurnchainParameters> {
        match (chain, network) {
            ("bitcoin", "mainnet") => Some(BurnchainParameters::bitcoin_mainnet()),
            ("bitcoin", "testnet") => Some(BurnchainParameters::bitcoin_testnet()),
            ("bitcoin", "regtest") => Some(BurnchainParameters::bitcoin_regtest()),
            _ => None,
        }
    }

    pub fn bitcoin_mainnet() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_MAINNET_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_MAINNET,
            stable_confirmations: 7,
            consensus_hash_lifetime: 24,
            first_block_height: BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT,
            first_block_hash: BurnchainHeaderHash::from_hex(BITCOIN_MAINNET_FIRST_BLOCK_HASH)
                .unwrap(),
            first_block_timestamp: BITCOIN_MAINNET_FIRST_BLOCK_TIMESTAMP,
            initial_reward_start_block: BITCOIN_MAINNET_INITIAL_REWARD_START_BLOCK,
        }
    }

    pub fn bitcoin_testnet() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_TESTNET_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_TESTNET,
            stable_confirmations: 7,
            consensus_hash_lifetime: 24,
            first_block_height: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT,
            first_block_hash: BurnchainHeaderHash::from_hex(BITCOIN_TESTNET_FIRST_BLOCK_HASH)
                .unwrap(),
            first_block_timestamp: BITCOIN_TESTNET_FIRST_BLOCK_TIMESTAMP,
            initial_reward_start_block: BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT - 10_000,
        }
    }

    pub fn bitcoin_regtest() -> BurnchainParameters {
        BurnchainParameters {
            chain_name: "bitcoin".to_string(),
            network_name: BITCOIN_REGTEST_NAME.to_string(),
            network_id: BITCOIN_NETWORK_ID_REGTEST,
            stable_confirmations: 1,
            consensus_hash_lifetime: 24,
            first_block_height: BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
            first_block_hash: BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH)
                .unwrap(),
            first_block_timestamp: BITCOIN_REGTEST_FIRST_BLOCK_TIMESTAMP,
            initial_reward_start_block: BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT,
        }
    }

    pub fn is_testnet(network_id: u32) -> bool {
        match network_id {
            BITCOIN_NETWORK_ID_TESTNET | BITCOIN_NETWORK_ID_REGTEST => true,
            _ => false,
        }
    }
}

/// This is an opaque representation of the underlying burnchain-specific principal that signed
/// this transaction.  It may not even map to an address, given that even in "simple" VMs like
/// bitcoin script, the "signer" may be only a part of a complex script.
///
/// The purpose of this struct is to capture a loggable representation of a principal that signed
/// this transaction.  It's not meant for use with consensus-critical code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnchainSigner(pub String);

impl fmt::Display for BurnchainSigner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.0)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BurnchainRecipient {
    pub address: PoxAddress,
    pub amount: u64,
}

#[derive(Debug, PartialEq, Clone)]
pub enum BurnchainTransaction {
    Bitcoin(BitcoinTransaction),
    // TODO: fill in more types as we support them
}

impl BurnchainTransaction {
    pub fn txid(&self) -> Txid {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.txid.clone(),
        }
    }

    pub fn vtxindex(&self) -> u32 {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.vtxindex,
        }
    }

    pub fn opcode(&self) -> u8 {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.opcode,
        }
    }

    pub fn data(&self) -> Vec<u8> {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.data.clone(),
        }
    }

    pub fn num_signers(&self) -> usize {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.inputs.len(),
        }
    }

    pub fn get_input_tx_ref(&self, input: usize) -> Option<&(Txid, u32)> {
        match self {
            BurnchainTransaction::Bitcoin(ref btc) => {
                btc.inputs.get(input).map(|txin| txin.tx_ref())
            }
        }
    }

    /// Get the BurnchainRecipients we are able to decode.
    /// A `None` value at slot `i` means "there is a recipient at slot `i`, but we don't know how
    /// to decode it`.
    pub fn get_recipients(&self) -> Vec<Option<BurnchainRecipient>> {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc
                .outputs
                .iter()
                .map(|ref o| BurnchainRecipient::try_from_bitcoin_output(o))
                .collect(),
        }
    }

    pub fn num_recipients(&self) -> usize {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.outputs.len(),
        }
    }

    pub fn get_burn_amount(&self) -> u64 {
        match *self {
            BurnchainTransaction::Bitcoin(ref btc) => btc.data_amt,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BurnchainBlock {
    Bitcoin(BitcoinBlock),
    // TODO: fill in some more types as we support them
}

#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainBlockHeader {
    pub block_height: u64,
    pub block_hash: BurnchainHeaderHash,
    pub parent_block_hash: BurnchainHeaderHash,
    pub num_txs: u64,
    pub timestamp: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Burnchain {
    pub peer_version: u32,
    pub network_id: u32,
    pub chain_name: String,
    pub network_name: String,
    pub working_dir: String,
    pub consensus_hash_lifetime: u32,
    pub stable_confirmations: u32,
    pub first_block_height: u64,
    pub first_block_hash: BurnchainHeaderHash,
    pub first_block_timestamp: u32,
    pub pox_constants: PoxConstants,
    pub initial_reward_start_block: u64,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PoxConstants {
    /// the length (in burn blocks) of the reward cycle
    pub reward_cycle_length: u32,
    /// the length (in burn blocks) of the prepare phase
    pub prepare_length: u32,
    /// the number of confirmations a PoX anchor block must
    ///  receive in order to become the anchor. must be at least > prepare_length/2
    pub anchor_threshold: u32,
    /// fraction of liquid STX that must vote to reject PoX for
    /// it to revert to PoB in the next reward cycle
    pub pox_rejection_fraction: u64,
    /// percentage of liquid STX that must participate for PoX
    ///  to occur
    pub pox_participation_threshold_pct: u64,
    /// last+1 block height of sunset phase
    pub sunset_end: u64,
    /// first block height of sunset phase
    pub sunset_start: u64,
    /// The auto unlock height for PoX v1 lockups before transition to PoX v2. This
    /// also defines the burn height at which PoX reward sets are calculated using
    /// PoX v2 rather than v1
    pub v1_unlock_height: u32,
    /// The auto unlock height for PoX v2 lockups during Epoch 2.2
    pub v2_unlock_height: u32,
    /// The auto unlock height for PoX v3 lockups during Epoch 2.5
    pub v3_unlock_height: u32,
    /// After this burn height, reward cycles use pox-3 for reward set data
    pub pox_3_activation_height: u32,
    /// After this burn height, reward cycles use pox-4 for reward set data
    pub pox_4_activation_height: u32,
    _shadow: PhantomData<()>,
}

impl PoxConstants {
    pub fn new(
        reward_cycle_length: u32,
        prepare_length: u32,
        anchor_threshold: u32,
        pox_rejection_fraction: u64,
        pox_participation_threshold_pct: u64,
        sunset_start: u64,
        sunset_end: u64,
        v1_unlock_height: u32,
        v2_unlock_height: u32,
        v3_unlock_height: u32,
        pox_3_activation_height: u32,
    ) -> PoxConstants {
        assert!(anchor_threshold > (prepare_length / 2));
        assert!(prepare_length < reward_cycle_length);
        assert!(sunset_start <= sunset_end);
        assert!(v2_unlock_height >= v1_unlock_height);
        assert!(v3_unlock_height >= v2_unlock_height);
        assert!(pox_3_activation_height >= v2_unlock_height);

        PoxConstants {
            reward_cycle_length,
            prepare_length,
            anchor_threshold,
            pox_rejection_fraction,
            pox_participation_threshold_pct,
            sunset_start,
            sunset_end,
            v1_unlock_height,
            v2_unlock_height,
            v3_unlock_height,
            pox_3_activation_height,
            pox_4_activation_height: v3_unlock_height,
            _shadow: PhantomData,
        }
    }
    #[cfg(test)]
    pub fn test_default() -> PoxConstants {
        // 20 reward slots; 10 prepare-phase slots
        PoxConstants::new(
            10,
            5,
            3,
            25,
            5,
            5000,
            10000,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        )
    }

    #[cfg(test)]
    /// Create a PoX constants used in tests with 5-block cycles,
    ///  3-block prepare phases, a threshold of 3, rejection fraction of 25%,
    ///  a participation threshold of 5% and no sunset or transition to pox-2 or beyond.
    pub(crate) fn test_20_no_sunset() -> PoxConstants {
        PoxConstants::new(
            5,
            3,
            3,
            25,
            5,
            u64::MAX,
            u64::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        )
    }

    /// Returns the PoX contract that is "active" at the given burn block height
    pub fn static_active_pox_contract(
        v1_unlock_height: u64,
        pox_3_activation_height: u64,
        pox_4_activation_height: u64,
        burn_height: u64,
    ) -> &'static str {
        if burn_height > pox_4_activation_height {
            POX_4_NAME
        } else if burn_height > pox_3_activation_height {
            POX_3_NAME
        } else if burn_height > v1_unlock_height {
            POX_2_NAME
        } else {
            POX_1_NAME
        }
    }

    /// Returns the PoX contract that is "active" at the given burn block height
    pub fn active_pox_contract(&self, burn_height: u64) -> &'static str {
        Self::static_active_pox_contract(
            u64::from(self.v1_unlock_height),
            u64::from(self.pox_3_activation_height),
            u64::from(self.pox_4_activation_height),
            burn_height,
        )
    }

    pub fn reward_slots(&self) -> u32 {
        (self.reward_cycle_length - self.prepare_length)
            * u32::try_from(OUTPUTS_PER_COMMIT).expect("FATAL: > 2^32 outputs per commit")
    }

    /// is participating_ustx enough to engage in PoX in the next reward cycle?
    pub fn enough_participation(&self, participating_ustx: u128, liquid_ustx: u128) -> bool {
        participating_ustx
            .checked_mul(100)
            .expect("OVERFLOW: uSTX overflowed u128")
            > liquid_ustx
                .checked_mul(u128::from(self.pox_participation_threshold_pct))
                .expect("OVERFLOW: uSTX overflowed u128")
    }

    pub fn mainnet_default() -> PoxConstants {
        PoxConstants::new(
            POX_REWARD_CYCLE_LENGTH,
            POX_PREPARE_WINDOW_LENGTH,
            80,
            25,
            5,
            BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT + POX_SUNSET_START,
            BITCOIN_MAINNET_FIRST_BLOCK_HEIGHT + POX_SUNSET_END,
            POX_V1_MAINNET_EARLY_UNLOCK_HEIGHT,
            POX_V2_MAINNET_EARLY_UNLOCK_HEIGHT,
            POX_V3_MAINNET_EARLY_UNLOCK_HEIGHT,
            BITCOIN_MAINNET_STACKS_24_BURN_HEIGHT
                .try_into()
                .expect("Epoch transition height must be <= u32::MAX"),
        )
    }

    // NOTE: this is the *old* pre-Nakamoto testnet
    pub fn testnet_default() -> PoxConstants {
        PoxConstants::new(
            POX_REWARD_CYCLE_LENGTH / 2,   // 1050
            POX_PREPARE_WINDOW_LENGTH / 2, // 50
            40,
            12,
            2,
            BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT + POX_SUNSET_START,
            BITCOIN_TESTNET_FIRST_BLOCK_HEIGHT + POX_SUNSET_END,
            POX_V1_TESTNET_EARLY_UNLOCK_HEIGHT,
            POX_V2_TESTNET_EARLY_UNLOCK_HEIGHT,
            POX_V3_TESTNET_EARLY_UNLOCK_HEIGHT,
            BITCOIN_TESTNET_STACKS_24_BURN_HEIGHT
                .try_into()
                .expect("Epoch transition height must be <= u32::MAX"),
        ) // total liquid supply is 40000000000000000 µSTX
    }

    pub fn nakamoto_testnet_default() -> PoxConstants {
        PoxConstants::new(900, 100, 51, 100, 0, u64::MAX, u64::MAX, 242, 243, 246, 244)
    }

    // TODO: add tests from mutation testing results #4838
    #[cfg_attr(test, mutants::skip)]
    pub fn regtest_default() -> PoxConstants {
        PoxConstants::new(
            5,
            3,
            2,
            3333333333333333,
            1,
            BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT + POX_SUNSET_START,
            BITCOIN_REGTEST_FIRST_BLOCK_HEIGHT + POX_SUNSET_END,
            1_000_000,
            2_000_000,
            4_000_000,
            3_000_000,
        )
    }

    /// Return true if PoX should sunset at all
    /// return false if not.
    pub fn has_pox_sunset(epoch_id: StacksEpochId) -> bool {
        epoch_id < StacksEpochId::Epoch21
    }

    /// Returns true if PoX has been fully disabled by the PoX sunset.
    /// Behavior is epoch-specific
    pub fn is_after_pox_sunset_end(&self, burn_block_height: u64, epoch_id: StacksEpochId) -> bool {
        if !Self::has_pox_sunset(epoch_id) {
            false
        } else {
            burn_block_height >= self.sunset_end
        }
    }

    /// Returns true if the burn height falls into the PoX sunset period.
    /// Returns false if not, or if the sunset isn't active in this epoch
    /// (Note that this is true if burn_block_height is beyond the sunset height)
    pub fn is_after_pox_sunset_start(
        &self,
        burn_block_height: u64,
        epoch_id: StacksEpochId,
    ) -> bool {
        if !Self::has_pox_sunset(epoch_id) {
            false
        } else {
            self.sunset_start <= burn_block_height
        }
    }

    /// The first block of the prepare phase during `reward_cycle`. This is the prepare phase _for the next cycle_.
    pub fn prepare_phase_start(&self, first_block_height: u64, reward_cycle: u64) -> u64 {
        let reward_cycle_start =
            self.reward_cycle_to_block_height(first_block_height, reward_cycle);
        let prepare_phase_start = reward_cycle_start + u64::from(self.reward_cycle_length)
            - u64::from(self.prepare_length);
        prepare_phase_start
    }

    /// Is this the first block to receive rewards in its cycle?
    /// This is the mod 1 block. Note: in nakamoto, the signer set for cycle N signs
    ///  the mod 0 block.
    pub fn is_reward_cycle_start(&self, first_block_height: u64, burn_height: u64) -> bool {
        let effective_height = burn_height - first_block_height;
        // first block of the new reward cycle
        (effective_height % u64::from(self.reward_cycle_length)) == 1
    }

    /// Is this the first block to be signed by the signer set in cycle N?
    /// This is the mod 0 block.
    pub fn is_naka_signing_cycle_start(&self, first_block_height: u64, burn_height: u64) -> bool {
        let effective_height = burn_height - first_block_height;
        // first block of the new reward cycle
        (effective_height % u64::from(self.reward_cycle_length)) == 0
    }

    /// return the first burn block which receives reward in `reward_cycle`.
    /// this is the modulo 1 block
    pub fn reward_cycle_to_block_height(&self, first_block_height: u64, reward_cycle: u64) -> u64 {
        // NOTE: the `+ 1` is because the height of the first block of a reward cycle is mod 1, not
        // mod 0.
        first_block_height + reward_cycle * u64::from(self.reward_cycle_length) + 1
    }

    /// the first burn block that must be *signed* by the signer set of `reward_cycle`.
    /// this is the modulo 0 block
    pub fn nakamoto_first_block_of_cycle(&self, first_block_height: u64, reward_cycle: u64) -> u64 {
        first_block_height + reward_cycle * u64::from(self.reward_cycle_length)
    }

    pub fn reward_cycle_index(&self, first_block_height: u64, burn_height: u64) -> Option<u64> {
        let effective_height = burn_height.checked_sub(first_block_height)?;
        Some(effective_height % u64::from(self.reward_cycle_length))
    }

    pub fn block_height_to_reward_cycle(
        &self,
        first_block_height: u64,
        block_height: u64,
    ) -> Option<u64> {
        Self::static_block_height_to_reward_cycle(
            block_height,
            first_block_height,
            u64::from(self.reward_cycle_length),
        )
    }

    /// Return the reward cycle that the current prepare phase corresponds to if `block_height` is _in_ a prepare
    /// phase. If it is not in a prepare phase, return None.
    pub fn reward_cycle_of_prepare_phase(
        &self,
        first_block_height: u64,
        block_height: u64,
    ) -> Option<u64> {
        if !self.is_in_prepare_phase(first_block_height, block_height) {
            return None;
        }
        // the None branches here should be unreachable, because if `first_block_height > block_height`,
        //   `is_in_prepare_phase` would have returned false, but no need to be unsafe anyways.
        let effective_height = block_height.checked_sub(first_block_height)?;
        let current_cycle = self.block_height_to_reward_cycle(first_block_height, block_height)?;
        if effective_height % u64::from(self.reward_cycle_length) == 0 {
            // if this is the "mod 0" block of a prepare phase, its corresponding reward cycle is the current one
            Some(current_cycle)
        } else {
            // otherwise, the corresponding reward cycle is actually the _next_ reward cycle
            Some(current_cycle + 1)
        }
    }

    pub fn is_in_prepare_phase(&self, first_block_height: u64, block_height: u64) -> bool {
        Self::static_is_in_prepare_phase(
            first_block_height,
            u64::from(self.reward_cycle_length),
            u64::from(self.prepare_length),
            block_height,
        )
    }

    pub fn static_is_in_prepare_phase(
        first_block_height: u64,
        reward_cycle_length: u64,
        prepare_length: u64,
        block_height: u64,
    ) -> bool {
        if block_height <= first_block_height {
            // not a reward cycle start if we're the first block after genesis.
            false
        } else {
            let effective_height = block_height - first_block_height;
            let reward_index = effective_height % reward_cycle_length;

            // NOTE: first block in reward cycle is mod 1, so mod 0 is the last block in the
            // prepare phase.
            // TODO: I *think* the logic of `== 0` here requires some further digging.
            //  `mod 0` may not have any rewards, but it does not behave like "prepare phase" blocks:
            //  is it already a member of reward cycle "N" where N = block_height / reward_cycle_len
            reward_index == 0 || reward_index > reward_cycle_length - prepare_length
        }
    }

    /// The prepare phase is the last prepare_phase_length blocks of the cycle
    /// This cannot include the 0 block for nakamoto
    pub fn is_in_naka_prepare_phase(&self, first_block_height: u64, block_height: u64) -> bool {
        Self::static_is_in_naka_prepare_phase(
            first_block_height,
            u64::from(self.reward_cycle_length),
            u64::from(self.prepare_length),
            block_height,
        )
    }

    /// The prepare phase is the last prepare_phase_length blocks of the cycle
    /// This cannot include the 0 block for nakamoto
    pub fn static_is_in_naka_prepare_phase(
        first_block_height: u64,
        reward_cycle_length: u64,
        prepare_length: u64,
        block_height: u64,
    ) -> bool {
        if block_height <= first_block_height {
            // not a reward cycle start if we're the first block after genesis.
            false
        } else {
            let effective_height = block_height - first_block_height;
            let reward_index = effective_height % reward_cycle_length;
            reward_index > reward_cycle_length - prepare_length
        }
    }

    /// Returns the active reward cycle at the given burn block height
    /// * `first_block_ht` - the first burn block height that the Stacks network monitored
    /// * `reward_cycle_len` - the length of each reward cycle in the network.
    pub fn static_block_height_to_reward_cycle(
        block_ht: u64,
        first_block_ht: u64,
        reward_cycle_len: u64,
    ) -> Option<u64> {
        if block_ht < first_block_ht {
            return None;
        }
        Some((block_ht - first_block_ht) / (reward_cycle_len))
    }
}

/// Structure for encoding our view of the network
#[derive(Debug, PartialEq, Clone)]
pub struct BurnchainView {
    /// last-seen block height (at chain tip)
    pub burn_block_height: u64,
    /// last-seen burn block hash
    pub burn_block_hash: BurnchainHeaderHash,
    /// latest stable block height (e.g. chain tip minus 7)
    pub burn_stable_block_height: u64,
    /// latest stable burn block hash
    pub burn_stable_block_hash: BurnchainHeaderHash,
    /// map all block heights from burn_block_height back to the oldest one we'll take for considering the peer a neighbor
    pub last_burn_block_hashes: HashMap<u64, BurnchainHeaderHash>,
    /// consensus hash of the current reward cycle's start block
    pub rc_consensus_hash: ConsensusHash,
}

/// The burnchain block's encoded state transition:
/// -- the new burn distribution
/// -- the sequence of valid blockstack operations that went into it
/// -- the set of previously-accepted leader VRF keys consumed
#[derive(Debug, Clone)]
pub struct BurnchainStateTransition {
    pub burn_dist: Vec<BurnSamplePoint>,
    pub accepted_ops: Vec<BlockstackOperationType>,
    pub consumed_leader_keys: Vec<LeaderKeyRegisterOp>,
    pub windowed_block_commits: Vec<Vec<LeaderBlockCommitOp>>,
    pub windowed_missed_commits: Vec<Vec<MissedBlockCommit>>,
}

/// The burnchain block's state transition's ops:
/// -- the new burn distribution
/// -- the sequence of valid blockstack operations that went into it
/// -- the set of previously-accepted leader VRF keys consumed
#[derive(Debug, Clone)]
pub struct BurnchainStateTransitionOps {
    pub accepted_ops: Vec<BlockstackOperationType>,
    pub consumed_leader_keys: Vec<LeaderKeyRegisterOp>,
}

#[derive(Debug)]
pub enum Error {
    /// Unsupported burn chain
    UnsupportedBurnchain,
    /// Bitcoin-related error
    Bitcoin(btc_error),
    /// burn database error
    DBError(db_error),
    /// Download error
    DownloadError(btc_error),
    /// Parse error
    ParseError,
    /// Thread channel error
    ThreadChannelError,
    /// Missing headers
    MissingHeaders,
    /// Missing parent block
    MissingParentBlock,
    /// Remote burnchain peer has misbehaved
    BurnchainPeerBroken,
    /// filesystem error
    FSError(io::Error),
    /// Operation processing error
    OpError(op_error),
    /// Try again error
    TrySyncAgain,
    UnknownBlock(BurnchainHeaderHash),
    NonCanonicalPoxId(PoxId, PoxId),
    CoordinatorClosed,
    /// Graceful shutdown error
    ShutdownInitiated,
    /// No epoch defined at that height
    NoStacksEpoch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnsupportedBurnchain => write!(f, "Unsupported burnchain"),
            Error::Bitcoin(ref btce) => fmt::Display::fmt(btce, f),
            Error::DBError(ref dbe) => fmt::Display::fmt(dbe, f),
            Error::DownloadError(ref btce) => fmt::Display::fmt(btce, f),
            Error::ParseError => write!(f, "Parse error"),
            Error::MissingHeaders => write!(f, "Missing block headers"),
            Error::MissingParentBlock => write!(f, "Missing parent block"),
            Error::ThreadChannelError => write!(f, "Error in thread channel"),
            Error::BurnchainPeerBroken => write!(f, "Remote burnchain peer has misbehaved"),
            Error::FSError(ref e) => fmt::Display::fmt(e, f),
            Error::OpError(ref e) => fmt::Display::fmt(e, f),
            Error::TrySyncAgain => write!(f, "Try synchronizing again"),
            Error::UnknownBlock(block) => write!(f, "Unknown burnchain block {}", block),
            Error::NonCanonicalPoxId(parent, child) => write!(
                f,
                "{} is not a descendant of the canonical parent PoXId: {}",
                parent, child
            ),
            Error::CoordinatorClosed => write!(f, "ChainsCoordinator channel hung up"),
            Error::ShutdownInitiated => write!(f, "Graceful shutdown was initiated"),
            Error::NoStacksEpoch => write!(
                f,
                "No Stacks epoch is defined at the height being evaluated"
            ),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::UnsupportedBurnchain => None,
            Error::Bitcoin(ref e) => Some(e),
            Error::DBError(ref e) => Some(e),
            Error::DownloadError(ref e) => Some(e),
            Error::ParseError => None,
            Error::MissingHeaders => None,
            Error::MissingParentBlock => None,
            Error::ThreadChannelError => None,
            Error::BurnchainPeerBroken => None,
            Error::FSError(ref e) => Some(e),
            Error::OpError(ref e) => Some(e),
            Error::TrySyncAgain => None,
            Error::UnknownBlock(_) => None,
            Error::NonCanonicalPoxId(_, _) => None,
            Error::CoordinatorClosed => None,
            Error::ShutdownInitiated => None,
            Error::NoStacksEpoch => None,
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        Error::DBError(e)
    }
}

impl From<sqlite_error> for Error {
    fn from(e: sqlite_error) -> Error {
        Error::DBError(db_error::SqliteError(e))
    }
}

impl From<btc_error> for Error {
    fn from(e: btc_error) -> Error {
        Error::Bitcoin(e)
    }
}

impl BurnchainView {
    #[cfg(test)]
    pub fn make_test_data(&mut self) {
        let oldest_height = if self.burn_stable_block_height < MAX_NEIGHBOR_BLOCK_DELAY {
            0
        } else {
            self.burn_stable_block_height - MAX_NEIGHBOR_BLOCK_DELAY
        };

        let mut ret = HashMap::new();
        for i in oldest_height..self.burn_block_height + 1 {
            if i == self.burn_stable_block_height {
                ret.insert(i, self.burn_stable_block_hash.clone());
            } else if i == self.burn_block_height {
                ret.insert(i, self.burn_block_hash.clone());
            } else {
                let data = {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(&i.to_le_bytes());
                    hasher.finalize()
                };
                let mut data_32 = [0x00; 32];
                data_32.copy_from_slice(&data[0..32]);
                ret.insert(i, BurnchainHeaderHash(data_32));
            }
        }
        self.last_burn_block_hashes = ret;
    }
}
