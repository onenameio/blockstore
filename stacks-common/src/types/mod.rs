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

use std::cell::LazyCell;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::sync::LazyLock;

#[cfg(feature = "canonical")]
pub mod sqlite;

use crate::address::c32::{c32_address, c32_address_decode};
use crate::address::{
    public_keys_to_address_hash, to_bits_p2pkh, AddressHashMode,
    C32_ADDRESS_VERSION_MAINNET_MULTISIG, C32_ADDRESS_VERSION_MAINNET_SINGLESIG,
    C32_ADDRESS_VERSION_TESTNET_MULTISIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use crate::consts::MICROSTACKS_PER_STACKS;
use crate::deps_common::bitcoin::blockdata::transaction::TxOut;
use crate::types::chainstate::{StacksAddress, StacksPublicKey};
use crate::util::hash::Hash160;
use crate::util::secp256k1::{MessageSignature, Secp256k1PublicKey};

pub mod chainstate;
pub mod net;

#[cfg(test)]
pub mod tests;

/// A container for public keys (compressed secp256k1 public keys)
pub struct StacksPublicKeyBuffer(pub [u8; 33]);
impl_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_array_hexstring_fmt!(StacksPublicKeyBuffer);
impl_byte_array_newtype!(StacksPublicKeyBuffer, u8, 33);
impl_byte_array_message_codec!(StacksPublicKeyBuffer, 33);
impl_byte_array_serde!(StacksPublicKeyBuffer);

impl StacksPublicKeyBuffer {
    pub fn from_public_key(pubkey: &Secp256k1PublicKey) -> StacksPublicKeyBuffer {
        let pubkey_bytes_vec = pubkey.to_bytes_compressed();
        let mut pubkey_bytes = [0u8; 33];
        pubkey_bytes.copy_from_slice(&pubkey_bytes_vec[..]);
        StacksPublicKeyBuffer(pubkey_bytes)
    }

    pub fn to_public_key(&self) -> Result<Secp256k1PublicKey, &'static str> {
        Secp256k1PublicKey::from_slice(&self.0)
            .map_err(|_e_str| "Failed to decode Stacks public key")
    }
}

pub trait PublicKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn verify(&self, data_hash: &[u8], sig: &MessageSignature) -> Result<bool, &'static str>;
}

pub trait PrivateKey: Clone + fmt::Debug + serde::Serialize + serde::de::DeserializeOwned {
    fn to_bytes(&self) -> Vec<u8>;
    fn sign(&self, data_hash: &[u8]) -> Result<MessageSignature, &'static str>;
}

pub trait Address: Clone + fmt::Debug + fmt::Display {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_string(from: &str) -> Option<Self>
    where
        Self: Sized;
    fn is_burn(&self) -> bool;
}

// sliding burnchain window over which a miner's past block-commit payouts will be used to weight
// its current block-commit in a sortition.
// This is the value used in epoch 2.x
pub const MINING_COMMITMENT_WINDOW: u8 = 6;

// how often a miner must commit in its mining commitment window in order to even be considered for
// sortition.
// Only relevant for Nakamoto (epoch 3.x)
pub const MINING_COMMITMENT_FREQUENCY_NAKAMOTO: u8 = 3;

#[repr(u32)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Copy, Serialize, Deserialize)]
pub enum StacksEpochId {
    Epoch10 = 0x01000,
    Epoch20 = 0x02000,
    Epoch2_05 = 0x02005,
    Epoch21 = 0x0200a,
    Epoch22 = 0x0200f,
    Epoch23 = 0x02014,
    Epoch24 = 0x02019,
    Epoch25 = 0x0201a,
    Epoch30 = 0x03000,
    Epoch31 = 0x03001,
}

#[derive(Debug)]
pub enum MempoolCollectionBehavior {
    ByStacksHeight,
    ByReceiveTime,
}

/// Struct describing an interval of time (measured in burnchain blocks) during which a coinbase is
/// allotted.  Applies to SIP-029 code paths and later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoinbaseInterval {
    /// amount of uSTX to award
    pub coinbase: u128,
    /// height of the chain after Stacks chain genesis at which this coinbase interval starts
    pub effective_start_height: u64,
}

// From SIP-029:
//
// | Coinbase Interval  | Bitcoin Height | Offset Height       | Approx. Supply   | STX Reward | Annual Inflation |
// |--------------------|----------------|---------------------|------------------|------------|------------------|
// | Current            | -              | -                   | 1,552,452,847    | 1000       | -                |
// | 1st                |   945,000      |   278,950           | 1,627,352,847    | 500 (50%)  | 3.23%            |
// | 2nd                | 1,050,000      |   383,950           | 1,679,852,847    | 250 (50%)  | 1.57%            |
// | 3rd                | 1,260,000      |   593,950           | 1,732,352,847    | 125 (50%)  | 0.76%            |
// | 4th                | 1,470,000      |   803,950           | 1,758,602,847    | 62.5 (50%) | 0.37%            |
// | -                  | 2,197,560      | 1,531,510           | 1,804,075,347    | 62.5 (0%)  | 0.18%            |
//
// The above is for mainnet, which has a burnchain year of 52596 blocks and starts at burnchain height 666050.

/// Mainnet coinbase intervals, as of SIP-029
pub static COINBASE_INTERVALS_MAINNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 278_950,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 383_950,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 593_950,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 803_950,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

/// Testnet coinbase intervals, as of SIP-029
pub static COINBASE_INTERVALS_TESTNET: LazyLock<[CoinbaseInterval; 5]> = LazyLock::new(|| {
    let emissions_schedule = [
        CoinbaseInterval {
            coinbase: 1_000 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 0,
        },
        CoinbaseInterval {
            coinbase: 500 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777,
        },
        CoinbaseInterval {
            coinbase: 250 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 7,
        },
        CoinbaseInterval {
            coinbase: 125 * u128::from(MICROSTACKS_PER_STACKS),
            effective_start_height: 77_777 * 14,
        },
        CoinbaseInterval {
            coinbase: (625 * u128::from(MICROSTACKS_PER_STACKS)) / 10,
            effective_start_height: 77_777 * 21,
        },
    ];
    assert!(CoinbaseInterval::check_order(&emissions_schedule));
    emissions_schedule
});

/// Used for testing to substitute a coinbase schedule
#[cfg(any(test, feature = "testing"))]
pub static COINBASE_INTERVALS_TEST: std::sync::Mutex<Option<Vec<CoinbaseInterval>>> =
    std::sync::Mutex::new(None);

#[cfg(any(test, feature = "testing"))]
pub fn set_test_coinbase_schedule(coinbase_schedule: Option<Vec<CoinbaseInterval>>) {
    match COINBASE_INTERVALS_TEST.lock() {
        Ok(mut schedule_guard) => {
            *schedule_guard = coinbase_schedule;
        }
        Err(_e) => {
            panic!("COINBASE_INTERVALS_TEST mutex poisoned");
        }
    }
}

impl CoinbaseInterval {
    /// Look up the value of a coinbase at an effective height.
    /// Precondition: `intervals` must be sorted in ascending order by `effective_start_height`
    pub fn get_coinbase_at_effective_height(
        intervals: &[CoinbaseInterval],
        effective_height: u64,
    ) -> u128 {
        if intervals.is_empty() {
            return 0;
        }
        if intervals.len() == 1 {
            if intervals[0].effective_start_height <= effective_height {
                return intervals[0].coinbase;
            } else {
                return 0;
            }
        }

        for i in 0..(intervals.len() - 1) {
            if intervals[i].effective_start_height <= effective_height
                && effective_height < intervals[i + 1].effective_start_height
            {
                return intervals[i].coinbase;
            }
        }

        // in last interval, which per the above checks is guaranteed to exist
        intervals.last().unwrap_or_else(|| unreachable!()).coinbase
    }

    /// Verify that a list of intervals is sorted in ascending order by `effective_start_height`
    pub fn check_order(intervals: &[CoinbaseInterval]) -> bool {
        if intervals.len() < 2 {
            return true;
        }

        let mut ht = intervals[0].effective_start_height;
        for interval in intervals.iter().skip(1) {
            if interval.effective_start_height < ht {
                return false;
            }
            ht = interval.effective_start_height;
        }
        true
    }
}

impl StacksEpochId {
    pub fn latest() -> StacksEpochId {
        StacksEpochId::Epoch31
    }

    /// In this epoch, how should the mempool perform garbage collection?
    pub fn mempool_garbage_behavior(&self) -> MempoolCollectionBehavior {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => MempoolCollectionBehavior::ByStacksHeight,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => {
                MempoolCollectionBehavior::ByReceiveTime
            }
        }
    }

    /// Returns whether or not this Epoch should perform
    ///  memory checks during analysis
    pub fn analysis_memory(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24 => false,
            StacksEpochId::Epoch25 | StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => true,
        }
    }

    /// Returns whether or not this Epoch should perform
    ///  Clarity value sanitization
    pub fn value_sanitizing(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23 => false,
            StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31 => true,
        }
    }

    /// Whether or not this epoch supports the punishment of PoX reward
    /// recipients using the bitvec scheme
    pub fn allows_pox_punishment(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => false,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => true,
        }
    }

    /// Whether or not this epoch interprets block commit OPs block hash field
    ///  as a new block hash or the StacksBlockId of a new tenure's parent tenure.
    pub fn block_commits_to_parent(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => false,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => true,
        }
    }

    /// Whether or not this epoch supports shadow blocks
    pub fn supports_shadow_blocks(&self) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => false,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => true,
        }
    }

    /// Does this epoch support unlocking PoX contributors that miss a slot?
    ///
    /// Epoch 2.0 - 2.05 didn't support this feature, but they weren't epoch-guarded on it. Instead,
    ///  the behavior never activates in those epochs because the Pox1 contract does not provide
    ///  `contibuted_stackers` information. This check maintains that exact semantics by returning
    ///  true for all epochs before 2.5. For 2.5 and after, this returns false.
    pub fn supports_pox_missed_slot_unlocks(&self) -> bool {
        self < &StacksEpochId::Epoch25
    }

    /// What is the sortition mining commitment window for this epoch?
    pub fn mining_commitment_window(&self) -> u8 {
        MINING_COMMITMENT_WINDOW
    }

    /// How often must a miner mine in order to be considered for sortition in its commitment
    /// window?
    pub fn mining_commitment_frequency(&self) -> u8 {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => 0,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => MINING_COMMITMENT_FREQUENCY_NAKAMOTO,
        }
    }

    /// Returns true for epochs which use Nakamoto blocks. These blocks use a
    /// different header format than the previous Stacks blocks, which among
    /// other changes includes a Stacks-specific timestamp.
    pub fn uses_nakamoto_blocks(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Returns whether or not this epoch uses the tip for reading burn block
    /// info in Clarity (3.0+ behavior) or should use the parent block's burn
    /// block (behavior before 3.0).
    pub fn clarity_uses_tip_burn_block(&self) -> bool {
        self >= &StacksEpochId::Epoch30
    }

    /// Does this epoch use the nakamoto reward set, or the epoch2 reward set?
    /// We use the epoch2 reward set in all pre-3.0 epochs.
    /// We also use the epoch2 reward set in the first 3.0 reward cycle.
    /// After that, we use the nakamoto reward set.
    pub fn uses_nakamoto_reward_set(
        &self,
        cur_reward_cycle: u64,
        first_epoch30_reward_cycle: u64,
    ) -> bool {
        match self {
            StacksEpochId::Epoch10
            | StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25 => false,
            StacksEpochId::Epoch30 | StacksEpochId::Epoch31 => {
                cur_reward_cycle > first_epoch30_reward_cycle
            }
        }
    }

    /// What is the coinbase (in uSTX) to award for the given burnchain height?
    /// Applies prior to SIP-029
    fn coinbase_reward_pre_sip029(
        &self,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        /*
        From https://forum.stacks.org/t/pox-consensus-and-stx-future-supply

        """

        1000 STX for years 0-4
        500 STX for years 4-8
        250 STX for years 8-12
        125 STX in perpetuity


        From the Token Whitepaper:

        We expect that once native mining goes live, approximately 4383 blocks will be pro-
        cessed per month, or approximately 52,596 blocks will be processed per year.

        """
        */
        // this is saturating subtraction for the initial reward calculation
        //   where we are computing the coinbase reward for blocks that occur *before*
        //   the `first_burn_block_height`
        let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
        let blocks_per_year = 52596;
        let stx_reward = if effective_ht < blocks_per_year * 4 {
            1000
        } else if effective_ht < blocks_per_year * 8 {
            500
        } else if effective_ht < blocks_per_year * 12 {
            250
        } else {
            125
        };

        stx_reward * (u128::from(MICROSTACKS_PER_STACKS))
    }

    /// Get the coinbase intervals to use.
    /// Can be overriden by tests
    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
        match COINBASE_INTERVALS_TEST.lock() {
            Ok(schedule_opt) => {
                if let Some(schedule) = (*schedule_opt).as_ref() {
                    info!("Use overridden coinbase schedule {:?}", &schedule);
                    return schedule.clone();
                }
            }
            Err(_e) => {
                panic!("COINBASE_INTERVALS_TEST mutex poisoned");
            }
        }

        if mainnet {
            COINBASE_INTERVALS_MAINNET.to_vec()
        } else {
            COINBASE_INTERVALS_TESTNET.to_vec()
        }
    }

    #[cfg(not(any(test, feature = "testing")))]
    pub(crate) fn get_coinbase_intervals(mainnet: bool) -> Vec<CoinbaseInterval> {
        if mainnet {
            COINBASE_INTERVALS_MAINNET.to_vec()
        } else {
            COINBASE_INTERVALS_TESTNET.to_vec()
        }
    }

    /// what are the offsets after chain-start when coinbase reductions occur?
    /// Applies at and after SIP-029.
    /// Uses coinbase intervals defined by COINBASE_INTERVALS_MAINNET, unless overridden by a unit
    /// or integration test.
    fn coinbase_reward_sip029(
        &self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        let effective_ht = current_burnchain_height.saturating_sub(first_burnchain_height);
        let coinbase_intervals = Self::get_coinbase_intervals(mainnet);
        CoinbaseInterval::get_coinbase_at_effective_height(&coinbase_intervals, effective_ht)
    }

    /// What is the coinbase to award?
    pub fn coinbase_reward(
        &self,
        mainnet: bool,
        first_burnchain_height: u64,
        current_burnchain_height: u64,
    ) -> u128 {
        match self {
            StacksEpochId::Epoch10 => {
                // Stacks is not active
                0
            }
            StacksEpochId::Epoch20
            | StacksEpochId::Epoch2_05
            | StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30 => {
                self.coinbase_reward_pre_sip029(first_burnchain_height, current_burnchain_height)
            }
            StacksEpochId::Epoch31 => self.coinbase_reward_sip029(
                mainnet,
                first_burnchain_height,
                current_burnchain_height,
            ),
        }
    }
}

impl std::fmt::Display for StacksEpochId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StacksEpochId::Epoch10 => write!(f, "1.0"),
            StacksEpochId::Epoch20 => write!(f, "2.0"),
            StacksEpochId::Epoch2_05 => write!(f, "2.05"),
            StacksEpochId::Epoch21 => write!(f, "2.1"),
            StacksEpochId::Epoch22 => write!(f, "2.2"),
            StacksEpochId::Epoch23 => write!(f, "2.3"),
            StacksEpochId::Epoch24 => write!(f, "2.4"),
            StacksEpochId::Epoch25 => write!(f, "2.5"),
            StacksEpochId::Epoch30 => write!(f, "3.0"),
            StacksEpochId::Epoch31 => write!(f, "3.1"),
        }
    }
}

impl TryFrom<u32> for StacksEpochId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<StacksEpochId, Self::Error> {
        match value {
            x if x == StacksEpochId::Epoch10 as u32 => Ok(StacksEpochId::Epoch10),
            x if x == StacksEpochId::Epoch20 as u32 => Ok(StacksEpochId::Epoch20),
            x if x == StacksEpochId::Epoch2_05 as u32 => Ok(StacksEpochId::Epoch2_05),
            x if x == StacksEpochId::Epoch21 as u32 => Ok(StacksEpochId::Epoch21),
            x if x == StacksEpochId::Epoch22 as u32 => Ok(StacksEpochId::Epoch22),
            x if x == StacksEpochId::Epoch23 as u32 => Ok(StacksEpochId::Epoch23),
            x if x == StacksEpochId::Epoch24 as u32 => Ok(StacksEpochId::Epoch24),
            x if x == StacksEpochId::Epoch25 as u32 => Ok(StacksEpochId::Epoch25),
            x if x == StacksEpochId::Epoch30 as u32 => Ok(StacksEpochId::Epoch30),
            x if x == StacksEpochId::Epoch31 as u32 => Ok(StacksEpochId::Epoch31),
            _ => Err("Invalid epoch"),
        }
    }
}

impl PartialOrd for StacksAddress {
    fn partial_cmp(&self, other: &StacksAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StacksAddress {
    fn cmp(&self, other: &StacksAddress) -> Ordering {
        match self.version.cmp(&other.version) {
            Ordering::Equal => self.bytes.cmp(&other.bytes),
            inequality => inequality,
        }
    }
}

impl StacksAddress {
    pub fn new(version: u8, hash: Hash160) -> StacksAddress {
        StacksAddress {
            version,
            bytes: hash,
        }
    }

    pub fn is_mainnet(&self) -> bool {
        match self.version {
            C32_ADDRESS_VERSION_MAINNET_MULTISIG | C32_ADDRESS_VERSION_MAINNET_SINGLESIG => true,
            C32_ADDRESS_VERSION_TESTNET_MULTISIG | C32_ADDRESS_VERSION_TESTNET_SINGLESIG => false,
            _ => false,
        }
    }

    pub fn burn_address(mainnet: bool) -> StacksAddress {
        StacksAddress {
            version: if mainnet {
                C32_ADDRESS_VERSION_MAINNET_SINGLESIG
            } else {
                C32_ADDRESS_VERSION_TESTNET_SINGLESIG
            },
            bytes: Hash160([0u8; 20]),
        }
    }

    /// Generate an address from a given address hash mode, signature threshold, and list of public
    /// keys.  Only return an address if the combination given is supported.
    /// The version is may be arbitrary.
    pub fn from_public_keys(
        version: u8,
        hash_mode: &AddressHashMode,
        num_sigs: usize,
        pubkeys: &Vec<StacksPublicKey>,
    ) -> Option<StacksAddress> {
        // must be sufficient public keys
        if pubkeys.len() < num_sigs {
            return None;
        }

        // address hash mode must be consistent with the number of keys
        match *hash_mode {
            AddressHashMode::SerializeP2PKH | AddressHashMode::SerializeP2WPKH => {
                // must be a single public key, and must require one signature
                if num_sigs != 1 || pubkeys.len() != 1 {
                    return None;
                }
            }
            _ => {}
        }

        // if segwit, then keys must all be compressed
        match *hash_mode {
            AddressHashMode::SerializeP2WPKH | AddressHashMode::SerializeP2WSH => {
                for pubkey in pubkeys {
                    if !pubkey.compressed() {
                        return None;
                    }
                }
            }
            _ => {}
        }

        let hash_bits = public_keys_to_address_hash(hash_mode, num_sigs, pubkeys);
        Some(StacksAddress::new(version, hash_bits))
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh(mainnet: bool, pubkey: &StacksPublicKey) -> StacksAddress {
        let bytes = to_bits_p2pkh(pubkey);
        Self::p2pkh_from_hash(mainnet, bytes)
    }

    /// Make a P2PKH StacksAddress
    pub fn p2pkh_from_hash(mainnet: bool, hash: Hash160) -> StacksAddress {
        let version = if mainnet {
            C32_ADDRESS_VERSION_MAINNET_SINGLESIG
        } else {
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG
        };
        Self {
            version,
            bytes: hash,
        }
    }
}

impl std::fmt::Display for StacksAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        c32_address(self.version, self.bytes.as_bytes())
            .expect("Stacks version is not C32-encodable")
            .fmt(f)
    }
}

impl Address for StacksAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.as_bytes().to_vec()
    }

    fn from_string(s: &str) -> Option<StacksAddress> {
        let (version, bytes) = c32_address_decode(s).ok()?;

        if bytes.len() != 20 {
            return None;
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&bytes[..]);
        Some(StacksAddress {
            version,
            bytes: Hash160(hash_bytes),
        })
    }

    fn is_burn(&self) -> bool {
        self.bytes == Hash160([0u8; 20])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct StacksEpoch<L> {
    pub epoch_id: StacksEpochId,
    pub start_height: u64,
    pub end_height: u64,
    pub block_limit: L,
    pub network_epoch: u8,
}

impl<L> StacksEpoch<L> {
    /// Determine which epoch, if any, in a list of epochs, a given burnchain height falls into.
    /// Returns Some(index) if there is such an epoch in the list.
    /// Returns None if not.
    pub fn find_epoch(epochs: &[StacksEpoch<L>], height: u64) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.start_height <= height && height < epoch.end_height {
                return Some(i);
            }
        }
        None
    }

    /// Find an epoch by its ID
    /// Returns Some(index) if the epoch is in the list
    /// Returns None if not
    pub fn find_epoch_by_id(epochs: &[StacksEpoch<L>], epoch_id: StacksEpochId) -> Option<usize> {
        for (i, epoch) in epochs.iter().enumerate() {
            if epoch.epoch_id == epoch_id {
                return Some(i);
            }
        }
        None
    }
}

// StacksEpochs are ordered by start block height
impl<L: PartialEq> PartialOrd for StacksEpoch<L> {
    fn partial_cmp(&self, other: &StacksEpoch<L>) -> Option<Ordering> {
        self.epoch_id.partial_cmp(&other.epoch_id)
    }
}

impl<L: PartialEq + Eq> Ord for StacksEpoch<L> {
    fn cmp(&self, other: &StacksEpoch<L>) -> Ordering {
        self.epoch_id.cmp(&other.epoch_id)
    }
}

/// A wrapper for holding a list of Epochs, indexable by StacksEpochId
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct EpochList<L: Clone>(Vec<StacksEpoch<L>>);

impl<L: Clone> EpochList<L> {
    pub fn new(epochs: &[StacksEpoch<L>]) -> EpochList<L> {
        EpochList(epochs.to_vec())
    }

    pub fn get(&self, index: StacksEpochId) -> Option<&StacksEpoch<L>> {
        self.0.get(StacksEpoch::find_epoch_by_id(&self.0, index)?)
    }

    pub fn get_mut(&mut self, index: StacksEpochId) -> Option<&mut StacksEpoch<L>> {
        let index = StacksEpoch::find_epoch_by_id(&self.0, index)?;
        self.0.get_mut(index)
    }

    /// Truncates the list after the given epoch id
    pub fn truncate_after(&mut self, epoch_id: StacksEpochId) {
        if let Some(index) = StacksEpoch::find_epoch_by_id(&self.0, epoch_id) {
            self.0.truncate(index + 1);
        }
    }

    /// Determine which epoch, if any, a given burnchain height falls into.
    pub fn epoch_id_at_height(&self, height: u64) -> Option<StacksEpochId> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].epoch_id)
    }

    /// Determine which epoch, if any, a given burnchain height falls into.
    pub fn epoch_at_height(&self, height: u64) -> Option<StacksEpoch<L>> {
        StacksEpoch::find_epoch(self, height).map(|idx| self.0[idx].clone())
    }

    /// Pushes a new `StacksEpoch` to the end of the list
    pub fn push(&mut self, epoch: StacksEpoch<L>) {
        if let Some(last) = self.0.last() {
            assert!(
                epoch.start_height == last.end_height && epoch.epoch_id > last.epoch_id,
                "Epochs must be pushed in order"
            );
        }
        self.0.push(epoch);
    }

    pub fn to_vec(&self) -> Vec<StacksEpoch<L>> {
        self.0.clone()
    }
}

impl<L: Clone> Index<StacksEpochId> for EpochList<L> {
    type Output = StacksEpoch<L>;
    fn index(&self, index: StacksEpochId) -> &StacksEpoch<L> {
        self.get(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> IndexMut<StacksEpochId> for EpochList<L> {
    fn index_mut(&mut self, index: StacksEpochId) -> &mut StacksEpoch<L> {
        self.get_mut(index)
            .expect("Invalid StacksEpochId: could not find corresponding epoch")
    }
}

impl<L: Clone> Deref for EpochList<L> {
    type Target = [StacksEpoch<L>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: Clone> DerefMut for EpochList<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
