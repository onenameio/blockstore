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

#![forbid(missing_docs)]
/*!
# libsigner: a library for creating and operating a Stacks Nakamato compliant signer.

Usage documentation can be found in the [README](https://github.com/stacks-network/stacks-blockchain/libsigner/README.md).
*/

#![allow(unused_imports)]
#![allow(dead_code)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate stacks_common;
extern crate clarity;
extern crate libc;

#[cfg(test)]
mod tests;

mod error;
mod events;
mod http;
mod runloop;
mod session;
mod signer_set;
/// v0 signer related code
pub mod v0;

use std::cmp::Eq;
use std::fmt::Debug;
use std::hash::Hash;

use blockstack_lib::version_string;
use clarity::codec::StacksMessageCodec;
use clarity::vm::types::QualifiedContractIdentifier;
use lazy_static::lazy_static;
use stacks_common::util::versions::get_long_version;


pub use crate::error::{EventError, RPCError};
pub use crate::events::{
    BlockProposal, EventReceiver, EventStopSignaler, SignerEvent, SignerEventReceiver,
    SignerEventTrait, SignerStopSignaler,
};
pub use crate::runloop::{RunningSigner, Signer, SignerRunLoop};
pub use crate::session::{SignerSession, StackerDBSession};
pub use crate::signer_set::{Error as ParseSignerEntriesError, SignerEntries};

/// A trait for message slots used for signer communication
pub trait MessageSlotID: Sized + Eq + Hash + Debug + Copy {
    /// The contract identifier for the message slot in stacker db
    fn stacker_db_contract(&self, mainnet: bool, reward_cycle: u64) -> QualifiedContractIdentifier;
    /// All possible Message Slot values
    fn all() -> &'static [Self];
}

/// A trait for signer messages used in signer communciation
pub trait SignerMessage<T: MessageSlotID>: StacksMessageCodec {
    /// The contract identifier for the message slot in stacker db
    fn msg_id(&self) -> Option<T>;
}

lazy_static! {
    /// The version string for the signer
    pub static ref VERSION_STRING: String = {
        get_long_version("stacks-signer")
    };
}
