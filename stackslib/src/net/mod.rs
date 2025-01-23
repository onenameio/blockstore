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

#[warn(unused_imports)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::io::prelude::*;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::{error, fmt, io};

use clarity::vm::analysis::contract_interface_builder::ContractInterface;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::errors::Error as InterpreterError;
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, TraitIdentifier,
};
use clarity::vm::{ClarityName, ContractName, Value};
use libstackerdb::{
    Error as libstackerdb_error, SlotMetadata, StackerDBChunkAckData, StackerDBChunkData,
};
use rand::{thread_rng, RngCore};
use regex::Regex;
use rusqlite::types::{ToSql, ToSqlOutput};
use serde::de::Error as de_Error;
use serde::ser::Error as ser_Error;
use serde::{Deserialize, Serialize};
use stacks_common::bitvec::BitVec;
use stacks_common::codec::{
    read_next, write_next, Error as codec_error, StacksMessageCodec,
    BURNCHAIN_HEADER_HASH_ENCODED_SIZE,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, PoxId, StacksAddress, StacksBlockId,
};
use stacks_common::types::net::{Error as AddrError, PeerAddress, PeerHost};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{
    hex_bytes, to_hex, Hash160, Sha256Sum, DOUBLE_SHA256_ENCODED_SIZE, HASH160_ENCODED_SIZE,
};
use stacks_common::util::secp256k1::{
    MessageSignature, Secp256k1PublicKey, MESSAGE_SIGNATURE_ENCODED_SIZE,
};
use stacks_common::util::{get_epoch_time_secs, log};
use {rusqlite, serde_json, url};

use self::dns::*;
use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::{Error as burnchain_error, Txid};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::{ConsensusHash, Opcodes};
use crate::chainstate::coordinator::comm::CoordinatorChannels;
use crate::chainstate::coordinator::Error as coordinator_error;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::boot::{
    BOOT_TEST_POX_4_AGG_KEY_CONTRACT, BOOT_TEST_POX_4_AGG_KEY_FNAME,
};
use crate::chainstate::stacks::db::blocks::MemPoolRejection;
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::Error as marf_error;
use crate::chainstate::stacks::{
    Error as chainstate_error, Error as chain_error, StacksBlock, StacksBlockHeader,
    StacksMicroblock, StacksPublicKey, StacksTransaction, TransactionPayload,
};
use crate::clarity_vm::clarity::Error as clarity_error;
use crate::core::mempool::*;
use crate::core::{StacksEpoch, POX_REWARD_CYCLE_LENGTH};
use crate::cost_estimates::metrics::CostMetric;
use crate::cost_estimates::{CostEstimator, FeeEstimator, FeeRateEstimate};
use crate::net::atlas::{Attachment, AttachmentInstance};
use crate::net::dns::*;
use crate::net::http::error::{HttpNotFound, HttpServerError};
use crate::net::http::{
    Error as HttpErr, HttpRequestContents, HttpRequestPreamble, HttpResponsePreamble,
};
use crate::net::httpcore::{
    HttpRequestContentsExtensions, StacksHttp, StacksHttpRequest, StacksHttpResponse, TipRequest,
};
use crate::net::p2p::{PeerNetwork, PendingMessages};
use crate::util_lib::bloom::{BloomFilter, BloomNodeHasher};
use crate::util_lib::boot::boot_code_tx_auth;
use crate::util_lib::db::{DBConn, Error as db_error};
use crate::util_lib::strings::UrlString;

/// Implements RPC API
pub mod api;
/// Implements `ASEntry4` object, which is used in db.rs to store the AS number of an IP address.
pub mod asn;
/// Implements the Atlas network. This network uses the infrastructure created in `src/net` to
/// discover peers, query attachment inventories, and download attachments.
pub mod atlas;
/// Implements the `ConversationP2P` object, a host-to-host session abstraction which allows
/// the node to recieve `StacksMessage` instances. The downstream consumer of this API is `PeerNetwork`.
/// To use OSI terminology, this module implements the session & presentation layers of the P2P network.
/// Other functionality includes (but is not limited to):
///     * set up & tear down of sessions
///     * dealing with and responding to invalid messages
///     * rate limiting messages
pub mod chat;
/// Implements serialization and deserialization for `StacksMessage` types.
/// Also has functionality to sign, verify, and ensure well-formedness of messages.
pub mod codec;
pub mod connection;
pub mod db;
/// Implements `DNSResolver`, a simple DNS resolver state machine. Also implements `DNSClient`,
/// which serves as an API for `DNSResolver`.
pub mod dns;
pub mod download;
pub mod http;
/// Links http crate to Stacks
pub mod httpcore;
pub mod inv;
pub mod mempool;
pub mod neighbors;
pub mod p2p;
/// Implements wrapper around `mio` crate, which itself is a wrapper around Linux's `epoll(2)` syscall.
/// Creates a pollable interface for sockets, and provides an API for registering and deregistering
/// sockets. This is used to control how many sockets are allocated for the two network servers: the
/// p2p server and the http server.
pub mod poll;
pub mod prune;
pub mod relay;
pub mod rpc;
pub mod server;
pub mod stackerdb;
pub mod unsolicited;

pub use crate::net::neighbors::{NeighborComms, PeerNetworkComms};
use crate::net::stackerdb::{StackerDBConfig, StackerDBSync, StackerDBSyncResult, StackerDBs};

#[cfg(test)]
pub mod tests;

#[derive(Debug)]
pub enum Error {
    /// Failed to encode
    SerializeError(String),
    /// Failed to read
    ReadError(io::Error),
    /// Failed to decode
    DeserializeError(String),
    /// Failed to write
    WriteError(io::Error),
    /// Underflow -- not enough bytes to form the message
    UnderflowError(String),
    /// Overflow -- message too big
    OverflowError(String),
    /// Wrong protocol family
    WrongProtocolFamily,
    /// Array is too big
    ArrayTooLong,
    /// Receive timed out
    RecvTimeout,
    /// Error signing a message
    SigningError(String),
    /// Error verifying a message
    VerifyingError(String),
    /// Read stream is drained.  Try again
    TemporarilyDrained,
    /// Read stream has reached EOF (socket closed, end-of-file reached, etc.)
    PermanentlyDrained,
    /// Failed to read from the FS
    FilesystemError,
    /// Database error
    DBError(db_error),
    /// Socket mutex was poisoned
    SocketMutexPoisoned,
    /// Socket not instantiated
    SocketNotConnectedToPeer,
    /// Not connected to peer
    ConnectionBroken,
    /// Connection could not be (re-)established
    ConnectionError,
    /// Too many outgoing messages
    OutboxOverflow,
    /// Too many incoming messages
    InboxOverflow,
    /// Send error
    SendError(String),
    /// Recv error
    RecvError(String),
    /// Invalid message
    InvalidMessage,
    /// Invalid network handle
    InvalidHandle,
    /// Network handle is full
    FullHandle,
    /// Invalid handshake
    InvalidHandshake,
    /// Stale neighbor
    StaleNeighbor,
    /// No such neighbor
    NoSuchNeighbor,
    /// Failed to bind
    BindError,
    /// Failed to poll
    PollError,
    /// Failed to accept
    AcceptError,
    /// Failed to register socket with poller
    RegisterError,
    /// Failed to query socket metadata
    SocketError,
    /// server is not bound to a socket
    NotConnected,
    /// Remote peer is not connected
    PeerNotConnected,
    /// Too many peers
    TooManyPeers,
    /// Peer already connected
    AlreadyConnected(usize, NeighborKey),
    /// Message already in progress
    InProgress,
    /// Peer is denied
    Denied,
    /// Data URL is not known
    NoDataUrl,
    /// Peer is transmitting too fast
    PeerThrottled,
    /// Error resolving a DNS name
    LookupError(String),
    /// MARF error, percolated up from chainstate
    MARFError(marf_error),
    /// Clarity VM error, percolated up from chainstate
    ClarityError(clarity_error),
    /// Catch-all for chainstate errors that don't map cleanly into network errors
    ChainstateError(String),
    /// Coordinator hung up
    CoordinatorClosed,
    /// view of state is stale (e.g. from the sortition db)
    StaleView,
    /// Tried to connect to myself
    ConnectionCycle,
    /// Requested data not found
    NotFoundError,
    /// Transient error (akin to EAGAIN)
    Transient(String),
    /// Expected end-of-stream, but had more data
    ExpectedEndOfStream,
    /// burnchain error
    BurnchainError(burnchain_error),
    /// chunk is stale
    StaleChunk {
        supplied_version: u32,
        latest_version: u32,
    },
    /// no such slot
    NoSuchSlot(QualifiedContractIdentifier, u32),
    /// no such DB
    NoSuchStackerDB(QualifiedContractIdentifier),
    /// stacker DB exists
    StackerDBExists(QualifiedContractIdentifier),
    /// slot signer is wrong
    BadSlotSigner(StacksAddress, u32),
    /// too many writes to a slot
    TooManySlotWrites {
        supplied_version: u32,
        max_writes: u32,
    },
    /// too frequent writes to a slot
    TooFrequentSlotWrites(u64),
    /// Invalid control smart contract for a Stacker DB
    InvalidStackerDBContract(QualifiedContractIdentifier, String),
    /// state machine step took too long
    StepTimeout,
    /// stacker DB chunk is too big
    StackerDBChunkTooBig(usize),
    /// HTTP error
    Http(HttpErr),
    /// Invalid state machine state reached
    InvalidState,
    /// Waiting for DNS resolution
    WaitingForDNS,
    /// No reward set for given reward cycle
    NoPoXRewardSet(u64),
}

impl From<libstackerdb_error> for Error {
    fn from(e: libstackerdb_error) -> Self {
        match e {
            libstackerdb_error::SigningError(s) => Error::SigningError(s),
            libstackerdb_error::VerifyingError(s) => Error::VerifyingError(s),
        }
    }
}

impl From<codec_error> for Error {
    fn from(e: codec_error) -> Self {
        match e {
            codec_error::SerializeError(s) => Error::SerializeError(s),
            codec_error::ReadError(e) => Error::ReadError(e),
            codec_error::DeserializeError(s) => Error::DeserializeError(s),
            codec_error::WriteError(e) => Error::WriteError(e),
            codec_error::UnderflowError(s) => Error::UnderflowError(s),
            codec_error::OverflowError(s) => Error::OverflowError(s),
            codec_error::ArrayTooLong => Error::ArrayTooLong,
            codec_error::SigningError(s) => Error::SigningError(s),
            codec_error::GenericError(_) => Error::InvalidMessage,
        }
    }
}

impl From<HttpErr> for Error {
    fn from(e: HttpErr) -> Error {
        Error::Http(e)
    }
}

impl From<AddrError> for Error {
    fn from(e: AddrError) -> Error {
        match e {
            AddrError::DecodeError(s) => Error::DeserializeError(s),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::SerializeError(ref s) => fmt::Display::fmt(s, f),
            Error::DeserializeError(ref s) => fmt::Display::fmt(s, f),
            Error::ReadError(ref io) => fmt::Display::fmt(io, f),
            Error::WriteError(ref io) => fmt::Display::fmt(io, f),
            Error::UnderflowError(ref s) => fmt::Display::fmt(s, f),
            Error::OverflowError(ref s) => fmt::Display::fmt(s, f),
            Error::WrongProtocolFamily => write!(f, "Improper use of protocol family"),
            Error::ArrayTooLong => write!(f, "Array too long"),
            Error::RecvTimeout => write!(f, "Packet receive timeout"),
            Error::SigningError(ref s) => fmt::Display::fmt(s, f),
            Error::VerifyingError(ref s) => fmt::Display::fmt(s, f),
            Error::TemporarilyDrained => {
                write!(f, "Temporarily out of bytes to read; try again later")
            }
            Error::PermanentlyDrained => write!(f, "Out of bytes to read"),
            Error::FilesystemError => write!(f, "Disk I/O error"),
            Error::DBError(ref e) => fmt::Display::fmt(e, f),
            Error::SocketMutexPoisoned => write!(f, "socket mutex was poisoned"),
            Error::SocketNotConnectedToPeer => write!(f, "not connected to peer"),
            Error::ConnectionBroken => write!(f, "connection to peer node is broken"),
            Error::ConnectionError => write!(f, "connection to peer could not be (re-)established"),
            Error::OutboxOverflow => write!(f, "too many outgoing messages queued"),
            Error::InboxOverflow => write!(f, "too many messages pending"),
            Error::SendError(ref s) => fmt::Display::fmt(s, f),
            Error::RecvError(ref s) => fmt::Display::fmt(s, f),
            Error::InvalidMessage => write!(f, "invalid message (malformed or bad signature)"),
            Error::InvalidHandle => write!(f, "invalid network handle"),
            Error::FullHandle => write!(f, "network handle is full and needs to be drained"),
            Error::InvalidHandshake => write!(f, "invalid handshake from remote peer"),
            Error::StaleNeighbor => write!(f, "neighbor is too far behind the chain tip"),
            Error::NoSuchNeighbor => write!(f, "no such neighbor"),
            Error::BindError => write!(f, "Failed to bind to the given address"),
            Error::PollError => write!(f, "Failed to poll"),
            Error::AcceptError => write!(f, "Failed to accept connection"),
            Error::RegisterError => write!(f, "Failed to register socket with poller"),
            Error::SocketError => write!(f, "Socket error"),
            Error::NotConnected => write!(f, "Not connected to peer network"),
            Error::PeerNotConnected => write!(f, "Remote peer is not connected to us"),
            Error::TooManyPeers => write!(f, "Too many peer connections open"),
            Error::AlreadyConnected(ref _id, ref _nk) => write!(f, "Peer already connected"),
            Error::InProgress => write!(f, "Message already in progress"),
            Error::Denied => write!(f, "Peer is denied"),
            Error::NoDataUrl => write!(f, "No data URL available"),
            Error::PeerThrottled => write!(f, "Peer is transmitting too fast"),
            Error::LookupError(ref s) => fmt::Display::fmt(s, f),
            Error::ChainstateError(ref s) => fmt::Display::fmt(s, f),
            Error::ClarityError(ref e) => fmt::Display::fmt(e, f),
            Error::MARFError(ref e) => fmt::Display::fmt(e, f),
            Error::CoordinatorClosed => write!(f, "Coordinator hung up"),
            Error::StaleView => write!(f, "State view is stale"),
            Error::ConnectionCycle => write!(f, "Tried to connect to myself"),
            Error::NotFoundError => write!(f, "Requested data not found"),
            Error::Transient(ref s) => write!(f, "Transient network error: {}", s),
            Error::ExpectedEndOfStream => write!(f, "Expected end-of-stream"),
            Error::BurnchainError(ref e) => fmt::Display::fmt(e, f),
            Error::StaleChunk {
                supplied_version,
                latest_version,
            } => {
                write!(
                    f,
                    "Stale DB chunk (supplied={},latest={})",
                    supplied_version, latest_version
                )
            }
            Error::NoSuchSlot(ref addr, ref slot_id) => {
                write!(f, "No such DB slot ({},{})", addr, slot_id)
            }
            Error::NoSuchStackerDB(ref addr) => {
                write!(f, "No such StackerDB {}", addr)
            }
            Error::StackerDBExists(ref addr) => {
                write!(f, "StackerDB already exists: {}", addr)
            }
            Error::BadSlotSigner(ref addr, ref slot_id) => {
                write!(f, "Bad DB slot signer ({},{})", addr, slot_id)
            }
            Error::TooManySlotWrites {
                supplied_version,
                max_writes,
            } => {
                write!(
                    f,
                    "Too many slot writes (max={},given={})",
                    max_writes, supplied_version
                )
            }
            Error::TooFrequentSlotWrites(ref deadline) => {
                write!(f, "Too frequent slot writes (deadline={})", deadline)
            }
            Error::InvalidStackerDBContract(ref contract_id, ref reason) => {
                write!(
                    f,
                    "Invalid StackerDB control smart contract {}: {}",
                    contract_id, reason
                )
            }
            Error::StepTimeout => write!(f, "State-machine step took too long"),
            Error::StackerDBChunkTooBig(ref sz) => {
                write!(f, "StackerDB chunk size is too big ({})", sz)
            }
            Error::Http(e) => fmt::Display::fmt(&e, f),
            Error::InvalidState => write!(f, "Invalid state-machine state reached"),
            Error::WaitingForDNS => write!(f, "Waiting for DNS resolution"),
            Error::NoPoXRewardSet(rc) => write!(f, "No PoX reward set for cycle {}", rc),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::SerializeError(ref _s) => None,
            Error::ReadError(ref io) => Some(io),
            Error::DeserializeError(ref _s) => None,
            Error::WriteError(ref io) => Some(io),
            Error::UnderflowError(ref _s) => None,
            Error::OverflowError(ref _s) => None,
            Error::WrongProtocolFamily => None,
            Error::ArrayTooLong => None,
            Error::RecvTimeout => None,
            Error::SigningError(ref _s) => None,
            Error::VerifyingError(ref _s) => None,
            Error::TemporarilyDrained => None,
            Error::PermanentlyDrained => None,
            Error::FilesystemError => None,
            Error::DBError(ref e) => Some(e),
            Error::SocketMutexPoisoned => None,
            Error::SocketNotConnectedToPeer => None,
            Error::ConnectionBroken => None,
            Error::ConnectionError => None,
            Error::OutboxOverflow => None,
            Error::InboxOverflow => None,
            Error::SendError(ref _s) => None,
            Error::RecvError(ref _s) => None,
            Error::InvalidMessage => None,
            Error::InvalidHandle => None,
            Error::FullHandle => None,
            Error::InvalidHandshake => None,
            Error::StaleNeighbor => None,
            Error::NoSuchNeighbor => None,
            Error::BindError => None,
            Error::PollError => None,
            Error::AcceptError => None,
            Error::RegisterError => None,
            Error::SocketError => None,
            Error::NotConnected => None,
            Error::PeerNotConnected => None,
            Error::TooManyPeers => None,
            Error::AlreadyConnected(ref _id, ref _nk) => None,
            Error::InProgress => None,
            Error::Denied => None,
            Error::NoDataUrl => None,
            Error::PeerThrottled => None,
            Error::LookupError(ref _s) => None,
            Error::ChainstateError(ref _s) => None,
            Error::ClarityError(ref e) => Some(e),
            Error::MARFError(ref e) => Some(e),
            Error::CoordinatorClosed => None,
            Error::StaleView => None,
            Error::ConnectionCycle => None,
            Error::NotFoundError => None,
            Error::Transient(ref _s) => None,
            Error::ExpectedEndOfStream => None,
            Error::BurnchainError(ref e) => Some(e),
            Error::StaleChunk { .. } => None,
            Error::NoSuchSlot(..) => None,
            Error::NoSuchStackerDB(..) => None,
            Error::StackerDBExists(..) => None,
            Error::BadSlotSigner(..) => None,
            Error::TooManySlotWrites { .. } => None,
            Error::TooFrequentSlotWrites(..) => None,
            Error::InvalidStackerDBContract(..) => None,
            Error::StepTimeout => None,
            Error::StackerDBChunkTooBig(..) => None,
            Error::Http(ref e) => Some(e),
            Error::InvalidState => None,
            Error::WaitingForDNS => None,
            Error::NoPoXRewardSet(..) => None,
        }
    }
}

impl From<chain_error> for Error {
    fn from(e: chain_error) -> Error {
        match e {
            chain_error::InvalidStacksBlock(s) => {
                Error::ChainstateError(format!("Invalid stacks block: {}", s))
            }
            chain_error::InvalidStacksMicroblock(msg, hash) => {
                Error::ChainstateError(format!("Invalid stacks microblock {:?}: {}", hash, msg))
            }
            chain_error::InvalidStacksTransaction(s, _) => {
                Error::ChainstateError(format!("Invalid stacks transaction: {}", s))
            }
            chain_error::PostConditionFailed(s) => {
                Error::ChainstateError(format!("Postcondition failed: {}", s))
            }
            chain_error::ClarityError(e) => Error::ClarityError(e),
            chain_error::DBError(e) => Error::DBError(e),
            chain_error::NetError(e) => e,
            chain_error::MARFError(e) => Error::MARFError(e),
            chain_error::ReadError(e) => Error::ReadError(e),
            chain_error::WriteError(e) => Error::WriteError(e),
            _ => Error::ChainstateError(format!("Stacks chainstate error: {:?}", &e)),
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        Error::DBError(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        Error::DBError(db_error::SqliteError(e))
    }
}

impl From<burnchain_error> for Error {
    fn from(e: burnchain_error) -> Self {
        Error::BurnchainError(e)
    }
}

impl From<clarity_error> for Error {
    fn from(e: clarity_error) -> Self {
        Error::ClarityError(e)
    }
}

impl From<InterpreterError> for Error {
    fn from(e: InterpreterError) -> Self {
        Error::ClarityError(e.into())
    }
}

#[cfg(test)]
impl PartialEq for Error {
    /// (make I/O errors comparable for testing purposes)
    fn eq(&self, other: &Self) -> bool {
        let s1 = format!("{:?}", self);
        let s2 = format!("{:?}", other);
        s1 == s2
    }
}

/// Extension trait for PeerHost to decode it from a UrlString
pub trait PeerHostExtensions {
    fn try_from_url(url_str: &UrlString) -> Option<PeerHost>;
}

impl PeerHostExtensions for PeerHost {
    fn try_from_url(url_str: &UrlString) -> Option<PeerHost> {
        let url = match url_str.parse_to_block_url() {
            Ok(url) => url,
            Err(_e) => {
                return None;
            }
        };

        let port = match url.port_or_known_default() {
            Some(port) => port,
            None => {
                return None;
            }
        };

        match url.host() {
            Some(url::Host::Domain(name)) => Some(PeerHost::DNS(name.to_string(), port)),
            Some(url::Host::Ipv4(addr)) => Some(PeerHost::from_socketaddr(&SocketAddr::new(
                IpAddr::V4(addr),
                port,
            ))),
            Some(url::Host::Ipv6(addr)) => Some(PeerHost::from_socketaddr(&SocketAddr::new(
                IpAddr::V6(addr),
                port,
            ))),
            None => None,
        }
    }
}

/// Runtime arguments to an RPC handler
#[derive(Default)]
pub struct RPCHandlerArgs<'a> {
    /// What height at which this node will terminate (testnet only)
    pub exit_at_block_height: Option<u64>,
    /// What's the hash of the genesis chainstate?
    pub genesis_chainstate_hash: Sha256Sum,
    /// event observer for the mempool
    pub event_observer: Option<&'a dyn MemPoolEventDispatcher>,
    /// tx runtime cost estimator
    pub cost_estimator: Option<&'a dyn CostEstimator>,
    /// tx fee estimator
    pub fee_estimator: Option<&'a dyn FeeEstimator>,
    /// tx runtime cost metric
    pub cost_metric: Option<&'a dyn CostMetric>,
    /// coordinator channels
    pub coord_comms: Option<&'a CoordinatorChannels>,
}

impl RPCHandlerArgs<'_> {
    pub fn get_estimators_ref(
        &self,
    ) -> Option<(&dyn CostEstimator, &dyn FeeEstimator, &dyn CostMetric)> {
        match (self.cost_estimator, self.fee_estimator, self.cost_metric) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }
}

/// Wrapper around Stacks chainstate data that an HTTP request handler might need
pub struct StacksNodeState<'a> {
    inner_network: Option<&'a mut PeerNetwork>,
    inner_sortdb: Option<&'a SortitionDB>,
    inner_chainstate: Option<&'a mut StacksChainState>,
    inner_mempool: Option<&'a mut MemPoolDB>,
    inner_rpc_args: Option<&'a RPCHandlerArgs<'a>>,
    relay_message: Option<StacksMessageType>,
    /// Are we in Initial Block Download (IBD) phase?
    ibd: bool,
}

impl<'a> StacksNodeState<'a> {
    pub fn new(
        inner_network: &'a mut PeerNetwork,
        inner_sortdb: &'a SortitionDB,
        inner_chainstate: &'a mut StacksChainState,
        inner_mempool: &'a mut MemPoolDB,
        inner_rpc_args: &'a RPCHandlerArgs<'a>,
        ibd: bool,
    ) -> StacksNodeState<'a> {
        StacksNodeState {
            inner_network: Some(inner_network),
            inner_sortdb: Some(inner_sortdb),
            inner_chainstate: Some(inner_chainstate),
            inner_mempool: Some(inner_mempool),
            inner_rpc_args: Some(inner_rpc_args),
            relay_message: None,
            ibd,
        }
    }

    /// Run func() with the inner state
    pub fn with_node_state<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(
            &mut PeerNetwork,
            &SortitionDB,
            &mut StacksChainState,
            &mut MemPoolDB,
            &RPCHandlerArgs<'a>,
        ) -> R,
    {
        let network = self
            .inner_network
            .take()
            .expect("FATAL: network not restored");
        let sortdb = self
            .inner_sortdb
            .take()
            .expect("FATAL: sortdb not restored");
        let chainstate = self
            .inner_chainstate
            .take()
            .expect("FATAL: chainstate not restored");
        let mempool = self
            .inner_mempool
            .take()
            .expect("FATAL: mempool not restored");
        let rpc_args = self
            .inner_rpc_args
            .take()
            .expect("FATAL: rpc args not restored");

        let res = func(network, sortdb, chainstate, mempool, rpc_args);

        self.inner_network = Some(network);
        self.inner_sortdb = Some(sortdb);
        self.inner_chainstate = Some(chainstate);
        self.inner_mempool = Some(mempool);
        self.inner_rpc_args = Some(rpc_args);

        res
    }

    pub fn canonical_stacks_tip_height(&mut self) -> u32 {
        self.with_node_state(|network, _, _, _, _| {
            network.burnchain_tip.canonical_stacks_tip_height as u32
        })
    }

    pub fn set_relay_message(&mut self, msg: StacksMessageType) {
        self.relay_message = Some(msg);
    }

    pub fn take_relay_message(&mut self) -> Option<StacksMessageType> {
        self.relay_message.take()
    }

    /// Load up the canonical Stacks chain tip.  Note that this is subject to both burn chain block
    /// Stacks block availability -- different nodes with different partial replicas of the Stacks chain state
    /// will return different values here.
    ///
    /// # Warn
    /// - There is a potential race condition. If this function is loading the latest unconfirmed
    /// tip, that tip may get invalidated by the time it is used in `maybe_read_only_clarity_tx`,
    /// which is used to load clarity state at a particular tip (which would lead to a 404 error).
    /// If this race condition occurs frequently, we can modify `maybe_read_only_clarity_tx` to
    /// re-load the unconfirmed chain tip. Refer to issue #2997.
    ///
    /// # Inputs
    /// - `tip_req` is given by the HTTP request as the optional query parameter for the chain tip
    /// hash.  It will be UseLatestAnchoredTip if there was no parameter given. If it is set to
    /// `latest`, the parameter will be set to UseLatestUnconfirmedTip.
    ///
    /// Returns the requested chain tip on success.
    /// If the chain tip could not be found, then it returns Err(HttpNotFound)
    /// If there was an error querying the DB, then it returns Err(HttpServerError)
    pub fn load_stacks_chain_tip(
        &mut self,
        preamble: &HttpRequestPreamble,
        contents: &HttpRequestContents,
    ) -> Result<StacksBlockId, StacksHttpResponse> {
        self.with_node_state(|_network, sortdb, chainstate, _mempool, _rpc_args| {
            let tip_req = contents.tip_request();
            match tip_req {
                TipRequest::UseLatestUnconfirmedTip => {
                    let unconfirmed_chain_tip_opt = match &mut chainstate.unconfirmed_state {
                        Some(unconfirmed_state) => {
                            match unconfirmed_state.get_unconfirmed_state_if_exists() {
                                Ok(res) => res,
                                Err(msg) => {
                                    return Err(StacksHttpResponse::new_error(
                                        preamble,
                                        &HttpNotFound::new(format!("No unconfirmed tip: {}", &msg)),
                                    ));
                                }
                            }
                        }
                        None => None,
                    };

                    if let Some(unconfirmed_chain_tip) = unconfirmed_chain_tip_opt {
                        Ok(unconfirmed_chain_tip)
                    } else {
                        match NakamotoChainState::get_canonical_block_header(
                            chainstate.db(),
                            sortdb,
                        ) {
                            Ok(Some(tip)) => Ok(StacksBlockId::new(
                                &tip.consensus_hash,
                                &tip.anchored_header.block_hash(),
                            )),
                            Ok(None) => {
                                return Err(StacksHttpResponse::new_error(
                                    preamble,
                                    &HttpNotFound::new("No such confirmed tip".to_string()),
                                ));
                            }
                            Err(e) => {
                                return Err(StacksHttpResponse::new_error(
                                    preamble,
                                    &HttpServerError::new(format!(
                                        "Failed to load chain tip: {:?}",
                                        &e
                                    )),
                                ));
                            }
                        }
                    }
                }
                TipRequest::SpecificTip(tip) => Ok(tip.clone()),
                TipRequest::UseLatestAnchoredTip => {
                    match NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb) {
                        Ok(Some(tip)) => Ok(StacksBlockId::new(
                            &tip.consensus_hash,
                            &tip.anchored_header.block_hash(),
                        )),
                        Ok(None) => {
                            return Err(StacksHttpResponse::new_error(
                                preamble,
                                &HttpNotFound::new(
                                    "No stacks chain tip exists at this point in time.".to_string(),
                                ),
                            ));
                        }
                        Err(e) => {
                            return Err(StacksHttpResponse::new_error(
                                preamble,
                                &HttpServerError::new(format!(
                                    "Failed to load chain tip: {:?}",
                                    &e
                                )),
                            ));
                        }
                    }
                }
            }
        })
    }
}

pub const STACKS_PUBLIC_KEY_ENCODED_SIZE: u32 = 33;

/// P2P message preamble -- included in all p2p network messages
#[derive(Debug, Clone, PartialEq)]
pub struct Preamble {
    pub peer_version: u32,                           // software version
    pub network_id: u32,                             // mainnet, testnet, etc.
    pub seq: u32, // message sequence number -- pairs this message to a request
    pub burn_block_height: u64, // last-seen block height (at chain tip)
    pub burn_block_hash: BurnchainHeaderHash, // hash of the last-seen burn block
    pub burn_stable_block_height: u64, // latest stable block height (e.g. chain tip minus 7)
    pub burn_stable_block_hash: BurnchainHeaderHash, // latest stable burnchain header hash.
    pub additional_data: u32, // RESERVED; pointer to additional data (should be all 0's if not used)
    pub signature: MessageSignature, // signature from the peer that sent this
    pub payload_len: u32,     // length of the following payload, including relayers vector
}

/// Request for a block inventory or a list of blocks.
/// Aligned to a PoX reward cycle.
/// This struct is used only in Stacks 2.x for Stacks 2.x inventories
#[derive(Debug, Clone, PartialEq)]
pub struct GetBlocksInv {
    /// Consensus hash at thestart of the reward cycle
    pub consensus_hash: ConsensusHash,
    /// Number of sortitions to ask for. Can be up to the reward cycle length.
    pub num_blocks: u16,
}

/// A bit vector that describes which block and microblock data node has data for in a given burn
/// chain block range.  Sent in reply to a GetBlocksInv for Stacks 2.x block data.
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksInvData {
    /// Number of bits in the block bit vector (not to exceed the reward cycle length)
    pub bitlen: u16,
    /// The block bitvector. block_bitvec[i] & (1 << j) != 0 means that this peer has the block for
    /// sortition 8*i + j.
    pub block_bitvec: Vec<u8>,
    /// The microblock bitvector. microblocks_bitvec[i] & (1 << j) != 0 means that this peer has
    /// the microblocks for sortition 8*i + j
    pub microblocks_bitvec: Vec<u8>,
}

/// Request for a tenure inventroy.
/// Aligned to a PoX reward cycle.
/// This struct is used only in Nakamoto, for Nakamoto inventories
#[derive(Debug, Clone, PartialEq)]
pub struct GetNakamotoInvData {
    /// Consensus hash at the start of the reward cycle
    pub consensus_hash: ConsensusHash,
}

/// A bit vector that describes Nakamoto tenure availability.  Sent in reply for GetBlocksInv for
/// Nakamoto block data.  The ith bit in `tenures` will be set if (1) there is a sortition in the
/// ith burnchain block in the requested reward cycle (note that 0 <= i < 2100 in production), and
/// (2) the remote node not only has the tenure blocks, but has processed them.
#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoInvData {
    /// The tenure bitvector.  tenures[i] & (1 << j) != 0 means that this peer has all the blocks
    /// for the tenure which began in sortition 8*i + j.  There will never be more than 1 reward
    /// cycle's worth of bits here, and since the largest supported reward cycle is 2100 blocks
    /// long (i.e. mainnet),
    pub tenures: BitVec<2100>,
}

/// Request for a PoX bitvector range.
/// Requests bits for [start_reward_cycle, start_reward_cycle + num_anchor_blocks)
#[derive(Debug, Clone, PartialEq)]
pub struct GetPoxInv {
    pub consensus_hash: ConsensusHash,
    pub num_cycles: u16, // how many bits to expect
}

/// Response to a GetPoxInv request
#[derive(Debug, Clone, PartialEq)]
pub struct PoxInvData {
    pub bitlen: u16,         // number of bits represented
    pub pox_bitvec: Vec<u8>, // a bit will be '1' if the node knows for sure the status of its reward cycle's anchor block; 0 if not.
}

/// Stacks epoch 2.x pushed block
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksDatum(pub ConsensusHash, pub StacksBlock);

/// Stacks epoch 2.x blocks pushed
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksData {
    pub blocks: Vec<BlocksDatum>,
}

/// Nakamoto epoch 3.x blocks pushed.
/// No need for a separate NakamotoBlocksDatum struct, because the consensus hashes that place this
/// block into the block stream are already embedded within the header
#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoBlocksData {
    pub blocks: Vec<NakamotoBlock>,
}

/// Microblocks pushed
#[derive(Debug, Clone, PartialEq)]
pub struct MicroblocksData {
    pub index_anchor_block: StacksBlockId,
    pub microblocks: Vec<StacksMicroblock>,
}

/// Block available hint
#[derive(Debug, Clone, PartialEq)]
pub struct BlocksAvailableData {
    pub available: Vec<(ConsensusHash, BurnchainHeaderHash)>,
}

/// A descriptor of a peer
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NeighborAddress {
    #[serde(rename = "ip")]
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub public_key_hash: Hash160, // used as a hint; useful for when a node trusts another node to be honest about this
}

impl fmt::Display for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}://{:?}",
            &self.public_key_hash,
            &self.addrbytes.to_socketaddr(self.port)
        )
    }
}

impl fmt::Debug for NeighborAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}://{:?}",
            &self.public_key_hash,
            &self.addrbytes.to_socketaddr(self.port)
        )
    }
}

impl NeighborAddress {
    pub fn clear_public_key(&mut self) {
        self.public_key_hash = Hash160([0u8; 20]);
    }

    pub fn from_neighbor_key(nk: NeighborKey, pkh: Hash160) -> NeighborAddress {
        NeighborAddress {
            addrbytes: nk.addrbytes,
            port: nk.port,
            public_key_hash: pkh,
        }
    }

    pub fn to_socketaddr(&self) -> SocketAddr {
        self.addrbytes.to_socketaddr(self.port)
    }
}

/// A descriptor of a list of known peers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NeighborsData {
    pub neighbors: Vec<NeighborAddress>,
}

/// Handshake request -- this is the first message sent to a peer.
/// The remote peer will reply a HandshakeAccept with just a preamble
/// if the peer accepts.  Otherwise it will get a HandshakeReject with just
/// a preamble.
///
/// To keep peer knowledge fresh, nodes will send handshakes to each other
/// as heartbeat messages.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeData {
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub services: u16, // bit field representing services this node offers
    pub node_public_key: StacksPublicKeyBuffer,
    pub expire_block_height: u64, // burn block height after which this node's key will be revoked,
    pub data_url: UrlString,
}

#[repr(u8)]
pub enum ServiceFlags {
    RELAY = 0x01,
    RPC = 0x02,
    STACKERDB = 0x04,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeAcceptData {
    pub handshake: HandshakeData, // this peer's handshake information
    pub heartbeat_interval: u32,  // hint as to how long this peer will remember you
}

#[derive(Debug, Clone, PartialEq)]
pub struct NackData {
    pub error_code: u32,
}
pub mod NackErrorCodes {
    /// A handshake has not yet been completed with the requester
    /// and it is required before the protocol can proceed
    pub const HandshakeRequired: u32 = 1;
    /// The request depends on a burnchain block that this peer does not recognize
    pub const NoSuchBurnchainBlock: u32 = 2;
    /// The remote peer has exceeded local per-peer bandwidth limits
    pub const Throttled: u32 = 3;
    /// The request depends on a PoX fork that this peer does not recognize as canonical
    pub const InvalidPoxFork: u32 = 4;
    /// The message received is not appropriate for the ongoing step in the protocol being executed
    pub const InvalidMessage: u32 = 5;
    /// The StackerDB requested is not known or configured on this node
    pub const NoSuchDB: u32 = 6;
    /// The StackerDB chunk request referred to an older copy of the chunk than this node has
    pub const StaleVersion: u32 = 7;
    /// The remote peer's view of the burnchain is too out-of-date for the protocol to continue
    pub const StaleView: u32 = 8;
    /// The StackerDB chunk request referred to a newer copy of the chunk that this node has
    pub const FutureVersion: u32 = 9;
    /// The referenced StackerDB state view is stale locally relative to the requested version
    pub const FutureView: u32 = 10;
}

#[derive(Debug, Clone, PartialEq)]
pub struct PingData {
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PongData {
    pub nonce: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NatPunchData {
    pub addrbytes: PeerAddress,
    pub port: u16,
    pub nonce: u32,
}

/// Inform the remote peer of (a page of) the list of stacker DB contracts this node supports
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBHandshakeData {
    /// current reward cycle consensus hash (i.e. the consensus hash of the Stacks tip in the
    /// current reward cycle, which commits to both the Stacks block tip and the underlying PoX
    /// history).
    pub rc_consensus_hash: ConsensusHash,
    /// list of smart contracts that we index.
    /// there can be as many as 256 entries.
    pub smart_contracts: Vec<QualifiedContractIdentifier>,
}

/// Request for a chunk inventory
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBGetChunkInvData {
    /// smart contract being used to determine chunk quantity and order
    pub contract_id: QualifiedContractIdentifier,
    /// consensus hash of the Stacks chain tip in this reward cycle
    pub rc_consensus_hash: ConsensusHash,
}

/// Inventory bitvector for chunks this node contains
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBChunkInvData {
    /// version vector of chunks available.
    /// The max-length is a protocol constant.
    pub slot_versions: Vec<u32>,
    /// number of outbound replicas the sender is connected to
    pub num_outbound_replicas: u32,
}

/// Request for a stacker DB chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBGetChunkData {
    /// smart contract being used to determine slot quantity and order
    pub contract_id: QualifiedContractIdentifier,
    /// consensus hash of the Stacks chain tip in this reward cycle
    pub rc_consensus_hash: ConsensusHash,
    /// slot ID
    pub slot_id: u32,
    /// last-seen slot version
    pub slot_version: u32,
}

/// Stacker DB chunk push
#[derive(Debug, Clone, PartialEq)]
pub struct StackerDBPushChunkData {
    /// smart contract being used to determine chunk quantity and order
    pub contract_id: QualifiedContractIdentifier,
    /// consensus hash of the Stacks chain tip in this reward cycle
    pub rc_consensus_hash: ConsensusHash,
    /// the pushed chunk
    pub chunk_data: StackerDBChunkData,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayData {
    pub peer: NeighborAddress,
    pub seq: u32,
}

/// All P2P message types
#[derive(Debug, Clone, PartialEq)]
pub enum StacksMessageType {
    Handshake(HandshakeData),
    HandshakeAccept(HandshakeAcceptData),
    HandshakeReject,
    GetNeighbors,
    Neighbors(NeighborsData),
    GetBlocksInv(GetBlocksInv),
    BlocksInv(BlocksInvData),
    GetPoxInv(GetPoxInv),
    PoxInv(PoxInvData),
    BlocksAvailable(BlocksAvailableData),
    MicroblocksAvailable(BlocksAvailableData),
    Blocks(BlocksData),
    Microblocks(MicroblocksData),
    Transaction(StacksTransaction),
    Nack(NackData),
    Ping(PingData),
    Pong(PongData),
    NatPunchRequest(u32),
    NatPunchReply(NatPunchData),
    // stacker DB
    StackerDBHandshakeAccept(HandshakeAcceptData, StackerDBHandshakeData),
    StackerDBGetChunkInv(StackerDBGetChunkInvData),
    StackerDBChunkInv(StackerDBChunkInvData),
    StackerDBGetChunk(StackerDBGetChunkData),
    StackerDBChunk(StackerDBChunkData),
    StackerDBPushChunk(StackerDBPushChunkData),
    // Nakamoto-specific
    GetNakamotoInv(GetNakamotoInvData),
    NakamotoInv(NakamotoInvData),
    NakamotoBlocks(NakamotoBlocksData),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StacksMessageID {
    Handshake = 0,
    HandshakeAccept = 1,
    HandshakeReject = 2,
    GetNeighbors = 3,
    Neighbors = 4,
    GetBlocksInv = 5,
    BlocksInv = 6,
    GetPoxInv = 7,
    PoxInv = 8,
    BlocksAvailable = 9,
    MicroblocksAvailable = 10,
    Blocks = 11,
    Microblocks = 12,
    Transaction = 13,
    Nack = 14,
    Ping = 15,
    Pong = 16,
    NatPunchRequest = 17,
    NatPunchReply = 18,
    // stackerdb
    StackerDBHandshakeAccept = 19,
    StackerDBGetChunkInv = 21,
    StackerDBChunkInv = 22,
    StackerDBGetChunk = 23,
    StackerDBChunk = 24,
    StackerDBPushChunk = 25,
    // nakamoto
    GetNakamotoInv = 26,
    NakamotoInv = 27,
    NakamotoBlocks = 28,
    // reserved
    Reserved = 255,
}

/// Message type for all P2P Stacks network messages
#[derive(Debug, Clone, PartialEq)]
pub struct StacksMessage {
    pub preamble: Preamble,
    pub relayers: Vec<RelayData>,
    pub payload: StacksMessageType,
}

/// Network messages implement this to have multiple messages in flight.
pub trait MessageSequence {
    fn request_id(&self) -> u32;
    fn get_message_name(&self) -> &'static str;
}

pub trait ProtocolFamily {
    type Preamble: StacksMessageCodec + Send + Sync + Clone + PartialEq + std::fmt::Debug;
    type Message: MessageSequence + Send + Sync + Clone + PartialEq + std::fmt::Debug;

    /// Return the maximum possible length of the serialized Preamble type
    fn preamble_size_hint(&mut self) -> usize;

    /// Determine how long the message payload will be, given the Preamble (may return None if the
    /// payload length cannot be determined solely by the Preamble).
    fn payload_len(&mut self, preamble: &Self::Preamble) -> Option<usize>;

    /// Given a byte buffer of a length at last that of the value returned by preamble_size_hint,
    /// parse a Preamble and return both the Preamble and the number of bytes actually consumed by it.
    fn read_preamble(&mut self, buf: &[u8]) -> Result<(Self::Preamble, usize), Error>;

    /// Given a preamble and a byte buffer, parse out a message and return both the message and the
    /// number of bytes actually consumed by it.  Only used if the message is _not_ streamed.  The
    /// buf slice is guaranteed to have at least `payload_len()` bytes if `payload_len()` returns
    /// Some(...).
    fn read_payload(
        &mut self,
        preamble: &Self::Preamble,
        buf: &[u8],
    ) -> Result<(Self::Message, usize), Error>;

    /// Given a preamble and a Read, attempt to stream a message.  This will be called if
    /// `payload_len()` returns None.  This method will be repeatedly called with new data until a
    /// message can be obtained; therefore, the ProtocolFamily implementation will need to do its
    /// own bufferring and state-tracking.
    fn stream_payload<R: Read>(
        &mut self,
        preamble: &Self::Preamble,
        fd: &mut R,
    ) -> Result<(Option<(Self::Message, usize)>, usize), Error>;

    /// Given a public key, a preamble, and the yet-to-be-parsed message bytes, verify the message
    /// authenticity.  Not all protocols need to do this.
    fn verify_payload_bytes(
        &mut self,
        key: &StacksPublicKey,
        preamble: &Self::Preamble,
        bytes: &[u8],
    ) -> Result<(), Error>;

    /// Given a Write and a Message, write it out.  This method is also responsible for generating
    /// and writing out a Preamble for its Message.
    fn write_message<W: Write>(&mut self, fd: &mut W, message: &Self::Message)
        -> Result<(), Error>;
}

// these implement the ProtocolFamily trait
#[derive(Debug, Clone, PartialEq)]
pub struct StacksP2P {}

// an array in our protocol can't exceed this many items
pub const ARRAY_MAX_LEN: u32 = u32::MAX;

// maximum number of neighbors in a NeighborsData
pub const MAX_NEIGHBORS_DATA_LEN: u32 = 128;

// number of peers to relay to, depending on outbound or inbound
pub const MAX_BROADCAST_OUTBOUND_RECEIVERS: usize = 8;
pub const MAX_BROADCAST_INBOUND_RECEIVERS: usize = 16;

// maximum number of blocks that can be announced as available
pub const BLOCKS_AVAILABLE_MAX_LEN: u32 = 32;

// maximum number of PoX reward cycles we can ask about
#[cfg(not(test))]
pub const GETPOXINV_MAX_BITLEN: u64 = 4096;
#[cfg(test)]
pub const GETPOXINV_MAX_BITLEN: u64 = 8;

// maximum number of Stacks epoch2.x blocks that can be pushed at once (even if the entire message is undersized).
// This bound is needed since it bounds the amount of I/O a peer can be asked to do to validate the
// message.
pub const BLOCKS_PUSHED_MAX: u32 = 32;

// maximum number of Nakamoto blocks that can be pushed at once (even if the entire message is undersized).
// This bound is needed since it bounds the amount of I/O a peer can be asked to do to validate the
// message.
pub const NAKAMOTO_BLOCKS_PUSHED_MAX: u32 = 32;

/// neighbor identifier
#[derive(Clone, Eq, PartialOrd, Ord)]
pub struct NeighborKey {
    pub peer_version: u32,
    pub network_id: u32,
    pub addrbytes: PeerAddress,
    pub port: u16,
}

impl Hash for NeighborKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // ignores peer version and network ID -- we don't accept or deal with messages that have
        // incompatible versions or network IDs in the first place
        let peer_major_version = self.peer_version & 0xff000000;
        peer_major_version.hash(state);
        self.addrbytes.hash(state);
        self.port.hash(state);
    }
}

impl PartialEq for NeighborKey {
    fn eq(&self, other: &NeighborKey) -> bool {
        // only check major version byte in peer_version
        self.network_id == other.network_id
            && (self.peer_version & 0xff000000) == (other.peer_version & 0xff000000)
            && self.addrbytes == other.addrbytes
            && self.port == other.port
    }
}

impl fmt::Display for NeighborKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let peer_version_str = if self.peer_version > 0 {
            format!("{:08x}", self.peer_version)
        } else {
            "UNKNOWN".to_string()
        };
        let network_id_str = if self.network_id > 0 {
            format!("{:08x}", self.network_id)
        } else {
            "UNKNOWN".to_string()
        };
        write!(
            f,
            "{}+{}://{:?}",
            peer_version_str,
            network_id_str,
            &self.addrbytes.to_socketaddr(self.port)
        )
    }
}

impl fmt::Debug for NeighborKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl NeighborKey {
    pub fn empty() -> NeighborKey {
        NeighborKey {
            peer_version: 0,
            network_id: 0,
            addrbytes: PeerAddress([0u8; 16]),
            port: 0,
        }
    }

    pub fn from_neighbor_address(
        peer_version: u32,
        network_id: u32,
        na: &NeighborAddress,
    ) -> NeighborKey {
        NeighborKey {
            peer_version,
            network_id,
            addrbytes: na.addrbytes.clone(),
            port: na.port,
        }
    }

    pub fn to_socketaddr(&self) -> SocketAddr {
        self.addrbytes.to_socketaddr(self.port)
    }
}

/// Entry in the neighbor set
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub addr: NeighborKey,

    // fields below this can change at runtime
    pub public_key: Secp256k1PublicKey,
    pub expire_block: u64,
    pub last_contact_time: u64, // time when we last authenticated with this peer via a Handshake

    pub allowed: i64, // allow deadline (negative == "forever")
    pub denied: i64,  // deny deadline (negative == "forever")

    pub asn: u32, // AS number
    pub org: u32, // organization identifier

    pub in_degree: u32,  // number of peers who list this peer as a neighbor
    pub out_degree: u32, // number of neighbors this peer has
}

impl PartialEq for Neighbor {
    /// Neighbor equality is based on having the same address and public key.
    /// Everything else can change at runtime
    fn eq(&self, other: &Neighbor) -> bool {
        self.addr == other.addr && self.public_key == other.public_key
    }
}

impl Neighbor {
    pub fn is_allowed(&self) -> bool {
        let now = get_epoch_time_secs();
        (self.allowed < 0 || (self.allowed as u64) > now)
            && !(self.denied < 0 || (self.denied as u64) > now)
    }

    pub fn is_always_allowed(&self) -> bool {
        self.allowed < 0
    }

    pub fn is_denied(&self) -> bool {
        let now = get_epoch_time_secs();
        !(self.allowed < 0 || (self.allowed as u64) > now)
            && (self.denied < 0 || (self.denied as u64) > now)
    }
}

impl fmt::Display for Neighbor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}@{}", self.public_key.to_hex(), self.addr)
    }
}

pub const NUM_NEIGHBORS: usize = 32;

// maximum number of unconfirmed microblocks can get streamed to us
pub const MAX_MICROBLOCKS_UNCONFIRMED: usize = 1024;

// maximum number of block headers we'll get streamed to us
pub const MAX_HEADERS: usize = 2100;

// how long a peer will be denied for if it misbehaves
#[cfg(test)]
pub const DENY_BAN_DURATION: u64 = 30; // seconds
#[cfg(not(test))]
pub const DENY_BAN_DURATION: u64 = 86400; // seconds (1 day)

pub const DENY_MIN_BAN_DURATION: u64 = 2;

/// Result of doing network work
#[derive(Clone, PartialEq, Debug)]
pub struct NetworkResult {
    /// Stacks chain tip when we began this pass
    pub stacks_tip: StacksBlockId,
    /// PoX ID as it was when we begin downloading blocks (set if we have downloaded new blocks)
    pub download_pox_id: Option<PoxId>,
    /// Network messages we received but did not handle
    pub unhandled_messages: HashMap<NeighborKey, Vec<StacksMessage>>,
    /// Stacks 2.x blocks we downloaded, and time taken
    pub blocks: Vec<(ConsensusHash, StacksBlock, u64)>,
    /// Stacks 2.x confiremd microblocks we downloaded, and time taken
    pub confirmed_microblocks: Vec<(ConsensusHash, Vec<StacksMicroblock>, u64)>,
    /// Nakamoto blocks we downloaded
    pub nakamoto_blocks: HashMap<StacksBlockId, NakamotoBlock>,
    /// all transactions pushed to us and their message relay hints
    pub pushed_transactions: HashMap<NeighborKey, Vec<(Vec<RelayData>, StacksTransaction)>>,
    /// all Stacks 2.x blocks pushed to us
    pub pushed_blocks: HashMap<NeighborKey, Vec<BlocksData>>,
    /// all Stacks 2.x microblocks pushed to us, and the relay hints from the message
    pub pushed_microblocks: HashMap<NeighborKey, Vec<(Vec<RelayData>, MicroblocksData)>>,
    /// all Stacks 3.x blocks pushed to us
    pub pushed_nakamoto_blocks: HashMap<NeighborKey, Vec<(Vec<RelayData>, NakamotoBlocksData)>>,
    /// transactions sent to us by the http server
    pub uploaded_transactions: Vec<StacksTransaction>,
    /// blocks sent to us via the http server
    pub uploaded_blocks: Vec<BlocksData>,
    /// blocks sent to us via the http server
    pub uploaded_nakamoto_blocks: Vec<NakamotoBlock>,
    /// microblocks sent to us by the http server
    pub uploaded_microblocks: Vec<MicroblocksData>,
    /// chunks we received from the HTTP server
    pub uploaded_stackerdb_chunks: Vec<StackerDBPushChunkData>,
    /// chunks we received from p2p push
    pub pushed_stackerdb_chunks: Vec<StackerDBPushChunkData>,
    /// Atlas attachments we obtained
    pub attachments: Vec<(AttachmentInstance, Attachment)>,
    /// transactions we downloaded via a mempool sync
    pub synced_transactions: Vec<StacksTransaction>,
    /// chunks for stacker DBs we downloaded
    pub stacker_db_sync_results: Vec<StackerDBSyncResult>,
    /// Number of times the network state machine has completed one pass
    pub num_state_machine_passes: u64,
    /// Number of times the Stacks 2.x inventory synchronization has completed one pass
    pub num_inv_sync_passes: u64,
    /// Number of times the Stacks 2.x block downloader has completed one pass
    pub num_download_passes: u64,
    /// Number of connected peers
    pub num_connected_peers: usize,
    /// The observed burnchain height
    pub burn_height: u64,
    /// The observed stacks coinbase height
    pub coinbase_height: u64,
    /// The observed stacks tip height (different in Nakamoto from coinbase height)
    pub stacks_tip_height: u64,
    /// The consensus hash of the stacks tip (prefixed `rc_` for historical reasons)
    pub rc_consensus_hash: ConsensusHash,
    /// The current StackerDB configs
    pub stacker_db_configs: HashMap<QualifiedContractIdentifier, StackerDBConfig>,
}

impl NetworkResult {
    pub fn new(
        stacks_tip: StacksBlockId,
        num_state_machine_passes: u64,
        num_inv_sync_passes: u64,
        num_download_passes: u64,
        num_connected_peers: usize,
        burn_height: u64,
        coinbase_height: u64,
        stacks_tip_height: u64,
        rc_consensus_hash: ConsensusHash,
        stacker_db_configs: HashMap<QualifiedContractIdentifier, StackerDBConfig>,
    ) -> NetworkResult {
        NetworkResult {
            stacks_tip,
            unhandled_messages: HashMap::new(),
            download_pox_id: None,
            blocks: vec![],
            confirmed_microblocks: vec![],
            nakamoto_blocks: HashMap::new(),
            pushed_transactions: HashMap::new(),
            pushed_blocks: HashMap::new(),
            pushed_microblocks: HashMap::new(),
            pushed_nakamoto_blocks: HashMap::new(),
            uploaded_transactions: vec![],
            uploaded_nakamoto_blocks: vec![],
            uploaded_blocks: vec![],
            uploaded_microblocks: vec![],
            uploaded_stackerdb_chunks: vec![],
            pushed_stackerdb_chunks: vec![],
            attachments: vec![],
            synced_transactions: vec![],
            stacker_db_sync_results: vec![],
            num_state_machine_passes,
            num_inv_sync_passes,
            num_download_passes,
            num_connected_peers,
            burn_height,
            coinbase_height,
            stacks_tip_height,
            rc_consensus_hash,
            stacker_db_configs,
        }
    }

    /// Get the set of all StacksBlocks represented
    fn all_block_ids(&self) -> HashSet<StacksBlockId> {
        let mut blocks: HashSet<_> = self
            .blocks
            .iter()
            .map(|(ch, blk, _)| StacksBlockId::new(&ch, &blk.block_hash()))
            .collect();

        let pushed_blocks: HashSet<_> = self
            .pushed_blocks
            .iter()
            .flat_map(|(_, block_list)| {
                block_list.iter().flat_map(|block_data| {
                    block_data
                        .blocks
                        .iter()
                        .map(|block_datum| {
                            StacksBlockId::new(&block_datum.0, &block_datum.1.block_hash())
                        })
                        .collect::<HashSet<_>>()
                })
            })
            .collect();

        let uploaded_blocks: HashSet<_> = self
            .uploaded_blocks
            .iter()
            .flat_map(|blk_data| {
                blk_data
                    .blocks
                    .iter()
                    .map(|blk| StacksBlockId::new(&blk.0, &blk.1.block_hash()))
            })
            .collect();

        blocks.extend(pushed_blocks);
        blocks.extend(uploaded_blocks);
        blocks
    }

    /// Get the set of all microblocks represented
    fn all_microblock_hashes(&self) -> HashSet<BlockHeaderHash> {
        let mut mblocks: HashSet<_> = self
            .confirmed_microblocks
            .iter()
            .flat_map(|(_, mblocks, _)| mblocks.iter().map(|mblk| mblk.block_hash()))
            .collect();

        let pushed_microblocks: HashSet<_> = self
            .pushed_microblocks
            .iter()
            .flat_map(|(_, mblock_list)| {
                mblock_list.iter().flat_map(|(_, mblock_data)| {
                    mblock_data
                        .microblocks
                        .iter()
                        .map(|mblock| mblock.block_hash())
                })
            })
            .collect();

        let uploaded_microblocks: HashSet<_> = self
            .uploaded_microblocks
            .iter()
            .flat_map(|mblk_data| mblk_data.microblocks.iter().map(|mblk| mblk.block_hash()))
            .collect();

        mblocks.extend(pushed_microblocks);
        mblocks.extend(uploaded_microblocks);
        mblocks
    }

    /// Get the set of all nakamoto blocks represented
    fn all_nakamoto_block_ids(&self) -> HashSet<StacksBlockId> {
        let mut naka_block_ids: HashSet<_> = self
            .nakamoto_blocks
            .iter()
            .map(|(_, nblk)| nblk.block_id())
            .collect();

        let pushed_nakamoto_blocks: HashSet<_> = self
            .pushed_nakamoto_blocks
            .iter()
            .map(|(_, naka_blocks_list)| {
                naka_blocks_list
                    .iter()
                    .map(|(_, naka_blocks)| {
                        naka_blocks
                            .blocks
                            .iter()
                            .map(|nblk| nblk.block_id())
                            .collect::<HashSet<_>>()
                    })
                    .collect::<Vec<HashSet<_>>>()
            })
            .collect::<Vec<Vec<HashSet<_>>>>()
            .into_iter()
            .flatten()
            .fold(HashSet::new(), |mut acc, next| {
                acc.extend(next);
                acc
            });

        let uploaded_nakamoto_blocks: HashSet<_> = self
            .uploaded_nakamoto_blocks
            .iter()
            .map(|nblk| nblk.block_id())
            .collect();

        naka_block_ids.extend(pushed_nakamoto_blocks);
        naka_block_ids.extend(uploaded_nakamoto_blocks);
        naka_block_ids
    }

    /// Get the set of all txids represented
    fn all_txids(&self) -> HashSet<Txid> {
        let mut txids: HashSet<_> = self
            .uploaded_transactions
            .iter()
            .map(|tx| tx.txid())
            .collect();
        let pushed_txids: HashSet<_> = self
            .pushed_transactions
            .iter()
            .map(|(_, tx_list)| {
                tx_list
                    .iter()
                    .map(|(_, tx)| tx.txid())
                    .collect::<HashSet<_>>()
            })
            .collect::<Vec<HashSet<_>>>()
            .into_iter()
            .fold(HashSet::new(), |mut acc, next| {
                acc.extend(next);
                acc
            });

        let synced_txids: HashSet<_> = self
            .synced_transactions
            .iter()
            .map(|tx| tx.txid())
            .collect();

        txids.extend(pushed_txids);
        txids.extend(synced_txids);
        txids
    }

    /// Get all unhandled message signatures.
    /// This is unique per message.
    fn all_msg_sigs(&self) -> HashSet<MessageSignature> {
        self.unhandled_messages
            .iter()
            .map(|(_, msgs)| {
                msgs.iter()
                    .map(|msg| msg.preamble.signature.clone())
                    .collect::<HashSet<_>>()
            })
            .fold(HashSet::new(), |mut acc, next| {
                acc.extend(next);
                acc
            })
    }

    /// Merge self into `newer`, and return `newer`.
    /// deduplicate messages when possible.
    pub fn update(mut self, mut newer: NetworkResult) -> Self {
        // merge unhandled messaegs, but deduplicate
        let newer_msgs = newer.all_msg_sigs();
        for (nk, mut msgs) in self.unhandled_messages.drain() {
            msgs.retain(|msg| {
                let retain = !newer_msgs.contains(&msg.preamble.signature);
                if !retain {
                    debug!(
                        "Drop duplicate p2p message {} seq {}",
                        &msg.get_message_name(),
                        &msg.preamble.seq
                    );
                }
                retain
            });
            if let Some(newer_msgs) = newer.unhandled_messages.get_mut(&nk) {
                newer_msgs.append(&mut msgs);
            } else {
                newer.unhandled_messages.insert(nk, msgs);
            }
        }

        let newer_blocks = newer.all_block_ids();
        let newer_microblocks = newer.all_microblock_hashes();
        let newer_naka_blocks = newer.all_nakamoto_block_ids();
        let newer_txids = newer.all_txids();

        // only retain blocks not found in `newer`
        self.blocks.retain(|(ch, blk, _)| {
            let block_id = StacksBlockId::new(&ch, &blk.block_hash());
            let retain = !newer_blocks.contains(&block_id);
            if !retain {
                debug!("Drop duplicate downloaded block {}", &block_id);
            }
            retain
        });
        newer.blocks.append(&mut self.blocks);

        // merge microblocks, but deduplicate
        self.confirmed_microblocks
            .retain_mut(|(_, ref mut mblocks, _)| {
                mblocks.retain(|mblk| {
                    let retain = !newer_microblocks.contains(&mblk.block_hash());
                    if !retain {
                        debug!(
                            "Drop duplicate downloaded microblock {}",
                            &mblk.block_hash()
                        );
                    }
                    retain
                });
                !mblocks.is_empty()
            });
        newer
            .confirmed_microblocks
            .append(&mut self.confirmed_microblocks);

        // merge nakamoto blocks, but deduplicate
        self.nakamoto_blocks.retain(|_, nblk| {
            let retain = !newer_naka_blocks.contains(&nblk.block_id());
            if !retain {
                debug!(
                    "Drop duplicate downloaded nakamoto block {}",
                    &nblk.block_id()
                );
            }
            retain
        });
        newer.nakamoto_blocks.extend(self.nakamoto_blocks.drain());

        // merge pushed transactions, but deduplicate
        for (nk, mut tx_data) in self.pushed_transactions.drain() {
            tx_data.retain(|(_, tx)| {
                let retain = !newer_txids.contains(&tx.txid());
                if !retain {
                    debug!("Drop duplicate pushed transaction {}", &tx.txid());
                }
                retain
            });
            if tx_data.is_empty() {
                continue;
            }

            if let Some(newer_tx_data) = newer.pushed_transactions.get_mut(&nk) {
                newer_tx_data.append(&mut tx_data);
            } else {
                newer.pushed_transactions.insert(nk, tx_data);
            }
        }

        // merge pushed blocks, but deduplicate
        for (nk, mut block_list) in self.pushed_blocks.drain() {
            block_list.retain_mut(|ref mut block_data| {
                block_data.blocks.retain(|blk_datum| {
                    let block_id = StacksBlockId::new(&blk_datum.0, &blk_datum.1.block_hash());
                    let retain = !newer_blocks.contains(&block_id);
                    if !retain {
                        debug!("Drop duplicate pushed block {}", &block_id);
                    }
                    retain
                });
                !block_data.blocks.is_empty()
            });
            if block_list.is_empty() {
                continue;
            }

            if let Some(newer_block_data) = newer.pushed_blocks.get_mut(&nk) {
                newer_block_data.append(&mut block_list);
            } else {
                newer.pushed_blocks.insert(nk, block_list);
            }
        }

        // merge pushed microblocks, but deduplicate
        for (nk, mut microblock_data) in self.pushed_microblocks.drain() {
            microblock_data.retain_mut(|(_, ref mut mblock_data)| {
                mblock_data.microblocks.retain(|mblk| {
                    let retain = !newer_microblocks.contains(&mblk.block_hash());
                    if !retain {
                        debug!("Drop duplicate pushed microblock {}", &mblk.block_hash());
                    }
                    retain
                });
                !mblock_data.microblocks.is_empty()
            });
            if microblock_data.is_empty() {
                continue;
            }

            if let Some(newer_microblock_data) = newer.pushed_microblocks.get_mut(&nk) {
                newer_microblock_data.append(&mut microblock_data);
            } else {
                newer.pushed_microblocks.insert(nk, microblock_data);
            }
        }

        // merge pushed nakamoto blocks, but deduplicate
        for (nk, mut nakamoto_block_data) in self.pushed_nakamoto_blocks.drain() {
            nakamoto_block_data.retain_mut(|(_, ref mut naka_blocks)| {
                naka_blocks.blocks.retain(|nblk| {
                    let retain = !newer_naka_blocks.contains(&nblk.block_id());
                    if !retain {
                        debug!("Drop duplicate pushed nakamoto block {}", &nblk.block_id());
                    }
                    retain
                });
                !naka_blocks.blocks.is_empty()
            });
            if nakamoto_block_data.is_empty() {
                continue;
            }

            if let Some(newer_nakamoto_data) = newer.pushed_nakamoto_blocks.get_mut(&nk) {
                newer_nakamoto_data.append(&mut nakamoto_block_data);
            } else {
                newer.pushed_nakamoto_blocks.insert(nk, nakamoto_block_data);
            }
        }

        // merge uploaded data, but deduplicate
        self.uploaded_transactions.retain(|tx| {
            let retain = !newer_txids.contains(&tx.txid());
            if !retain {
                debug!("Drop duplicate uploaded transaction {}", &tx.txid());
            }
            retain
        });
        self.uploaded_blocks.retain_mut(|ref mut blk_data| {
            blk_data.blocks.retain(|blk| {
                let block_id = StacksBlockId::new(&blk.0, &blk.1.block_hash());
                let retain = !newer_blocks.contains(&block_id);
                if !retain {
                    debug!("Drop duplicate uploaded block {}", &block_id);
                }
                retain
            });

            !blk_data.blocks.is_empty()
        });
        self.uploaded_microblocks.retain_mut(|ref mut mblock_data| {
            mblock_data.microblocks.retain(|mblk| {
                let retain = !newer_microblocks.contains(&mblk.block_hash());
                if !retain {
                    debug!("Drop duplicate uploaded microblock {}", &mblk.block_hash());
                }
                retain
            });

            !mblock_data.microblocks.is_empty()
        });
        self.uploaded_nakamoto_blocks.retain(|nblk| {
            let retain = !newer_naka_blocks.contains(&nblk.block_id());
            if !retain {
                debug!(
                    "Drop duplicate uploaded nakamoto block {}",
                    &nblk.block_id()
                );
            }
            retain
        });

        newer
            .uploaded_transactions
            .append(&mut self.uploaded_transactions);
        newer.uploaded_blocks.append(&mut self.uploaded_blocks);
        newer
            .uploaded_microblocks
            .append(&mut self.uploaded_microblocks);
        newer
            .uploaded_nakamoto_blocks
            .append(&mut self.uploaded_nakamoto_blocks);

        // merge uploaded/pushed stackerdb, but drop stale versions
        let newer_stackerdb_chunk_versions: HashMap<_, _> = newer
            .uploaded_stackerdb_chunks
            .iter()
            .chain(newer.pushed_stackerdb_chunks.iter())
            .map(|chunk| {
                (
                    (
                        chunk.contract_id.clone(),
                        chunk.rc_consensus_hash.clone(),
                        chunk.chunk_data.slot_id,
                    ),
                    chunk.chunk_data.slot_version,
                )
            })
            .collect();

        self.uploaded_stackerdb_chunks.retain(|push_chunk| {
            if push_chunk.rc_consensus_hash != newer.rc_consensus_hash {
                debug!(
                    "Drop pushed StackerDB chunk for {} due to stale view ({} != {}): {:?}",
                    &push_chunk.contract_id,
                    &push_chunk.rc_consensus_hash,
                    &newer.rc_consensus_hash,
                    &push_chunk.chunk_data
                );
                return false;
            }
            if let Some(version) = newer_stackerdb_chunk_versions.get(&(
                push_chunk.contract_id.clone(),
                push_chunk.rc_consensus_hash.clone(),
                push_chunk.chunk_data.slot_id,
            )) {
                let retain = push_chunk.chunk_data.slot_version > *version;
                if !retain {
                    debug!(
                        "Drop pushed StackerDB chunk for {} due to stale version: {:?}",
                        &push_chunk.contract_id, &push_chunk.chunk_data
                    );
                }
                retain
            } else {
                true
            }
        });

        self.pushed_stackerdb_chunks.retain(|push_chunk| {
            if push_chunk.rc_consensus_hash != newer.rc_consensus_hash {
                debug!(
                    "Drop uploaded StackerDB chunk for {} due to stale view ({} != {}): {:?}",
                    &push_chunk.contract_id,
                    &push_chunk.rc_consensus_hash,
                    &newer.rc_consensus_hash,
                    &push_chunk.chunk_data
                );
                return false;
            }
            if let Some(version) = newer_stackerdb_chunk_versions.get(&(
                push_chunk.contract_id.clone(),
                push_chunk.rc_consensus_hash.clone(),
                push_chunk.chunk_data.slot_id,
            )) {
                let retain = push_chunk.chunk_data.slot_version > *version;
                if !retain {
                    debug!(
                        "Drop uploaded StackerDB chunk for {} due to stale version: {:?}",
                        &push_chunk.contract_id, &push_chunk.chunk_data
                    );
                }
                retain
            } else {
                true
            }
        });

        newer
            .uploaded_stackerdb_chunks
            .append(&mut self.uploaded_stackerdb_chunks);
        newer
            .pushed_stackerdb_chunks
            .append(&mut self.pushed_stackerdb_chunks);

        // dedup sync'ed transactions
        self.synced_transactions.retain(|tx| {
            let retain = !newer_txids.contains(&tx.txid());
            if !retain {
                debug!("Drop duplicate sync'ed transaction {}", &tx.txid());
            }
            retain
        });

        newer
            .synced_transactions
            .append(&mut self.synced_transactions);

        // no dedup here, but do merge
        newer
            .stacker_db_sync_results
            .append(&mut self.stacker_db_sync_results);
        newer.attachments.append(&mut self.attachments);

        newer
    }

    pub fn has_blocks(&self) -> bool {
        !self.blocks.is_empty() || !self.pushed_blocks.is_empty()
    }

    pub fn has_microblocks(&self) -> bool {
        !self.confirmed_microblocks.is_empty()
            || !self.pushed_microblocks.is_empty()
            || !self.uploaded_microblocks.is_empty()
    }

    pub fn has_nakamoto_blocks(&self) -> bool {
        !self.nakamoto_blocks.is_empty()
            || !self.pushed_nakamoto_blocks.is_empty()
            || !self.uploaded_nakamoto_blocks.is_empty()
    }

    pub fn has_transactions(&self) -> bool {
        !self.pushed_transactions.is_empty()
            || !self.uploaded_transactions.is_empty()
            || !self.synced_transactions.is_empty()
    }

    pub fn has_attachments(&self) -> bool {
        !self.attachments.is_empty()
    }

    pub fn has_stackerdb_chunks(&self) -> bool {
        self.stacker_db_sync_results
            .iter()
            .any(|x| !x.chunks_to_store.is_empty())
            || !self.uploaded_stackerdb_chunks.is_empty()
            || !self.pushed_stackerdb_chunks.is_empty()
    }

    pub fn transactions(&self) -> Vec<StacksTransaction> {
        self.pushed_transactions
            .values()
            .flat_map(|pushed_txs| pushed_txs.iter().map(|(_, tx)| tx.clone()))
            .chain(self.uploaded_transactions.iter().map(|x| x.clone()))
            .chain(self.synced_transactions.iter().map(|x| x.clone()))
            .collect()
    }

    pub fn has_data_to_store(&self) -> bool {
        self.has_blocks()
            || self.has_microblocks()
            || self.has_nakamoto_blocks()
            || self.has_transactions()
            || self.has_attachments()
            || self.has_stackerdb_chunks()
    }

    pub fn has_block_data_to_store(&self) -> bool {
        self.has_blocks() || self.has_microblocks() || self.has_nakamoto_blocks()
    }

    pub fn consume_unsolicited(&mut self, unhandled_messages: PendingMessages) {
        for ((_event_id, neighbor_key), messages) in unhandled_messages.into_iter() {
            for message in messages.into_iter() {
                match message.payload {
                    StacksMessageType::Blocks(block_data) => {
                        if let Some(blocks_msgs) = self.pushed_blocks.get_mut(&neighbor_key) {
                            blocks_msgs.push(block_data);
                        } else {
                            self.pushed_blocks
                                .insert(neighbor_key.clone(), vec![block_data]);
                        }
                    }
                    StacksMessageType::Microblocks(mblock_data) => {
                        if let Some(mblocks_msgs) = self.pushed_microblocks.get_mut(&neighbor_key) {
                            mblocks_msgs.push((message.relayers, mblock_data));
                        } else {
                            self.pushed_microblocks.insert(
                                neighbor_key.clone(),
                                vec![(message.relayers, mblock_data)],
                            );
                        }
                    }
                    StacksMessageType::Transaction(tx_data) => {
                        if let Some(tx_msgs) = self.pushed_transactions.get_mut(&neighbor_key) {
                            tx_msgs.push((message.relayers, tx_data));
                        } else {
                            self.pushed_transactions
                                .insert(neighbor_key.clone(), vec![(message.relayers, tx_data)]);
                        }
                    }
                    StacksMessageType::NakamotoBlocks(block_data) => {
                        if let Some(nakamoto_blocks_msgs) =
                            self.pushed_nakamoto_blocks.get_mut(&neighbor_key)
                        {
                            nakamoto_blocks_msgs.push((message.relayers, block_data));
                        } else {
                            self.pushed_nakamoto_blocks
                                .insert(neighbor_key.clone(), vec![(message.relayers, block_data)]);
                        }
                    }
                    StacksMessageType::StackerDBPushChunk(chunk_data) => {
                        self.pushed_stackerdb_chunks.push(chunk_data)
                    }
                    _ => {
                        // forward along
                        if let Some(messages) = self.unhandled_messages.get_mut(&neighbor_key) {
                            messages.push(message);
                        } else {
                            self.unhandled_messages
                                .insert(neighbor_key.clone(), vec![message]);
                        }
                    }
                }
            }
        }
    }

    pub fn consume_http_uploads(&mut self, msgs: Vec<StacksMessageType>) {
        for msg in msgs.into_iter() {
            match msg {
                StacksMessageType::Transaction(tx_data) => {
                    self.uploaded_transactions.push(tx_data);
                }
                StacksMessageType::Blocks(block_data) => {
                    self.uploaded_blocks.push(block_data);
                }
                StacksMessageType::Microblocks(mblock_data) => {
                    self.uploaded_microblocks.push(mblock_data);
                }
                StacksMessageType::StackerDBPushChunk(chunk_data) => {
                    self.uploaded_stackerdb_chunks.push(chunk_data);
                }
                StacksMessageType::NakamotoBlocks(data) => {
                    self.uploaded_nakamoto_blocks.extend(data.blocks);
                }
                _ => {
                    // drop
                    warn!("Dropping unknown HTTP message");
                }
            }
        }
    }

    pub fn consume_stacker_db_sync_results(&mut self, mut msgs: Vec<StackerDBSyncResult>) {
        self.stacker_db_sync_results.append(&mut msgs);
    }

    pub fn consume_nakamoto_blocks(&mut self, blocks: HashMap<ConsensusHash, Vec<NakamotoBlock>>) {
        for (_ch, blocks) in blocks.into_iter() {
            for block in blocks.into_iter() {
                let block_id = block.block_id();
                if self.nakamoto_blocks.contains_key(&block_id) {
                    continue;
                }
                self.nakamoto_blocks.insert(block_id, block);
            }
        }
    }
}

pub trait Requestable: std::fmt::Display {
    fn get_url(&self) -> &UrlString;

    fn make_request_type(&self, peer_host: PeerHost) -> StacksHttpRequest;
}

#[cfg(test)]
pub mod test {
    use std::collections::HashMap;
    use std::io::{Cursor, ErrorKind, Read, Write};
    use std::net::*;
    use std::ops::{Deref, DerefMut};
    use std::sync::mpsc::sync_channel;
    use std::sync::Mutex;
    use std::{fs, io, thread};

    use clarity::boot_util::boot_code_id;
    use clarity::types::sqlite::NO_PARAMS;
    use clarity::vm::ast::parser::v1::CONTRACT_MAX_NAME_LENGTH;
    use clarity::vm::ast::ASTRules;
    use clarity::vm::costs::ExecutionCost;
    use clarity::vm::database::STXBalance;
    use clarity::vm::types::*;
    use clarity::vm::ClarityVersion;
    use rand::{Rng, RngCore};
    use stacks_common::address::*;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::deps_common::bitcoin::network::serialize::BitcoinHash;
    use stacks_common::types::chainstate::TrieHash;
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::*;
    use stacks_common::util::secp256k1::*;
    use stacks_common::util::uint::*;
    use stacks_common::util::vrf::*;
    use {mio, rand};

    use self::nakamoto::test_signers::TestSigners;
    use super::*;
    use crate::burnchains::bitcoin::address::*;
    use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
    use crate::burnchains::bitcoin::keys::*;
    use crate::burnchains::bitcoin::spv::BITCOIN_GENESIS_BLOCK_HASH_REGTEST;
    use crate::burnchains::bitcoin::*;
    use crate::burnchains::burnchain::*;
    use crate::burnchains::db::{BurnchainDB, BurnchainHeaderReader};
    use crate::burnchains::tests::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb;
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::burn::*;
    use crate::chainstate::coordinator::tests::*;
    use crate::chainstate::coordinator::*;
    use crate::chainstate::nakamoto::tests::node::TestStacker;
    use crate::chainstate::stacks::address::PoxAddress;
    use crate::chainstate::stacks::boot::test::get_parent_tip;
    use crate::chainstate::stacks::boot::*;
    use crate::chainstate::stacks::db::accounts::MinerReward;
    use crate::chainstate::stacks::db::{StacksChainState, *};
    use crate::chainstate::stacks::events::{StacksBlockEventData, StacksTransactionReceipt};
    use crate::chainstate::stacks::miner::*;
    use crate::chainstate::stacks::tests::chain_histories::mine_smart_contract_block_contract_call_microblock;
    use crate::chainstate::stacks::tests::*;
    use crate::chainstate::stacks::{StacksMicroblockHeader, *};
    use crate::chainstate::*;
    use crate::clarity::vm::clarity::TransactionConnection;
    use crate::core::{EpochList, StacksEpoch, StacksEpochExtension, NETWORK_P2P_PORT};
    use crate::net::asn::*;
    use crate::net::atlas::*;
    use crate::net::chat::*;
    use crate::net::codec::*;
    use crate::net::connection::*;
    use crate::net::db::*;
    use crate::net::neighbors::*;
    use crate::net::p2p::*;
    use crate::net::poll::*;
    use crate::net::relay::*;
    use crate::net::Error as net_error;
    use crate::util_lib::boot::boot_code_test_addr;
    use crate::util_lib::strings::*;

    impl StacksMessageCodec for BlockstackOperationType {
        fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
            match self {
                BlockstackOperationType::LeaderKeyRegister(ref op) => op.consensus_serialize(fd),
                BlockstackOperationType::LeaderBlockCommit(ref op) => op.consensus_serialize(fd),
                BlockstackOperationType::TransferStx(_)
                | BlockstackOperationType::DelegateStx(_)
                | BlockstackOperationType::PreStx(_)
                | BlockstackOperationType::VoteForAggregateKey(_)
                | BlockstackOperationType::StackStx(_) => Ok(()),
            }
        }

        fn consensus_deserialize<R: Read>(
            fd: &mut R,
        ) -> Result<BlockstackOperationType, codec_error> {
            panic!("not used");
        }
    }

    // emulate a socket
    pub struct NetCursor<T> {
        c: Cursor<T>,
        closed: bool,
        block: bool,
        read_error: Option<io::ErrorKind>,
        write_error: Option<io::ErrorKind>,
    }

    impl<T> NetCursor<T> {
        pub fn new(inner: T) -> NetCursor<T> {
            NetCursor {
                c: Cursor::new(inner),
                closed: false,
                block: false,
                read_error: None,
                write_error: None,
            }
        }

        pub fn close(&mut self) {
            self.closed = true;
        }

        pub fn block(&mut self) {
            self.block = true;
        }

        pub fn unblock(&mut self) {
            self.block = false;
        }

        pub fn set_read_error(&mut self, e: Option<io::ErrorKind>) {
            self.read_error = e;
        }

        pub fn set_write_error(&mut self, e: Option<io::ErrorKind>) {
            self.write_error = e;
        }
    }

    impl<T> Deref for NetCursor<T> {
        type Target = Cursor<T>;
        fn deref(&self) -> &Cursor<T> {
            &self.c
        }
    }

    impl<T> DerefMut for NetCursor<T> {
        fn deref_mut(&mut self) -> &mut Cursor<T> {
            &mut self.c
        }
    }

    impl<T> Read for NetCursor<T>
    where
        T: AsRef<[u8]>,
    {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.block {
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            if self.closed {
                return Ok(0);
            }
            match self.read_error {
                Some(ref e) => {
                    return Err(io::Error::from((*e).clone()));
                }
                None => {}
            }

            let sz = self.c.read(buf)?;
            if sz == 0 {
                // when reading from a non-blocking socket, a return value of 0 indicates the
                // remote end was closed.  For this reason, when we're out of bytes to read on our
                // inner cursor, but still have bytes, we need to re-interpret this as EWOULDBLOCK.
                return Err(io::Error::from(ErrorKind::WouldBlock));
            } else {
                return Ok(sz);
            }
        }
    }

    impl Write for NetCursor<&mut [u8]> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.block {
                return Err(io::Error::from(ErrorKind::WouldBlock));
            }
            if self.closed {
                return Err(io::Error::from(ErrorKind::Other)); // EBADF
            }
            match self.write_error {
                Some(ref e) => {
                    return Err(io::Error::from((*e).clone()));
                }
                None => {}
            }
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }

    impl Write for NetCursor<&mut Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }

    impl Write for NetCursor<Vec<u8>> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.c.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.c.flush()
        }
    }

    /// make a TCP server and a pair of TCP client sockets
    pub fn make_tcp_sockets() -> (
        mio::tcp::TcpListener,
        mio::tcp::TcpStream,
        mio::tcp::TcpStream,
    ) {
        let mut rng = rand::thread_rng();
        let (std_listener, port) = {
            let std_listener;
            let mut next_port;
            loop {
                next_port = 1024 + (rng.next_u32() % (65535 - 1024));
                let hostport = format!("127.0.0.1:{}", next_port);
                std_listener = match std::net::TcpListener::bind(
                    &hostport.parse::<std::net::SocketAddr>().unwrap(),
                ) {
                    Ok(sock) => sock,
                    Err(e) => match e.kind() {
                        io::ErrorKind::AddrInUse => {
                            continue;
                        }
                        _ => {
                            assert!(false, "TcpListener::bind({}): {:?}", &hostport, &e);
                            unreachable!();
                        }
                    },
                };
                break;
            }
            (std_listener, next_port)
        };

        let std_sock_1 = std::net::TcpStream::connect(
            &format!("127.0.0.1:{}", port)
                .parse::<std::net::SocketAddr>()
                .unwrap(),
        )
        .unwrap();
        let sock_1 = mio::tcp::TcpStream::from_stream(std_sock_1).unwrap();
        let (std_sock_2, _) = std_listener.accept().unwrap();
        let sock_2 = mio::tcp::TcpStream::from_stream(std_sock_2).unwrap();

        sock_1.set_nodelay(true).unwrap();
        sock_2.set_nodelay(true).unwrap();

        let listener = mio::tcp::TcpListener::from_std(std_listener).unwrap();

        (listener, sock_1, sock_2)
    }

    #[derive(Clone)]
    pub struct TestEventObserverBlock {
        pub block: StacksBlockEventData,
        pub metadata: StacksHeaderInfo,
        pub receipts: Vec<StacksTransactionReceipt>,
        pub parent: StacksBlockId,
        pub winner_txid: Txid,
        pub matured_rewards: Vec<MinerReward>,
        pub matured_rewards_info: Option<MinerRewardInfo>,
        pub reward_set_data: Option<RewardSetData>,
    }

    pub struct TestEventObserver {
        blocks: Mutex<Vec<TestEventObserverBlock>>,
    }

    impl TestEventObserver {
        pub fn get_blocks(&self) -> Vec<TestEventObserverBlock> {
            self.blocks.lock().unwrap().deref().to_vec()
        }

        pub fn new() -> TestEventObserver {
            TestEventObserver {
                blocks: Mutex::new(vec![]),
            }
        }
    }

    impl BlockEventDispatcher for TestEventObserver {
        fn announce_block(
            &self,
            block: &StacksBlockEventData,
            metadata: &StacksHeaderInfo,
            receipts: &[events::StacksTransactionReceipt],
            parent: &StacksBlockId,
            winner_txid: Txid,
            matured_rewards: &[accounts::MinerReward],
            matured_rewards_info: Option<&MinerRewardInfo>,
            parent_burn_block_hash: BurnchainHeaderHash,
            parent_burn_block_height: u32,
            parent_burn_block_timestamp: u64,
            _anchor_block_cost: &ExecutionCost,
            _confirmed_mblock_cost: &ExecutionCost,
            pox_constants: &PoxConstants,
            reward_set_data: &Option<RewardSetData>,
            _signer_bitvec: &Option<BitVec<4000>>,
            _block_timestamp: Option<u64>,
            _coinbase_height: u64,
        ) {
            self.blocks.lock().unwrap().push(TestEventObserverBlock {
                block: block.clone(),
                metadata: metadata.clone(),
                receipts: receipts.to_owned(),
                parent: parent.clone(),
                winner_txid,
                matured_rewards: matured_rewards.to_owned(),
                matured_rewards_info: matured_rewards_info.map(|info| info.clone()),
                reward_set_data: reward_set_data.clone(),
            })
        }

        fn announce_burn_block(
            &self,
            _burn_block: &BurnchainHeaderHash,
            _burn_block_height: u64,
            _rewards: Vec<(PoxAddress, u64)>,
            _burns: u64,
            _reward_recipients: Vec<PoxAddress>,
            _consensus_hash: &ConsensusHash,
        ) {
            // pass
        }
    }

    // describes a peer's initial configuration
    #[derive(Debug, Clone)]
    pub struct TestPeerConfig {
        pub network_id: u32,
        pub peer_version: u32,
        pub current_block: u64,
        pub private_key: Secp256k1PrivateKey,
        pub private_key_expire: u64,
        pub initial_neighbors: Vec<Neighbor>,
        pub asn4_entries: Vec<ASEntry4>,
        pub burnchain: Burnchain,
        pub connection_opts: ConnectionOptions,
        pub server_port: u16,
        pub http_port: u16,
        pub asn: u32,
        pub org: u32,
        pub allowed: i64,
        pub denied: i64,
        pub data_url: UrlString,
        pub test_name: String,
        pub initial_balances: Vec<(PrincipalData, u64)>,
        pub initial_lockups: Vec<ChainstateAccountLockup>,
        pub spending_account: TestMiner,
        pub setup_code: String,
        pub epochs: Option<EpochList>,
        /// If some(), TestPeer should check the PoX-2 invariants
        /// on cycle numbers bounded (inclusive) by the supplied u64s
        pub check_pox_invariants: Option<(u64, u64)>,
        /// Which stacker DBs will this peer replicate?
        pub stacker_dbs: Vec<QualifiedContractIdentifier>,
        /// Stacker DB configurations for each stacker_dbs entry above, if different from
        /// StackerDBConfig::noop()
        pub stacker_db_configs: Vec<Option<StackerDBConfig>>,
        /// What services should this peer support?
        pub services: u16,
        /// aggregate public key to use
        /// (NOTE: will be used post-Nakamoto)
        pub aggregate_public_key: Option<Vec<u8>>,
        pub test_stackers: Option<Vec<TestStacker>>,
        pub test_signers: Option<TestSigners>,
    }

    impl TestPeerConfig {
        pub fn default() -> TestPeerConfig {
            let conn_opts = ConnectionOptions::default();
            let start_block = 0;
            let mut burnchain = Burnchain::default_unittest(
                start_block,
                &BurnchainHeaderHash::from_hex(BITCOIN_GENESIS_BLOCK_HASH_REGTEST).unwrap(),
            );

            burnchain.pox_constants = PoxConstants::test_20_no_sunset();
            let mut spending_account = TestMinerFactory::new().next_miner(
                &burnchain,
                1,
                1,
                AddressHashMode::SerializeP2PKH,
            );
            spending_account.test_with_tx_fees = false; // manually set transaction fees

            TestPeerConfig {
                network_id: 0x80000000,
                peer_version: 0x01020304,
                current_block: start_block + (burnchain.consensus_hash_lifetime + 1) as u64,
                private_key: Secp256k1PrivateKey::new(),
                private_key_expire: start_block + conn_opts.private_key_lifetime,
                initial_neighbors: vec![],
                asn4_entries: vec![],
                burnchain,
                connection_opts: conn_opts,
                server_port: 32000,
                http_port: 32001,
                asn: 0,
                org: 0,
                allowed: 0,
                denied: 0,
                data_url: "".into(),
                test_name: "".into(),
                initial_balances: vec![],
                initial_lockups: vec![],
                spending_account,
                setup_code: "".into(),
                epochs: None,
                check_pox_invariants: None,
                stacker_db_configs: vec![],
                stacker_dbs: vec![],
                services: (ServiceFlags::RELAY as u16)
                    | (ServiceFlags::RPC as u16)
                    | (ServiceFlags::STACKERDB as u16),
                aggregate_public_key: None,
                test_stackers: None,
                test_signers: None,
            }
        }

        pub fn from_port(p: u16) -> TestPeerConfig {
            let mut config = TestPeerConfig {
                server_port: p,
                http_port: p + 1,
                ..TestPeerConfig::default()
            };
            config.data_url =
                UrlString::try_from(format!("http://127.0.0.1:{}", config.http_port).as_str())
                    .unwrap();
            config
        }

        pub fn new(test_name: &str, p2p_port: u16, rpc_port: u16) -> TestPeerConfig {
            let mut config = TestPeerConfig {
                test_name: test_name.into(),
                server_port: p2p_port,
                http_port: rpc_port,
                ..TestPeerConfig::default()
            };
            config.data_url =
                UrlString::try_from(format!("http://127.0.0.1:{}", config.http_port).as_str())
                    .unwrap();
            config
        }

        pub fn add_neighbor(&mut self, n: &Neighbor) {
            self.initial_neighbors.push(n.clone());
        }

        pub fn to_neighbor(&self) -> Neighbor {
            Neighbor {
                addr: NeighborKey {
                    peer_version: self.peer_version,
                    network_id: self.network_id,
                    addrbytes: PeerAddress([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1,
                    ]),
                    port: self.server_port,
                },
                public_key: Secp256k1PublicKey::from_private(&self.private_key),
                expire_block: self.private_key_expire,

                // not known yet
                last_contact_time: 0,
                allowed: self.allowed,
                denied: self.denied,
                asn: self.asn,
                org: self.org,
                in_degree: 0,
                out_degree: 0,
            }
        }

        pub fn to_peer_host(&self) -> PeerHost {
            PeerHost::IP(
                PeerAddress([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]),
                self.http_port,
            )
        }

        pub fn get_stacker_db_configs(
            &self,
        ) -> HashMap<QualifiedContractIdentifier, StackerDBConfig> {
            let mut ret = HashMap::new();
            for (contract_id, config_opt) in
                self.stacker_dbs.iter().zip(self.stacker_db_configs.iter())
            {
                if let Some(config) = config_opt {
                    ret.insert(contract_id.clone(), config.clone());
                } else {
                    ret.insert(contract_id.clone(), StackerDBConfig::noop());
                }
            }
            ret
        }

        pub fn add_stacker_db(
            &mut self,
            contract_id: QualifiedContractIdentifier,
            config: StackerDBConfig,
        ) {
            self.stacker_dbs.push(contract_id);
            self.stacker_db_configs.push(Some(config));
        }
    }

    pub fn dns_thread_start(max_inflight: u64) -> (DNSClient, thread::JoinHandle<()>) {
        let (mut resolver, client) = DNSResolver::new(max_inflight);
        let jh = thread::spawn(move || {
            resolver.thread_main();
        });
        (client, jh)
    }

    pub fn dns_thread_shutdown(dns_client: DNSClient, thread_handle: thread::JoinHandle<()>) {
        drop(dns_client);
        thread_handle.join().unwrap();
    }

    pub struct TestPeer<'a> {
        pub config: TestPeerConfig,
        pub network: PeerNetwork,
        pub sortdb: Option<SortitionDB>,
        pub miner: TestMiner,
        pub stacks_node: Option<TestStacksNode>,
        pub relayer: Relayer,
        pub mempool: Option<MemPoolDB>,
        pub chainstate_path: String,
        pub indexer: Option<BitcoinIndexer>,
        pub coord: ChainsCoordinator<
            'a,
            TestEventObserver,
            (),
            OnChainRewardSetProvider<'a, TestEventObserver>,
            (),
            (),
            BitcoinIndexer,
        >,
        /// list of malleablized blocks produced when mining.
        pub malleablized_blocks: Vec<NakamotoBlock>,
        pub mine_malleablized_blocks: bool,
        /// tenure-start block of tenure to mine on.
        /// gets consumed on the call to begin_nakamoto_tenure
        pub nakamoto_parent_tenure_opt: Option<Vec<NakamotoBlock>>,
    }

    impl<'a> TestPeer<'a> {
        pub fn new(config: TestPeerConfig) -> TestPeer<'a> {
            TestPeer::new_with_observer(config, None)
        }

        pub fn test_path(config: &TestPeerConfig) -> String {
            let random = thread_rng().gen::<u64>();
            let random_bytes = to_hex(&random.to_be_bytes());
            format!(
                "/tmp/stacks-node-tests/units-test-peer/{}-{}",
                &config.test_name, random_bytes
            )
        }

        pub fn stackerdb_path(config: &TestPeerConfig) -> String {
            format!("{}/stacker_db.sqlite", &Self::test_path(config))
        }

        pub fn make_test_path(config: &TestPeerConfig) -> String {
            let test_path = TestPeer::test_path(&config);
            match fs::metadata(&test_path) {
                Ok(_) => {
                    fs::remove_dir_all(&test_path).unwrap();
                }
                Err(_) => {}
            };

            fs::create_dir_all(&test_path).unwrap();
            test_path
        }

        fn init_stackerdb_syncs(
            root_path: &str,
            peerdb: &PeerDB,
            stacker_dbs: &mut HashMap<QualifiedContractIdentifier, StackerDBConfig>,
        ) -> HashMap<QualifiedContractIdentifier, (StackerDBConfig, StackerDBSync<PeerNetworkComms>)>
        {
            let stackerdb_path = format!("{}/stacker_db.sqlite", root_path);
            let mut stacker_db_syncs = HashMap::new();
            let local_peer = PeerDB::get_local_peer(peerdb.conn()).unwrap();
            for (i, (contract_id, db_config)) in stacker_dbs.iter_mut().enumerate() {
                let initial_peers = PeerDB::find_stacker_db_replicas(
                    peerdb.conn(),
                    local_peer.network_id,
                    &contract_id,
                    0,
                    10000000,
                )
                .unwrap()
                .into_iter()
                .map(|neighbor| NeighborAddress::from_neighbor(&neighbor))
                .collect();

                db_config.hint_replicas = initial_peers;
                let stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();
                let stacker_db_sync = StackerDBSync::new(
                    contract_id.clone(),
                    &db_config,
                    PeerNetworkComms::new(),
                    stacker_dbs,
                );

                stacker_db_syncs.insert(contract_id.clone(), (db_config.clone(), stacker_db_sync));
            }
            stacker_db_syncs
        }

        pub fn neighbor_with_observer(
            &self,
            privkey: StacksPrivateKey,
            observer: Option<&'a TestEventObserver>,
        ) -> TestPeer<'a> {
            let mut config = self.config.clone();
            config.private_key = privkey;
            config.test_name = format!(
                "{}.neighbor-{}",
                &self.config.test_name,
                Hash160::from_node_public_key(&StacksPublicKey::from_private(
                    &self.config.private_key
                ))
            );
            config.server_port = 0;
            config.http_port = 0;
            config.test_stackers = self.config.test_stackers.clone();
            config.initial_neighbors = vec![self.to_neighbor()];

            let peer = TestPeer::new_with_observer(config, observer);
            peer
        }

        pub fn new_with_observer(
            mut config: TestPeerConfig,
            observer: Option<&'a TestEventObserver>,
        ) -> TestPeer<'a> {
            let test_path = TestPeer::make_test_path(&config);
            let mut miner_factory = TestMinerFactory::new();
            miner_factory.chain_id = config.network_id;
            let mut miner =
                miner_factory.next_miner(&config.burnchain, 1, 1, AddressHashMode::SerializeP2PKH);
            // manually set fees
            miner.test_with_tx_fees = false;

            config.burnchain.working_dir = get_burnchain(&test_path, None).working_dir;

            let epochs = config.epochs.clone().unwrap_or_else(|| {
                StacksEpoch::unit_test_pre_2_05(config.burnchain.first_block_height)
            });

            let mut sortdb = SortitionDB::connect(
                &config.burnchain.get_db_path(),
                config.burnchain.first_block_height,
                &config.burnchain.first_block_hash,
                0,
                &epochs,
                config.burnchain.pox_constants.clone(),
                None,
                true,
            )
            .unwrap();

            let first_burnchain_block_height = config.burnchain.first_block_height;
            let first_burnchain_block_hash = config.burnchain.first_block_hash;

            let _burnchain_blocks_db = BurnchainDB::connect(
                &config.burnchain.get_burnchaindb_path(),
                &config.burnchain,
                true,
            )
            .unwrap();

            let chainstate_path = get_chainstate_path_str(&test_path);
            let peerdb_path = format!("{}/peers.sqlite", &test_path);

            let mut peerdb = PeerDB::connect(
                &peerdb_path,
                true,
                config.network_id,
                config.burnchain.network_id,
                None,
                config.private_key_expire,
                PeerAddress::from_ipv4(127, 0, 0, 1),
                config.server_port,
                config.data_url.clone(),
                &config.asn4_entries,
                Some(&config.initial_neighbors),
                &config.stacker_dbs,
            )
            .unwrap();
            {
                // bootstrap nodes *always* allowed
                let tx = peerdb.tx_begin().unwrap();
                for initial_neighbor in config.initial_neighbors.iter() {
                    PeerDB::set_allow_peer(
                        &tx,
                        initial_neighbor.addr.network_id,
                        &initial_neighbor.addr.addrbytes,
                        initial_neighbor.addr.port,
                        -1,
                    )
                    .unwrap();
                }
                PeerDB::set_local_services(&tx, config.services).unwrap();
                tx.commit().unwrap();
            }

            let atlasdb_path = format!("{}/atlas.sqlite", &test_path);
            let atlasdb = AtlasDB::connect(AtlasConfig::new(false), &atlasdb_path, true).unwrap();

            let agg_pub_key_opt = config.aggregate_public_key.clone();

            let conf = config.clone();
            let post_flight_callback = move |clarity_tx: &mut ClarityTx| {
                let mut receipts = vec![];

                if let Some(agg_pub_key) = agg_pub_key_opt {
                    debug!("Setting aggregate public key to {}", &to_hex(&agg_pub_key));
                    NakamotoChainState::aggregate_public_key_bootcode(clarity_tx, agg_pub_key);
                } else {
                    debug!("Not setting aggregate public key");
                }
                // add test-specific boot code
                if !conf.setup_code.is_empty() {
                    let receipt = clarity_tx.connection().as_transaction(|clarity| {
                        let boot_code_addr = boot_code_test_addr();
                        let boot_code_account = StacksAccount {
                            principal: boot_code_addr.to_account_principal(),
                            nonce: 0,
                            stx_balance: STXBalance::zero(),
                        };

                        let boot_code_auth = boot_code_tx_auth(boot_code_addr);

                        debug!(
                            "Instantiate test-specific boot code contract '{}.{}' ({} bytes)...",
                            &boot_code_addr.to_string(),
                            &conf.test_name,
                            conf.setup_code.len()
                        );

                        let smart_contract = TransactionPayload::SmartContract(
                            TransactionSmartContract {
                                name: ContractName::try_from(
                                    conf.test_name
                                        .replace("::", "-")
                                        .chars()
                                        .skip(
                                            conf.test_name
                                                .len()
                                                .saturating_sub(CONTRACT_MAX_NAME_LENGTH),
                                        )
                                        .collect::<String>()
                                        .trim_start_matches(|c: char| !c.is_alphabetic())
                                        .to_string(),
                                )
                                .expect("FATAL: invalid boot-code contract name"),
                                code_body: StacksString::from_str(&conf.setup_code)
                                    .expect("FATAL: invalid boot code body"),
                            },
                            None,
                        );

                        let boot_code_smart_contract = StacksTransaction::new(
                            TransactionVersion::Testnet,
                            boot_code_auth.clone(),
                            smart_contract,
                        );
                        StacksChainState::process_transaction_payload(
                            clarity,
                            &boot_code_smart_contract,
                            &boot_code_account,
                            ASTRules::PrecheckSize,
                        )
                        .unwrap()
                    });
                    receipts.push(receipt);
                }
                debug!("Bootup receipts: {:?}", &receipts);
            };

            let mut boot_data = ChainStateBootData::new(
                &config.burnchain,
                config.initial_balances.clone(),
                Some(Box::new(post_flight_callback)),
            );

            if !config.initial_lockups.is_empty() {
                let lockups = config.initial_lockups.clone();
                boot_data.get_bulk_initial_lockups =
                    Some(Box::new(move || Box::new(lockups.into_iter())));
            }

            let (chainstate, _) = StacksChainState::open_and_exec(
                false,
                config.network_id,
                &chainstate_path,
                Some(&mut boot_data),
                None,
            )
            .unwrap();

            let indexer = BitcoinIndexer::new_unit_test(&config.burnchain.working_dir);
            let mut coord = ChainsCoordinator::test_new_full(
                &config.burnchain,
                config.network_id,
                &test_path,
                OnChainRewardSetProvider(observer),
                observer,
                indexer,
                None,
            );
            coord.handle_new_burnchain_block().unwrap();

            let mut stacks_node = TestStacksNode::from_chainstate(chainstate);

            {
                // pre-populate burnchain, if running on bitcoin
                let prev_snapshot = SortitionDB::get_first_block_snapshot(sortdb.conn()).unwrap();
                let mut fork = TestBurnchainFork::new(
                    prev_snapshot.block_height,
                    &prev_snapshot.burn_header_hash,
                    &prev_snapshot.index_root,
                    0,
                );
                for i in prev_snapshot.block_height..config.current_block {
                    let burn_block = {
                        let ic = sortdb.index_conn();
                        let mut burn_block = fork.next_block(&ic);
                        stacks_node.add_key_register(&mut burn_block, &mut miner);
                        burn_block
                    };
                    fork.append_block(burn_block);

                    fork.mine_pending_blocks_pox(&mut sortdb, &config.burnchain, &mut coord);
                }
            }

            let local_addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config.server_port);
            let http_local_addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), config.http_port);

            {
                let tx = peerdb.tx_begin().unwrap();
                PeerDB::set_local_ipaddr(
                    &tx,
                    &PeerAddress::from_socketaddr(&SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        config.server_port,
                    )),
                    config.server_port,
                )
                .unwrap();
                PeerDB::set_local_private_key(&tx, &config.private_key, config.private_key_expire)
                    .unwrap();

                tx.commit().unwrap();
            }

            let local_peer = PeerDB::get_local_peer(peerdb.conn()).unwrap();
            let burnchain_view = {
                let chaintip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn()).unwrap();
                SortitionDB::get_burnchain_view(&sortdb.index_conn(), &config.burnchain, &chaintip)
                    .unwrap()
            };
            let stackerdb_path = format!("{}/stacker_db.sqlite", &test_path);
            let mut stacker_dbs_conn = StackerDBs::connect(&stackerdb_path, true).unwrap();
            let relayer_stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();
            let p2p_stacker_dbs = StackerDBs::connect(&stackerdb_path, true).unwrap();

            let mut old_stackerdb_configs = HashMap::new();
            for (i, contract) in config.stacker_dbs.iter().enumerate() {
                old_stackerdb_configs.insert(
                    contract.clone(),
                    config
                        .stacker_db_configs
                        .get(i)
                        .map(|config| config.clone().unwrap_or(StackerDBConfig::noop()))
                        .unwrap_or(StackerDBConfig::noop()),
                );
            }
            let mut stackerdb_configs = stacker_dbs_conn
                .create_or_reconfigure_stackerdbs(
                    &mut stacks_node.chainstate,
                    &sortdb,
                    old_stackerdb_configs,
                    &config.connection_opts,
                )
                .expect("Failed to refresh stackerdb configs");

            let stacker_db_syncs =
                Self::init_stackerdb_syncs(&test_path, &peerdb, &mut stackerdb_configs);

            let stackerdb_contracts: Vec<_> =
                stacker_db_syncs.keys().map(|cid| cid.clone()).collect();

            let burnchain_db = config.burnchain.open_burnchain_db(false).unwrap();

            let mut peer_network = PeerNetwork::new(
                peerdb,
                atlasdb,
                p2p_stacker_dbs,
                burnchain_db,
                local_peer,
                config.peer_version,
                config.burnchain.clone(),
                burnchain_view,
                config.connection_opts.clone(),
                stacker_db_syncs,
                epochs.clone(),
            );
            peer_network.set_stacker_db_configs(config.get_stacker_db_configs());

            peer_network.bind(&local_addr, &http_local_addr).unwrap();
            let relayer = Relayer::from_p2p(&mut peer_network, relayer_stacker_dbs);
            let mempool = MemPoolDB::open_test(false, config.network_id, &chainstate_path).unwrap();
            let indexer = BitcoinIndexer::new_unit_test(&config.burnchain.working_dir);

            // extract bound ports (which may be different from what's in the config file, if e.g.
            // they were 0)
            let p2p_port = peer_network.bound_neighbor_key().port;
            let http_port = peer_network.http.as_ref().unwrap().http_server_addr.port();

            debug!("Bound to (p2p={}, http={})", p2p_port, http_port);
            config.server_port = p2p_port;
            config.http_port = http_port;

            config.data_url =
                UrlString::try_from(format!("http://127.0.0.1:{}", http_port).as_str()).unwrap();

            peer_network
                .peerdb
                .update_local_peer(
                    config.network_id,
                    config.burnchain.network_id,
                    config.data_url.clone(),
                    p2p_port,
                    &stackerdb_contracts,
                )
                .unwrap();

            let local_peer = PeerDB::get_local_peer(peer_network.peerdb.conn()).unwrap();
            debug!(
                "{:?}: initial neighbors: {:?}",
                &local_peer, &config.initial_neighbors
            );
            peer_network.local_peer = local_peer;

            TestPeer {
                config,
                network: peer_network,
                sortdb: Some(sortdb),
                miner,
                stacks_node: Some(stacks_node),
                relayer,
                mempool: Some(mempool),
                chainstate_path,
                coord,
                indexer: Some(indexer),
                malleablized_blocks: vec![],
                mine_malleablized_blocks: true,
                nakamoto_parent_tenure_opt: None,
            }
        }

        pub fn connect_initial(&mut self) -> Result<(), net_error> {
            let local_peer = PeerDB::get_local_peer(self.network.peerdb.conn()).unwrap();
            let chain_view = match self.sortdb {
                Some(ref mut sortdb) => {
                    let chaintip =
                        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
                    SortitionDB::get_burnchain_view(
                        &sortdb.index_conn(),
                        &self.config.burnchain,
                        &chaintip,
                    )
                    .unwrap()
                }
                None => panic!("Misconfigured peer: no sortdb"),
            };

            self.network.local_peer = local_peer;
            self.network.chain_view = chain_view;

            for n in self.config.initial_neighbors.iter() {
                self.network.connect_peer(&n.addr).map(|_| ())?;
            }
            Ok(())
        }

        pub fn local_peer(&self) -> &LocalPeer {
            &self.network.local_peer
        }

        pub fn add_neighbor(
            &mut self,
            n: &mut Neighbor,
            stacker_dbs: Option<&[QualifiedContractIdentifier]>,
            bootstrap: bool,
        ) {
            let tx = self.network.peerdb.tx_begin().unwrap();
            n.save(&tx, stacker_dbs).unwrap();
            if bootstrap {
                PeerDB::set_initial_peer(
                    &tx,
                    self.config.network_id,
                    &n.addr.addrbytes,
                    n.addr.port,
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }

        // TODO: DRY up from PoxSyncWatchdog
        pub fn infer_initial_burnchain_block_download(
            burnchain: &Burnchain,
            last_processed_height: u64,
            burnchain_height: u64,
        ) -> bool {
            let ibd =
                last_processed_height + (burnchain.stable_confirmations as u64) < burnchain_height;
            if ibd {
                debug!(
                    "PoX watchdog: {} + {} < {}, so initial block download",
                    last_processed_height, burnchain.stable_confirmations, burnchain_height
                );
            } else {
                debug!(
                    "PoX watchdog: {} + {} >= {}, so steady-state",
                    last_processed_height, burnchain.stable_confirmations, burnchain_height
                );
            }
            ibd
        }

        pub fn step(&mut self) -> Result<NetworkResult, net_error> {
            let sortdb = self.sortdb.take().unwrap();
            let stacks_node = self.stacks_node.take().unwrap();
            let burn_tip_height = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .unwrap()
                .block_height;
            let stacks_tip_height = NakamotoChainState::get_canonical_block_header(
                stacks_node.chainstate.db(),
                &sortdb,
            )
            .unwrap()
            .map(|hdr| hdr.anchored_header.height())
            .unwrap_or(0);
            let ibd = TestPeer::infer_initial_burnchain_block_download(
                &self.config.burnchain,
                stacks_tip_height,
                burn_tip_height,
            );
            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);

            self.step_with_ibd(ibd)
        }

        pub fn step_with_ibd(&mut self, ibd: bool) -> Result<NetworkResult, net_error> {
            self.step_with_ibd_and_dns(ibd, None)
        }

        pub fn step_with_ibd_and_dns(
            &mut self,
            ibd: bool,
            dns_client: Option<&mut DNSClient>,
        ) -> Result<NetworkResult, net_error> {
            let sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();
            let indexer = self.indexer.take().unwrap();

            let old_tip = self.network.stacks_tip.clone();

            let ret = self.network.run(
                &indexer,
                &sortdb,
                &mut stacks_node.chainstate,
                &mut mempool,
                dns_client,
                false,
                ibd,
                100,
                &RPCHandlerArgs::default(),
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
            self.mempool = Some(mempool);
            self.indexer = Some(indexer);

            ret
        }

        pub fn run_with_ibd(
            &mut self,
            ibd: bool,
            dns_client: Option<&mut DNSClient>,
        ) -> Result<(NetworkResult, ProcessedNetReceipts), net_error> {
            let net_result = self.step_with_ibd_and_dns(ibd, dns_client)?;
            let mut sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();
            let indexer = self.indexer.take().unwrap();

            let receipts_res = self.relayer.process_network_result(
                self.network.get_local_peer(),
                &mut net_result.clone(),
                &self.network.burnchain,
                &mut sortdb,
                &mut stacks_node.chainstate,
                &mut mempool,
                ibd,
                None,
                None,
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
            self.mempool = Some(mempool);
            self.indexer = Some(indexer);

            self.coord.handle_new_burnchain_block().unwrap();
            self.coord.handle_new_stacks_block().unwrap();
            self.coord.handle_new_nakamoto_stacks_block().unwrap();

            receipts_res.map(|receipts| (net_result, receipts))
        }

        pub fn step_dns(&mut self, dns_client: &mut DNSClient) -> Result<NetworkResult, net_error> {
            let sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();
            let indexer = BitcoinIndexer::new_unit_test(&self.config.burnchain.working_dir);

            let burn_tip_height = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .unwrap()
                .block_height;
            let stacks_tip_height = NakamotoChainState::get_canonical_block_header(
                stacks_node.chainstate.db(),
                &sortdb,
            )
            .unwrap()
            .map(|hdr| hdr.anchored_header.height())
            .unwrap_or(0);
            let ibd = TestPeer::infer_initial_burnchain_block_download(
                &self.config.burnchain,
                stacks_tip_height,
                burn_tip_height,
            );
            let indexer = BitcoinIndexer::new_unit_test(&self.config.burnchain.working_dir);

            let old_tip = self.network.stacks_tip.clone();

            let ret = self.network.run(
                &indexer,
                &sortdb,
                &mut stacks_node.chainstate,
                &mut mempool,
                Some(dns_client),
                false,
                ibd,
                100,
                &RPCHandlerArgs::default(),
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
            self.mempool = Some(mempool);

            ret
        }

        pub fn refresh_burnchain_view(&mut self) {
            let sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let indexer = BitcoinIndexer::new_unit_test(&self.config.burnchain.working_dir);

            self.network
                .refresh_burnchain_view(&indexer, &sortdb, &mut stacks_node.chainstate, false)
                .unwrap();

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
        }

        pub fn refresh_reward_cycles(&mut self) {
            let sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();

            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let tip_block_id = self.network.stacks_tip.block_id();
            let tip_height = self.network.stacks_tip.height;

            self.network
                .refresh_reward_cycles(
                    &sortdb,
                    &mut stacks_node.chainstate,
                    &tip,
                    &tip_block_id,
                    tip_height,
                )
                .unwrap();

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
        }

        pub fn for_each_convo_p2p<F, R>(&mut self, mut f: F) -> Vec<Result<R, net_error>>
        where
            F: FnMut(usize, &mut ConversationP2P) -> Result<R, net_error>,
        {
            let mut ret = vec![];
            for (event_id, convo) in self.network.peers.iter_mut() {
                let res = f(*event_id, convo);
                ret.push(res);
            }
            ret
        }

        pub fn get_burnchain_db(&self, readwrite: bool) -> BurnchainDB {
            let burnchain_db =
                BurnchainDB::open(&self.config.burnchain.get_burnchaindb_path(), readwrite)
                    .unwrap();
            burnchain_db
        }

        pub fn get_sortition_at_height(&self, height: u64) -> Option<BlockSnapshot> {
            let sortdb = self.sortdb.as_ref().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let sort_handle = sortdb.index_handle(&tip.sortition_id);
            sort_handle.get_block_snapshot_by_height(height).unwrap()
        }

        pub fn get_burnchain_block_ops(
            &self,
            burn_block_hash: &BurnchainHeaderHash,
        ) -> Vec<BlockstackOperationType> {
            let burnchain_db =
                BurnchainDB::open(&self.config.burnchain.get_burnchaindb_path(), false).unwrap();
            burnchain_db
                .get_burnchain_block_ops(burn_block_hash)
                .unwrap()
        }

        pub fn get_burnchain_block_ops_at_height(
            &self,
            height: u64,
        ) -> Option<Vec<BlockstackOperationType>> {
            let sortdb = self.sortdb.as_ref().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let sort_handle = sortdb.index_handle(&tip.sortition_id);
            let Some(sn) = sort_handle.get_block_snapshot_by_height(height).unwrap() else {
                return None;
            };
            Some(self.get_burnchain_block_ops(&sn.burn_header_hash))
        }

        pub fn next_burnchain_block(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, true, true, true, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_diverge(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, true, true, true, true);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_and_missing_pox_anchor(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            self.inner_next_burnchain_block(blockstack_ops, true, true, true, false)
        }

        pub fn next_burnchain_block_raw(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, false, false, true, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_raw_sortition_only(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let x = self.inner_next_burnchain_block(blockstack_ops, false, false, false, false);
            (x.0, x.1, x.2)
        }

        pub fn next_burnchain_block_raw_and_missing_pox_anchor(
            &mut self,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            self.inner_next_burnchain_block(blockstack_ops, false, false, true, false)
        }

        pub fn set_ops_consensus_hash(
            blockstack_ops: &mut Vec<BlockstackOperationType>,
            ch: &ConsensusHash,
        ) {
            for op in blockstack_ops.iter_mut() {
                match op {
                    BlockstackOperationType::LeaderKeyRegister(ref mut data) => {
                        data.consensus_hash = (*ch).clone();
                    }
                    _ => {}
                }
            }
        }

        pub fn set_ops_burn_header_hash(
            blockstack_ops: &mut Vec<BlockstackOperationType>,
            bhh: &BurnchainHeaderHash,
        ) {
            for op in blockstack_ops.iter_mut() {
                op.set_burn_header_hash(bhh.clone());
            }
        }

        pub fn make_next_burnchain_block(
            burnchain: &Burnchain,
            tip_block_height: u64,
            tip_block_hash: &BurnchainHeaderHash,
            num_ops: u64,
            ops_determine_block_header: bool,
        ) -> BurnchainBlockHeader {
            test_debug!(
                "make_next_burnchain_block: tip_block_height={} tip_block_hash={} num_ops={}",
                tip_block_height,
                tip_block_hash,
                num_ops
            );
            let indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);
            let parent_hdr = indexer
                .read_burnchain_header(tip_block_height)
                .unwrap()
                .unwrap();

            test_debug!("parent hdr ({}): {:?}", &tip_block_height, &parent_hdr);
            assert_eq!(&parent_hdr.block_hash, tip_block_hash);

            let now = BURNCHAIN_TEST_BLOCK_TIME;
            let block_header_hash = BurnchainHeaderHash::from_bitcoin_hash(
                &BitcoinIndexer::mock_bitcoin_header(
                    &parent_hdr.block_hash,
                    (now as u32)
                        + if ops_determine_block_header {
                            num_ops as u32
                        } else {
                            0
                        },
                )
                .bitcoin_hash(),
            );
            test_debug!(
                "Block header hash at {} is {}",
                tip_block_height + 1,
                &block_header_hash
            );

            let block_header = BurnchainBlockHeader {
                block_height: tip_block_height + 1,
                block_hash: block_header_hash.clone(),
                parent_block_hash: parent_hdr.block_hash.clone(),
                num_txs: num_ops,
                timestamp: now,
            };

            block_header
        }

        pub fn add_burnchain_block(
            burnchain: &Burnchain,
            block_header: &BurnchainBlockHeader,
            blockstack_ops: Vec<BlockstackOperationType>,
        ) {
            let mut burnchain_db =
                BurnchainDB::open(&burnchain.get_burnchaindb_path(), true).unwrap();

            let mut indexer = BitcoinIndexer::new_unit_test(&burnchain.working_dir);

            test_debug!(
                "Store header and block ops for {}-{} ({})",
                &block_header.block_hash,
                &block_header.parent_block_hash,
                block_header.block_height
            );
            indexer.raw_store_header(block_header.clone()).unwrap();
            burnchain_db
                .raw_store_burnchain_block(
                    &burnchain,
                    &indexer,
                    block_header.clone(),
                    blockstack_ops,
                )
                .unwrap();

            Burnchain::process_affirmation_maps(
                &burnchain,
                &mut burnchain_db,
                &indexer,
                block_header.block_height,
            )
            .unwrap();
        }

        /// Generate and commit the next burnchain block with the given block operations.
        /// * if `set_consensus_hash` is true, then each op's consensus_hash field will be set to
        /// that of the resulting block snapshot.
        /// * if `set_burn_hash` is true, then each op's burnchain header hash field will be set to
        /// that of the resulting block snapshot.
        ///
        /// Returns (
        ///     burnchain tip block height,
        ///     burnchain tip block hash,
        ///     burnchain tip consensus hash,
        ///     Option<missing PoX anchor block hash>
        /// )
        fn inner_next_burnchain_block(
            &mut self,
            mut blockstack_ops: Vec<BlockstackOperationType>,
            set_consensus_hash: bool,
            set_burn_hash: bool,
            update_burnchain: bool,
            ops_determine_block_header: bool,
        ) -> (
            u64,
            BurnchainHeaderHash,
            ConsensusHash,
            Option<BlockHeaderHash>,
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let (block_height, block_hash, epoch_id) = {
                let tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn()).unwrap();
                let epoch_id = SortitionDB::get_stacks_epoch(&sortdb.conn(), tip.block_height + 1)
                    .unwrap()
                    .unwrap()
                    .epoch_id;

                if set_consensus_hash {
                    TestPeer::set_ops_consensus_hash(&mut blockstack_ops, &tip.consensus_hash);
                }

                let block_header = Self::make_next_burnchain_block(
                    &self.config.burnchain,
                    tip.block_height,
                    &tip.burn_header_hash,
                    blockstack_ops.len() as u64,
                    ops_determine_block_header,
                );

                if set_burn_hash {
                    TestPeer::set_ops_burn_header_hash(
                        &mut blockstack_ops,
                        &block_header.block_hash,
                    );
                }

                if update_burnchain {
                    Self::add_burnchain_block(
                        &self.config.burnchain,
                        &block_header,
                        blockstack_ops.clone(),
                    );
                }
                (block_header.block_height, block_header.block_hash, epoch_id)
            };

            let missing_pox_anchor_block_hash_opt = if epoch_id < StacksEpochId::Epoch30 {
                self.coord
                    .handle_new_burnchain_block()
                    .unwrap()
                    .into_missing_block_hash()
            } else if self.coord.handle_new_nakamoto_burnchain_block().unwrap() {
                None
            } else {
                Some(BlockHeaderHash([0x00; 32]))
            };

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };

            test_debug!(
                "\n\n{:?}: after burn block {:?}, tip PoX ID is {:?}\n\n",
                &self.to_neighbor().addr,
                &block_hash,
                &pox_id
            );

            let tip = SortitionDB::get_canonical_burn_chain_tip(&sortdb.conn()).unwrap();
            self.sortdb = Some(sortdb);
            (
                block_height,
                block_hash,
                tip.consensus_hash,
                missing_pox_anchor_block_hash_opt,
            )
        }

        /// Pre-process an epoch 2.x Stacks block.
        /// Validate it and store it to staging.
        pub fn preprocess_stacks_block(&mut self, block: &StacksBlock) -> Result<bool, String> {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res = {
                let sn = {
                    let ic = sortdb.index_conn();
                    let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                    let sn_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &block.block_hash(),
                    )
                    .unwrap();
                    if sn_opt.is_none() {
                        return Err(format!(
                            "No such block in canonical burn fork: {}",
                            &block.block_hash()
                        ));
                    }
                    sn_opt.unwrap()
                };

                let parent_sn = {
                    let db_handle = sortdb.index_handle(&sn.sortition_id);
                    let parent_sn = db_handle
                        .get_block_snapshot(&sn.parent_burn_header_hash)
                        .unwrap();
                    parent_sn.unwrap()
                };

                let ic = sortdb.index_conn();
                node.chainstate
                    .preprocess_anchored_block(
                        &ic,
                        &sn.consensus_hash,
                        block,
                        &parent_sn.consensus_hash,
                        5,
                    )
                    .map_err(|e| format!("Failed to preprocess anchored block: {:?}", &e))
            };
            if res.is_ok() {
                let pox_id = {
                    let ic = sortdb.index_conn();
                    let tip_sort_id =
                        SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                    let sortdb_reader =
                        SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                    sortdb_reader.get_pox_id().unwrap()
                };
                test_debug!(
                    "\n\n{:?}: after stacks block {:?}, tip PoX ID is {:?}\n\n",
                    &self.to_neighbor().addr,
                    &block.block_hash(),
                    &pox_id
                );
                self.coord.handle_new_stacks_block().unwrap();
            }

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Preprocess epoch 2.x microblocks.
        /// Validate them and store them to staging.
        pub fn preprocess_stacks_microblocks(
            &mut self,
            microblocks: &[StacksMicroblock],
        ) -> Result<bool, String> {
            assert!(!microblocks.is_empty());
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res = {
                let anchor_block_hash = microblocks[0].header.prev_block.clone();
                let sn = {
                    let ic = sortdb.index_conn();
                    let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                    let sn_opt = SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &anchor_block_hash,
                    )
                    .unwrap();
                    if sn_opt.is_none() {
                        return Err(format!(
                            "No such block in canonical burn fork: {}",
                            &anchor_block_hash
                        ));
                    }
                    sn_opt.unwrap()
                };

                let mut res = Ok(true);
                for mblock in microblocks.iter() {
                    res = node
                        .chainstate
                        .preprocess_streamed_microblock(
                            &sn.consensus_hash,
                            &anchor_block_hash,
                            mblock,
                        )
                        .map_err(|e| format!("Failed to preprocess microblock: {:?}", &e));

                    if res.is_err() {
                        break;
                    }
                }
                res
            };

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Store the given epoch 2.x Stacks block and microblock to staging, and then try and
        /// process them.
        pub fn process_stacks_epoch_at_tip(
            &mut self,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            {
                let ic = sortdb.index_conn();
                let tip = SortitionDB::get_canonical_burn_chain_tip(&ic).unwrap();
                node.chainstate
                    .preprocess_stacks_epoch(&ic, &tip, block, microblocks)
                    .unwrap();
            }
            self.coord.handle_new_stacks_block().unwrap();

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };
            test_debug!(
                "\n\n{:?}: after stacks block {:?}, tip PoX ID is {:?}\n\n",
                &self.to_neighbor().addr,
                &block.block_hash(),
                &pox_id
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        /// Store the given epoch 2.x Stacks block and microblock to the given node's staging,
        /// using the given sortition DB as well, and then try and process them.
        fn inner_process_stacks_epoch_at_tip(
            &mut self,
            sortdb: &SortitionDB,
            node: &mut TestStacksNode,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) -> Result<(), coordinator_error> {
            {
                let ic = sortdb.index_conn();
                let tip = SortitionDB::get_canonical_burn_chain_tip(&ic)?;
                node.chainstate
                    .preprocess_stacks_epoch(&ic, &tip, block, microblocks)?;
            }
            self.coord.handle_new_stacks_block()?;

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn())?;
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id)?;
                sortdb_reader.get_pox_id()?;
            };
            test_debug!(
                "\n\n{:?}: after stacks block {:?}, tip PoX ID is {:?}\n\n",
                &self.to_neighbor().addr,
                &block.block_hash(),
                &pox_id
            );
            Ok(())
        }

        /// Store the given epoch 2.x Stacks block and microblock to the given node's staging,
        /// and then try and process them.
        pub fn process_stacks_epoch_at_tip_checked(
            &mut self,
            block: &StacksBlock,
            microblocks: &[StacksMicroblock],
        ) -> Result<(), coordinator_error> {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let res =
                self.inner_process_stacks_epoch_at_tip(&sortdb, &mut node, block, microblocks);
            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            res
        }

        /// Accept a new Stacks block and microblocks via the relayer, and then try to process
        /// them.
        pub fn process_stacks_epoch(
            &mut self,
            block: &StacksBlock,
            consensus_hash: &ConsensusHash,
            microblocks: &[StacksMicroblock],
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            {
                let ic = sortdb.index_conn();
                Relayer::process_new_anchored_block(
                    &ic,
                    &mut node.chainstate,
                    consensus_hash,
                    block,
                    0,
                )
                .unwrap();

                let block_hash = block.block_hash();
                for mblock in microblocks.iter() {
                    node.chainstate
                        .preprocess_streamed_microblock(consensus_hash, &block_hash, mblock)
                        .unwrap();
                }
            }
            self.coord.handle_new_stacks_block().unwrap();

            let pox_id = {
                let ic = sortdb.index_conn();
                let tip_sort_id = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
                let sortdb_reader = SortitionHandleConn::open_reader(&ic, &tip_sort_id).unwrap();
                sortdb_reader.get_pox_id().unwrap()
            };

            test_debug!(
                "\n\n{:?}: after stacks block {:?}, tip PoX ID is {:?}\n\n",
                &self.to_neighbor().addr,
                &block.block_hash(),
                &pox_id
            );

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        pub fn add_empty_burnchain_block(&mut self) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            self.next_burnchain_block(vec![])
        }

        pub fn mine_empty_tenure(&mut self) -> (u64, BurnchainHeaderHash, ConsensusHash) {
            let (burn_ops, ..) = self.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
            let result = self.next_burnchain_block(burn_ops);
            // remove the last block commit so that the testpeer doesn't try to build off of this tenure
            self.miner.block_commits.pop();
            result
        }

        pub fn mempool(&mut self) -> &mut MemPoolDB {
            self.mempool.as_mut().unwrap()
        }

        pub fn chainstate(&mut self) -> &mut StacksChainState {
            &mut self.stacks_node.as_mut().unwrap().chainstate
        }

        pub fn chainstate_ref(&self) -> &StacksChainState {
            &self.stacks_node.as_ref().unwrap().chainstate
        }

        pub fn sortdb(&mut self) -> &mut SortitionDB {
            self.sortdb.as_mut().unwrap()
        }

        pub fn sortdb_ref(&mut self) -> &SortitionDB {
            self.sortdb.as_ref().unwrap()
        }

        pub fn with_dbs<F, R>(&mut self, f: F) -> R
        where
            F: FnOnce(&mut TestPeer, &mut SortitionDB, &mut TestStacksNode, &mut MemPoolDB) -> R,
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();

            let res = f(self, &mut sortdb, &mut stacks_node, &mut mempool);

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            self.mempool = Some(mempool);
            res
        }

        pub fn with_db_state<F, R>(&mut self, f: F) -> Result<R, net_error>
        where
            F: FnOnce(
                &mut SortitionDB,
                &mut StacksChainState,
                &mut Relayer,
                &mut MemPoolDB,
            ) -> Result<R, net_error>,
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();

            let res = f(
                &mut sortdb,
                &mut stacks_node.chainstate,
                &mut self.relayer,
                &mut mempool,
            );

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            self.mempool = Some(mempool);
            res
        }

        pub fn with_mining_state<F, R>(&mut self, f: F) -> Result<R, net_error>
        where
            F: FnOnce(
                &mut SortitionDB,
                &mut TestMiner,
                &mut TestMiner,
                &mut TestStacksNode,
            ) -> Result<R, net_error>,
        {
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut sortdb = self.sortdb.take().unwrap();
            let res = f(
                &mut sortdb,
                &mut self.miner,
                &mut self.config.spending_account,
                &mut stacks_node,
            );
            self.sortdb = Some(sortdb);
            self.stacks_node = Some(stacks_node);
            res
        }

        pub fn with_network_state<F, R>(&mut self, f: F) -> Result<R, net_error>
        where
            F: FnOnce(
                &mut SortitionDB,
                &mut StacksChainState,
                &mut PeerNetwork,
                &mut Relayer,
                &mut MemPoolDB,
            ) -> Result<R, net_error>,
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();

            let res = f(
                &mut sortdb,
                &mut stacks_node.chainstate,
                &mut self.network,
                &mut self.relayer,
                &mut mempool,
            );

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            self.mempool = Some(mempool);
            res
        }

        pub fn with_peer_state<F, R>(&mut self, f: F) -> Result<R, net_error>
        where
            F: FnOnce(
                &mut TestPeer,
                &mut SortitionDB,
                &mut StacksChainState,
                &mut MemPoolDB,
            ) -> Result<R, net_error>,
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut stacks_node = self.stacks_node.take().unwrap();
            let mut mempool = self.mempool.take().unwrap();

            let res = f(self, &mut sortdb, &mut stacks_node.chainstate, &mut mempool);

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            self.mempool = Some(mempool);
            res
        }

        /// Make a tenure with the given transactions. Creates a coinbase tx with the given nonce, and then increments
        /// the provided reference.
        pub fn tenure_with_txs(
            &mut self,
            txs: &[StacksTransaction],
            coinbase_nonce: &mut usize,
        ) -> StacksBlockId {
            let microblock_privkey = self.miner.next_microblock_privkey();
            let microblock_pubkeyhash =
                Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_privkey));
            let tip =
                SortitionDB::get_canonical_burn_chain_tip(&self.sortdb.as_ref().unwrap().conn())
                    .unwrap();
            let burnchain = self.config.burnchain.clone();

            let (burn_ops, stacks_block, microblocks) = self.make_tenure(
                |ref mut miner,
                 ref mut sortdb,
                 ref mut chainstate,
                 vrf_proof,
                 ref parent_opt,
                 ref parent_microblock_header_opt| {
                    let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                    let coinbase_tx = make_coinbase(miner, *coinbase_nonce);

                    let mut block_txs = vec![coinbase_tx];
                    block_txs.extend_from_slice(txs);

                    let block_builder = StacksBlockBuilder::make_regtest_block_builder(
                        &burnchain,
                        &parent_tip,
                        vrf_proof,
                        tip.total_burn,
                        microblock_pubkeyhash,
                    )
                    .unwrap();
                    let (anchored_block, _size, _cost) =
                        StacksBlockBuilder::make_anchored_block_from_txs(
                            block_builder,
                            chainstate,
                            &sortdb.index_handle(&tip.sortition_id),
                            block_txs,
                        )
                        .unwrap();
                    (anchored_block, vec![])
                },
            );

            let (_, _, consensus_hash) = self.next_burnchain_block(burn_ops);
            self.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            *coinbase_nonce += 1;

            let tip_id = StacksBlockId::new(&consensus_hash, &stacks_block.block_hash());

            if let Some((start_check_cycle, end_check_cycle)) = self.config.check_pox_invariants {
                pox_2_tests::check_all_stacker_link_invariants(
                    self,
                    &tip_id,
                    start_check_cycle,
                    end_check_cycle,
                );
            }

            self.refresh_burnchain_view();

            let (stacks_tip_ch, stacks_tip_bh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(self.sortdb().conn()).unwrap();
            assert_eq!(
                self.network.stacks_tip.block_id(),
                StacksBlockId::new(&stacks_tip_ch, &stacks_tip_bh)
            );

            tip_id
        }

        /// Make a tenure, using `tenure_builder` to generate a Stacks block and a list of
        /// microblocks.
        pub fn make_tenure<F>(
            &mut self,
            mut tenure_builder: F,
        ) -> (
            Vec<BlockstackOperationType>,
            StacksBlock,
            Vec<StacksMicroblock>,
        )
        where
            F: FnMut(
                &mut TestMiner,
                &mut SortitionDB,
                &mut StacksChainState,
                VRFProof,
                Option<&StacksBlock>,
                Option<&StacksMicroblockHeader>,
            ) -> (StacksBlock, Vec<StacksMicroblock>),
        {
            let mut sortdb = self.sortdb.take().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

            let mut burn_block = TestBurnchainBlock::new(&tip, 0);
            let mut stacks_node = self.stacks_node.take().unwrap();

            let parent_block_opt = stacks_node.get_last_anchored_block(&self.miner);
            let parent_sortition_opt = match parent_block_opt.as_ref() {
                Some(parent_block) => {
                    let ic = sortdb.index_conn();
                    SortitionDB::get_block_snapshot_for_winning_stacks_block(
                        &ic,
                        &tip.sortition_id,
                        &parent_block.block_hash(),
                    )
                    .unwrap()
                }
                None => None,
            };

            let parent_microblock_header_opt =
                get_last_microblock_header(&stacks_node, &self.miner, parent_block_opt.as_ref());
            let last_key = stacks_node.get_last_key(&self.miner);

            let network_id = self.config.network_id;
            let chainstate_path = self.chainstate_path.clone();
            let burn_block_height = burn_block.block_height;

            let proof = self
                .miner
                .make_proof(
                    &last_key.public_key,
                    &burn_block.parent_snapshot.sortition_hash,
                )
                .expect(&format!(
                    "FATAL: no private key for {}",
                    last_key.public_key.to_hex()
                ));

            let (stacks_block, microblocks) = tenure_builder(
                &mut self.miner,
                &mut sortdb,
                &mut stacks_node.chainstate,
                proof,
                parent_block_opt.as_ref(),
                parent_microblock_header_opt.as_ref(),
            );

            let mut block_commit_op = stacks_node.make_tenure_commitment(
                &sortdb,
                &mut burn_block,
                &mut self.miner,
                &stacks_block,
                microblocks.clone(),
                1000,
                &last_key,
                parent_sortition_opt.as_ref(),
            );

            // patch up block-commit -- these blocks all mine off of genesis
            if stacks_block.header.parent_block == BlockHeaderHash([0u8; 32]) {
                block_commit_op.parent_block_ptr = 0;
                block_commit_op.parent_vtxindex = 0;
            }

            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);

            // patch in reward set info
            match get_next_recipients(
                &tip,
                &mut stacks_node.chainstate,
                &mut sortdb,
                &self.config.burnchain,
                &OnChainRewardSetProvider::new(),
                true,
            ) {
                Ok(recipients) => {
                    block_commit_op.commit_outs = match recipients {
                        Some(info) => {
                            let mut recipients = info
                                .recipients
                                .into_iter()
                                .map(|x| x.0)
                                .collect::<Vec<PoxAddress>>();
                            if recipients.len() == 1 {
                                recipients.push(PoxAddress::standard_burn_address(false));
                            }
                            recipients
                        }
                        None => {
                            if self
                                .config
                                .burnchain
                                .is_in_prepare_phase(burn_block.block_height)
                            {
                                vec![PoxAddress::standard_burn_address(false)]
                            } else {
                                vec![
                                    PoxAddress::standard_burn_address(false),
                                    PoxAddress::standard_burn_address(false),
                                ]
                            }
                        }
                    };
                    test_debug!(
                        "Block commit at height {} has {} recipients: {:?}",
                        block_commit_op.block_height,
                        block_commit_op.commit_outs.len(),
                        &block_commit_op.commit_outs
                    );
                }
                Err(e) => {
                    panic!("Failure fetching recipient set: {:?}", e);
                }
            };

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            (
                vec![
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    BlockstackOperationType::LeaderBlockCommit(block_commit_op),
                ],
                stacks_block,
                microblocks,
            )
        }

        /// Produce a default, non-empty tenure for epoch 2.x
        pub fn make_default_tenure(
            &mut self,
        ) -> (
            Vec<BlockstackOperationType>,
            StacksBlock,
            Vec<StacksMicroblock>,
        ) {
            let sortdb = self.sortdb.take().unwrap();
            let mut burn_block = {
                let sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
                TestBurnchainBlock::new(&sn, 0)
            };

            let mut stacks_node = self.stacks_node.take().unwrap();

            let parent_block_opt = stacks_node.get_last_anchored_block(&self.miner);
            let parent_microblock_header_opt =
                get_last_microblock_header(&stacks_node, &self.miner, parent_block_opt.as_ref());
            let last_key = stacks_node.get_last_key(&self.miner);

            let network_id = self.config.network_id;
            let chainstate_path = self.chainstate_path.clone();
            let burn_block_height = burn_block.block_height;

            let (stacks_block, microblocks, block_commit_op) = stacks_node.mine_stacks_block(
                &sortdb,
                &mut self.miner,
                &mut burn_block,
                &last_key,
                parent_block_opt.as_ref(),
                1000,
                |mut builder, ref mut miner, ref sortdb| {
                    let (mut miner_chainstate, _) =
                        StacksChainState::open(false, network_id, &chainstate_path, None).unwrap();
                    let sort_iconn = sortdb.index_handle_at_tip();

                    let mut miner_epoch_info = builder
                        .pre_epoch_begin(&mut miner_chainstate, &sort_iconn, true)
                        .unwrap();
                    let mut epoch = builder
                        .epoch_begin(&sort_iconn, &mut miner_epoch_info)
                        .unwrap()
                        .0;

                    let (stacks_block, microblocks) =
                        mine_smart_contract_block_contract_call_microblock(
                            &mut epoch,
                            &mut builder,
                            miner,
                            burn_block_height as usize,
                            parent_microblock_header_opt.as_ref(),
                        );

                    builder.epoch_finish(epoch).unwrap();
                    (stacks_block, microblocks)
                },
            );

            let leader_key_op = stacks_node.add_key_register(&mut burn_block, &mut self.miner);

            self.stacks_node = Some(stacks_node);
            self.sortdb = Some(sortdb);
            (
                vec![
                    BlockstackOperationType::LeaderKeyRegister(leader_key_op),
                    BlockstackOperationType::LeaderBlockCommit(block_commit_op),
                ],
                stacks_block,
                microblocks,
            )
        }

        pub fn to_neighbor(&self) -> Neighbor {
            self.config.to_neighbor()
        }

        pub fn to_peer_host(&self) -> PeerHost {
            self.config.to_peer_host()
        }

        pub fn get_public_key(&self) -> Secp256k1PublicKey {
            let local_peer = PeerDB::get_local_peer(&self.network.peerdb.conn()).unwrap();
            Secp256k1PublicKey::from_private(&local_peer.private_key)
        }

        pub fn get_peerdb_conn(&self) -> &DBConn {
            self.network.peerdb.conn()
        }

        pub fn get_burnchain_view(&mut self) -> Result<BurnchainView, db_error> {
            let sortdb = self.sortdb.take().unwrap();
            let view_res = {
                let chaintip =
                    SortitionDB::get_canonical_burn_chain_tip(&sortdb.index_conn()).unwrap();
                SortitionDB::get_burnchain_view(
                    &sortdb.index_conn(),
                    &self.config.burnchain,
                    &chaintip,
                )
            };
            self.sortdb = Some(sortdb);
            view_res
        }

        pub fn dump_frontier(&self) {
            let conn = self.network.peerdb.conn();
            let peers = PeerDB::get_all_peers(conn).unwrap();
            debug!("--- BEGIN ALL PEERS ({}) ---", peers.len());
            debug!("{:#?}", &peers);
            debug!("--- END ALL PEERS ({}) -----", peers.len());
        }

        pub fn p2p_socketaddr(&self) -> SocketAddr {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                self.config.server_port,
            )
        }

        pub fn make_client_convo(&self) -> ConversationP2P {
            ConversationP2P::new(
                self.config.network_id,
                self.config.peer_version,
                &self.config.burnchain,
                &SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    self.config.server_port,
                ),
                &self.config.connection_opts,
                false,
                0,
                self.config
                    .epochs
                    .clone()
                    .unwrap_or(StacksEpoch::unit_test_3_0(0)),
            )
        }

        pub fn make_client_local_peer(&self, privk: StacksPrivateKey) -> LocalPeer {
            LocalPeer::new(
                self.config.network_id,
                self.network.local_peer.parent_network_id,
                PeerAddress::from_socketaddr(&SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    self.config.server_port,
                )),
                self.config.server_port,
                Some(privk),
                u64::MAX,
                UrlString::try_from(format!("http://127.0.0.1:{}", self.config.http_port).as_str())
                    .unwrap(),
                vec![],
            )
        }

        pub fn get_burn_block_height(&self) -> u64 {
            SortitionDB::get_canonical_burn_chain_tip(
                &self.sortdb.as_ref().expect("Failed to get sortdb").conn(),
            )
            .expect("Failed to get canonical burn chain tip")
            .block_height
        }

        pub fn get_reward_cycle(&self) -> u64 {
            let block_height = self.get_burn_block_height();
            self.config
                .burnchain
                .block_height_to_reward_cycle(block_height)
                .expect(&format!(
                    "Failed to get reward cycle for block height {}",
                    block_height
                ))
        }

        /// Verify that the sortition DB migration into Nakamoto worked correctly.
        pub fn check_nakamoto_migration(&mut self) {
            let mut sortdb = self.sortdb.take().unwrap();
            let mut node = self.stacks_node.take().unwrap();
            let chainstate = &mut node.chainstate;

            let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
            let epochs = SortitionDB::get_stacks_epochs(sortdb.conn()).unwrap();
            let epoch_3_idx =
                StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap();
            let epoch_3 = epochs[epoch_3_idx].clone();

            let mut all_chain_tips = sortdb.get_all_stacks_chain_tips().unwrap();
            let mut all_preprocessed_reward_sets =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn()).unwrap();

            // see that we can reconstruct the canonical chain tips for epoch 2.5 and earlier
            // NOTE: the migration logic DOES NOT WORK and IS NOT MEANT TO WORK with Nakamoto blocks,
            // so test this only with epoch 2 blocks before the epoch2-3 transition.
            let epoch2_sns: Vec<_> = sortdb
                .get_all_snapshots()
                .unwrap()
                .into_iter()
                .filter(|sn| sn.block_height + 1 < epoch_3.start_height)
                .collect();

            let epoch2_chs: HashSet<_> = epoch2_sns
                .iter()
                .map(|sn| sn.consensus_hash.clone())
                .collect();

            let expected_epoch2_chain_tips: Vec<_> = all_chain_tips
                .clone()
                .into_iter()
                .filter(|tip| epoch2_chs.contains(&tip.1))
                .collect();

            let tx = sortdb.tx_begin().unwrap();
            tx.execute(
                "CREATE TABLE stacks_chain_tips_backup AS SELECT * FROM stacks_chain_tips;",
                NO_PARAMS,
            )
            .unwrap();
            tx.execute("DELETE FROM stacks_chain_tips;", NO_PARAMS)
                .unwrap();
            tx.commit().unwrap();

            // NOTE: this considers each and every snapshot, but we only care about epoch2.x
            sortdb.apply_schema_8_stacks_chain_tips(&tip).unwrap();
            let migrated_epoch2_chain_tips: Vec<_> = sortdb
                .get_all_stacks_chain_tips()
                .unwrap()
                .into_iter()
                .filter(|tip| epoch2_chs.contains(&tip.1))
                .collect();

            // what matters is that the last tip is the same, and that each sortition has a chain tip.
            // depending on block arrival order, different sortitions might have witnessed different
            // stacks blocks as their chain tips, however.
            assert_eq!(
                migrated_epoch2_chain_tips.last().unwrap(),
                expected_epoch2_chain_tips.last().unwrap()
            );
            assert_eq!(
                migrated_epoch2_chain_tips.len(),
                expected_epoch2_chain_tips.len()
            );

            // restore
            let tx = sortdb.tx_begin().unwrap();
            tx.execute("DROP TABLE stacks_chain_tips;", NO_PARAMS)
                .unwrap();
            tx.execute(
                "ALTER TABLE stacks_chain_tips_backup RENAME TO stacks_chain_tips;",
                NO_PARAMS,
            )
            .unwrap();
            tx.commit().unwrap();

            // see that we calculate all the prior reward set infos
            let mut expected_epoch2_reward_sets: Vec<_> =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn())
                    .unwrap()
                    .into_iter()
                    .filter(|(sort_id, rc_info)| {
                        let sn = SortitionDB::get_block_snapshot(sortdb.conn(), &sort_id)
                            .unwrap()
                            .unwrap();
                        let rc_sn = sortdb
                            .pox_constants
                            .block_height_to_reward_cycle(
                                sortdb.first_block_height,
                                sn.block_height,
                            )
                            .unwrap();
                        let rc_height = sortdb
                            .pox_constants
                            .reward_cycle_to_block_height(sortdb.first_block_height, rc_sn + 1);
                        sn.block_height <= epoch_3.start_height && sn.block_height < rc_height
                    })
                    .collect();

            let tx = sortdb.tx_begin().unwrap();
            tx.execute("CREATE TABLE preprocessed_reward_sets_backup AS SELECT * FROM preprocessed_reward_sets;", NO_PARAMS).unwrap();
            tx.execute("DELETE FROM preprocessed_reward_sets;", NO_PARAMS)
                .unwrap();
            tx.commit().unwrap();

            let migrator = SortitionDBMigrator::new(
                self.config.burnchain.clone(),
                &self.chainstate_path,
                None,
            )
            .unwrap();
            sortdb
                .apply_schema_8_preprocessed_reward_sets(&tip, migrator)
                .unwrap();

            let mut migrated_epoch2_reward_sets: Vec<_> =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn())
                    .unwrap()
                    .into_iter()
                    .filter(|(sort_id, rc_info)| {
                        let sn = SortitionDB::get_block_snapshot(sortdb.conn(), &sort_id)
                            .unwrap()
                            .unwrap();
                        sn.block_height < epoch_3.start_height
                    })
                    .collect();

            expected_epoch2_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));
            migrated_epoch2_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));

            assert_eq!(expected_epoch2_reward_sets, migrated_epoch2_reward_sets);

            let tx = sortdb.tx_begin().unwrap();
            tx.execute("DROP TABLE preprocessed_reward_sets;", NO_PARAMS)
                .unwrap();
            tx.execute(
                "ALTER TABLE preprocessed_reward_sets_backup RENAME TO preprocessed_reward_sets;",
                NO_PARAMS,
            )
            .unwrap();
            tx.commit().unwrap();

            // sanity check -- restored tables are the same
            let mut restored_chain_tips = sortdb.get_all_stacks_chain_tips().unwrap();
            let mut restored_reward_sets =
                SortitionDB::get_all_preprocessed_reward_sets(sortdb.conn()).unwrap();

            all_chain_tips.sort_by(|a, b| a.0.cmp(&b.0));
            restored_chain_tips.sort_by(|a, b| a.0.cmp(&b.0));

            all_preprocessed_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));
            restored_reward_sets.sort_by(|a, b| a.0.cmp(&b.0));

            assert_eq!(restored_chain_tips, all_chain_tips);
            assert_eq!(restored_reward_sets, all_preprocessed_reward_sets);

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
        }

        /// Verify that all malleablized blocks are duly processed
        pub fn check_malleablized_blocks(
            &self,
            all_blocks: Vec<NakamotoBlock>,
            expected_siblings: usize,
        ) {
            if !self.mine_malleablized_blocks {
                return;
            }
            for block in all_blocks.iter() {
                let sighash = block.header.signer_signature_hash();
                let siblings = self
                    .chainstate_ref()
                    .nakamoto_blocks_db()
                    .get_blocks_at_height(block.header.chain_length);

                debug!("Expect {} siblings: {:?}", expected_siblings, &siblings);
                assert_eq!(siblings.len(), expected_siblings);

                for sibling in siblings {
                    let (processed, orphaned) = NakamotoChainState::get_nakamoto_block_status(
                        self.chainstate_ref().nakamoto_blocks_db(),
                        self.chainstate_ref().db(),
                        &sibling.header.consensus_hash,
                        &sibling.header.block_hash(),
                    )
                    .unwrap()
                    .unwrap();
                    assert!(processed);
                    assert!(!orphaned);
                }
            }
        }

        /// Set the nakamoto tenure to mine on
        pub fn mine_nakamoto_on(&mut self, parent_tenure: Vec<NakamotoBlock>) {
            self.nakamoto_parent_tenure_opt = Some(parent_tenure);
        }

        /// Clear the tenure to mine on. This causes the miner to build on the canonical tip
        pub fn mine_nakamoto_on_canonical_tip(&mut self) {
            self.nakamoto_parent_tenure_opt = None;
        }

        /// Get an account off of a tip
        pub fn get_account(
            &mut self,
            tip: &StacksBlockId,
            account: &PrincipalData,
        ) -> StacksAccount {
            let sortdb = self.sortdb.take().expect("FATAL: sortdb not restored");
            let mut node = self
                .stacks_node
                .take()
                .expect("FATAL: chainstate not restored");

            let acct = node
                .chainstate
                .maybe_read_only_clarity_tx(
                    &sortdb.index_handle_at_block(&node.chainstate, tip).unwrap(),
                    tip,
                    |clarity_tx| StacksChainState::get_account(clarity_tx, account),
                )
                .unwrap()
                .unwrap();

            self.sortdb = Some(sortdb);
            self.stacks_node = Some(node);
            acct
        }
    }

    pub fn to_addr(sk: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(
            C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
            &AddressHashMode::SerializeP2PKH,
            1,
            &vec![StacksPublicKey::from_private(sk)],
        )
        .unwrap()
    }
}
