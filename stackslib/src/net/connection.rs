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

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::mpsc::{
    sync_channel, Receiver, RecvError, RecvTimeoutError, SyncSender, TryRecvError, TrySendError,
};
use std::time::Duration;
use std::{io, net};

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{QualifiedContractIdentifier, BOUND_VALUE_SERIALIZATION_HEX};
use stacks_common::codec::{StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::net::PeerAddress;
use stacks_common::util::hash::to_hex;
use stacks_common::util::pipe::*;
use stacks_common::util::secp256k1::Secp256k1PublicKey;
use stacks_common::util::{get_epoch_time_secs, log, sleep_ms};

use crate::chainstate::burn::ConsensusHash;
use crate::core::mempool::MAX_BLOOM_COUNTER_TXS;
use crate::monitoring::{update_inbound_bandwidth, update_outbound_bandwidth};
use crate::net::codec::*;
use crate::net::download::BLOCK_DOWNLOAD_INTERVAL;
use crate::net::inv::{INV_REWARD_CYCLES, INV_SYNC_INTERVAL};
use crate::net::neighbors::{
    MAX_NEIGHBOR_AGE, NEIGHBOR_REQUEST_TIMEOUT, NEIGHBOR_WALK_INTERVAL, NUM_INITIAL_WALKS,
    WALK_MAX_DURATION, WALK_MIN_DURATION, WALK_RESET_INTERVAL, WALK_RESET_PROB, WALK_RETRY_COUNT,
    WALK_SEED_PROBABILITY, WALK_STATE_TIMEOUT,
};
use crate::net::{
    Error as net_error, MessageSequence, NeighborAddress, Preamble, ProtocolFamily, RelayData,
    StacksHttp, StacksP2P,
};

/// The default maximum age in seconds of a block that can be validated by the block proposal endpoint
pub const DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS: u64 = 600;

/// Receiver notification handle.
/// When a message with the expected `seq` value arrives, send it to an expected receiver (possibly
/// in another thread) via the given `receiver_input` channel.
#[derive(Debug)]
struct ReceiverNotify<P: ProtocolFamily> {
    expected_seq: u32,
    receiver_input: SyncSender<P::Message>,
    ttl: u64, // absolute deadline by which this message needs a reply (in seconds since the epoch)
}

impl<P: ProtocolFamily> ReceiverNotify<P> {
    pub fn new(seq: u32, input: SyncSender<P::Message>, ttl: u64) -> ReceiverNotify<P> {
        ReceiverNotify {
            expected_seq: seq,
            receiver_input: input,
            ttl,
        }
    }

    /// Send this message to the waiting receiver, consuming this notification handle.
    /// May fail silently.
    pub fn send(self, msg: P::Message) {
        let msg_name = msg.get_message_name().to_string();
        let msg_id = msg.request_id();
        match self.receiver_input.send(msg) {
            Ok(_) => {}
            Err(e) => {
                debug!(
                    "Failed to reply message {} ({} {}): {:?}",
                    self.expected_seq, msg_name, msg_id, &e
                );
            }
        }
    }
}

/// Opaque structure for waiting or a reply.  Contains the other end of a ReceiverNotify that lives
/// in a connection's outbox.
#[derive(Debug)]
pub struct NetworkReplyHandle<P: ProtocolFamily> {
    receiver_output: Option<Receiver<P::Message>>,
    request_pipe_write: Option<PipeWrite>, // caller feeds in the message via this pipe endpoint.  Set to None on flush
    deadline: u64,
    socket_event_id: usize,
}

impl<P: ProtocolFamily> NetworkReplyHandle<P> {
    pub fn new(
        output: Receiver<P::Message>,
        write: PipeWrite,
        socket_event_id: usize,
    ) -> NetworkReplyHandle<P> {
        NetworkReplyHandle {
            receiver_output: Some(output),
            request_pipe_write: Some(write),
            deadline: 0,
            socket_event_id,
        }
    }

    pub fn new_relay(write: PipeWrite, socket_event_id: usize) -> NetworkReplyHandle<P> {
        NetworkReplyHandle {
            receiver_output: None,
            request_pipe_write: Some(write),
            deadline: 0,
            socket_event_id,
        }
    }

    /// deadline is in seconds
    pub fn set_deadline(&mut self, dl: u64) {
        self.deadline = dl;
    }

    /// Get the associated socket event ID hint
    pub fn get_event_id(&self) -> usize {
        self.socket_event_id
    }

    /// Are we expecting a reply?
    pub fn expects_reply(&self) -> bool {
        self.receiver_output.is_some()
    }

    /// Try to flush and receive.
    /// Only call this once all sender data is buffered up.
    /// Consumed the handle if it succeeds in both emptying the message buffer and getting a message.
    /// Returns itself if it still has data to flush, or if it's still waiting for a reply.
    pub fn try_send_recv(mut self) -> Result<P::Message, Result<NetworkReplyHandle<P>, net_error>> {
        if self.request_pipe_write.is_some() {
            match self.try_flush() {
                Ok(b) => {
                    if b {
                        // flushed all data; try to receive a reply.
                        self.try_recv()
                    } else {
                        // still have buffered data
                        Err(Ok(self))
                    }
                }
                Err(e) => {
                    // broken pipe
                    Err(Err(e))
                }
            }
        } else {
            // done sending, so just try to receive
            self.try_recv()
        }
    }

    /// Poll on this handle.
    /// Consumes this handle if it succeeds in getting a message.
    /// Returns itself if there is no pending message.
    /// If a deadline is set to something non-zero, then fail if the deadline passed (this handle
    /// is destroyed in the process).
    pub fn try_recv(mut self) -> Result<P::Message, Result<NetworkReplyHandle<P>, net_error>> {
        if self.deadline > 0 && self.deadline < get_epoch_time_secs() {
            debug!(
                "Reply deadline for event {} at {} exceeded (now = {})",
                self.socket_event_id,
                self.deadline,
                get_epoch_time_secs()
            );
            return Err(Err(net_error::RecvTimeout));
        }
        match self.receiver_output {
            Some(ref mut output) => {
                let res = output.try_recv();
                match res {
                    Ok(message) => Ok(message),
                    Err(TryRecvError::Empty) => Err(Ok(self)), // try again,
                    Err(TryRecvError::Disconnected) => {
                        debug!("receiver_output.try_recv() disconnected -- sender endpoint is dead and the receiver endpoint is drained");
                        Err(Err(net_error::ConnectionBroken))
                    }
                }
            }
            None => Err(Err(net_error::InvalidHandle)),
        }
    }

    /// Receive the outstanding message from our peer within the allotted time (pass -1 for "wait forever").
    /// Destroys the NetworkReplyHandle in the process.  You can only call this once!
    /// Timeout is in seconds.
    pub fn recv(mut self, timeout: i64) -> Result<P::Message, net_error> {
        match self.receiver_output {
            Some(ref mut output) => {
                if timeout < 0 {
                    output.recv().map_err(|_e| {
                        debug!("recv error: {:?}", &_e);
                        net_error::ConnectionBroken
                    })
                } else {
                    output
                        .recv_timeout(Duration::new(timeout as u64, 0))
                        .map_err(|_e| {
                            debug!("recv timeout error: {:?}", &_e);
                            net_error::ConnectionBroken
                        })
                }
            }
            None => Err(net_error::InvalidHandle),
        }
    }

    /// Flush the inner pipe writer and drop it
    fn pipe_flush(&mut self) -> io::Result<()> {
        match self.request_pipe_write.take() {
            Some(mut fd) => fd.flush(),
            None => Ok(()),
        }
    }

    /// Try to flush the inner pipe writer.  If we succeed, drop the inner pipe if
    /// `drop_on_success` is true.  Returns `true` if we drained the write end, `false` if not.
    pub fn try_flush_ex(&mut self, drop_on_success: bool) -> Result<bool, net_error> {
        let ret;
        let fd_opt = match self.request_pipe_write.take() {
            Some(mut fd) => {
                ret = fd.try_flush().map_err(net_error::WriteError)?;
                if ret && drop_on_success {
                    // all data flushed, and we won't send more.
                    None
                } else {
                    // still have data to send, or we will send more.
                    debug!(
                        "Still have data to send, drop_on_success = {}, ret = {}",
                        drop_on_success, ret
                    );
                    Some(fd)
                }
            }
            None => {
                ret = true;
                None
            }
        };
        self.request_pipe_write = fd_opt;
        if drop_on_success {
            Ok(self.request_pipe_write.is_none())
        } else {
            Ok(ret)
        }
    }

    /// Try to flush the inner pipe writer.  If we succeed, drop the inner pipe.
    /// Only call this once you're done sending -- this is just to move the data along.
    /// Return true if we're done sending; false if we need to call this again.
    pub fn try_flush(&mut self) -> Result<bool, net_error> {
        self.try_flush_ex(true)
    }

    /// Get a mutable reference to the inner pipe, if we have it
    pub fn inner_pipe_out(&mut self) -> Option<&mut PipeWrite> {
        self.request_pipe_write.as_mut()
    }
}

impl<P: ProtocolFamily> Write for NetworkReplyHandle<P> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.request_pipe_write {
            Some(ref mut pipe) => pipe.write(bytes),
            None => {
                test_debug!("NetworkReplyHandle pipe write is defunct");
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }
    }

    #[cfg_attr(test, mutants::skip)]
    fn flush(&mut self) -> io::Result<()> {
        self.pipe_flush()
    }
}

/// In-flight message to a remote peer.
/// When a reply is received, it may be forwarded along to an optional ReceiverNotify.
#[derive(Debug)]
struct InflightMessage<P: ProtocolFamily> {
    pipe_read: Option<PipeRead>,
    notify: Option<ReceiverNotify<P>>,
}

#[derive(Debug)]
struct ConnectionInbox<P: ProtocolFamily> {
    public_key: Option<Secp256k1PublicKey>,

    // completely-parsed incoming messages that do _not_ get sent out to a waiting receiver
    inbox: VecDeque<P::Message>,
    inbox_maxlen: usize,

    // partially-parsed incoming messages
    preamble: Option<P::Preamble>,
    buf: Vec<u8>,
    message_ptr: usize, // index into buf where the message begins
    payload_ptr: usize, // for payloads of unknown length, this points to where to read next
}

#[derive(Debug)]
struct ConnectionOutbox<P: ProtocolFamily> {
    // message to send
    outbox: VecDeque<InflightMessage<P>>,
    outbox_maxlen: usize,

    pending_message_fd: Option<PipeRead>,
    socket_out_buf: Vec<u8>,
    socket_out_ptr: usize,

    // in-flight messages
    inflight: VecDeque<ReceiverNotify<P>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionOptions {
    pub inbox_maxlen: usize,
    pub outbox_maxlen: usize,
    pub connect_timeout: u64,
    pub handshake_timeout: u64,
    pub timeout: u64,
    pub idle_timeout: u64,
    pub heartbeat: u32,
    pub private_key_lifetime: u64,
    pub num_neighbors: u64,
    pub num_clients: u64,
    pub soft_num_neighbors: u64,
    pub soft_num_clients: u64,
    pub max_neighbors_per_host: u64,
    pub max_clients_per_host: u64,
    pub soft_max_neighbors_per_host: u64,
    pub soft_max_neighbors_per_org: u64,
    pub soft_max_clients_per_host: u64,
    pub max_neighbors_of_neighbor: u64,
    pub max_http_clients: u64,
    pub neighbor_request_timeout: u64,
    pub max_neighbor_age: u64,
    /// How many walk steps to take when the node has booted up.  This influences how quickly the
    /// node will find new peers on start-up.  This describes the maximum length of such walks.
    pub num_initial_walks: u64,
    /// How many walk state-machine restarts to take when the node has boote dup.  This influences
    /// how quickly the node will find new peers on start-up.  This describes the maximum number of
    /// such walk state-machine run-throughs.
    pub walk_retry_count: u64,
    /// How often, in seconds, to run the walk state machine.
    pub walk_interval: u64,
    /// The regularity of doing an inbound neighbor walk (as opposed to an outbound neighbor walk).
    /// Every `walk_inbound_ratio + 1`-th walk will be an inbound neighbor walk.
    pub walk_inbound_ratio: u64,
    /// Minimum number of steps a walk will run until it can be reset.
    pub walk_min_duration: u64,
    /// Maximum number of steps a walk will run until forcibly reset.
    pub walk_max_duration: u64,
    /// Probabiility that the walk will be reset once `walk_min_duration` steps are taken.
    pub walk_reset_prob: f64,
    /// Maximum number of seconds a walk can last before being reset.
    pub walk_reset_interval: u64,
    /// Maximum number of seconds a walk can remain in the same state before being reset.
    pub walk_state_timeout: u64,
    /// If the node is booting up, or if the node is not connected to an always-allowed peer and
    /// there are one or more such peers in the peers DB, then this controls the probability that
    /// the node will attempt to start a walk to an always-allowed peer.  It's good to have this
    /// close to, but not equal to 1.0, so that if the node can't reach any always-allowed peer for
    /// some reason but can reach other neighbors, then neighbor walks can continue.
    pub walk_seed_probability: f64,
    /// How often, if ever, to log our neighbors via DEBG.
    /// Units are milliseconds.  A value of 0 means "never".
    pub log_neighbors_freq: u64,
    pub inv_sync_interval: u64,
    pub inv_reward_cycles: u64,
    pub download_interval: u64,
    pub pingback_timeout: u64,
    pub dns_timeout: u128,
    pub max_inflight_blocks: u64,
    pub max_inflight_attachments: u64,
    pub max_attachment_retry_count: u64,
    pub read_only_call_limit: ExecutionCost,
    pub maximum_call_argument_size: u32,
    pub max_block_push_bandwidth: u64,
    pub max_microblocks_push_bandwidth: u64,
    pub max_transaction_push_bandwidth: u64,
    pub max_stackerdb_push_bandwidth: u64,
    pub max_nakamoto_block_push_bandwidth: u64,
    pub max_sockets: usize,
    pub public_ip_address: Option<(PeerAddress, u16)>,
    pub public_ip_request_timeout: u64,
    pub public_ip_timeout: u64,
    pub public_ip_max_retries: u64,
    pub max_block_push: u64,
    pub max_microblock_push: u64,
    pub antientropy_retry: u64,
    pub antientropy_public: bool,
    /// maximum number of Stacks 2.x BlocksAvailable messages that can be buffered before processing
    pub max_buffered_blocks_available: u64,
    /// maximum number of Stacks 2.x MicroblocksAvailable that can be buffered before processing
    pub max_buffered_microblocks_available: u64,
    /// maximum number of Stacks 2.x pushed Block messages we can buffer before processing
    pub max_buffered_blocks: u64,
    /// maximum number of Stacks 2.x pushed Microblock messages we can buffer before processing
    pub max_buffered_microblocks: u64,
    /// maximum number of pushed Nakamoto Block messages we can buffer before processing
    pub max_buffered_nakamoto_blocks: u64,
    /// maximum number of pushed StackerDB chunk messages we can buffer before processing
    pub max_buffered_stackerdb_chunks: u64,
    /// how often to query a remote peer for its mempool, in seconds
    pub mempool_sync_interval: u64,
    /// how many transactions to ask for in a mempool query
    pub mempool_max_tx_query: u64,
    /// how long a mempool sync is allowed to take, in total, before timing out
    pub mempool_sync_timeout: u64,
    /// socket read buffer size
    pub socket_recv_buffer_size: u32,
    /// socket write buffer size
    pub socket_send_buffer_size: u32,
    /// whether or not to announce or accept neighbors that are behind private networks
    pub private_neighbors: bool,
    /// maximum number of confirmations for a nakamoto block's sortition for which it will be
    /// pushed
    pub max_nakamoto_block_relay_age: u64,
    /// minimum amount of time between requests to push nakamoto blocks (millis)
    pub nakamoto_push_interval_ms: u128,
    /// minimum amount of time between requests to push nakamoto blocks (millis)
    pub nakamoto_inv_sync_burst_interval_ms: u128,
    /// time between unconfirmed downloader runs
    pub nakamoto_unconfirmed_downloader_interval_ms: u128,
    /// The authorization token to enable privileged RPC endpoints
    pub auth_token: Option<String>,
    /// The maximum age in seconds of a block that can be validated by the block proposal endpoint
    pub block_proposal_max_age_secs: u64,
    /// StackerDB replicas to talk to for a particular smart contract
    pub stackerdb_hint_replicas: HashMap<QualifiedContractIdentifier, Vec<NeighborAddress>>,

    // fault injection
    /// Disable neighbor walk and discovery
    pub disable_neighbor_walk: bool,
    /// Disable sharing neighbors to a remote requester
    pub disable_chat_neighbors: bool,
    /// Disable block inventory sync state machine
    pub disable_inv_sync: bool,
    /// Disable sending inventory messages to a remote requester
    pub disable_inv_chat: bool,
    /// Disable block download state machine
    pub disable_block_download: bool,
    /// Disable network pruning
    pub disable_network_prune: bool,
    /// Disable banning misbehaving peers
    pub disable_network_bans: bool,
    /// Disable block availability advertisement
    pub disable_block_advertisement: bool,
    /// Disable block pushing
    pub disable_block_push: bool,
    /// Disable microblock pushing
    pub disable_microblock_push: bool,
    /// Disable walk pingbacks -- don't attempt to walk to a remote peer even if it contacted us
    /// first
    pub disable_pingbacks: bool,
    /// Disable walking to inbound neighbors
    pub disable_inbound_walks: bool,
    /// Disable all attempts to learn our IP address
    pub disable_natpunch: bool,
    /// Disable handshakes from inbound neighbors
    pub disable_inbound_handshakes: bool,
    /// Disable getting chunks from StackerDB (e.g. to test push-only)
    pub disable_stackerdb_get_chunks: bool,
    /// Disable running stackerdb sync altogether (e.g. to test push-only)
    pub disable_stackerdb_sync: bool,
    /// Unconditionally disconnect a peer after this amount of time
    pub force_disconnect_interval: Option<u64>,
    /// If set to true, this forces the p2p state machine to believe that it is running in
    /// the reward cycle in which Nakamoto activates, and thus needs to run both the epoch
    /// 2.x and Nakamoto state machines.
    pub force_nakamoto_epoch_transition: bool,
    /// Reject blocks that were pushed
    pub reject_blocks_pushed: bool,

    // test facilitation
    /// Do not require that an unsolicited message originate from an authenticated, connected
    /// neighbor
    pub test_disable_unsolicited_message_authentication: bool,
}

impl std::default::Default for ConnectionOptions {
    fn default() -> ConnectionOptions {
        ConnectionOptions {
            inbox_maxlen: 1024,
            outbox_maxlen: 1024,
            connect_timeout: 10, // how long a socket can be in a connecting state
            handshake_timeout: 30, // how long before a peer must send a handshake, after connecting
            timeout: 30,         // how long to wait for a reply to a request
            idle_timeout: 15, // how long a non-request HTTP connection can be idle before it's closed
            heartbeat: 3600,  // send a heartbeat once an hour by default
            private_key_lifetime: 4302, // key expires after ~1 month
            num_neighbors: 32, // how many outbound connections we can have, full-stop
            num_clients: 256, // how many inbound connections we can have, full-stop
            soft_num_neighbors: 20, // how many outbound connections we can have, before we start pruning them
            soft_num_clients: 128, // how many inbound connections we can have, before we start pruning them
            max_neighbors_per_host: 10, // how many outbound connections we can have per IP address, full-stop
            max_clients_per_host: 10, // how many inbound connections we can have per IP address, full-stop
            soft_max_neighbors_per_host: 10, // how many outbound connections we can have per IP address, before we start pruning them
            soft_max_neighbors_per_org: 10, // how many outbound connections we can have per AS-owning organization, before we start pruning them
            soft_max_clients_per_host: 10, // how many inbound connections we can have per IP address, before we start pruning them,
            max_neighbors_of_neighbor: 10,
            max_http_clients: 10,
            neighbor_request_timeout: NEIGHBOR_REQUEST_TIMEOUT, // how long to wait for a neighbor request
            max_neighbor_age: MAX_NEIGHBOR_AGE,
            num_initial_walks: NUM_INITIAL_WALKS,
            walk_retry_count: WALK_RETRY_COUNT,
            walk_interval: NEIGHBOR_WALK_INTERVAL, // how often to do a neighbor walk.
            walk_inbound_ratio: 2, // walk inbound neighbors twice as often as outbound by default
            walk_min_duration: WALK_MIN_DURATION,
            walk_max_duration: WALK_MAX_DURATION,
            walk_reset_prob: WALK_RESET_PROB,
            walk_reset_interval: WALK_RESET_INTERVAL,
            walk_state_timeout: WALK_STATE_TIMEOUT,
            walk_seed_probability: WALK_SEED_PROBABILITY,
            log_neighbors_freq: 60_000,
            inv_sync_interval: INV_SYNC_INTERVAL, // how often to synchronize block inventories
            inv_reward_cycles: INV_REWARD_CYCLES, // how many reward cycles of blocks to sync in a non-full inventory sync
            download_interval: BLOCK_DOWNLOAD_INTERVAL, // how often to scan for blocks to download
            pingback_timeout: 60,
            dns_timeout: 15_000,            // DNS timeout, in millis
            max_inflight_blocks: 6,         // number of parallel block downloads
            max_inflight_attachments: 6,    // number of parallel attachments downloads
            max_attachment_retry_count: 32, // how many attempt to get an attachment before giving up
            read_only_call_limit: ExecutionCost {
                write_length: 0,
                write_count: 0,
                read_length: 100000,
                read_count: 30,
                runtime: 1_000_000_000,
            },
            maximum_call_argument_size: 20 * BOUND_VALUE_SERIALIZATION_HEX,
            max_block_push_bandwidth: 0, // infinite upload bandwidth allowed
            max_microblocks_push_bandwidth: 0, // infinite upload bandwidth allowed
            max_transaction_push_bandwidth: 0, // infinite upload bandwidth allowed
            max_stackerdb_push_bandwidth: 0, // infinite upload bandwidth allowed
            max_nakamoto_block_push_bandwidth: 0, // infinite upload bandwidth allowed
            max_sockets: 800,            // maximum number of client sockets we'll ever register
            public_ip_address: None,     // resolve it at runtime by default
            public_ip_request_timeout: 60, // how often we can attempt to look up our public IP address
            public_ip_timeout: 3600,       // re-learn the public IP ever hour, if it's not given
            public_ip_max_retries: 3, // maximum number of retries before self-throttling for $public_ip_timeout
            max_block_push: 10, // maximum number of blocksData messages to push out via our anti-entropy protocol
            max_microblock_push: 10, // maximum number of microblocks messages to push out via our anti-entropy protocol
            antientropy_retry: 3600, // retry pushing data once every hour
            antientropy_public: true, // run antientropy even if we're NOT NAT'ed
            max_buffered_blocks_available: 5,
            max_buffered_microblocks_available: 5,
            max_buffered_blocks: 5,
            max_buffered_microblocks: 1024,
            max_buffered_nakamoto_blocks: 1024,
            max_buffered_stackerdb_chunks: 4096,
            mempool_sync_interval: 30, // number of seconds in-between mempool sync
            mempool_max_tx_query: 128, // maximum number of transactions to visit per mempool query
            mempool_sync_timeout: 180, // how long a mempool sync can go for (3 minutes)
            socket_recv_buffer_size: 131072, // Linux default
            socket_send_buffer_size: 16384, // Linux default
            private_neighbors: true,
            max_nakamoto_block_relay_age: 6,
            nakamoto_push_interval_ms: 30_000, // re-send a block no more than once every 30 seconds
            nakamoto_inv_sync_burst_interval_ms: 1_000, // wait 1 second after a sortition before running inventory sync
            nakamoto_unconfirmed_downloader_interval_ms: 5_000, // run unconfirmed downloader once every 5 seconds
            auth_token: None,
            block_proposal_max_age_secs: DEFAULT_BLOCK_PROPOSAL_MAX_AGE_SECS,
            stackerdb_hint_replicas: HashMap::new(),

            // no faults on by default
            disable_neighbor_walk: false,
            disable_chat_neighbors: false,
            disable_inv_sync: false,
            disable_inv_chat: false,
            disable_block_download: false,
            disable_network_prune: false,
            disable_network_bans: false,
            disable_block_advertisement: false,
            disable_block_push: false,
            disable_microblock_push: false,
            disable_pingbacks: false,
            disable_inbound_walks: false,
            disable_natpunch: false,
            disable_inbound_handshakes: false,
            disable_stackerdb_get_chunks: false,
            disable_stackerdb_sync: false,
            force_disconnect_interval: None,
            force_nakamoto_epoch_transition: false,
            reject_blocks_pushed: false,

            // no test facilitations on by default
            test_disable_unsolicited_message_authentication: false,
        }
    }
}

#[derive(Debug)]
pub struct NetworkConnection<P: ProtocolFamily> {
    pub options: ConnectionOptions,
    pub protocol: P,
    inbox: ConnectionInbox<P>,
    outbox: ConnectionOutbox<P>,
}

impl<P: ProtocolFamily> ConnectionInbox<P> {
    pub fn new(
        max_messages: usize,
        public_key_opt: Option<Secp256k1PublicKey>,
    ) -> ConnectionInbox<P> {
        ConnectionInbox {
            public_key: public_key_opt,
            inbox: VecDeque::with_capacity(max_messages),
            inbox_maxlen: max_messages,
            preamble: None,
            buf: vec![],
            message_ptr: 0,
            payload_ptr: 0,
        }
    }

    /// Fill up the preamble buffer, up to P::preamble_size_hint().
    /// Return the number of bytes consumed.
    fn buffer_preamble_bytes(&mut self, protocol: &mut P, bytes: &[u8]) -> usize {
        let max_preamble_len = protocol.preamble_size_hint();
        if self.buf.len() >= max_preamble_len {
            return 0;
        }

        let to_consume = if self.buf.len() + bytes.len() <= max_preamble_len {
            bytes.len()
        } else {
            max_preamble_len - self.buf.len()
        };

        let _len = self.buf.len();
        self.buf.extend_from_slice(&bytes[0..to_consume]);

        trace!(
            "Buffer {} bytes out of max {} for preamble (buf went from {} to {} bytes)",
            to_consume,
            max_preamble_len,
            _len,
            self.buf.len()
        );
        to_consume
    }

    /// try to consume buffered data to form a message preamble.
    /// returns an option of the preamble consumed and the number of bytes used from the bytes slice
    #[cfg_attr(test, mutants::skip)]
    fn consume_preamble(
        &mut self,
        protocol: &mut P,
        bytes: &[u8],
    ) -> Result<(Option<P::Preamble>, usize), net_error> {
        let bytes_consumed = self.buffer_preamble_bytes(protocol, bytes);
        let preamble_opt = match protocol.read_preamble(&self.buf) {
            Ok((preamble, preamble_len)) => {
                assert!((preamble_len as u32) < MAX_MESSAGE_LEN); // enforced by protocol family

                test_debug!("Got preamble {:?} of {} bytes", &preamble, preamble_len);

                if let Some(payload_len) = protocol.payload_len(&preamble) {
                    if (payload_len as u32) >= MAX_MESSAGE_LEN {
                        // message would be too big
                        return Err(net_error::DeserializeError(format!(
                            "Preamble payload length {} is too big",
                            payload_len
                        )));
                    }
                }

                self.message_ptr = preamble_len;
                self.payload_ptr = preamble_len;
                Some(preamble)
            }
            Err(net_error::DeserializeError(errmsg)) => {
                // will never be valid
                warn!("Invalid message preamble: {}", &errmsg);
                debug!("Buffer ({}): {:?}", self.buf.len(), &self.buf);
                debug!("Bytes ({}): {:?}", bytes.len(), bytes.to_vec());
                debug!("Message ptr: {}", self.message_ptr);
                debug!("Payload ptr: {}", self.payload_ptr);
                debug!("Preamble: {:?}", &self.preamble);
                return Err(net_error::InvalidMessage);
            }
            Err(net_error::UnderflowError(_)) => {
                // not enough data to form a preamble yet
                if bytes_consumed == 0 && !bytes.is_empty() {
                    // preamble is too long
                    return Err(net_error::DeserializeError(
                        "Preamble size would exceed maximum allowed size".to_string(),
                    ));
                }

                trace!(
                    "Not enough data to consume a preamble (bytes_consumed = {}, bytes.len() = {})",
                    bytes_consumed,
                    bytes.len()
                );
                None
            }
            Err(e) => {
                // other
                return Err(e);
            }
        };
        Ok((preamble_opt, bytes_consumed))
    }

    /// buffer up bytes for a message
    #[cfg_attr(test, mutants::skip)]
    fn buffer_message_bytes(&mut self, bytes: &[u8], message_len_opt: Option<usize>) -> usize {
        let message_len = message_len_opt.unwrap_or(MAX_MESSAGE_LEN as usize);
        let buffered_so_far = self.buf[self.message_ptr..].len();
        let mut to_consume = bytes.len();
        let total_avail: u128 = (buffered_so_far as u128) + (to_consume as u128); // can't overflow
        if total_avail > message_len as u128 {
            trace!(
                "self.message_ptr = {}, message_len = {}, to_consume = {}",
                self.message_ptr,
                message_len,
                to_consume
            );

            to_consume = if message_len > buffered_so_far {
                message_len - buffered_so_far
            } else {
                // can happen if we receive so much data when parsing the preamble that we've
                // also already received the message, and part of the next preamble (or more).
                0
            };
        }

        trace!("Consume {} bytes from input buffer", to_consume);
        self.buf.extend_from_slice(&bytes[0..to_consume]);
        to_consume
    }

    /// Try and consume a payload from our internal buffer when the length of the payload is given
    /// in the preamble.
    fn consume_payload_known_length(
        &mut self,
        protocol: &mut P,
        preamble: &P::Preamble,
    ) -> Result<Option<P::Message>, net_error> {
        let payload_len_opt = protocol.payload_len(preamble);
        let payload_len = payload_len_opt.expect("BUG: payload length assumed to be known");

        // reading a payload of known length
        if self.buf[self.message_ptr..].len() >= payload_len {
            // definitely have enough data to form a message
            if let Some(ref pubk) = self.public_key {
                protocol.verify_payload_bytes(pubk, preamble, &self.buf[self.message_ptr..])?;
            }

            // consume the message
            let message_opt = match protocol.read_payload(preamble, &self.buf[self.message_ptr..]) {
                Ok((message, message_len)) => {
                    test_debug!("Got message of {} bytes with {:?}", message_len, preamble);
                    let next_message_ptr = self.message_ptr.checked_add(message_len).ok_or(
                        net_error::OverflowError("Overflowed buffer pointer".to_string()),
                    )?;

                    // begin parsing at the end of this message
                    let mut trailer = vec![];
                    trailer.extend_from_slice(&self.buf[next_message_ptr..]);

                    self.message_ptr = 0;
                    self.payload_ptr = 0;
                    self.buf = trailer;

                    if !self.buf.is_empty() {
                        test_debug!(
                            "Buffer has {} bytes remaining: {:?}",
                            self.buf.len(),
                            &self.buf.to_vec()
                        );
                    }
                    Some(message)
                }
                Err(e) => {
                    // will never be valid, even if underflowed, since the preamble ought to have
                    // told us the message length
                    debug!(
                        "Invalid message payload: {:?}.  Preamble was {:?}",
                        &e, &preamble
                    );
                    return Err(net_error::InvalidMessage);
                }
            };
            Ok(message_opt)
        } else {
            // not enough data yet
            Ok(None)
        }
    }

    /// Try to consume buffered data to form a message, where we don't know how long the message
    /// is.  Stream it into the protocol, and see what the protocol spits out.
    fn consume_payload_unknown_length(
        &mut self,
        protocol: &mut P,
        preamble: &P::Preamble,
    ) -> Result<Option<P::Message>, net_error> {
        let to_buffer = &self.buf[self.payload_ptr..];
        let mut cursor = io::Cursor::new(to_buffer);

        trace!("Stream up to {} payload bytes", to_buffer.len());
        let (message_opt, bytes_consumed) = protocol.stream_payload(preamble, &mut cursor)?;

        trace!("Streamed {} payload bytes", bytes_consumed);
        self.payload_ptr =
            self.payload_ptr
                .checked_add(bytes_consumed)
                .ok_or(net_error::OverflowError(
                    "Overflowed payload pointer".to_string(),
                ))?;

        let ret = match message_opt {
            Some((message, _message_len)) => {
                test_debug!(
                    "Streamed {} bytes to form a message from preamble {:?}",
                    _message_len,
                    preamble
                );

                let next_message_ptr = self.payload_ptr;

                // begin parsing at the end of this message
                let mut trailer = vec![];
                trailer.extend_from_slice(&self.buf[next_message_ptr..]);

                self.message_ptr = 0;
                self.payload_ptr = 0;
                self.buf = trailer;

                trace!("Input buffer reset to {} bytes", self.buf.len());
                trace!("buf is now: {:?}", &self.buf);
                Some(message)
            }
            None => {
                // not enough data
                test_debug!(
                    "Got preamble {:?}, but no streamed message (buffered {} bytes)",
                    &preamble,
                    bytes_consumed
                );
                None
            }
        };
        Ok(ret)
    }

    /// Try to consume buffered data to form a message.
    /// This method may consume enough data to form multiple messages; in that case, this will
    /// return the first such message.  Call this repeatedly with an empty bytes array to get all
    /// messages.
    fn consume_payload(
        &mut self,
        protocol: &mut P,
        preamble: &P::Preamble,
        bytes: &[u8],
    ) -> Result<(Option<P::Message>, usize), net_error> {
        let payload_len_opt = protocol.payload_len(preamble);
        let bytes_consumed = self.buffer_message_bytes(bytes, payload_len_opt);

        if payload_len_opt.is_some() {
            let message_opt = self.consume_payload_known_length(protocol, preamble)?;
            Ok((message_opt, bytes_consumed))
        } else {
            let message_opt = self.consume_payload_unknown_length(protocol, preamble)?;
            Ok((message_opt, bytes_consumed))
        }
    }

    /// Consume messages while we have space in our inbox.
    /// It is possible for this method to append more messages to the inbox than inbox_maxsize.
    /// However, since only so many messages can fit into buf, the number of messages that can be
    /// inserted into the inbox beyond inbox_maxsize is still limited.  Subsequent calls to
    /// recv_bytes() will prevent more data from being read from the socket until the messages are
    /// dequeued.
    ///
    /// Returns nothing on success, and enqueues zero or more messages into our inbox.
    /// Returns net_error::InvalidMessage if a message could not be parsed or authenticated.
    fn consume_messages(&mut self, protocol: &mut P, buf: &[u8]) -> Result<(), net_error> {
        let mut offset = 0;
        loop {
            if self.inbox.len() > self.inbox_maxlen {
                return Err(net_error::InboxOverflow);
            }

            let bytes_consumed_preamble = if self.preamble.is_none() {
                trace!(
                    "Try to consume a preamble from {} bytes",
                    buf[offset..].len()
                );

                let (preamble_opt, bytes_consumed) =
                    self.consume_preamble(protocol, &buf[offset..])?;
                self.preamble = preamble_opt;

                trace!("Consumed message preamble in {} bytes", bytes_consumed);
                bytes_consumed
            } else {
                0
            };

            offset += bytes_consumed_preamble;
            if offset == buf.len() {
                break;
            }

            let mut consumed_message = false;
            let bytes_consumed_message = {
                let mut preamble_opt = self.preamble.take();
                let bytes_consumed = if let Some(ref mut preamble) = preamble_opt {
                    let (message_opt, bytes_consumed) =
                        self.consume_payload(protocol, preamble, &buf[offset..])?;
                    match message_opt {
                        Some(message) => {
                            // queue up
                            test_debug!(
                                "Consumed message '{}' (request {}) in {} bytes",
                                message.get_message_name(),
                                message.request_id(),
                                bytes_consumed
                            );
                            self.inbox.push_back(message);
                            consumed_message = true;
                        }
                        None => {}
                    };

                    bytes_consumed
                } else {
                    0
                };

                self.preamble = preamble_opt;
                bytes_consumed
            };

            if consumed_message {
                self.preamble = None;
            }

            offset += bytes_consumed_message;
            if offset == buf.len() {
                break;
            }
        }

        // we can buffer bytes faster than we can process messages, so be sure to drain the buffer
        // before returning.
        if !self.buf.is_empty() {
            loop {
                let mut consumed_message = false;

                if self.preamble.is_none() {
                    let (preamble_opt, _bytes_consumed) = self.consume_preamble(protocol, &[])?;
                    self.preamble = preamble_opt;
                    if self.preamble.is_some() {
                        test_debug!(
                            "Consumed buffered message preamble in {} bytes",
                            _bytes_consumed
                        );
                    }
                };

                if self.preamble.is_some() {
                    let mut preamble_opt = self.preamble.take();
                    if let Some(ref mut preamble) = preamble_opt {
                        let (message_opt, _bytes_consumed) =
                            self.consume_payload(protocol, preamble, &[])?;
                        match message_opt {
                            Some(message) => {
                                // queue up
                                test_debug!("Consumed buffered message '{}' (request {}) from {} input buffer bytes", message.get_message_name(), message.request_id(), _bytes_consumed);
                                self.inbox.push_back(message);
                                consumed_message = true;
                            }
                            None => {}
                        }
                    }
                    self.preamble = preamble_opt;

                    if consumed_message {
                        // next message
                        self.preamble = None;
                    }
                }

                if !consumed_message {
                    // nothing more to do
                    break;
                }
            }
        }

        Ok(())
    }

    /// Read bytes from an input stream, buffer them up, try to parse the buffer
    /// into messages, and enqueue the messages into the inbox.
    /// Returns net_error::RecvError if we couldn't read from the fd
    fn recv_bytes<R: Read>(&mut self, protocol: &mut P, fd: &mut R) -> Result<usize, net_error> {
        if self.inbox.len() > self.inbox_maxlen {
            return Err(net_error::InboxOverflow);
        }

        let mut blocked = false;
        let mut total_read = 0;
        let mut socket_closed = false;
        while !blocked {
            // get the next bytes
            // NOTE: it's important that buf not be too big, since up to buf.len()-1 bytes may need
            // to be copied if a message boundary isn't aligned with buf (which is usually the
            // case).
            let mut buf = [0u8; 65536];
            let num_read = match fd.read(&mut buf) {
                Ok(0) => {
                    // remote fd is closed, but do try to consume all remaining bytes in the buffer
                    socket_closed = true;
                    blocked = true;
                    Ok(0)
                }
                Ok(count) => Ok(count),
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock
                        || (cfg!(windows) && e.kind() == io::ErrorKind::TimedOut)
                    {
                        blocked = true;
                        Ok(0)
                    } else if e.kind() == io::ErrorKind::BrokenPipe
                        || e.kind() == io::ErrorKind::ConnectionReset
                    {
                        // write endpoint is dead
                        debug!("reader was reset: {:?}", &e);
                        socket_closed = true;
                        blocked = true;
                        Ok(0)
                    } else {
                        debug!("Failed to read from fd: {:?}", &e);
                        Err(net_error::RecvError(format!("Failed to read: {:?}", &e)))
                    }
                }
            }?;

            total_read += num_read;

            if num_read > 0 || total_read > 0 {
                debug!("read {} bytes; {} total", num_read, total_read);
            }

            if num_read > 0 {
                // decode into message stream
                self.consume_messages(protocol, &buf[0..num_read])?;
            }
        }

        if socket_closed && total_read == 0 {
            return Err(net_error::PermanentlyDrained);
        }
        update_inbound_bandwidth(total_read as i64);
        Ok(total_read)
    }

    /// Get the oldest message received in the inbox
    pub fn next_message(&mut self) -> Option<P::Message> {
        self.inbox.pop_front()
    }

    /// How many queued messsages do we have?
    pub fn num_messages(&self) -> usize {
        self.inbox.len()
    }
}

impl<P: ProtocolFamily> ConnectionOutbox<P> {
    pub fn new(outbox_maxlen: usize) -> ConnectionOutbox<P> {
        ConnectionOutbox {
            outbox: VecDeque::with_capacity(outbox_maxlen),
            outbox_maxlen,
            pending_message_fd: None,
            socket_out_buf: vec![],
            socket_out_ptr: 0,
            inflight: VecDeque::new(),
        }
    }

    fn begin_next_message(&mut self) -> Option<PipeRead> {
        if self.outbox.is_empty() {
            // nothing to send
            return None;
        }

        let mut pending_message_fd = self.outbox.get_mut(0).unwrap().pipe_read.take();
        match pending_message_fd {
            Some(ref mut fd) => fd.set_nonblocking(true),
            None => {
                panic!("No read pipe for message");
            }
        }

        pending_message_fd
    }

    fn finish_message(&mut self) {
        assert!(!self.outbox.is_empty());

        // wake up any receivers when (if) we get a reply
        let mut inflight_message = self.outbox.pop_front();
        let receiver_notify_opt = inflight_message.take();

        match receiver_notify_opt {
            None => {}
            Some(receiver_notify) => {
                if receiver_notify.notify.is_some() {
                    self.inflight.push_back(receiver_notify.notify.unwrap());
                }
            }
        }
    }

    fn queue_message(
        &mut self,
        pipe_read: PipeRead,
        recv_notify: Option<ReceiverNotify<P>>,
    ) -> Result<(), net_error> {
        if self.outbox.len() > self.outbox_maxlen {
            test_debug!(
                "Outbox has {} messages (max {})",
                self.outbox.len(),
                self.outbox_maxlen
            );
            return Err(net_error::OutboxOverflow);
        }

        let inflight = InflightMessage {
            pipe_read: Some(pipe_read),
            notify: recv_notify,
        };
        self.outbox.push_back(inflight);
        Ok(())
    }

    /// Write queued messages to the given W
    /// Returns number of bytes sent out to fd.
    fn send_bytes<W: Write>(&mut self, fd: &mut W) -> Result<usize, net_error> {
        let mut total_sent = 0;
        let mut blocked = false;
        let mut disconnected = false;
        let mut message_eof = false;
        while !blocked && !disconnected && !message_eof {
            if self.pending_message_fd.is_none() {
                self.pending_message_fd = self.begin_next_message();
            }

            let _nr_input = match self.pending_message_fd {
                Some(ref mut message_fd) => {
                    // consume from message-writer until we're out of data
                    // TODO: make this configurable
                    let mut buf = [0u8; 8192];
                    let nr_input = match message_fd.read(&mut buf) {
                        Ok(0) => {
                            // no more data from writer
                            test_debug!("Connection message pipe returned 0 bytes; assuming EOF");
                            message_eof = true;
                            0
                        }
                        Ok(read_len) => {
                            test_debug!("Connection message pipe returned {} bytes", read_len);
                            read_len
                        }
                        Err(ioe) => match ioe.kind() {
                            io::ErrorKind::WouldBlock => {
                                // no data consumed, but we may need to make a break for it
                                blocked = true;
                                0
                            }
                            io::ErrorKind::TimedOut => {
                                // sometimes happens on Windows
                                if cfg!(windows) {
                                    blocked = true;
                                    0
                                } else {
                                    return Err(net_error::WriteError(ioe));
                                }
                            }
                            io::ErrorKind::BrokenPipe => {
                                // no more data from writer
                                trace!("Connection message pipe broke; assuming EOF");
                                message_eof = true;
                                0
                            }
                            _ => {
                                return Err(net_error::ReadError(ioe));
                            }
                        },
                    };

                    self.socket_out_buf.extend_from_slice(&buf[0..nr_input]);

                    test_debug!(
                        "Connection buffered {} bytes from pipe ({} total, ptr = {}, blocked = {})",
                        nr_input,
                        self.socket_out_buf.len(),
                        self.socket_out_ptr,
                        blocked
                    );
                    nr_input
                }
                None => {
                    // out of pending messages
                    test_debug!("Connection is out of pending messages");
                    break;
                }
            };

            if self.socket_out_ptr < self.socket_out_buf.len() {
                // have pending bytes.
                // send as many bytes as we can
                let num_written_res = fd.write(&self.socket_out_buf[self.socket_out_ptr..]);
                let num_written = match num_written_res {
                    Ok(0) => {
                        // indicates that the remote peer is no longer receiving
                        disconnected = true;
                        Ok(0)
                    }
                    Ok(count) => Ok(count),
                    Err(e) => {
                        if e.kind() == io::ErrorKind::WouldBlock
                            || (cfg!(windows) && e.kind() == io::ErrorKind::TimedOut)
                        {
                            blocked = true;
                            Ok(0)
                        } else {
                            debug!("Failed to write to fd: {:?}", &e);
                            Err(net_error::SendError(format!(
                                "Failed to send {} bytes",
                                self.socket_out_buf.len() - self.socket_out_ptr
                            )))
                        }
                    }
                }?;

                self.socket_out_ptr += num_written;

                test_debug!(
                    "Connection wrote {} bytes to socket (buffer len = {}, ptr = {})",
                    num_written,
                    self.socket_out_buf.len(),
                    self.socket_out_ptr
                );

                total_sent += num_written;
            }

            if message_eof && self.socket_out_ptr >= self.socket_out_buf.len() {
                // no pending bytes, so we must have a message
                test_debug!("End of message, {} bytes sent", self.socket_out_ptr);
                self.finish_message();

                self.pending_message_fd = None;
                self.socket_out_buf.clear();
                self.socket_out_ptr = 0;
            }
        }

        test_debug!(
            "Connection send_bytes finished: blocked = {}, disconnected = {}, eof = {}",
            blocked,
            disconnected,
            message_eof,
        );

        if total_sent == 0 && disconnected && !blocked {
            return Err(net_error::PeerNotConnected);
        }
        update_outbound_bandwidth(total_sent as i64);
        Ok(total_sent)
    }

    /// How many queued messsages do we have?
    #[cfg_attr(test, mutants::skip)]
    pub fn num_messages(&self) -> usize {
        self.outbox.len()
    }
}

impl<P: ProtocolFamily + Clone> NetworkConnection<P> {
    pub fn new(
        protocol: P,
        options: &ConnectionOptions,
        public_key_opt: Option<Secp256k1PublicKey>,
    ) -> NetworkConnection<P> {
        NetworkConnection {
            protocol,
            options: (*options).clone(),

            inbox: ConnectionInbox::new(options.inbox_maxlen, public_key_opt),
            outbox: ConnectionOutbox::new(options.outbox_maxlen),
        }
    }

    /// Determine if a (possibly unauthenticated) message was solicited
    pub fn is_solicited(&self, msg: &P::Message) -> bool {
        let mut solicited = false;
        for i in 0..self.outbox.inflight.len() {
            let inflight = self.outbox.inflight.get(i).unwrap();
            if inflight.expected_seq == msg.request_id() {
                // this message is in reply to this inflight message
                solicited = true;
                break;
            }
        }

        solicited
    }

    /// Fulfill an outstanding request with a message.
    /// Return the message itself if the message was unsolicited
    pub fn fulfill_request(&mut self, msg: P::Message) -> Option<P::Message> {
        // relay to next waiting receiver
        let mut outbox_index = 0;
        let mut solicited = false;
        for i in 0..self.outbox.inflight.len() {
            let inflight = self.outbox.inflight.get(i).unwrap();
            if inflight.expected_seq == msg.request_id() {
                // this message is in reply to this inflight message
                outbox_index = i;
                solicited = true;
                break;
            }
        }

        if solicited {
            let fulfilled = self.outbox.inflight.remove(outbox_index).unwrap(); // safe since solicited
            fulfilled.send(msg);
            None
        } else {
            Some(msg)
        }
    }

    /// Send any messages we got to waiting receivers.
    /// Return the list of unsolicited messages (such as blocks and transactions).
    pub fn drain_inbox(&mut self) -> Vec<P::Message> {
        let mut unsolicited = vec![];
        loop {
            let in_msg_opt = self.inbox.next_message();
            match in_msg_opt {
                None => {
                    // drained
                    break;
                }
                Some(msg) => {
                    // relay to next waiting receiver
                    let out_msg_opt = self.fulfill_request(msg);
                    match out_msg_opt {
                        None => {}
                        Some(m) => unsolicited.push(m),
                    };
                }
            }
        }

        return unsolicited;
    }

    /// Clear out timed-out requests.
    /// Returns number of messages drained.
    pub fn drain_timeouts(&mut self) -> usize {
        let now = get_epoch_time_secs();
        let mut to_remove = vec![];
        for i in 0..self.outbox.inflight.len() {
            match self.outbox.inflight.get_mut(i) {
                None => {
                    to_remove.push(i);
                    continue;
                }
                Some(inflight) => {
                    if inflight.ttl < now {
                        // expired
                        debug!(
                            "Request timed out: seq={} ttl={} now={}",
                            inflight.expected_seq, inflight.ttl, now
                        );
                        to_remove.push(i);
                    }
                }
            }
        }

        let res = to_remove.len();

        to_remove.reverse();
        for i in to_remove {
            // destroy the channel, causing anyone waiting for a reply to get an error.
            self.outbox.inflight.remove(i);
        }

        res
    }

    /// Send a message and expect a reply.
    /// Caller will need to write the message bytes into the resulting NetworkReplyHandle, and call
    /// flush() on it to make sure the data gets written out to the socket.
    /// ttl is in seconds
    pub fn make_request_handle(
        &mut self,
        request_id: u32,
        timeout: u64,
        socket_event_id: usize,
    ) -> Result<NetworkReplyHandle<P>, net_error> {
        let (send_ch, recv_ch) = sync_channel(1);
        let recv_notify = ReceiverNotify::new(request_id, send_ch, timeout + get_epoch_time_secs());

        let (pipe_read, pipe_write) = Pipe::new();
        let mut recv_handle = NetworkReplyHandle::new(recv_ch, pipe_write, socket_event_id);
        recv_handle.set_deadline(timeout + get_epoch_time_secs());

        self.outbox.queue_message(pipe_read, Some(recv_notify))?;
        Ok(recv_handle)
    }

    /// Forward a message and expect no reply
    /// Returns a Write-able handle into which the message should be written, and flushed.
    pub fn make_relay_handle(
        &mut self,
        socket_event_id: usize,
    ) -> Result<NetworkReplyHandle<P>, net_error> {
        let (pipe_read, pipe_write) = Pipe::new();
        self.outbox.queue_message(pipe_read, None)?;

        let send_handle = NetworkReplyHandle::new_relay(pipe_write, socket_event_id);
        Ok(send_handle)
    }

    /// Send data
    pub fn send_data<W: Write>(&mut self, fd: &mut W) -> Result<usize, net_error> {
        self.outbox.send_bytes(fd)
    }

    /// Receive data
    #[cfg_attr(test, mutants::skip)]
    pub fn recv_data<R: Read>(&mut self, fd: &mut R) -> Result<usize, net_error> {
        self.inbox.recv_bytes(&mut self.protocol, fd)
    }

    /// how many inbox messages pending?
    pub fn inbox_len(&self) -> usize {
        self.inbox.num_messages()
    }

    /// how many outbox messages pending?
    pub fn outbox_len(&self) -> usize {
        self.outbox.num_messages()
    }

    /// get the next inbox message
    pub fn next_inbox_message(&mut self) -> Option<P::Message> {
        self.inbox.next_message()
    }

    /// set the public key
    pub fn set_public_key(&mut self, pubk: Option<Secp256k1PublicKey>) {
        self.inbox.public_key = pubk;
    }

    /// Get a copy of the public key
    pub fn get_public_key(&self) -> Option<Secp256k1PublicKey> {
        match self.inbox.public_key {
            Some(pubk) => Some(pubk.clone()),
            None => None,
        }
    }

    /// Get a copy of the public key
    pub fn ref_public_key(&self) -> Option<&Secp256k1PublicKey> {
        self.inbox.public_key.as_ref()
    }

    /// do we have a public key
    pub fn has_public_key(&self) -> bool {
        self.inbox.public_key.is_some()
    }

    /// send a protocol message
    pub fn send_message<W: Write>(
        &mut self,
        fd: &mut W,
        msg: &P::Message,
    ) -> Result<(), net_error> {
        self.protocol.write_message(fd, msg)
    }
}

pub type ConnectionP2P = NetworkConnection<StacksP2P>;
pub type ReplyHandleP2P = NetworkReplyHandle<StacksP2P>;

pub type ConnectionHttp = NetworkConnection<StacksHttp>;
pub type ReplyHandleHttp = NetworkReplyHandle<StacksHttp>;

#[cfg(test)]
mod test {
    use std::io::prelude::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::{io, thread};

    use rand;
    use rand::RngCore;
    use stacks_common::util::pipe::*;
    use stacks_common::util::secp256k1::*;
    use stacks_common::util::*;

    use super::*;
    use crate::chainstate::stacks::test::make_codec_test_block;
    use crate::net::http::*;
    use crate::net::test::{make_tcp_sockets, NetCursor};
    use crate::net::*;
    use crate::util_lib::test::*;

    fn test_connection_relay_producer_consumer<P, F>(
        mut protocol: P,
        mut conn: NetworkConnection<P>,
        message_factory: F,
    ) where
        P: ProtocolFamily + 'static + Send + Clone,
        F: Fn(u32) -> P::Message,
    {
        assert_eq!(conn.options.outbox_maxlen, conn.options.inbox_maxlen);

        let mut messages = vec![];

        for i in 0..conn.options.outbox_maxlen {
            // send
            if i % 100 == 0 {
                test_debug!("Generated {} messages...", i);
            }
            let msg = message_factory(i as u32);
            messages.push(msg);
        }

        let expected_messages = messages.clone();

        let mut pipes = vec![]; // keep pipes in-scope
        for i in 0..conn.options.outbox_maxlen {
            let pipe = conn.make_relay_handle(0).unwrap();
            pipes.push(pipe);
        }

        // in the background, flush these pipes
        let pusher = thread::spawn(move || {
            let mut i = 0;

            // push the message, and force pipes to go out of scope to close the write end
            while !pipes.is_empty() {
                let mut p = pipes.remove(0);
                protocol.write_message(&mut p, &messages[i]).unwrap();
                i += 1;

                test_debug!("Flush pipe {}", i);
                let _ = p.flush();
                test_debug!("Flushed pipe {}", i);
            }

            test_debug!("Pusher exit");
        });

        let (server, mut read, mut write) = make_tcp_sockets();

        read.set_send_buffer_size(8192).unwrap();
        read.set_recv_buffer_size(8192).unwrap();

        write.set_send_buffer_size(8192).unwrap();
        write.set_recv_buffer_size(8192).unwrap();

        let shared_state = Arc::new(Mutex::new(conn));
        let sender_shared_state = shared_state.clone();

        // in the background, send out all messages
        let sender = thread::spawn(move || {
            let mut done = false;
            while !done {
                match sender_shared_state.lock() {
                    Ok(ref mut conn) => {
                        if conn.outbox.num_messages() > 0 {
                            let nw = conn.send_data(&mut write).unwrap();
                            if nw == 0 {
                                thread::yield_now();
                            }
                            if nw > 0 {
                                test_debug!("Written {} bytes", nw);
                            }
                        } else {
                            done = true;
                        }
                    }
                    Err(e) => {
                        assert!(false, "{:?}", &e);
                        unreachable!();
                    }
                }
            }
            let _ = write.flush();
            test_debug!("Sender exit");
        });

        let mut drained = false;
        let mut total_bytes = 0;
        while !drained {
            match shared_state.lock() {
                Ok(ref mut conn) => {
                    // in the foreground, get the messages
                    let nr = match conn.recv_data(&mut read) {
                        Ok(cnt) => {
                            if cnt == 0 {
                                thread::yield_now();
                            }

                            cnt
                        }
                        Err(e) => match e {
                            net_error::PermanentlyDrained => {
                                drained = true;
                                0
                            }
                            _ => {
                                assert!(false, "{:?}", &e);
                                unreachable!();
                            }
                        },
                    };

                    if nr > 0 {
                        test_debug!("Received {} bytes", nr);
                        total_bytes += nr;
                    }
                }
                Err(e) => {
                    assert!(false, "{:?}", &e);
                    unreachable!();
                }
            }
        }

        test_debug!("Received {} bytes in total", total_bytes);

        match shared_state.lock() {
            Ok(ref mut conn) => {
                test_debug!(
                    "conn inbox buf has {} bytes, message_ptr = {}",
                    conn.inbox.buf.len(),
                    conn.inbox.message_ptr
                );
                test_debug!(
                    "conn outbox has {} bytes, socket_buf_ptr = {}",
                    conn.outbox.socket_out_buf.len(),
                    conn.outbox.socket_out_ptr
                );

                assert_eq!(conn.inbox.buf.len(), 0);
                assert_eq!(conn.inbox.message_ptr, 0);
                assert_eq!(conn.outbox.socket_out_buf.len(), 0);
                assert_eq!(conn.outbox.socket_out_ptr, 0);

                let recved = conn.drain_inbox();
                assert_eq!(recved.len(), expected_messages.len());
                assert_eq!(recved, expected_messages);
            }
            Err(e) => {
                assert!(false, "{:?}", &e);
                unreachable!();
            }
        }

        sender.join().unwrap();
        pusher.join().unwrap();
    }

    fn test_connection_request_producer_consumer<P, F>(
        mut protocol: P,
        mut conn: NetworkConnection<P>,
        message_factory: F,
    ) where
        P: ProtocolFamily + 'static + Send + Clone,
        F: Fn(u32) -> P::Message,
    {
        assert_eq!(conn.options.outbox_maxlen, conn.options.inbox_maxlen);

        let mut messages = vec![];

        for i in 0..conn.options.outbox_maxlen {
            // send
            if i % 100 == 0 {
                test_debug!("Generated {} messages...", i);
            }
            let msg = message_factory(i as u32);
            messages.push(msg);
        }

        let expected_messages = messages.clone();

        let mut handles = vec![]; // keep pipes in-scope
        for i in 0..conn.options.outbox_maxlen {
            let handle = conn
                .make_request_handle(messages[i].request_id(), 60, 0)
                .unwrap();
            handles.push(handle);
        }

        let (sx, rx) = sync_channel(1);

        // in the background, flush these pipes
        let pusher = thread::spawn(move || {
            let mut i = 0;
            let mut rhs = vec![];

            // push the message, and force pipes to go out of scope to close the write end
            while !handles.is_empty() {
                let mut rh = handles.remove(0);
                protocol.write_message(&mut rh, &messages[i]).unwrap();
                i += 1;

                test_debug!("Flush handle {}", i);
                let _ = rh.flush();
                test_debug!("Flushed handle {}", i);

                rhs.push(rh);
            }

            sx.send(rhs).unwrap();
            test_debug!("Pusher exit");
        });

        let (server, mut read, mut write) = make_tcp_sockets();

        read.set_send_buffer_size(8192).unwrap();
        read.set_recv_buffer_size(8192).unwrap();

        write.set_send_buffer_size(8192).unwrap();
        write.set_recv_buffer_size(8192).unwrap();

        let shared_state = Arc::new(Mutex::new(conn));
        let sender_shared_state = shared_state.clone();

        // in the background, send out all messages
        let sender = thread::spawn(move || {
            let mut done = false;
            while !done {
                match sender_shared_state.lock() {
                    Ok(ref mut conn) => {
                        if conn.outbox.num_messages() > 0 {
                            let nw = conn.send_data(&mut write).unwrap();
                            if nw > 0 {
                                test_debug!("Written {} bytes", nw);
                            }
                        } else {
                            done = true;
                        }
                    }
                    Err(e) => {
                        assert!(false, "{:?}", &e);
                        unreachable!();
                    }
                }
            }
            let _ = write.flush();
            test_debug!("Sender exit");
        });

        let mut drained = false;
        let mut total_bytes = 0;
        while !drained {
            match shared_state.lock() {
                Ok(ref mut conn) => {
                    // in the foreground, get the messages
                    let nr = match conn.recv_data(&mut read) {
                        Ok(cnt) => cnt,
                        Err(e) => match e {
                            net_error::PermanentlyDrained => {
                                drained = true;
                                0
                            }
                            _ => {
                                assert!(false, "{:?}", &e);
                                unreachable!();
                            }
                        },
                    };

                    if nr > 0 {
                        test_debug!("Received {} bytes", nr);
                        total_bytes += nr;
                    }
                }
                Err(e) => {
                    assert!(false, "{:?}", &e);
                    unreachable!();
                }
            }
        }

        test_debug!("Received {} bytes in total", total_bytes);

        let mut flushed_handles = rx.recv().unwrap();

        match shared_state.lock() {
            Ok(ref mut conn) => {
                test_debug!(
                    "conn inbox buf has {} bytes, message_ptr = {}",
                    conn.inbox.buf.len(),
                    conn.inbox.message_ptr
                );
                test_debug!(
                    "conn outbox has {} bytes, socket_buf_ptr = {}",
                    conn.outbox.socket_out_buf.len(),
                    conn.outbox.socket_out_ptr
                );

                assert_eq!(conn.inbox.buf.len(), 0);
                assert_eq!(conn.inbox.message_ptr, 0);
                assert_eq!(conn.outbox.socket_out_buf.len(), 0);
                assert_eq!(conn.outbox.socket_out_ptr, 0);

                // fulfill everything
                let recved = conn.drain_inbox();

                // everything was sent to the handles -- all solicited
                assert_eq!(recved.len(), 0);
            }
            Err(e) => {
                assert!(false, "{:?}", &e);
                unreachable!();
            }
        }

        // got all messages
        let mut recved = vec![];
        for (i, rh) in flushed_handles.drain(..).enumerate() {
            test_debug!("recv {}", i);
            let res = rh.recv(0).unwrap();
            recved.push(res);
        }

        assert_eq!(recved, expected_messages);

        sender.join().unwrap();
        pusher.join().unwrap();
    }

    fn ping_factory(request_id: u32) -> StacksMessage {
        let mut rng = rand::thread_rng();
        let nonce = rng.next_u32();
        let mut ping = StacksMessage::new(
            0x12345678,
            0x9abcdef0,
            12345,
            &BurnchainHeaderHash([0x11; 32]),
            12339,
            &BurnchainHeaderHash([0x22; 32]),
            StacksMessageType::Ping(PingData { nonce }),
        );
        let privkey = Secp256k1PrivateKey::new();
        ping.sign(request_id, &privkey).unwrap();
        ping
    }

    #[test]
    fn test_connection_ping_relay_producer_consumer() {
        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5000;
        conn_opts.outbox_maxlen = 5000;

        let conn = ConnectionP2P::new(StacksP2P::new(), &conn_opts, None);

        test_connection_relay_producer_consumer(StacksP2P::new(), conn, ping_factory);
    }

    #[test]
    fn test_connection_ping_request_producer_consumer() {
        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5000;
        conn_opts.outbox_maxlen = 5000;

        let conn = ConnectionP2P::new(StacksP2P::new(), &conn_opts, None);

        test_connection_request_producer_consumer(StacksP2P::new(), conn, ping_factory);
    }

    #[test]
    fn connection_relay_send() {
        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let mut conn = ConnectionP2P::new(StacksP2P::new(), &conn_opts, None);

        // send
        let mut ping = StacksMessage::new(
            0x12345678,
            0x9abcdef0,
            12345,
            &BurnchainHeaderHash([0x11; 32]),
            12339,
            &BurnchainHeaderHash([0x22; 32]),
            StacksMessageType::Ping(PingData { nonce: 0x01020304 }),
        );

        let privkey = Secp256k1PrivateKey::new();
        ping.sign(1, &privkey).unwrap();

        let mut pipes = vec![]; // keep pipes in-scope
        for i in 0..5 {
            test_debug!("Write ping {}", i);
            let mut pipe = conn.make_relay_handle(0).unwrap();
            ping.consensus_serialize(&mut pipe).unwrap();
            pipes.push(pipe);
        }

        fn flush_all(pipes: &mut Vec<ReplyHandleP2P>) {
            for ref mut p in pipes.iter_mut() {
                let _ = p.try_flush();
            }
        }

        // 5 ping messages queued; no one expecting a reply
        for i in 0..5 {
            assert!(conn.outbox.outbox.get(i).unwrap().notify.is_none());
        }

        // size of one ping
        let ping_size = {
            let mut tmp = vec![];
            ping.consensus_serialize(&mut tmp).unwrap();
            tmp.len()
        };

        let mut ping_vec = vec![0; ping_size];
        let write_buf_len = ping_vec.len();
        let mut write_buf = NetCursor::new(ping_vec.as_mut_slice());

        // send one ping
        let mut nw = 0;
        while nw < write_buf_len {
            nw += conn.send_data(&mut write_buf).unwrap();
            flush_all(&mut pipes);
        }

        // 4 messages queued
        assert_eq!(conn.outbox.outbox.len(), 4);

        // 1 message serialized and buffered out, and it should be our ping.
        assert_eq!(
            StacksMessage::consensus_deserialize(&mut io::Cursor::new(
                &write_buf.get_ref().to_vec()
            ))
            .unwrap(),
            ping
        );

        // relay 1.5 pings
        let mut ping_buf_15 = vec![0; ping_size + (ping_size / 2)];
        let write_buf_15_len = ping_buf_15.len();
        let mut write_buf_15 = NetCursor::new(ping_buf_15.as_mut_slice());

        nw = 0;
        while nw < write_buf_15_len {
            nw += conn.send_data(&mut write_buf_15).unwrap();
            flush_all(&mut pipes);
        }

        // 3 messages still queued (the one partially-sent)
        assert_eq!(conn.outbox.outbox.len(), 3);
        assert_eq!(nw, ping_size + ping_size / 2);

        // buffer is partially full, with (ping_size / 2) bytes (the first half of a ping)
        assert_eq!(conn.outbox.socket_out_ptr, ping_size / 2);

        // the (ping_size / 2) bytes should be half a ping
        let mut serialized_ping = vec![];
        ping.consensus_serialize(&mut serialized_ping).unwrap();
        assert_eq!(
            conn.outbox.socket_out_buf[0..conn.outbox.socket_out_ptr],
            serialized_ping[0..conn.outbox.socket_out_ptr]
        );

        let mut half_ping =
            conn.outbox.socket_out_buf.clone()[0..conn.outbox.socket_out_ptr].to_vec();
        let mut ping_buf_05 = vec![0; 2 * ping_size - (ping_size + ping_size / 2)];

        // flush the remaining half-ping
        let write_buf_05_len = ping_buf_05.len();
        let mut write_buf_05 = NetCursor::new(ping_buf_05.as_mut_slice());

        nw = 0;
        while nw < write_buf_05_len {
            nw += conn.send_data(&mut write_buf_05).unwrap();
            flush_all(&mut pipes);
        }

        // 2 messages still queued
        assert_eq!(conn.outbox.outbox.len(), 2);

        // buffer is now empty
        assert_eq!(conn.outbox.socket_out_ptr, 0);

        // the combined ping buffers should be the serialized ping
        let mut combined_ping_buf = vec![];
        combined_ping_buf.append(&mut half_ping);
        combined_ping_buf.extend_from_slice(&write_buf_05.get_mut());

        assert_eq!(combined_ping_buf, serialized_ping);

        // receive the rest
        let mut ping_drain = vec![0; ping_size * 2];
        let drain_fd_len = ping_drain.len();
        let mut drain_fd = NetCursor::new(ping_drain.as_mut_slice());

        nw = 0;
        while nw < drain_fd_len {
            nw += conn.send_data(&mut drain_fd).unwrap();
            flush_all(&mut pipes);
        }

        assert_eq!(nw, ping_size * 2);
        assert_eq!(conn.outbox.outbox.len(), 0);
    }

    #[test]
    fn connection_relay_send_recv() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey = Secp256k1PublicKey::from_private(&privkey);

        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
            },
            public_key: pubkey.clone(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            allowed: -1,
            denied: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0,
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let mut conn = ConnectionP2P::new(StacksP2P::new(), &conn_opts, Some(neighbor.public_key));

        // send
        let mut ping_vec = vec![];
        let mut ping_size = 0;
        let mut pipes = vec![];
        for i in 0..5 {
            let mut ping = StacksMessage::new(
                0x12345678,
                0x9abcdef0,
                12345 + i,
                &BurnchainHeaderHash([0x11; 32]),
                12339 + i,
                &BurnchainHeaderHash([0x22; 32]),
                StacksMessageType::Ping(PingData { nonce: 0x01020304 }),
            );

            ping.sign(i as u32, &privkey).unwrap();
            ping_size = {
                let mut tmp = vec![];
                ping.consensus_serialize(&mut tmp).unwrap();
                tmp.len()
            };

            let mut pipe = conn.make_relay_handle(0).unwrap();
            ping.consensus_serialize(&mut pipe).unwrap();
            pipes.push(pipe);
            ping_vec.push(ping);
        }

        let pinger = thread::spawn(move || {
            let mut i = 0;
            while !pipes.is_empty() {
                let mut p = pipes.remove(0);
                i += 1;

                p.flush().unwrap();
            }
        });

        // buffer to send/receive everything
        let mut ping_buf = vec![0u8; 5 * ping_size];

        {
            let len = ping_buf.len();
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let mut nw = 0;
            while nw < len {
                nw += conn.send_data(&mut ping_fd).unwrap();
            }
            assert_eq!(nw, ping_size * 5);
        }

        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_read = conn.recv_data(&mut ping_fd).unwrap();
            assert_eq!(num_read, 5 * ping_size);
        }

        // all messages received? note that they are all unsolicited
        let msgs = conn.drain_inbox();
        assert_eq!(msgs, ping_vec);

        pinger.join().unwrap();
    }

    #[ignore] // fails intermittently when run via `cargo test`
    #[test]
    fn connection_send_recv() {
        with_timeout(100, || {
            let privkey = Secp256k1PrivateKey::new();
            let pubkey = Secp256k1PublicKey::from_private(&privkey);

            let neighbor = Neighbor {
                addr: NeighborKey {
                    peer_version: 0x12345678,
                    network_id: 0x9abcdef0,
                    addrbytes: PeerAddress([
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                        0x0c, 0x0d, 0x0e, 0x0f,
                    ]),
                    port: 12345,
                },
                public_key: pubkey.clone(),
                expire_block: 23456,
                last_contact_time: 1552509642,
                allowed: -1,
                denied: -1,
                asn: 34567,
                org: 45678,
                in_degree: 0,
                out_degree: 0,
            };

            let mut conn_opts = ConnectionOptions::default();
            conn_opts.inbox_maxlen = 5;
            conn_opts.outbox_maxlen = 5;

            let mut conn =
                ConnectionP2P::new(StacksP2P::new(), &conn_opts, Some(neighbor.public_key));

            // send
            let mut ping_vec = vec![];
            let mut handle_vec = vec![];
            let mut ping_size = 0;
            for i in 0..5 {
                let mut ping = StacksMessage::new(
                    0x12345678,
                    0x9abcdef0,
                    12345 + i,
                    &BurnchainHeaderHash([0x11; 32]),
                    12339 + i,
                    &BurnchainHeaderHash([0x22; 32]),
                    StacksMessageType::Ping(PingData {
                        nonce: (0x01020304 + i) as u32,
                    }),
                );

                ping.sign(i as u32, &privkey).unwrap();

                ping_size = {
                    let mut tmp = vec![];
                    ping.consensus_serialize(&mut tmp).unwrap();
                    tmp.len()
                };

                let mut handle = conn.make_request_handle(ping.request_id(), 60, 0).unwrap();
                ping.consensus_serialize(&mut handle).unwrap();

                handle_vec.push(handle);
                ping_vec.push(ping);
            }

            let (sx, rx) = sync_channel(1);

            let pinger = thread::spawn(move || {
                let mut rhs = vec![];

                while !handle_vec.is_empty() {
                    let mut handle = handle_vec.remove(0);
                    handle.flush().unwrap();
                    rhs.push(handle);
                }

                sx.send(rhs).unwrap();
            });

            let mut ping_buf = vec![0u8; 5 * ping_size];

            {
                let len = ping_buf.len();
                let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
                let mut nw = 0;
                while nw < len {
                    nw += conn.send_data(&mut ping_fd).unwrap();
                }
                assert_eq!(len, ping_size * 5);
            }

            let flushed_handles = rx.recv().unwrap();

            {
                let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
                let num_read = conn.recv_data(&mut ping_fd).unwrap();
                assert_eq!(num_read, 5 * ping_size);
            }

            // all messages are solicited, so inbox should be empty
            let msgs = conn.drain_inbox();
            assert_eq!(msgs, vec![]);

            let mut recved = vec![];
            for rh in flushed_handles {
                let res = rh.recv(0).unwrap();
                recved.push(res);
            }

            assert_eq!(recved, ping_vec);

            pinger.join().unwrap();
        })
    }

    #[test]
    fn connection_send_recv_timeout() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey = Secp256k1PublicKey::from_private(&privkey);

        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]),
                port: 12345,
            },
            public_key: pubkey.clone(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            allowed: -1,
            denied: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0,
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let mut conn = ConnectionP2P::new(StacksP2P::new(), &conn_opts, Some(neighbor.public_key));

        // send
        let mut ping_vec = vec![];
        let mut handle_vec = vec![];
        let mut ping_size = 0;
        for i in 0..5 {
            let mut ping = StacksMessage::new(
                0x12345678,
                0x9abcdef0,
                12345 + i,
                &BurnchainHeaderHash([0x11; 32]),
                12339 + i,
                &BurnchainHeaderHash([0x22; 32]),
                StacksMessageType::Ping(PingData {
                    nonce: (0x01020304 + i) as u32,
                }),
            );

            ping.sign(i as u32, &privkey).unwrap();
            ping_size = {
                let mut tmp = vec![];
                ping.consensus_serialize(&mut tmp).unwrap();
                tmp.len()
            };

            // 1-second timeout
            let mut handle = conn.make_request_handle(ping.request_id(), 1, 0).unwrap();
            ping.consensus_serialize(&mut handle).unwrap();

            handle_vec.push(handle);
            ping_vec.push(ping);
        }

        let (sx, rx) = sync_channel(1);

        let pinger = thread::spawn(move || {
            let mut rhs = vec![];

            while !handle_vec.is_empty() {
                let mut handle = handle_vec.remove(0);
                handle.flush().unwrap();
                rhs.push(handle);
            }

            sx.send(rhs).unwrap();
        });

        // buffer to send/receive everything
        let mut ping_buf = vec![0u8; 5 * ping_size];

        {
            let len = ping_buf.len();
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let mut nw = 0;
            while nw < len {
                nw += conn.send_data(&mut ping_fd).unwrap();
            }

            assert_eq!(nw, ping_size * 5);
        }

        let flushed_handles = rx.recv().unwrap();

        // wait 3 seconds
        test_debug!("Wait 3 seconds for Pings to time out");
        sleep_ms(3000);
        conn.drain_timeouts();

        // all messages timed out
        assert_eq!(conn.outbox.inflight.len(), 0);

        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_read = conn.recv_data(&mut ping_fd).unwrap();

            // data can still be received, but it won't be relayed.
            assert_eq!(num_read, ping_size * 5);
        }

        // messages not relayed, so they'll show up as queued in the inbox instead
        let msgs = conn.drain_inbox();
        assert_eq!(msgs, ping_vec);

        // all handles should be closed with the ConnectionBroken error
        for h in flushed_handles {
            let res = h.recv(0);
            assert_eq!(res, Err(net_error::ConnectionBroken));
        }

        pinger.join().unwrap();
    }
}
