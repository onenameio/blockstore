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

use std::collections::{HashMap, HashSet};
use std::{cmp, mem};

use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Hash160;
use stacks_common::util::log;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::{Address, PublicKey};
use crate::core::PEER_VERSION_TESTNET;
use crate::net::connection::{ConnectionOptions, ReplyHandleP2P};
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::neighbors::{
    NeighborWalk, NeighborWalkDB, NeighborWalkResult, MAX_NEIGHBOR_BLOCK_DELAY,
    NEIGHBOR_MINIMUM_CONTACT_INTERVAL,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{
    Error as net_error, HandshakeData, Neighbor, NeighborAddress, NeighborKey, PeerAddress,
    StacksMessage, StacksMessageType, NUM_NEIGHBORS,
};

/// A trait for representing session state for a set of connected neighbors, for the purposes of executing some P2P
/// algorithm.
pub trait NeighborComms {
    /// Add a neighbor and its event ID as connecting
    fn add_connecting<NK: ToNeighborKey>(
        &mut self,
        network: &PeerNetwork,
        nk: &NK,
        event_id: usize,
    );
    /// Get a connecting neighbor's event ID
    fn get_connecting<NK: ToNeighborKey>(&self, network: &PeerNetwork, nk: &NK) -> Option<usize>;
    /// Remove a neighbor from connecting state
    fn remove_connecting<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK);
    /// Remove a neighbor from connecting state due to an error
    fn remove_connecting_error<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK);
    /// Mark a neighbor as dead (inactive, unreachable, etc.)
    fn add_dead<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK);
    /// Mark a neighbor as broken (in protocol violation)
    fn add_broken<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK);
    /// Pin a connection -- prevent it from getting pruned
    fn pin_connection(&mut self, event_id: usize);
    /// Unpin a connection -- allow it to get pruned
    fn unpin_connection(&mut self, event_id: usize);
    /// Get the collection of pinned connections
    fn get_pinned_connections(&self) -> &HashSet<usize>;
    /// Clear all pinned connections and return them.
    /// List items are guaranteed to be unique
    fn clear_pinned_connections(&mut self) -> HashSet<usize>;
    /// Is the connection pinned?
    fn is_pinned(&self, event_id: usize) -> bool;
    /// Add an in-flight request to begin polling on
    fn add_batch_request(&mut self, naddr: NeighborAddress, rh: ReplyHandleP2P);
    /// Get the number of inflight requests
    fn count_inflight(&self) -> usize;
    /// Does a given neighbor have an inflight request?
    fn has_inflight(&self, naddr: &NeighborAddress) -> bool;
    /// Poll for any received messages.
    fn collect_replies(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Vec<(NeighborAddress, StacksMessage)>;
    /// Take all dead neighbors
    fn take_dead_neighbors(&mut self) -> HashSet<NeighborKey>;
    /// Take all broken neighbors
    fn take_broken_neighbors(&mut self) -> HashSet<NeighborKey>;
    /// Cancel any ongoing requests.  Any messages that had been enqueued from
    /// `add_batch_request()` will not be delivered after this call completes.
    fn cancel_inflight(&mut self);

    /// Send off a handshake to a remote peer.
    /// Fails if not connected.
    fn neighbor_handshake<NK: ToNeighborKey>(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_addr: &NK,
    ) -> Result<ReplyHandleP2P, net_error> {
        let nk = neighbor_addr.to_neighbor_key(network);

        // send handshake.
        let handshake_data = HandshakeData::from_local_peer(network.get_local_peer());

        debug!(
            "{:?}: send Handshake to {:?}",
            network.get_local_peer(),
            &nk
        );

        let msg = network
            .sign_for_neighbor(&nk, StacksMessageType::Handshake(handshake_data))
            .map_err(|e| {
                info!(
                    "{:?}: Failed to sign for peer {:?}",
                    network.get_local_peer(),
                    &nk
                );
                self.add_dead(network, &nk);
                e
            })?;

        network
            .send_neighbor_message(&nk, msg, network.get_connection_opts().timeout)
            .map_err(|e| {
                debug!(
                    "{:?}: Not connected: {:?} ({:?})",
                    network.get_local_peer(),
                    &nk,
                    &e
                );
                self.add_dead(network, &nk);
                net_error::PeerNotConnected
            })
    }

    /// Connect to a neighbor if we're not connected yet, and send it a handshake.
    /// Returns Ok(Some(handle)) if the handshake is now sending
    /// Returns Ok(None) if we're still connecting. The caller should try again.
    /// Returns Err(..) if connection or sending failed for some reason.
    fn neighbor_connect_and_handshake<NK: ToNeighborKey>(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_addr: &NK,
    ) -> Result<Option<ReplyHandleP2P>, net_error> {
        let nk = neighbor_addr.to_neighbor_key(network);
        if network.is_registered(&nk) {
            // already connected
            self.remove_connecting(network, &nk);
            return self.neighbor_handshake(network, &nk).map(Some);
        }

        if let Some(event_id) = self.get_connecting(network, &nk) {
            // is the peer network still working?
            if !network.is_connecting(event_id) {
                debug!("{:?}: Failed to connect to {:?} (event {} no longer connecting; assumed timed out)", network.get_local_peer(), event_id, &nk);
                self.remove_connecting_error(network, &nk);
                return Err(net_error::PeerNotConnected);
            }

            // still connecting
            debug!(
                "{:?}: still connecting to {:?} (event {})",
                network.get_local_peer(),
                &nk,
                event_id
            );
            return Ok(None);
        }

        match network.can_register_peer(&nk, true) {
            Ok(_) => {
                let event_id = network.connect_peer(&nk).map_err(|_e| {
                    debug!(
                        "{:?}: Failed to connect to {:?}: {:?}",
                        network.get_local_peer(),
                        &nk,
                        &_e
                    );
                    net_error::PeerNotConnected
                })?;

                // remember this in the walk result
                self.add_connecting(network, &nk, event_id);

                // force the caller to try again -- we're not registered yet
                debug!(
                    "{:?}: Connecting to {:?} (event {})",
                    network.get_local_peer(),
                    &nk,
                    event_id
                );
                return Ok(None);
            }
            Err(net_error::AlreadyConnected(_event_id, alt_nk)) => {
                test_debug!(
                    "{:?}: already connected to {:?} as event {} ({:?})",
                    network.get_local_peer(),
                    &nk,
                    _event_id,
                    &alt_nk
                );
                self.remove_connecting(network, &alt_nk);
                return self.neighbor_handshake(network, &alt_nk).map(Some);
            }
            Err(e) => {
                info!(
                    "{:?}: could not connect to {:?}: {:?}",
                    network.get_local_peer(),
                    &nk,
                    &e
                );
                return Err(e);
            }
        }
    }

    /// Connect to a remote neighbor, and get back a reply handle which we can use to wait for a
    /// handshake response.  If the neighbor is already connected, then just send a handshake.
    ///
    /// Normally, the caller would track the returned reply handle with a call to
    /// `add_batch_request()`.  However, this is ommitted here for callers who want to do their own
    /// polling.
    ///
    /// Return Ok(Some(handle)) if we connected.
    /// Return Ok(None) if we're in the process of connecting, and should try again.
    /// Return Err(..) if we fail
    fn neighbor_session_begin_only<NK: ToNeighborKey>(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_addr: &NK,
        neighbor_pubkh: &Hash160,
    ) -> Result<Option<ReplyHandleP2P>, net_error> {
        let nk = neighbor_addr.to_neighbor_key(network);
        match network.can_register_peer_with_pubkey(&nk, true, &neighbor_pubkh) {
            Ok(_) => self.neighbor_connect_and_handshake(network, &nk),
            Err(net_error::AlreadyConnected(event_id, handshake_nk)) => {
                // already connected, but on a possibly-different address.
                // If the already-connected handle is inbound,
                // then try to connect to this address anyway in
                // order to maximize our outbound connections we have.
                if let Some(convo) = network.get_p2p_convo(event_id) {
                    if !convo.is_outbound() {
                        test_debug!("{:?}: Already connected to {:?} on inbound event {} (address {:?}). Try to establish outbound connection to {:?} {:?}.",
                               network.get_local_peer(), &nk, &event_id, &handshake_nk, &neighbor_pubkh, &nk);

                        self.remove_connecting(network, &nk);
                        return self.neighbor_handshake(network, &nk).map(Some);
                    }
                    test_debug!(
                        "{:?}: Already connected to {:?} on event {} (address: {:?})",
                        network.get_local_peer(),
                        &nk,
                        &event_id,
                        &handshake_nk
                    );
                    self.remove_connecting(network, &handshake_nk);
                    let handle = self.neighbor_handshake(network, &handshake_nk)?;
                    return Ok(Some(handle));
                }

                // should never be reachable
                error!(
                    "AlreadyConnected error on event {} has no conversation",
                    event_id
                );
                return Err(net_error::PeerNotConnected);
            }
            Err(e) => {
                test_debug!(
                    "{:?}: Failed to check connection to {:?}: {:?}. No handshake sent.",
                    network.get_local_peer(),
                    &nk,
                    &e
                );
                return Err(e);
            }
        }
    }

    /// Connect to a remote neighbor, optionally connecting to it first.
    /// If successful, a Handshake message will be sent, and the returned HandshakeAccept or
    /// HandshakeReject can be obtained with a follow up call to `collect_replies()`
    ///
    /// Return Ok(true) if we connected.
    /// Return Ok(false) if we're in the process of connecting, and should try again.
    fn neighbor_session_begin(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_addr: &NeighborAddress,
    ) -> Result<bool, net_error> {
        let handle_opt = self.neighbor_session_begin_only(
            network,
            neighbor_addr,
            &neighbor_addr.public_key_hash,
        )?;
        if let Some(handle) = handle_opt {
            self.add_batch_request(neighbor_addr.clone(), handle);
            return Ok(true);
        }

        // still trying
        Ok(false)
    }

    /// Send a message to a connected neighbor.
    /// Fails if the neighbor is not connected.
    ///
    /// If successful, the caller usually calls `add_batch_request()`.  This
    /// is not carried out here because the caller may instead want to do a blocking wait
    /// with the given reply handle (or do its own batching).
    fn neighbor_send_only<NK: ToNeighborKey>(
        network: &mut PeerNetwork,
        neighbor_addr: &NK,
        msg_payload: StacksMessageType,
    ) -> Result<ReplyHandleP2P, net_error> {
        let nk = neighbor_addr.to_neighbor_key(network);
        let msg = network.sign_for_neighbor(&nk, msg_payload)?;
        network.send_neighbor_message(&nk, msg, network.get_connection_opts().timeout)
    }

    /// Send a message to a connected neighbor.
    /// If successful, the reply handle is then tracked via a follow-up call to
    /// `add_batch_request()`.
    /// Fails if the neighbor is not connected.
    fn neighbor_send(
        &mut self,
        network: &mut PeerNetwork,
        neighbor_addr: &NeighborAddress,
        msg_payload: StacksMessageType,
    ) -> Result<(), net_error> {
        let handle = Self::neighbor_send_only(network, neighbor_addr, msg_payload)?;
        self.add_batch_request(neighbor_addr.clone(), handle);
        Ok(())
    }

    /// Try to receive a message from a peer handle.
    /// On success, consume the reply handle and return the StacksMessage.
    /// On error, either return the reply handle so we can try again, or return an error if we
    /// encounter an irrecoverable failure.
    fn neighbor_try_recv(
        &mut self,
        network: &mut PeerNetwork,
        mut req: ReplyHandleP2P,
    ) -> Result<StacksMessage, Result<ReplyHandleP2P, net_error>> {
        if let Err(e) = network.saturate_p2p_socket(req.get_event_id(), &mut req) {
            return Err(Err(e));
        }

        match req.try_send_recv() {
            Ok(message) => {
                return Ok(message);
            }
            Err(Ok(same_req)) => {
                // try again
                return Err(Ok(same_req));
            }
            Err(Err(e)) => {
                // disconnected
                debug!(
                    "{:?}: Failed to get reply: {:?}",
                    network.get_local_peer(),
                    &e
                );
                return Err(Err(e));
            }
        }
    }

    /// Get the next message from the given reply handle option.
    /// If the next message is obtained, then the reply handle option is set to None.
    /// If the next message is not obtained, but the reply is still in-flight, then capture and
    /// preserve the reply handle in the given argument. The caller should try again later.
    /// If there was an error, then the reply handle option is set to None and an error is
    /// returned. The given NeighborKey is marked as dead.
    fn poll_next_reply<NK: ToNeighborKey>(
        &mut self,
        network: &mut PeerNetwork,
        req_nk: &NK,
        req: &mut Option<ReplyHandleP2P>,
    ) -> Result<Option<StacksMessage>, net_error> {
        match req.take() {
            Some(rh) => match self.neighbor_try_recv(network, rh) {
                Ok(message) => Ok(Some(message)),
                Err(Ok(rh)) => {
                    req.replace(rh);
                    Ok(None)
                }
                Err(Err(e)) => {
                    self.add_dead(network, req_nk);
                    Err(e)
                }
            },
            None => Err(net_error::PeerNotConnected),
        }
    }

    /// Are we connected and handshake'd already to a neighbor?
    fn has_neighbor_session<NK: ToNeighborKey>(&self, network: &PeerNetwork, nk: &NK) -> bool {
        let Some(convo) = network.get_neighbor_convo(&nk.to_neighbor_key(network)) else {
            return false;
        };
        convo.is_authenticated() && convo.peer_version > 0
    }

    /// Are we in the process of connecting to a neighbor?
    fn is_neighbor_connecting<NK: ToNeighborKey>(&self, network: &PeerNetwork, nk: &NK) -> bool {
        if network.is_connecting_neighbor(&nk.to_neighbor_key(network)) {
            return true;
        }
        let Some(event_id) = self.get_connecting(network, nk) else {
            return false;
        };
        network.is_connecting(event_id)
    }

    /// Reset all comms
    fn reset(&mut self) {
        let _ = self.take_broken_neighbors();
        let _ = self.take_dead_neighbors();
        self.cancel_inflight();
        self.clear_pinned_connections();
    }
}

/// Transport-level API for peer network state machines.
/// Prod implementation of NeighborComms.
pub struct PeerNetworkComms {
    /// Set of PeerNetwork event IDs that this walk is tracking (so they won't get pruned)
    events: HashSet<usize>,
    /// Map of neighbors we're currently trying to connect to (binds their addresses to their event IDs)
    connecting: HashMap<NeighborKey, usize>,
    /// Set of neighbors that died during our comms session
    dead_connections: HashSet<NeighborKey>,
    /// Set of neighbors who misbehaved during our comms session
    broken_connections: HashSet<NeighborKey>,
    /// Ongoing batch of p2p requests.  Will be `None` if there are no inflight requests.
    ongoing_batch_request: Option<NeighborCommsRequest>,
}

impl PeerNetworkComms {
    pub fn new() -> PeerNetworkComms {
        PeerNetworkComms {
            events: HashSet::new(),
            connecting: HashMap::new(),
            dead_connections: HashSet::new(),
            broken_connections: HashSet::new(),
            ongoing_batch_request: None,
        }
    }

    /// Drive socket I/O on all outstanding messages and gather up any received messages.
    /// Remove handled messages from `state`, and perform the polling (and bookkeeping of dead/broken neighbors) via `neighbor_set`
    fn drive_socket_io<NS: NeighborComms>(
        network: &mut PeerNetwork,
        state: &mut HashMap<NeighborAddress, ReplyHandleP2P>,
        neighbor_set: &mut NS,
    ) -> Vec<(NeighborAddress, StacksMessage)> {
        let mut inflight = HashMap::new();
        let mut ret = vec![];
        let stable_block_height = network.get_chain_view().burn_stable_block_height;
        for (naddr, rh) in state.drain() {
            let mut req_opt = Some(rh);
            let message = match neighbor_set.poll_next_reply(network, &naddr, &mut req_opt) {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    if let Some(rh) = req_opt {
                        // keep trying
                        debug!("{:?}: keep polling {}", network.get_local_peer(), naddr);
                        inflight.insert(naddr, rh);
                    }
                    continue;
                }
                Err(_e) => {
                    // peer was already marked as dead in the given network set
                    debug!(
                        "{:?}: peer {} is dead: {:?}",
                        network.get_local_peer(),
                        naddr,
                        &_e
                    );
                    continue;
                }
            };

            if NeighborCommsRequest::is_message_stale(&message, stable_block_height) {
                debug!(
                    "{:?}: Remote neighbor {:?} is still bootstrapping (at block {})",
                    &network.get_local_peer(),
                    &naddr,
                    message.preamble.burn_stable_block_height
                );
                continue;
            }

            ret.push((naddr, message));
        }
        state.extend(inflight);
        ret
    }
}

impl NeighborComms for PeerNetworkComms {
    fn add_connecting<NK: ToNeighborKey>(
        &mut self,
        network: &PeerNetwork,
        nk: &NK,
        event_id: usize,
    ) {
        self.connecting
            .insert(nk.to_neighbor_key(network), event_id);
        self.pin_connection(event_id);
    }

    fn get_connecting<NK: ToNeighborKey>(&self, network: &PeerNetwork, nk: &NK) -> Option<usize> {
        self.connecting
            .get(&nk.to_neighbor_key(network))
            .map(|event_ref| *event_ref)
    }

    /// Remove a connecting neighbor because it connected
    fn remove_connecting<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK) {
        self.connecting.remove(&nk.to_neighbor_key(network));
    }

    /// Remove a connecting neighbor due to an error.  The connection will be unpinned.
    fn remove_connecting_error<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK) {
        let event_id_opt = self.connecting.remove(&nk.to_neighbor_key(network));
        if let Some(event_id) = event_id_opt {
            self.unpin_connection(event_id);
        }
    }

    fn add_dead<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK) {
        self.dead_connections.insert(nk.to_neighbor_key(network));
    }

    fn add_broken<NK: ToNeighborKey>(&mut self, network: &PeerNetwork, nk: &NK) {
        self.broken_connections.insert(nk.to_neighbor_key(network));
    }

    fn pin_connection(&mut self, event_id: usize) {
        self.events.insert(event_id);
    }

    fn unpin_connection(&mut self, event_id: usize) {
        self.events.remove(&event_id);
    }

    fn get_pinned_connections(&self) -> &HashSet<usize> {
        &self.events
    }

    fn clear_pinned_connections(&mut self) -> HashSet<usize> {
        let events = mem::replace(&mut self.events, HashSet::new());
        events
    }

    fn is_pinned(&self, event_id: usize) -> bool {
        self.events.contains(&event_id)
    }

    #[cfg_attr(test, mutants::skip)]
    fn add_batch_request(&mut self, naddr: NeighborAddress, rh: ReplyHandleP2P) {
        if let Some(ref mut batch) = self.ongoing_batch_request.as_mut() {
            batch.add(naddr, rh);
        } else {
            let mut batch = NeighborCommsRequest::new();
            batch.add(naddr, rh);
            self.ongoing_batch_request = Some(batch);
        }
    }

    fn count_inflight(&self) -> usize {
        self.ongoing_batch_request
            .as_ref()
            .map(|batch| batch.count_inflight())
            .unwrap_or(0)
    }

    fn has_inflight(&self, naddr: &NeighborAddress) -> bool {
        self.ongoing_batch_request
            .as_ref()
            .map(|batch| batch.state.contains_key(naddr))
            .unwrap_or(false)
    }

    fn collect_replies(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Vec<(NeighborAddress, StacksMessage)> {
        let mut ret = vec![];
        let mut clear = false;
        let mut ongoing_batch_request = self.ongoing_batch_request.take();
        if let Some(batch) = ongoing_batch_request.as_mut() {
            ret = Self::drive_socket_io(network, &mut batch.state, self);
            if batch.count_inflight() == 0 {
                clear = true;
            }
        }
        if clear {
            self.ongoing_batch_request = None;
        } else {
            self.ongoing_batch_request = ongoing_batch_request;
        }
        ret
    }

    fn cancel_inflight(&mut self) {
        self.ongoing_batch_request = None;
    }

    fn take_dead_neighbors(&mut self) -> HashSet<NeighborKey> {
        let dead = mem::replace(&mut self.dead_connections, HashSet::new());
        dead
    }

    fn take_broken_neighbors(&mut self) -> HashSet<NeighborKey> {
        let broken = mem::replace(&mut self.broken_connections, HashSet::new());
        broken
    }
}

/// This is a helper trait to ensure that a given struct can be turned into a NeighborKey for the
/// purposes of maintaining the active peer set
pub trait ToNeighborKey {
    fn to_neighbor_key(&self, network: &PeerNetwork) -> NeighborKey;
}

impl ToNeighborKey for NeighborKey {
    fn to_neighbor_key(&self, _network: &PeerNetwork) -> NeighborKey {
        self.clone()
    }
}

impl ToNeighborKey for NeighborAddress {
    fn to_neighbor_key(&self, network: &PeerNetwork) -> NeighborKey {
        // NOTE: PartialEq and Hash for NeighborKey ignore the low bits of peer version
        // and ignore network ID, and the ConversationP2P ensures that we never even connect
        // to a node with the wrong network ID or wrong peer version bits anyway, so
        // it's safe to use the local node's copies of this data to construct a
        // NeighborKey for the purposes of later disconnecting from it.
        NeighborKey::from_neighbor_address(
            network.bound_neighbor_key().peer_version,
            network.bound_neighbor_key().network_id,
            self,
        )
    }
}

/// This struct represents a batch of in-flight requests to a set of peers, identified by a
/// neighbor key (or something that converts to it)
#[derive(Debug)]
pub struct NeighborCommsRequest {
    state: HashMap<NeighborAddress, ReplyHandleP2P>,
}

impl NeighborCommsRequest {
    pub fn new() -> NeighborCommsRequest {
        NeighborCommsRequest {
            state: HashMap::new(),
        }
    }

    pub fn add(&mut self, naddr: NeighborAddress, rh: ReplyHandleP2P) {
        self.state.insert(naddr, rh);
    }

    /// Is a given message too stale to be acted upon?
    /// This would be true if the node's reported burnchain block height is too far in the past.
    pub fn is_message_stale(msg: &StacksMessage, burn_block_height: u64) -> bool {
        msg.preamble.burn_stable_block_height + MAX_NEIGHBOR_BLOCK_DELAY < burn_block_height
    }

    /// How many inflight requests remaining?
    #[cfg_attr(test, mutants::skip)]
    pub fn count_inflight(&self) -> usize {
        self.state.len()
    }
}
