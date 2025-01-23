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

use std::collections::{HashMap, HashSet};
use std::{cmp, mem};

use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::types::net::PeerHost;
use stacks_common::util::hash::Hash160;
use stacks_common::util::log;
use stacks_common::util::secp256k1::Secp256k1PublicKey;

use crate::burnchains::{Address, PublicKey};
use crate::core::PEER_VERSION_TESTNET;
use crate::net::connection::{ConnectionOptions, ReplyHandleP2P};
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::neighbors::comms::ToNeighborKey;
use crate::net::neighbors::{
    NeighborWalk, NeighborWalkDB, NeighborWalkResult, MAX_NEIGHBOR_BLOCK_DELAY,
    NEIGHBOR_MINIMUM_CONTACT_INTERVAL,
};
use crate::net::p2p::PeerNetwork;
use crate::net::server::HttpPeer;
use crate::net::{
    Error as NetError, HandshakeData, Neighbor, NeighborAddress, NeighborKey, PeerAddress,
    PeerHostExtensions, StacksHttpRequest, StacksHttpResponse, StacksMessage, StacksMessageType,
    NUM_NEIGHBORS,
};

/// This struct represents a batch of in-flight RPCs to a set of peers, identified by a
/// neighbor key (or something that converts to it)
#[derive(Debug)]
pub struct NeighborRPC {
    state: HashMap<NeighborAddress, (usize, Option<StacksHttpRequest>)>,
    dead: HashSet<NeighborKey>,
    broken: HashSet<NeighborKey>,
}

impl NeighborRPC {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
            dead: HashSet::new(),
            broken: HashSet::new(),
        }
    }

    /// Add a dead neighbor -- a neighbor which failed to communicate with us.
    pub fn add_dead(&mut self, network: &PeerNetwork, naddr: &NeighborAddress) {
        self.dead.insert(naddr.to_neighbor_key(network));
    }

    /// Add a broken neighbor -- a neighbor which violated protocol.
    pub fn add_broken(&mut self, network: &PeerNetwork, naddr: &NeighborAddress) {
        self.broken.insert(naddr.to_neighbor_key(network));
    }

    /// Is a neighbor dead?
    pub fn is_dead(&self, network: &PeerNetwork, naddr: &NeighborAddress) -> bool {
        self.dead.contains(&naddr.to_neighbor_key(network))
    }

    /// Is a neighbor broken
    pub fn is_broken(&self, network: &PeerNetwork, naddr: &NeighborAddress) -> bool {
        self.broken.contains(&naddr.to_neighbor_key(network))
    }

    /// Is a neighbor dead or broken?
    pub fn is_dead_or_broken(&self, network: &PeerNetwork, naddr: &NeighborAddress) -> bool {
        let nk = naddr.to_neighbor_key(network);
        self.dead.contains(&nk) || self.broken.contains(&nk)
    }

    /// Extract the list of dead neighbors
    pub fn take_dead(&mut self) -> HashSet<NeighborKey> {
        std::mem::replace(&mut self.dead, HashSet::new())
    }

    /// Extract the list of broken neighbors
    pub fn take_broken(&mut self) -> HashSet<NeighborKey> {
        std::mem::replace(&mut self.broken, HashSet::new())
    }

    /// Collect all in-flight replies into a vec.
    /// This also pushes data into each connection's socket write buffer,
    /// so the client of this module should eagerly call this over and over again.
    pub fn collect_replies(
        &mut self,
        network: &mut PeerNetwork,
    ) -> Vec<(NeighborAddress, StacksHttpResponse)> {
        let mut inflight = HashMap::new();
        let mut dead = vec![];
        let mut ret = vec![];
        for (naddr, (event_id, mut request_opt)) in self.state.drain() {
            let response = match NeighborRPC::poll_next_reply(network, event_id, &mut request_opt) {
                Ok(Some(response)) => response,
                Ok(None) => {
                    // keep trying
                    debug!("Still waiting for next reply from {}", &naddr);
                    inflight.insert(naddr, (event_id, request_opt));
                    continue;
                }
                Err(NetError::WaitingForDNS) => {
                    // keep trying
                    debug!(
                        "Could not yet poll next reply from {}: waiting for DNS",
                        &naddr
                    );
                    inflight.insert(naddr, (event_id, request_opt));
                    continue;
                }
                Err(_e) => {
                    // declare this neighbor as dead by default
                    debug!("Failed to poll next reply from {}: {:?}", &naddr, &_e);
                    dead.push(naddr);
                    continue;
                }
            };

            ret.push((naddr, response));
        }
        for naddr in dead.into_iter() {
            self.add_dead(network, &naddr);
        }
        self.state.extend(inflight);
        ret
    }

    /// How many inflight requests remaining?
    pub fn count_inflight(&self) -> usize {
        self.state.len()
    }

    /// Does a neighbor have an in-flight request?
    pub fn has_inflight(&self, naddr: &NeighborAddress) -> bool {
        self.state.contains_key(naddr)
    }

    /// Find the PeerHost to use when creating a Stacks HTTP request.
    /// Returns Some(host) if we're connected and authenticated to this peer
    /// Returns None otherwise.
    pub fn get_peer_host(network: &PeerNetwork, addr: &NeighborAddress) -> Option<PeerHost> {
        let nk = addr.to_neighbor_key(network);
        let convo = network.get_neighbor_convo(&nk)?;
        PeerHost::try_from_url(&convo.data_url)
    }

    /// Send an HTTP request to the given neighbor's HTTP endpoint.
    /// Returns Ok(()) if we successfully queue the request.
    /// Returns Err(..) if we fail to connect to the remote peer for some reason.
    pub fn send_request(
        &mut self,
        network: &mut PeerNetwork,
        naddr: NeighborAddress,
        request: StacksHttpRequest,
    ) -> Result<(), NetError> {
        let nk = naddr.to_neighbor_key(network);
        let convo = network
            .get_neighbor_convo(&nk)
            .ok_or(NetError::PeerNotConnected)?;
        let data_url = convo.data_url.clone();
        let data_addr = if let Some(ip) = convo.data_ip {
            ip.clone()
        } else if convo.waiting_for_dns() {
            debug!(
                "{}: have not resolved {} data URL {} yet: waiting for DNS",
                network.get_local_peer(),
                &convo,
                &data_url
            );
            return Err(NetError::WaitingForDNS);
        } else {
            debug!(
                "{}: have not resolved {} data URL {} yet, and not waiting for DNS",
                network.get_local_peer(),
                &convo,
                &data_url
            );
            return Err(NetError::PeerNotConnected);
        };

        let event_id =
            PeerNetwork::with_network_state(network, |ref mut network, ref mut network_state| {
                PeerNetwork::with_http(network, |ref mut network, ref mut http| {
                    match http.connect_http(network_state, network, data_url, data_addr, None) {
                        Ok(event_id) => Ok(event_id),
                        Err(NetError::AlreadyConnected(event_id, _)) => Ok(event_id),
                        Err(e) => {
                            return Err(e);
                        }
                    }
                })
            })?;

        debug!(
            "Send request to {} on event {}: {:?}",
            &naddr, event_id, &request
        );
        self.state.insert(naddr, (event_id, Some(request)));
        Ok(())
    }

    /// Drive I/O on a given network conversation.
    /// Send the HTTP request if we haven't already done so, saturate the underlying TCP socket
    /// with bytes, and poll the event loop for any completed messages.  If we get one, then return
    /// it.
    ///
    /// Returns Ok(Some(response)) if the HTTP request completed
    /// Returns Ok(None) if we are still connecting to the remote peer, or waiting for it to reply
    /// Returns Err(NetError::WaitingForDNS) if we're still waiting to resolve the peer's data URL
    /// Returns Err(..) if we fail to connect, or if we are unable to receive a reply.
    fn poll_next_reply(
        network: &mut PeerNetwork,
        event_id: usize,
        request_opt: &mut Option<StacksHttpRequest>,
    ) -> Result<Option<StacksHttpResponse>, NetError> {
        PeerNetwork::with_http(network, |network, http| {
            // make sure we're connected
            let (Some(ref mut convo), Some(ref mut socket)) =
                http.get_conversation_and_socket(event_id)
            else {
                if http.is_connecting(event_id) {
                    debug!(
                        "{:?}: HTTP event {} is not connected yet",
                        &network.local_peer, event_id
                    );
                    return Ok(None);
                } else {
                    // conversation died
                    debug!("{:?}: HTTP event {} hung up", &network.local_peer, event_id);
                    return Err(NetError::PeerNotConnected);
                }
            };

            // drive socket I/O
            if let Some(request) = request_opt.take() {
                convo.send_request(request)?;
            };
            HttpPeer::saturate_http_socket(socket, convo)?;

            // see if we got any data
            let Some(http_response) = convo.try_get_response() else {
                if !convo.is_idle() {
                    // still waiting
                    debug!(
                        "{:?}: HTTP event {} is still waiting for a response",
                        &network.local_peer, event_id
                    );
                }
                return Ok(None);
            };

            Ok(Some(http_response))
        })
    }
}
