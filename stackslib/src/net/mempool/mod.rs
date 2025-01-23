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

use std::net::SocketAddr;

use rand::prelude::*;
use rand::thread_rng;
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};
use url;

use crate::burnchains::Txid;
use crate::chainstate::stacks::StacksTransaction;
use crate::core::MemPoolDB;
use crate::net::chat::ConversationP2P;
use crate::net::dns::{DNSClient, DNSRequest};
use crate::net::httpcore::StacksHttpRequest;
use crate::net::inv::inv2x::*;
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, HttpRequestContents};
use crate::util_lib::strings::UrlString;

/// The four states the mempool sync state machine can be in
#[derive(Debug, Clone, PartialEq)]
pub enum MempoolSyncState {
    /// Picking an outbound peer
    PickOutboundPeer,
    /// Resolving its data URL to a SocketAddr. Contains the data URL, DNS request handle, and
    /// mempool page ID
    ResolveURL(UrlString, DNSRequest, Txid),
    /// Sending the request for mempool transactions. Contains the data URL, resolved socket, and
    /// mempool page.
    SendQuery(UrlString, SocketAddr, Txid),
    /// Receiving the mempool response. Contains the URL, socket address, and event ID
    RecvResponse(UrlString, SocketAddr, usize),
}

/// Mempool synchronization state machine
#[derive(Debug, Clone, PartialEq)]
pub struct MempoolSync {
    /// what state are we in?
    mempool_state: MempoolSyncState,
    /// when's the next mempool sync start?
    mempool_sync_deadline: u64,
    /// how long can the sync go for?
    mempool_sync_timeout: u64,
    /// how many complete syncs have happened
    mempool_sync_completions: u64,
    /// how many txs have been sync'ed?
    pub(crate) mempool_sync_txs: u64,
    /// what's the API endpoint?
    api_endpoint: String,
}

impl MempoolSync {
    pub fn new() -> Self {
        Self {
            mempool_state: MempoolSyncState::PickOutboundPeer,
            mempool_sync_deadline: 0,
            mempool_sync_timeout: 0,
            mempool_sync_completions: 0,
            mempool_sync_txs: 0,
            api_endpoint: "/v2/mempool/query".to_string(),
        }
    }

    /// Do a mempool sync. Return any transactions we might receive.
    #[cfg_attr(test, mutants::skip)]
    pub fn run(
        &mut self,
        network: &mut PeerNetwork,
        dns_client_opt: &mut Option<&mut DNSClient>,
        mempool: &MemPoolDB,
        ibd: bool,
    ) -> Option<Vec<StacksTransaction>> {
        if ibd {
            return None;
        }

        return match self.do_mempool_sync(network, dns_client_opt, mempool) {
            (true, txs_opt) => {
                // did we run to completion?
                if let Some(txs) = txs_opt {
                    debug!(
                        "{:?}: Mempool sync obtained {} transactions from mempool sync, and done receiving",
                        &network.get_local_peer(),
                        txs.len()
                    );

                    self.mempool_sync_deadline =
                        get_epoch_time_secs() + network.get_connection_opts().mempool_sync_interval;
                    self.mempool_sync_completions = self.mempool_sync_completions.saturating_add(1);
                    self.mempool_sync_txs = self.mempool_sync_txs.saturating_add(txs.len() as u64);
                    Some(txs)
                } else {
                    None
                }
            }
            (false, txs_opt) => {
                // did we get some transactions, but have more to get?
                if let Some(txs) = txs_opt {
                    debug!(
                        "{:?}: Mempool sync obtained {} transactions from mempool sync, but have more",
                        &network.get_local_peer(),
                        txs.len()
                    );

                    self.mempool_sync_txs = self.mempool_sync_txs.saturating_add(txs.len() as u64);
                    Some(txs)
                } else {
                    None
                }
            }
        };
    }

    /// Reset a mempool sync
    fn mempool_sync_reset(&mut self) {
        self.mempool_state = MempoolSyncState::PickOutboundPeer;
        self.mempool_sync_timeout = 0;
    }

    /// Pick a peer to mempool sync with.
    /// Returns Ok(None) if we're done syncing the mempool.
    /// Returns Ok(Some(..)) if we're not done, and can proceed
    /// Returns the new sync state -- either ResolveURL if we need to resolve a data URL,
    /// or SendQuery if we got the IP address and can just issue the query.
    #[cfg_attr(test, mutants::skip)]
    fn mempool_sync_pick_outbound_peer(
        &mut self,
        network: &mut PeerNetwork,
        dns_client_opt: &mut Option<&mut DNSClient>,
        page_id: &Txid,
    ) -> Result<Option<MempoolSyncState>, NetError> {
        let num_peers = network.get_num_p2p_convos();
        if num_peers == 0 {
            debug!("No peers connected; cannot do mempool sync");
            return Ok(None);
        }

        let mut idx = thread_rng().gen::<usize>() % num_peers;
        let mut mempool_sync_data_url = None;
        let mut mempool_sync_data_url_and_sockaddr = None;
        for _ in 0..num_peers {
            let Some((_event_id, convo)) = network.iter_peer_convos().skip(idx).next() else {
                idx = 0;
                continue;
            };
            idx = (idx + 1) % num_peers;

            // only talk to authenticated, outbound peers
            if !convo.is_authenticated() || !convo.is_outbound() {
                continue;
            }
            // peer must support mempool protocol
            if !ConversationP2P::supports_mempool_query(convo.peer_services) {
                continue;
            }
            // has a data URL?
            if convo.data_url.is_empty() {
                continue;
            }
            // already resolved?
            if let Some(sockaddr) = convo.data_ip.as_ref() {
                mempool_sync_data_url_and_sockaddr =
                    Some((convo.data_url.clone(), sockaddr.clone()));
                break;
            }
            // can we resolve the data URL?
            let url = convo.data_url.clone();
            if dns_client_opt.is_none() {
                if let Ok(Some(_)) = PeerNetwork::try_get_url_ip(&url) {
                } else {
                    // need a DNS client for this one
                    continue;
                }
            }

            // will resolve
            mempool_sync_data_url = Some(url);
            break;
        }

        if let Some((url_str, sockaddr)) = mempool_sync_data_url_and_sockaddr {
            // already resolved
            return Ok(Some(MempoolSyncState::SendQuery(
                url_str,
                sockaddr,
                page_id.clone(),
            )));
        } else if let Some(url) = mempool_sync_data_url {
            // will need to resolve
            self.mempool_sync_begin_resolve_data_url(network, url, dns_client_opt, page_id)
        } else {
            debug!("No peer has a data URL, so no mempool sync can happen");
            Ok(None)
        }
    }

    /// Begin resolving the DNS host of a data URL for mempool sync.
    /// Returns Ok(None) if we're done syncing the mempool.
    /// Returns Ok(Some(..)) if we're not done, and can proceed
    /// Returns the new sync state -- either ResolveURL if we need to resolve a data URL,
    /// or SendQuery if we got the IP address and can just issue the query.
    #[cfg_attr(test, mutants::skip)]
    fn mempool_sync_begin_resolve_data_url(
        &self,
        network: &PeerNetwork,
        url_str: UrlString,
        dns_client_opt: &mut Option<&mut DNSClient>,
        page_id: &Txid,
    ) -> Result<Option<MempoolSyncState>, NetError> {
        // start resolving
        let url = url_str.parse_to_block_url()?;
        let port = match url.port_or_known_default() {
            Some(p) => p,
            None => {
                warn!("Unsupported URL {:?}: unknown port", &url);
                return Ok(None);
            }
        };

        // bare IP address?
        if let Some(addr) = PeerNetwork::try_get_url_ip(&url_str)? {
            return Ok(Some(MempoolSyncState::SendQuery(
                url_str,
                addr,
                page_id.clone(),
            )));
        } else if let Some(url::Host::Domain(domain)) = url.host() {
            if let Some(ref mut dns_client) = dns_client_opt {
                // begin DNS query
                match dns_client.queue_lookup(
                    domain,
                    port,
                    get_epoch_time_ms() + network.get_connection_opts().dns_timeout,
                ) {
                    Ok(_) => {}
                    Err(_) => {
                        warn!("Failed to queue DNS lookup on {}", &url_str);
                        return Ok(None);
                    }
                }
                return Ok(Some(MempoolSyncState::ResolveURL(
                    url_str,
                    DNSRequest::new(domain.to_string(), port, 0),
                    page_id.clone(),
                )));
            } else {
                // can't proceed -- no DNS client
                return Ok(None);
            }
        } else {
            // can't proceed
            return Ok(None);
        }
    }

    /// Resolve our picked mempool sync peer's data URL.
    /// Returns Ok(true, ..) if we're done syncing the mempool.
    /// Returns Ok(false, ..) if there's more to do
    /// Returns the socket addr if we ever succeed in resolving it.
    #[cfg_attr(test, mutants::skip)]
    fn mempool_sync_resolve_data_url(
        url_str: &UrlString,
        request: &DNSRequest,
        dns_client_opt: &mut Option<&mut DNSClient>,
    ) -> Result<(bool, Option<SocketAddr>), NetError> {
        if let Ok(Some(addr)) = PeerNetwork::try_get_url_ip(url_str) {
            // URL contains an IP address -- go with that
            Ok((false, Some(addr)))
        } else if let Some(dns_client) = dns_client_opt {
            // keep trying to resolve
            match dns_client.poll_lookup(&request.host, request.port) {
                Ok(Some(dns_response)) => match dns_response.result {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.pop() {
                            // resolved!
                            return Ok((false, Some(addr)));
                        } else {
                            warn!("DNS returned no results for {}", url_str);
                            return Ok((true, None));
                        }
                    }
                    Err(msg) => {
                        warn!("DNS failed to look up {:?}: {}", &url_str, msg);
                        return Ok((true, None));
                    }
                },
                Ok(None) => {
                    // still in-flight
                    return Ok((false, None));
                }
                Err(e) => {
                    warn!("DNS lookup failed on {:?}: {:?}", url_str, &e);
                    return Ok((true, None));
                }
            }
        } else {
            // can't do anything
            debug!("No DNS client, and URL contains a domain, so no mempool sync can happen");
            return Ok((true, None));
        }
    }

    /// Ask the remote peer for its mempool, connecting to it in the process if need be.
    /// Returns Ok((true, ..)) if we're done mempool syncing
    /// Returns Ok((false, ..)) if there's more to do
    /// Returns the event ID on success
    #[cfg_attr(test, mutants::skip)]
    fn mempool_sync_send_query(
        &mut self,
        network: &mut PeerNetwork,
        url: &UrlString,
        addr: &SocketAddr,
        mempool: &MemPoolDB,
        page_id: Txid,
    ) -> Result<(bool, Option<usize>), NetError> {
        let sync_data = mempool.make_mempool_sync_data()?;
        let request = StacksHttpRequest::new_for_peer(
            PeerHost::from_socketaddr(addr),
            "POST".into(),
            self.api_endpoint.clone(),
            HttpRequestContents::new()
                .query_arg("page_id".into(), format!("{}", &page_id))
                .payload_stacks(&sync_data),
        )?;

        let event_id = network.connect_or_send_http_request(url.clone(), addr.clone(), request)?;
        return Ok((false, Some(event_id)));
    }

    /// Receive the mempool sync response.
    /// Return Ok(true, ..) if we're done with the mempool sync.
    /// Return Ok(false, ..) if we have more work to do.
    /// Returns the page ID of the next request to make, and the list of transactions we got
    #[cfg_attr(test, mutants::skip)]
    fn mempool_sync_recv_response(
        &mut self,
        network: &mut PeerNetwork,
        event_id: usize,
    ) -> Result<(bool, Option<Txid>, Option<Vec<StacksTransaction>>), NetError> {
        PeerNetwork::with_http(network, |network, http| {
            match http.get_conversation(event_id) {
                None => {
                    if http.is_connecting(event_id) {
                        debug!(
                            "{:?}: Mempool sync event {} is not connected yet",
                            &network.local_peer, event_id
                        );
                        return Ok((false, None, None));
                    } else {
                        // conversation died
                        debug!("{:?}: Mempool sync peer hung up", &network.local_peer);
                        return Ok((true, None, None));
                    }
                }
                Some(ref mut convo) => {
                    match convo.try_get_response() {
                        None => {
                            // still waiting
                            debug!(
                                "{:?}: Mempool sync event {} still waiting for a response",
                                &network.get_local_peer(),
                                event_id
                            );
                            return Ok((false, None, None));
                        }
                        Some(http_response) => match http_response.decode_mempool_txs_page() {
                            Ok((txs, page_id_opt)) => {
                                debug!("{:?}: Mempool sync received response for {} txs, next page {:?}", &network.local_peer, txs.len(), &page_id_opt);
                                return Ok((true, page_id_opt, Some(txs)));
                            }
                            Err(e) => {
                                warn!(
                                    "{:?}: Mempool sync request did not receive a txs page: {:?}",
                                    &network.local_peer, &e
                                );
                                return Ok((true, None, None));
                            }
                        },
                    }
                }
            }
        })
    }

    /// Do a mempool sync
    /// Return true if we're done and can advance to the next state.
    /// Returns the transactions as well if the sync ran to completion.
    #[cfg_attr(test, mutants::skip)]
    fn do_mempool_sync(
        &mut self,
        network: &mut PeerNetwork,
        dns_client_opt: &mut Option<&mut DNSClient>,
        mempool: &MemPoolDB,
    ) -> (bool, Option<Vec<StacksTransaction>>) {
        if get_epoch_time_secs() <= self.mempool_sync_deadline {
            debug!(
                "{:?}: Wait until {} to do a mempool sync",
                &network.get_local_peer(),
                self.mempool_sync_deadline
            );
            return (true, None);
        }

        if self.mempool_sync_timeout == 0 {
            // begin new sync
            self.mempool_sync_timeout =
                get_epoch_time_secs() + network.get_connection_opts().mempool_sync_timeout;
        } else if get_epoch_time_secs() > self.mempool_sync_timeout {
            debug!(
                "{:?}: Mempool sync took too long; terminating",
                &network.get_local_peer()
            );
            self.mempool_sync_reset();
            return (true, None);
        }

        // try advancing states until we get blocked.
        // Once we get blocked, return.
        loop {
            let cur_state = self.mempool_state.clone();
            debug!(
                "{:?}: Mempool sync state is {:?}",
                &network.get_local_peer(),
                &cur_state
            );
            match cur_state {
                MempoolSyncState::PickOutboundPeer => {
                    // 1. pick a random outbound conversation.
                    match self.mempool_sync_pick_outbound_peer(
                        network,
                        dns_client_opt,
                        &Txid([0u8; 32]),
                    ) {
                        Ok(Some(next_state)) => {
                            // success! can advance to either resolve a URL or to send a query
                            self.mempool_state = next_state;
                        }
                        Ok(None) => {
                            // done
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                        Err(e) => {
                            // done; need reset
                            warn!("mempool_sync_pick_outbound_peer returned {:?}", &e);
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                    }
                }
                MempoolSyncState::ResolveURL(ref url_str, ref dns_request, ref page_id) => {
                    // 2. resolve its data URL
                    match Self::mempool_sync_resolve_data_url(url_str, dns_request, dns_client_opt)
                    {
                        Ok((false, Some(addr))) => {
                            // success! advance
                            self.mempool_state =
                                MempoolSyncState::SendQuery(url_str.clone(), addr, page_id.clone());
                        }
                        Ok((false, None)) => {
                            // try again later
                            return (false, None);
                        }
                        Ok((true, _)) => {
                            // done
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                        Err(e) => {
                            // failed
                            warn!(
                                "mempool_sync_resolve_data_url({}) failed: {:?}",
                                url_str, &e
                            );
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                    }
                }
                MempoolSyncState::SendQuery(ref url, ref addr, ref page_id) => {
                    // 3. ask for the remote peer's mempool's novel txs
                    // address must be resolvable
                    if !network.get_connection_opts().private_neighbors
                        && PeerAddress::from_socketaddr(&addr).is_in_private_range()
                    {
                        debug!(
                            "{:?}: Mempool sync skips {}, which has private IP",
                            network.get_local_peer(),
                            &addr
                        );
                        self.mempool_sync_reset();
                        return (true, None);
                    }
                    debug!(
                        "{:?}: Mempool sync will query {} for mempool transactions at {}",
                        &network.get_local_peer(),
                        url,
                        page_id
                    );
                    match self.mempool_sync_send_query(network, url, addr, mempool, page_id.clone())
                    {
                        Ok((false, Some(event_id))) => {
                            // success! advance
                            debug!("{:?}: Mempool sync query {} for mempool transactions at {} on event {}", &network.get_local_peer(), url, page_id, event_id);
                            self.mempool_state =
                                MempoolSyncState::RecvResponse(url.clone(), addr.clone(), event_id);
                        }
                        Ok((false, None)) => {
                            // try again later
                            return (false, None);
                        }
                        Ok((true, _)) => {
                            // done
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                        Err(e) => {
                            // done
                            warn!("mempool_sync_send_query({}) returned {:?}", url, &e);
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                    }
                }
                MempoolSyncState::RecvResponse(ref url, ref addr, ref event_id) => {
                    match self.mempool_sync_recv_response(network, *event_id) {
                        Ok((true, next_page_id_opt, Some(txs))) => {
                            debug!(
                                "{:?}: Mempool sync received {} transactions; next page is {:?}",
                                &network.get_local_peer(),
                                txs.len(),
                                &next_page_id_opt
                            );

                            // done! got data
                            let ret = match next_page_id_opt {
                                Some(next_page_id) => {
                                    // get the next page
                                    self.mempool_state = MempoolSyncState::SendQuery(
                                        url.clone(),
                                        addr.clone(),
                                        next_page_id,
                                    );
                                    false
                                }
                                None => {
                                    // done
                                    self.mempool_sync_reset();
                                    true
                                }
                            };
                            return (ret, Some(txs));
                        }
                        Ok((true, _, None)) => {
                            // done! did not get data
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                        Ok((false, _, None)) => {
                            // still receiving; try again later
                            return (false, None);
                        }
                        Ok((false, _, Some(_))) => {
                            // should never happen
                            if cfg!(test) {
                                panic!("Reached invalid state in {:?}, aborting...", &cur_state);
                            }
                            warn!("Reached invalid state in {:?}, resetting...", &cur_state);
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                        Err(e) => {
                            // likely a network error
                            warn!("mempool_sync_recv_response returned {:?}", &e);
                            self.mempool_sync_reset();
                            return (true, None);
                        }
                    }
                }
            }
        }
    }
}

impl PeerNetwork {
    /// Run the internal mempool sync machine
    pub fn run_mempool_sync(
        &mut self,
        dns_client: &mut Option<&mut DNSClient>,
        mempool: &MemPoolDB,
        ibd: bool,
    ) -> Option<Vec<StacksTransaction>> {
        let Some(mut mempool_sync) = self.mempool_sync.take() else {
            return None;
        };

        let res = mempool_sync.run(self, dns_client, mempool, ibd);

        self.mempool_sync = Some(mempool_sync);
        res
    }
}
