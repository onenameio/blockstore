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

use clarity::vm::types::{StacksAddressExtensions, StandardPrincipalData};
use rand::prelude::*;
use rand::thread_rng;
use stacks_common::util::hash::*;
use stacks_common::util::sleep_ms;

use crate::core::{
    EpochList, StacksEpoch, StacksEpochId, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_TESTNET, STACKS_EPOCH_MAX,
};
use crate::net::asn::*;
use crate::net::chat::*;
use crate::net::db::*;
use crate::net::neighbors::*;
use crate::net::test::*;
use crate::net::{Error as net_error, *};
use crate::util_lib::test::*;

const TEST_IN_OUT_DEGREES: u64 = 0x1;

#[test]
fn test_step_walk_1_neighbor_plain() {
    with_timeout(600, || {
        let peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while (walk_1_count < 20 || walk_2_count < 20)
            || (!peer_1.network.public_ip_confirmed)
            || peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .is_none()
        {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 learned and confirmed its public IP address from peer 2
        assert!(peer_1.network.get_local_peer().public_ip_address.is_some());
        assert_eq!(
            peer_1
                .network
                .get_local_peer()
                .public_ip_address
                .clone()
                .unwrap(),
            (
                PeerAddress::from_socketaddr(&"127.0.0.1:1".parse::<SocketAddr>().unwrap()),
                peer_1.config.server_port,
            )
        );
        assert!(peer_1.network.public_ip_learned);
        assert!(peer_1.network.public_ip_confirmed);

        // peer 2 learned nothing, despite trying
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
    })
}

#[test]
fn test_step_walk_1_neighbor_plain_no_natpunch() {
    with_timeout(600, || {
        let peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        // simulate peer 2 not knowing how to handle a natpunch request
        peer_2_config.connection_opts.disable_natpunch = true;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let mut stats_1 = None;

        while (walk_1_count < 20 || walk_2_count < 20) || stats_1.is_none() {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.dead_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            if let Some(s) = peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
            {
                stats_1 = Some(s);
            }

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = stats_1.unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 did not learn IP address
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());
        assert!(!peer_1.network.public_ip_confirmed);

        // peer 2 did not learn IP address
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
        assert!(!peer_2.network.public_ip_confirmed);
    })
}

#[test]
fn test_step_walk_1_neighbor_denied() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.walk_retry_count = 10;
        peer_2_config.connection_opts.walk_retry_count = 10;
        peer_1_config.connection_opts.walk_interval = 1;
        peer_2_config.connection_opts.walk_interval = 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, but peer 1 has denied peer 2
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        {
            let tx = peer_1.network.peerdb.tx_begin().unwrap();
            PeerDB::add_deny_cidr(&tx, &PeerAddress::from_ipv4(127, 0, 0, 1), 128).unwrap();
            tx.commit().unwrap();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_1_retries = 0;
        let mut walk_2_retries = 0;
        let mut walk_1_total = 0;
        let mut walk_2_total = 0;

        // walks just don't start.
        // neither peer learns their public IP addresses.
        while walk_1_retries < 20 && walk_2_retries < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            walk_1_total = peer_1.network.walk_count;
            walk_2_total = peer_2.network.walk_count;

            assert_eq!(walk_1_total, 0);
            assert_eq!(walk_2_total, 0);

            walk_1_retries = peer_1.network.walk_retries;
            walk_2_retries = peer_2.network.walk_retries;

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        assert!(peer_1.network.public_ip_learned);
        assert!(!peer_1.network.public_ip_confirmed);
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());

        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
    })
}

#[test]
fn test_step_walk_1_neighbor_bad_epoch() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.walk_retry_count = 10;
        peer_2_config.connection_opts.walk_retry_count = 10;
        peer_1_config.connection_opts.walk_interval = 1;
        peer_2_config.connection_opts.walk_interval = 1;

        // peer 1 thinks its always epoch 2.0
        peer_1_config.peer_version = 0x18000000;
        peer_1_config.epochs = Some(EpochList::new(&[StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        }]));

        // peer 2 thinks its always epoch 2.05
        peer_2_config.peer_version = 0x18000005;
        peer_2_config.epochs = Some(EpochList::new(&[StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        }]));

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peers know about each other, but peer 2 never talks to peer 1 since it believes that
        // it's in a wholly different epoch
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_1_retries = 0;
        let mut walk_2_retries = 0;
        let mut walk_1_total = 0;
        let mut walk_2_total = 0;

        // walks just don't start.
        // neither peer learns their public IP addresses.
        while walk_1_retries < 20 && walk_2_retries < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            walk_1_total = peer_1.network.walk_count;
            walk_2_total = peer_2.network.walk_count;

            assert_eq!(walk_1_total, 0);
            assert_eq!(walk_2_total, 0);

            walk_1_retries = peer_1.network.walk_attempts;
            walk_2_retries = peer_2.network.walk_attempts;

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;

            debug!("attempts: {},{}", walk_1_retries, walk_2_retries);
        }

        assert!(peer_1.network.public_ip_learned);
        assert!(!peer_1.network.public_ip_confirmed);
        assert!(peer_1.network.get_local_peer().public_ip_address.is_none());

        assert!(peer_2.network.public_ip_learned);
        assert!(!peer_2.network.public_ip_confirmed);
        assert!(peer_2.network.get_local_peer().public_ip_address.is_none());
    })
}

#[test]
fn test_step_walk_1_neighbor_heartbeat_ping() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.heartbeat = 10;
        peer_2_config.connection_opts.heartbeat = 10;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        info!("Completed walk round {} step(s)", i);

        peer_1.dump_frontier();
        peer_2.dump_frontier();

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 is in peer 1's frontier DB
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        assert_eq!(peer_1.network.relay_handles.len(), 0);
        assert_eq!(peer_2.network.relay_handles.len(), 0);

        info!("Wait 60 seconds for ping timeout");
        sleep_ms(60000);

        peer_1.network.queue_ping_heartbeats();
        peer_2.network.queue_ping_heartbeats();

        // pings queued
        assert_eq!(peer_1.network.relay_handles.len(), 1);
        assert_eq!(peer_2.network.relay_handles.len(), 1);
    })
}

#[test]
fn test_step_walk_1_neighbor_bootstrapping() {
    with_timeout(600, || {
        let peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, but peer 1 doesn't add peer 2 to its frontier becuase peer 2 is
        // too far behind.
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        // advance peer 1
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_1.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let neighbor_2 = peer_2.to_neighbor();

        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);

                    // peer 2 never gets added to peer 1's frontier
                    assert!(!w.frontier.contains_key(&neighbor_2.addr));
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {i} step(s)");

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
fn test_step_walk_1_neighbor_behind() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.disable_natpunch = true;
        peer_2_config.connection_opts.disable_natpunch = true;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, and peer 1 adds peer 2 to its frontier even though peer 2 does
        // not, because peer 2 is too far ahead
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        // advance peer 2
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_2.add_empty_burnchain_block();
        }

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        while (walk_1_count < 20 && walk_2_count < 20)
            || peer_1
                .network
                .get_neighbor_stats(&peer_2.to_neighbor().addr)
                .is_none()
        {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);

                    // peer 1 never gets added to peer 2's frontier
                    assert!(!w.frontier.contains_key(&neighbor_1.addr));
                }
                None => {}
            };

            i += 1;

            debug!("Peer 1 begin neighbor stats:");
            for (nk, _) in peer_1.network.events.iter() {
                match peer_1.network.get_neighbor_stats(nk) {
                    Some(ns) => {
                        debug!("   have stats for {:?}", &nk);
                    }
                    None => {
                        debug!("   (no stats for {:?})", &nk);
                    }
                }
            }
            debug!("Peer 1 end neighbor stats");
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1, even though peer 1 is very behind peer 2
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    })
}

#[test]
fn test_step_walk_10_neighbors_of_neighbor_plain() {
    with_timeout(600, || {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors.
        // Goal: peer 1 learns about the 10 other neighbors.
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::new(function_name!(), 0, 0);

            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;

            let p = TestPeer::new(n);

            peer_2.add_neighbor(&mut p.to_neighbor(), None, false);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        // Do two full walks
        let mut i = 0;
        let mut did_connect = false;
        while !did_connect {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                i += 1;
            }

            // peer 1 must have handshaked with all of peer 2's neighbors if this test will pass
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_handshakes = 0;
            for peer in &peer_2_neighbors {
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n.addr.network_id,
                    &n.addr.addrbytes,
                    n.addr.port,
                )
                .unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    }
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        test_debug!("confirmed handshake with peer {:?}", &n.addr);
                        num_handshakes += 1;
                    }
                }
            }

            if num_handshakes < 10 {
                continue;
            }

            // peer 1 learned that peer 2 has an out-degree of 10 (10 neighbors) and an in-degree of 1 if this test will pass
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(
                peer_1_dbconn,
                n2.addr.network_id,
                &n2.addr.addrbytes,
                n2.addr.port,
            )
            .unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                }
                Some(p2) => {
                    test_debug!("p2 degrees = {}/{}", p2.in_degree, p2.out_degree);
                    if p2.out_degree >= 11 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 11);
                        did_connect = true;
                    }
                }
            }
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
fn test_step_walk_10_neighbors_of_neighbor_bootstrapping() {
    with_timeout(600, || {
        // peer 1 has peer 2 as its neighbor.
        // peer 2 has 10 other neighbors, 5 of which are too far behind peer 1.
        // Goal: peer 1 learns about the 5 fresher neighbors.
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut peer_2_neighbors = vec![];
        for i in 0..10 {
            let mut n = TestPeerConfig::new(function_name!(), 0, 0);

            // turn off features we don't use
            n.connection_opts.disable_inv_sync = true;
            n.connection_opts.disable_block_download = true;

            let p = TestPeer::new(n);
            peer_2.add_neighbor(&mut p.to_neighbor(), None, true);
            peer_2_neighbors.push(p);
        }

        // peer 1 crawls peer 2
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);

        // advance peer 1 and peer 2, and some of peer 2's neighbors
        for i in 0..MAX_NEIGHBOR_BLOCK_DELAY + 1 {
            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
            for j in 0..5 {
                peer_2_neighbors[j].add_empty_burnchain_block();
            }
        }

        // next, make peer 1 discover peer 2's neighbors and peer 2's in/out degree.
        let mut steps = 0;
        let mut did_handshakes = false;
        while !did_handshakes {
            let mut walk_1_count = 0;
            let mut walk_2_count = 0;
            while walk_1_count < 20 && walk_2_count < 20 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                for j in 0..10 {
                    let _ = peer_2_neighbors[j].step();
                }

                walk_1_count = peer_1.network.walk_total_step_count;
                walk_2_count = peer_2.network.walk_total_step_count;

                test_debug!(
                    "peer 1 took {} walk steps; peer 2 took {} walk steps",
                    walk_1_count,
                    walk_2_count
                );

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                steps += 1;
            }

            peer_1.dump_frontier();
            peer_2.dump_frontier();

            // check if peer 1 handshaked with all of peer 2's _fresh_ neighbors
            let peer_1_dbconn = peer_1.get_peerdb_conn();
            let mut num_contacted = 0; // should be 5 when test finishes
            for i in 0..5 {
                let peer = &peer_2_neighbors[i];
                let n = peer.to_neighbor();
                let p_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    n.addr.network_id,
                    &n.addr.addrbytes,
                    n.addr.port,
                )
                .unwrap();
                match p_opt {
                    None => {
                        test_debug!("no such peer: {:?}", &n.addr);
                    }
                    Some(p) => {
                        assert_eq!(p.public_key, n.public_key);
                        assert_eq!(p.expire_block, n.expire_block);
                        num_contacted += 1;
                    }
                }

                let stale_peer = &peer_2_neighbors[i + 5];
                let stale_n = stale_peer.to_neighbor();
                let stale_peer_opt = PeerDB::get_peer(
                    peer_1_dbconn,
                    stale_n.addr.network_id,
                    &stale_n.addr.addrbytes,
                    stale_n.addr.port,
                )
                .unwrap();
                match stale_peer_opt {
                    None => {}
                    Some(_) => {
                        test_debug!("stale peer contacted: {:?}", &stale_n.addr);
                        assert!(false);
                    }
                }
            }

            test_debug!(
                "Peer 1 has contactd {} of Peer 2's neighbors",
                num_contacted
            );

            if num_contacted < 5 {
                continue;
            }

            // peer 1 learned that peer 2 has an out-degree of 6 (peer_1 + 5 fresh neighbors) and an in-degree of 1
            let n2 = peer_2.to_neighbor();
            let p2_opt = PeerDB::get_peer(
                peer_1_dbconn,
                n2.addr.network_id,
                &n2.addr.addrbytes,
                n2.addr.port,
            )
            .unwrap();
            match p2_opt {
                None => {
                    test_debug!("no peer 2");
                }
                Some(p2) => {
                    if p2.out_degree >= 6 && p2.in_degree >= 1 {
                        assert_eq!(p2.out_degree, 6);
                        did_handshakes = true;
                    }
                }
            }
        }

        debug!("Completed walk round {} step(s)", steps);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_plain() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        // NOTE: 2x the max walk duration
        while walk_1_count < 20 || walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        // peer 2 contacted peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr)
            .unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 2 was added to the peer DB of peer 1
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 1 was added to the peer DB of peer 2
        let peer_2_dbconn = peer_2.get_peerdb_conn();
        match PeerDB::get_peer(
            peer_2_dbconn,
            neighbor_1.addr.network_id,
            &neighbor_1.addr.addrbytes,
            neighbor_1.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_1.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_1.public_key);
                assert_eq!(p.expire_block, neighbor_1.expire_block);
            }
        }

        // walks were reset at least once
        assert!(peer_1.network.walk_count > 0);
        assert!(peer_2.network.walk_count > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_state_timeout() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        peer_1_config.connection_opts.walk_state_timeout = 1;
        peer_2_config.connection_opts.walk_state_timeout = 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

        for _i in 0..10 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            let walk_1_count = peer_1.network.walk_total_step_count;
            let walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            sleep_ms(3_000);
        }

        // state resets trigger walk resets
        assert!(peer_1.network.walk_resets > 0);
        assert!(peer_2.network.walk_resets > 0);
    })
}

#[test]
fn test_step_walk_2_neighbors_walk_timeout() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // short-lived walks...
        peer_1_config.connection_opts.walk_max_duration = 10;
        peer_2_config.connection_opts.walk_max_duration = 10;

        peer_1_config.connection_opts.walk_state_timeout = 20;
        peer_2_config.connection_opts.walk_state_timeout = 20;

        peer_1_config.connection_opts.walk_reset_interval = 10;
        peer_2_config.connection_opts.walk_reset_interval = 10;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_step_count = 0;
        let mut walk_2_step_count = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;

        while walk_1_step_count < 20 || walk_2_step_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_step_count = peer_1.network.walk_total_step_count;
            walk_2_step_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_step_count,
                walk_2_step_count
            );

            if walk_1_count < peer_1.network.walk_count || walk_2_count < peer_2.network.walk_count
            {
                // force walk to time out
                sleep_ms(11_000);
            }

            walk_1_count = peer_1
                .network
                .walk
                .as_ref()
                .map(|w| w.walk_step_count)
                .unwrap_or(0);
            walk_2_count = peer_1
                .network
                .walk
                .as_ref()
                .map(|w| w.walk_step_count)
                .unwrap_or(0);

            i += 1;
        }

        // walk timeouts trigger walk resets
        assert!(peer_1.network.walk_resets > 0);
        assert!(peer_2.network.walk_resets > 0);
    })
}

#[test]
fn test_step_walk_3_neighbors_inbound() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_3_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;
        peer_3_config.allowed = -1;

        peer_1_config.connection_opts.disable_pingbacks = true;
        peer_2_config.connection_opts.disable_pingbacks = true;
        peer_3_config.connection_opts.disable_pingbacks = true;

        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_3_config.connection_opts.disable_inv_sync = true;

        peer_1_config.connection_opts.disable_block_download = true;
        peer_2_config.connection_opts.disable_block_download = true;
        peer_3_config.connection_opts.disable_block_download = true;

        peer_1_config.connection_opts.log_neighbors_freq = 1;
        peer_2_config.connection_opts.log_neighbors_freq = 1;
        peer_3_config.connection_opts.log_neighbors_freq = 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);
        let mut peer_3 = TestPeer::new(peer_3_config);

        // Peer 2 and peer 3 are public nodes that don't know about each other, but peer 1 lists
        // both of them as outbound neighbors.  Goal is for peer 2 to learn about peer 3, and vice
        // versa, by crawling peer 1 through an inbound neighbor walk.
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_1.add_neighbor(&mut peer_3.to_neighbor(), None, true);

        let mut i = 0;
        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut walk_3_count = 0;
        let mut peer_1_frontier_size = 0;
        let mut peer_2_frontier_size = 0;
        let mut peer_3_frontier_size = 0;
        while peer_2_frontier_size < 2 || peer_3_frontier_size < 2 {
            let _ = peer_1.step();
            let _ = peer_2.step();
            let _ = peer_3.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;
            walk_3_count = peer_3.network.walk_total_step_count;

            test_debug!("========");
            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps; peer 3 took {} steps",
                walk_1_count,
                walk_2_count,
                walk_3_count
            );
            test_debug!(
                "peer 1 frontier size: {}, peer 2 frontier size: {}, peer 3 frontier size: {}",
                peer_1_frontier_size,
                peer_2_frontier_size,
                peer_3_frontier_size
            );
            test_debug!("========");

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_3.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            for (i, peer) in [&peer_1, &peer_2, &peer_3].iter().enumerate() {
                let db = peer.get_peerdb_conn();
                let neighbors = PeerDB::get_all_peers(db).unwrap();
                test_debug!("Begin neighbor dump from {:?}", &peer.to_neighbor().addr);
                for n in neighbors {
                    test_debug!("   {:?}", &n.addr);
                }
                test_debug!("End neighbor dump from {:?}", &peer.to_neighbor().addr);
            }

            peer_1_frontier_size = PeerDB::get_all_peers(peer_1.get_peerdb_conn())
                .unwrap()
                .len();
            peer_2_frontier_size = PeerDB::get_all_peers(peer_2.get_peerdb_conn())
                .unwrap()
                .len();
            peer_3_frontier_size = PeerDB::get_all_peers(peer_3.get_peerdb_conn())
                .unwrap()
                .len();

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();
        let neighbor_3 = peer_3.to_neighbor();

        // peer 2 was added to the peer DB of peer 1
        let peer_1_dbconn = peer_1.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_1_dbconn,
            neighbor_2.addr.network_id,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }

        // peer 3 was added to the peer DB of peer 1
        match PeerDB::get_peer_by_port(
            peer_1_dbconn,
            neighbor_3.addr.network_id,
            neighbor_3.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_3.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_3.public_key);
                assert_eq!(p.expire_block, neighbor_3.expire_block);
            }
        }

        // peer 2 was added to the peer DB of peer 3
        let peer_2_dbconn = peer_2.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_2_dbconn,
            neighbor_3.addr.network_id,
            neighbor_3.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_3.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_3.public_key);
                assert_eq!(p.expire_block, neighbor_3.expire_block);
            }
        }

        // peer 3 was added to the peer DB of peer 2
        let peer_3_dbconn = peer_3.get_peerdb_conn();
        match PeerDB::get_peer_by_port(
            peer_3_dbconn,
            neighbor_2.addr.network_id,
            neighbor_2.addr.port,
        )
        .unwrap()
        {
            None => {
                test_debug!("no such peer: {:?}", &neighbor_2.addr);
                assert!(false);
            }
            Some(p) => {
                assert_eq!(p.public_key, neighbor_2.public_key);
                assert_eq!(p.expire_block, neighbor_2.expire_block);
            }
        }
    })
}

#[test]
fn test_step_walk_2_neighbors_rekey() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let mut peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.allowed = -1;
        peer_2_config.allowed = -1;

        // turn off features we don't use
        peer_1_config.connection_opts.disable_inv_sync = true;
        peer_1_config.connection_opts.disable_block_download = true;

        peer_2_config.connection_opts.disable_inv_sync = true;
        peer_2_config.connection_opts.disable_block_download = true;

        let first_block_height = peer_1_config.current_block + 1;

        // make keys expire soon
        peer_1_config.private_key_expire = first_block_height + 3;
        peer_2_config.private_key_expire = first_block_height + 4;

        peer_1_config.connection_opts.private_key_lifetime = 5;
        peer_2_config.connection_opts.private_key_lifetime = 5;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        // peer 1 crawls peer 2, and peer 2 crawls peer 1
        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1.to_neighbor(), None, true);

        let initial_public_key_1 = peer_1.get_public_key();
        let initial_public_key_2 = peer_2.get_public_key();

        // walk for a bit
        for i in 0..10 {
            for j in 0..5 {
                let _ = peer_1.step();
                let _ = peer_2.step();

                match peer_1.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };

                match peer_2.network.walk {
                    Some(ref w) => {
                        assert_eq!(w.result.broken_connections.len(), 0);
                        assert_eq!(w.result.replaced_neighbors.len(), 0);
                    }
                    None => {}
                };
            }

            peer_1.add_empty_burnchain_block();
            peer_2.add_empty_burnchain_block();
        }

        // peer 1 contacted peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr)
            .unwrap();
        assert!(stats_1.last_contact_time > 0);
        assert!(stats_1.last_handshake_time > 0);
        assert!(stats_1.last_send_time > 0);
        assert!(stats_1.last_recv_time > 0);
        assert!(stats_1.bytes_rx > 0);
        assert!(stats_1.bytes_tx > 0);

        // peer 2 contacted peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr)
            .unwrap();
        assert!(stats_2.last_contact_time > 0);
        assert!(stats_2.last_handshake_time > 0);
        assert!(stats_2.last_send_time > 0);
        assert!(stats_2.last_recv_time > 0);
        assert!(stats_2.bytes_rx > 0);
        assert!(stats_2.bytes_tx > 0);

        let neighbor_1 = peer_1.to_neighbor();
        let neighbor_2 = peer_2.to_neighbor();

        // peer 1 was added to the peer DB of peer 2
        assert!(PeerDB::get_peer(
            peer_1.network.peerdb.conn(),
            neighbor_2.addr.network_id,
            &neighbor_2.addr.addrbytes,
            neighbor_2.addr.port
        )
        .unwrap()
        .is_some());

        // peer 2 was added to the peer DB of peer 1
        assert!(PeerDB::get_peer(
            peer_2.network.peerdb.conn(),
            neighbor_1.addr.network_id,
            &neighbor_1.addr.addrbytes,
            neighbor_1.addr.port
        )
        .unwrap()
        .is_some());

        // new keys
        assert!(peer_1.get_public_key() != initial_public_key_1);
        assert!(peer_2.get_public_key() != initial_public_key_2);
    })
}

#[test]
fn test_step_walk_2_neighbors_different_networks() {
    with_timeout(600, || {
        let mut peer_1_config = TestPeerConfig::new(function_name!(), 0, 0);
        let peer_2_config = TestPeerConfig::new(function_name!(), 0, 0);

        peer_1_config.network_id = peer_2_config.network_id + 1;

        let mut peer_1 = TestPeer::new(peer_1_config);
        let mut peer_2 = TestPeer::new(peer_2_config);

        let mut peer_1_neighbor = peer_1.to_neighbor();
        peer_1_neighbor.addr.network_id = peer_2.config.network_id;

        peer_1.add_neighbor(&mut peer_2.to_neighbor(), None, true);
        peer_2.add_neighbor(&mut peer_1_neighbor, None, true);

        let mut walk_1_count = 0;
        let mut walk_2_count = 0;
        let mut i = 0;
        while walk_1_count < 20 && walk_2_count < 20 {
            let _ = peer_1.step();
            let _ = peer_2.step();

            walk_1_count = peer_1.network.walk_total_step_count;
            walk_2_count = peer_2.network.walk_total_step_count;

            test_debug!(
                "peer 1 took {} walk steps; peer 2 took {} walk steps",
                walk_1_count,
                walk_2_count
            );

            match peer_1.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            match peer_2.network.walk {
                Some(ref w) => {
                    assert_eq!(w.result.broken_connections.len(), 0);
                    assert_eq!(w.result.replaced_neighbors.len(), 0);
                }
                None => {}
            };

            i += 1;
        }

        debug!("Completed walk round {} step(s)", i);

        // peer 1 did NOT contact peer 2
        let stats_1 = peer_1
            .network
            .get_neighbor_stats(&peer_2.to_neighbor().addr);
        assert!(stats_1.is_none());

        // peer 2 did NOT contact peer 1
        let stats_2 = peer_2
            .network
            .get_neighbor_stats(&peer_1.to_neighbor().addr);
        assert!(stats_2.is_none());
    })
}
