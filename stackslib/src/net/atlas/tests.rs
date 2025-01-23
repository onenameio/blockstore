// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
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

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::{thread, time};

use clarity::vm::types::QualifiedContractIdentifier;
use rusqlite::params;
use stacks_common::types::chainstate::{BlockHeaderHash, StacksBlockId};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::util::hash::Hash160;

use super::download::{
    AttachmentRequest, AttachmentsBatch, AttachmentsBatchStateContext, AttachmentsInventoryRequest,
    BatchedRequestsResult, ReliabilityReport,
};
use super::{
    AtlasConfig, AtlasDB, Attachment, AttachmentInstance, AttachmentPage, GetAttachmentsInvResponse,
};
use crate::burnchains::Txid;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::StacksChainState;
use crate::net::connection::ConnectionOptions;
use crate::net::http::{HttpResponsePayload, HttpResponsePreamble, HttpVersion};
use crate::net::httpcore::StacksHttpResponse;
use crate::net::Requestable;
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::u64_to_sql;
use crate::util_lib::strings::UrlString;

fn new_attachment_from(content: &str) -> Attachment {
    Attachment {
        content: content.as_bytes().to_vec(),
    }
}

#[cfg(test)]
fn new_attachment_instance_from(
    attachment: &Attachment,
    attachment_index: u32,
    block_height: u64,
) -> AttachmentInstance {
    AttachmentInstance {
        content_hash: attachment.hash().clone(),
        attachment_index,
        stacks_block_height: block_height,
        index_block_hash: StacksBlockId([block_height as u8; 32]),
        metadata: "".to_string(),
        contract_id: QualifiedContractIdentifier::transient(),
        tx_id: Txid([0; 32]),
        canonical_stacks_tip_height: Some(block_height),
    }
}

fn new_attachments_batch_from(
    attachment_instances: Vec<AttachmentInstance>,
    retry_count: u32,
) -> AttachmentsBatch {
    let mut attachments_batch = AttachmentsBatch::new();
    for attachment_instance in attachment_instances.iter() {
        attachments_batch.track_attachment(&attachment_instance);
    }
    for _ in 0..retry_count {
        attachments_batch.bump_retry_count();
    }
    attachments_batch
}

fn new_peers(peers: Vec<(&str, u32, u32)>) -> HashMap<UrlString, ReliabilityReport> {
    let mut new_peers = HashMap::new();
    for (url, req_sent, req_success) in peers {
        let url = UrlString::try_from(url.to_string().as_str()).unwrap();
        new_peers.insert(url, ReliabilityReport::new(req_sent, req_success));
    }
    new_peers
}

#[cfg(test)]
fn new_attachment_request(
    sources: Vec<(&str, u32, u32)>,
    content_hash: &Hash160,
    block_height: u64,
) -> AttachmentRequest {
    let sources = {
        let mut s = HashMap::new();
        for (url, req_sent, req_success) in sources {
            let url = UrlString::try_from(url.to_string()).unwrap();
            s.insert(url, ReliabilityReport::new(req_sent, req_success));
        }
        s
    };
    AttachmentRequest {
        sources,
        content_hash: content_hash.clone(),
        stacks_block_height: block_height,
        canonical_stacks_tip_height: Some(block_height),
    }
}

#[cfg(test)]
fn new_attachments_inventory_request(
    url: &str,
    pages: Vec<u32>,
    block_height: u64,
    req_sent: u32,
    req_success: u32,
) -> AttachmentsInventoryRequest {
    let url = UrlString::try_from(url.to_string().as_str()).unwrap();

    AttachmentsInventoryRequest {
        url,
        stacks_block_height: block_height,
        pages,
        contract_id: QualifiedContractIdentifier::transient(),
        index_block_hash: StacksBlockId([0x00; 32]),
        reliability_report: ReliabilityReport::new(req_sent, req_success),
        canonical_stacks_tip_height: Some(block_height),
    }
}

fn new_attachments_inventory_response(pages: Vec<(u32, Vec<u8>)>) -> StacksHttpResponse {
    let pages = pages
        .into_iter()
        .map(|(index, inventory)| AttachmentPage { index, inventory })
        .collect();
    let response = GetAttachmentsInvResponse {
        block_id: StacksBlockId([0u8; 32]),
        pages,
    };

    let response_json = serde_json::to_value(&response).unwrap();
    let body = HttpResponsePayload::try_from_json(response_json).unwrap();

    StacksHttpResponse::new(
        HttpResponsePreamble::raw_ok_json(HttpVersion::Http11, false),
        body,
    )
}

#[test]
fn test_attachment_instance_parsing() {
    use clarity::vm;
    use stacks_common::util::hash::MerkleHashFunc;

    let contract_id = QualifiedContractIdentifier::transient();
    let stacks_block_height = 0;
    let index_block_hash = StacksBlockId([0x00; 32]);

    let value_1 = vm::execute(
        r#"
    {
        attachment: {
            attachment-index: u1,
            hash: 0x,
            metadata: {
                name: "stacks"
            }
        }
    }
    "#,
    )
    .unwrap()
    .unwrap();
    let attachment_instance_1 = AttachmentInstance::try_new_from_value(
        &value_1,
        &contract_id,
        index_block_hash.clone(),
        stacks_block_height,
        Txid([0; 32]),
        Some(stacks_block_height),
    )
    .unwrap();
    assert_eq!(attachment_instance_1.attachment_index, 1);
    assert_eq!(attachment_instance_1.content_hash, Hash160::empty());

    let value_2 = vm::execute(
        r#"
    {
        attachment: {
            attachment-index: u2,
            hash: 0xd37581093088f5237a8dc885f38c231e42389cb2,
            metadata: {
                name: "stacks"
            }
        }
    }
    "#,
    )
    .unwrap()
    .unwrap();
    let attachment_instance_2 = AttachmentInstance::try_new_from_value(
        &value_2,
        &contract_id,
        index_block_hash.clone(),
        stacks_block_height,
        Txid([0; 32]),
        Some(stacks_block_height),
    )
    .unwrap();
    assert_eq!(attachment_instance_2.attachment_index, 2);
    assert_eq!(
        attachment_instance_2.content_hash,
        Hash160::from_hex("d37581093088f5237a8dc885f38c231e42389cb2").unwrap()
    );

    let value_3 = vm::execute(
        r#"
    {
        attachment: {
            attachment-index: u3,
            hash: 0xd37581093088f5237a8dc885f38c231e42389cb2
        }
    }
    "#,
    )
    .unwrap()
    .unwrap();
    let attachment_instance_3 = AttachmentInstance::try_new_from_value(
        &value_3,
        &contract_id,
        index_block_hash.clone(),
        stacks_block_height,
        Txid([0; 32]),
        Some(stacks_block_height),
    )
    .unwrap();
    assert_eq!(attachment_instance_3.attachment_index, 3);
    assert_eq!(
        attachment_instance_3.content_hash,
        Hash160::from_hex("d37581093088f5237a8dc885f38c231e42389cb2").unwrap()
    );

    let values = [
        vm::execute(
            r#"
    {
        attachment: {
            position-in-page: 1,
            page-index: u1,
            hash: 0x
        }
    }
    "#,
        )
        .unwrap()
        .unwrap(),
        vm::execute(
            r#"
    {
        attachment: {
            position-in-page: u1,
            page-index: u1,
            hash: 0x1323
        }
    }
    "#,
        )
        .unwrap()
        .unwrap(),
        vm::execute(
            r#"
    {
        attachment: {
            position-in-page: u1,
            pages-index: u1,
            hash: 0x
        }
    }
    "#,
        )
        .unwrap()
        .unwrap(),
    ];

    for value in values.iter() {
        assert!(AttachmentInstance::try_new_from_value(
            &value,
            &contract_id,
            index_block_hash.clone(),
            stacks_block_height,
            Txid([0; 32]),
            Some(stacks_block_height)
        )
        .is_none());
    }
}

#[test]
fn test_attachments_batch_ordering() {
    // Ensuring that when batches are being queued, we are correctly dequeueing, based on the following priorities:
    // 1) the batch that has been the least retried,
    // 2) if tie, the batch that will lead to the maximum number of downloads,
    // 3) if tie, the most oldest batch

    // Batch 1: 4 attachments, never tried, emitted at block #1
    let attachments_batch_1 = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&new_attachment_from("facade01"), 1, 1),
            new_attachment_instance_from(&new_attachment_from("facade02"), 2, 1),
            new_attachment_instance_from(&new_attachment_from("facade03"), 3, 1),
            new_attachment_instance_from(&new_attachment_from("facade04"), 4, 1),
        ],
        0,
    );

    // Batch 2: 5 attachments, never tried, emitted at block #2
    let attachments_batch_2 = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&new_attachment_from("facade11"), 1, 2),
            new_attachment_instance_from(&new_attachment_from("facade12"), 2, 2),
            new_attachment_instance_from(&new_attachment_from("facade13"), 3, 2),
            new_attachment_instance_from(&new_attachment_from("facade14"), 4, 2),
            new_attachment_instance_from(&new_attachment_from("facade15"), 5, 2),
        ],
        0,
    );

    // Batch 3: 4 attachments, tried once, emitted at block #3, assuming page_size = 8
    let attachments_batch_3 = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&new_attachment_from("facade21"), 8, 3),
            new_attachment_instance_from(&new_attachment_from("facade22"), 9, 3),
            new_attachment_instance_from(&new_attachment_from("facade23"), 10, 3),
            new_attachment_instance_from(&new_attachment_from("facade24"), 11, 3),
        ],
        1,
    );

    // Batch 1: 4 attachments, never tried, emitted at block #4
    let attachments_batch_4 = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&new_attachment_from("facade31"), 16, 4),
            new_attachment_instance_from(&new_attachment_from("facade32"), 17, 4),
            new_attachment_instance_from(&new_attachment_from("facade33"), 18, 4),
            new_attachment_instance_from(&new_attachment_from("facade34"), 19, 4),
        ],
        0,
    );

    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachments_batch_1.clone());
    priority_queue.push(attachments_batch_2.clone());
    priority_queue.push(attachments_batch_3.clone());
    priority_queue.push(attachments_batch_4.clone());

    // According to the rules above, the expected order is:
    // 1) Batch 2 (tie on retry count with 1 and 4 -> attachments count)
    // 2) Batch 1 (tie on retry count with 4 -> tie on attachments count 4 -> block height)
    // 3) Batch 4 (retry count)
    // 4) Batch 3
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_2);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_1);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_4);
    assert_eq!(priority_queue.pop().unwrap(), attachments_batch_3);
}

#[test]
fn test_attachments_inventory_requests_ordering() {
    // Ensuring that when we're flooding a set of peers with GetAttachmentsInventory requests, the order is based on the following rules:
    // 1) Nodes with highest ratio successful requests / total requests
    // 2) if tie, biggest number of total requests
    let attachments_inventory_1_request =
        new_attachments_inventory_request("http://localhost:20443", vec![0, 1], 1, 0, 0);

    let attachments_inventory_2_request =
        new_attachments_inventory_request("http://localhost:30443", vec![0, 1], 1, 2, 1);

    let attachments_inventory_3_request =
        new_attachments_inventory_request("http://localhost:40443", vec![0, 1], 1, 2, 2);

    let attachments_inventory_4_request =
        new_attachments_inventory_request("http://localhost:50443", vec![0, 1], 1, 4, 4);

    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachments_inventory_2_request.clone());
    priority_queue.push(attachments_inventory_1_request.clone());
    priority_queue.push(attachments_inventory_4_request.clone());
    priority_queue.push(attachments_inventory_3_request.clone());

    // According to the rules above, the expected order is:
    // 1) Request 4
    // 2) Request 3
    // 2) Request 2
    // 3) Request 1
    assert_eq!(
        priority_queue.pop().unwrap(),
        attachments_inventory_4_request
    );
    assert_eq!(
        priority_queue.pop().unwrap(),
        attachments_inventory_3_request
    );
    assert_eq!(
        priority_queue.pop().unwrap(),
        attachments_inventory_2_request
    );
    assert_eq!(
        priority_queue.pop().unwrap(),
        attachments_inventory_1_request
    );
}

#[test]
fn test_attachment_requests_ordering() {
    // Ensuring that when we're downloading some attachments, the order is based on the following rules:
    // 1) attachments that are the least available
    // 2) if tie, starting with the most reliable peer
    let attachment_1 = new_attachment_from("facade01");
    let attachment_2 = new_attachment_from("facade02");
    let attachment_3 = new_attachment_from("facade03");
    let attachment_4 = new_attachment_from("facade04");

    let attachment_1_request = new_attachment_request(
        vec![
            ("http://localhost:20443", 2, 2),
            ("http://localhost:40443", 0, 1),
        ],
        &attachment_1.hash(),
        10,
    );

    let attachment_2_request = new_attachment_request(
        vec![
            ("http://localhost:20443", 2, 2),
            ("http://localhost:40443", 0, 1),
            ("http://localhost:30443", 0, 1),
        ],
        &attachment_2.hash(),
        10,
    );

    let attachment_3_request = new_attachment_request(
        vec![("http://localhost:30443", 0, 1)],
        &attachment_3.hash(),
        10,
    );

    let attachment_4_request = new_attachment_request(
        vec![("http://localhost:50443", 4, 4)],
        &attachment_4.hash(),
        10,
    );

    let mut priority_queue = BinaryHeap::new();
    priority_queue.push(attachment_1_request.clone());
    priority_queue.push(attachment_3_request.clone());
    priority_queue.push(attachment_4_request.clone());
    priority_queue.push(attachment_2_request.clone());

    // According to the rules above, the expected order is:
    // 1) Request 4
    // 2) Request 3
    // 3) Request 1
    // 4) Request 2
    assert_eq!(priority_queue.pop().unwrap(), attachment_4_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_3_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_1_request);
    assert_eq!(priority_queue.pop().unwrap(), attachment_2_request);
}

#[test]
fn test_attachments_batch_constructs() {
    let page_size = AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
    let attachment_instance_1 =
        new_attachment_instance_from(&new_attachment_from("facade11"), page_size * 0 + 1, 1);
    let attachment_instance_2 =
        new_attachment_instance_from(&new_attachment_from("facade12"), page_size * 0 + 2, 1);
    let attachment_instance_3 =
        new_attachment_instance_from(&new_attachment_from("facade13"), page_size * 0 + 3, 1);
    let attachment_instance_4 =
        new_attachment_instance_from(&new_attachment_from("facade14"), page_size * 0 + 4, 1);
    let attachment_instance_5 =
        new_attachment_instance_from(&new_attachment_from("facade15"), page_size * 1 + 1, 1);

    let mut attachments_batch = AttachmentsBatch::new();
    attachments_batch.track_attachment(&attachment_instance_1);
    attachments_batch.track_attachment(&attachment_instance_2);
    attachments_batch.track_attachment(&attachment_instance_3);
    attachments_batch.track_attachment(&attachment_instance_4);
    attachments_batch.track_attachment(&attachment_instance_5);

    let default_contract_id = QualifiedContractIdentifier::transient();

    assert_eq!(attachments_batch.attachments_instances_count(), 5);
    assert_eq!(
        attachments_batch
            .get_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        2
    );

    attachments_batch.resolve_attachment(&attachment_instance_5.content_hash);
    assert_eq!(attachments_batch.attachments_instances_count(), 4);
    assert_eq!(
        attachments_batch
            .get_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        1
    );

    // should be idempotent
    attachments_batch.resolve_attachment(&attachment_instance_5.content_hash);
    assert_eq!(attachments_batch.attachments_instances_count(), 4);

    attachments_batch.resolve_attachment(&attachment_instance_2.content_hash);
    attachments_batch.resolve_attachment(&attachment_instance_3.content_hash);
    attachments_batch.resolve_attachment(&attachment_instance_4.content_hash);
    assert_eq!(attachments_batch.has_fully_succeed(), false);

    attachments_batch.resolve_attachment(&attachment_instance_1.content_hash);
    assert_eq!(attachments_batch.has_fully_succeed(), true);
    assert_eq!(
        attachments_batch
            .get_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        0
    );
}

#[test]
fn test_attachments_batch_pages() {
    let page_size = AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
    let attachment_instance_1 =
        new_attachment_instance_from(&new_attachment_from("facade11"), page_size * 0, 1);
    let attachment_instance_2 =
        new_attachment_instance_from(&new_attachment_from("facade12"), page_size * 1, 1);
    let attachment_instance_3 =
        new_attachment_instance_from(&new_attachment_from("facade13"), page_size * 2, 1);
    let attachment_instance_4 =
        new_attachment_instance_from(&new_attachment_from("facade14"), page_size * 3, 1);
    let attachment_instance_5 =
        new_attachment_instance_from(&new_attachment_from("facade15"), page_size * 4, 1);
    let attachment_instance_6 =
        new_attachment_instance_from(&new_attachment_from("facade16"), page_size * 5, 1);
    let attachment_instance_7 =
        new_attachment_instance_from(&new_attachment_from("facade17"), page_size * 6, 1);
    let attachment_instance_8 =
        new_attachment_instance_from(&new_attachment_from("facade18"), page_size * 7, 1);
    let attachment_instance_9 =
        new_attachment_instance_from(&new_attachment_from("facade19"), page_size * 8, 1);
    let attachment_instance_10 =
        new_attachment_instance_from(&new_attachment_from("facade20"), page_size * 9, 1);

    let mut attachments_batch = AttachmentsBatch::new();
    attachments_batch.track_attachment(&attachment_instance_1);
    attachments_batch.track_attachment(&attachment_instance_2);
    attachments_batch.track_attachment(&attachment_instance_3);
    attachments_batch.track_attachment(&attachment_instance_4);
    attachments_batch.track_attachment(&attachment_instance_5);
    attachments_batch.track_attachment(&attachment_instance_6);
    attachments_batch.track_attachment(&attachment_instance_7);
    attachments_batch.track_attachment(&attachment_instance_8);
    attachments_batch.track_attachment(&attachment_instance_9);
    attachments_batch.track_attachment(&attachment_instance_10);

    let default_contract_id = QualifiedContractIdentifier::transient();

    assert_eq!(attachments_batch.attachments_instances_count(), 10);
    assert_eq!(
        attachments_batch
            .get_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        10
    );

    assert_eq!(
        attachments_batch
            .get_paginated_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        2
    );

    attachments_batch.resolve_attachment(&attachment_instance_1.content_hash);
    attachments_batch.resolve_attachment(&attachment_instance_2.content_hash);
    attachments_batch.resolve_attachment(&attachment_instance_3.content_hash);

    // Assuming MAX_ATTACHMENT_INV_PAGES_PER_REQUEST = 8
    assert_eq!(
        attachments_batch
            .get_paginated_missing_pages_for_contract_id(&default_contract_id)
            .len(),
        1
    );
}

#[test]
fn test_downloader_context_attachment_inventories_requests() {
    let localhost = PeerHost::from_host_port("127.0.0.1".to_string(), 1024);
    let page_size = AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;
    let attachments_batch = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&new_attachment_from("facade01"), page_size * 1 + 1, 1),
            new_attachment_instance_from(&new_attachment_from("facade02"), page_size * 1 + 2, 1),
            new_attachment_instance_from(&new_attachment_from("facade03"), page_size * 1 + 3, 1),
            new_attachment_instance_from(&new_attachment_from("facade04"), page_size * 2 + 1, 1),
        ],
        0,
    );
    let peers = new_peers(vec![
        ("http://localhost:20443", 2, 2),
        ("http://localhost:30443", 3, 3),
        ("http://localhost:40443", 0, 0),
    ]);
    let context =
        AttachmentsBatchStateContext::new(attachments_batch, peers, &ConnectionOptions::default());

    let mut request_queue = context.get_prioritized_attachments_inventory_requests();
    let request = request_queue.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    assert_eq!(&**request.get_url(), "http://localhost:30443");
    debug!("request path = {}", request_type.request_path());
    assert!(
        request_type.request_path() == "/v2/attachments/inv?index_block_hash=0101010101010101010101010101010101010101010101010101010101010101&pages_indexes=1%2C2" ||
        request_type.request_path() == "/v2/attachments/inv?pages_indexes=1%2C2&index_block_hash=0101010101010101010101010101010101010101010101010101010101010101"
    );

    let request = request_queue.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    assert_eq!(&**request.get_url(), "http://localhost:20443");
    debug!("request path = {}", request_type.request_path());
    assert!(
        request_type.request_path() == "/v2/attachments/inv?index_block_hash=0101010101010101010101010101010101010101010101010101010101010101&pages_indexes=1%2C2" ||
        request_type.request_path() == "/v2/attachments/inv?pages_indexes=1%2C2&index_block_hash=0101010101010101010101010101010101010101010101010101010101010101"
    );

    let request = request_queue.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    assert_eq!(&**request.get_url(), "http://localhost:40443");
    debug!("request path = {}", request_type.request_path());
    assert!(
        request_type.request_path() == "/v2/attachments/inv?index_block_hash=0101010101010101010101010101010101010101010101010101010101010101&pages_indexes=1%2C2" ||
        request_type.request_path() == "/v2/attachments/inv?pages_indexes=1%2C2&index_block_hash=0101010101010101010101010101010101010101010101010101010101010101"
    );
}

#[test]
fn test_downloader_context_attachment_requests() {
    let attachment_1 = new_attachment_from("facade01");
    let attachment_2 = new_attachment_from("facade02");
    let attachment_3 = new_attachment_from("facade03");
    let attachment_4 = new_attachment_from("facade04");

    let localhost = PeerHost::from_host_port("127.0.0.1".to_string(), 1024);
    let page_size = AttachmentInstance::ATTACHMENTS_INV_PAGE_SIZE;

    let attachments_batch = new_attachments_batch_from(
        vec![
            new_attachment_instance_from(&attachment_1, page_size * 0, 1),
            new_attachment_instance_from(&attachment_2, page_size * 0 + 1, 1),
            new_attachment_instance_from(&attachment_3, page_size * 0 + 2, 1),
            new_attachment_instance_from(&attachment_4, page_size * 1, 1),
        ],
        0,
    );
    let peers = new_peers(vec![
        ("http://localhost:20443", 4, 4),
        ("http://localhost:30443", 3, 3),
        ("http://localhost:40443", 2, 2),
        ("http://localhost:50443", 1, 1),
    ]);
    let context =
        AttachmentsBatchStateContext::new(attachments_batch, peers, &ConnectionOptions::default());

    let mut inventories_requests = context.get_prioritized_attachments_inventory_requests();
    let mut inventories_results = BatchedRequestsResult::empty();

    let request_1 = inventories_requests.pop().unwrap();
    let peer_url_1 = request_1.get_url().clone();
    let request_2 = inventories_requests.pop().unwrap();
    let peer_url_2 = request_2.get_url().clone();
    let request_3 = inventories_requests.pop().unwrap();
    let peer_url_3 = request_3.get_url().clone();
    let request_4 = inventories_requests.pop().unwrap();
    let peer_url_4 = request_4.get_url().clone();
    let mut responses = HashMap::new();

    let response_1 =
        new_attachments_inventory_response(vec![(0, vec![1, 1, 1]), (1, vec![0, 0, 0])]);
    responses.insert(peer_url_1.clone(), Some(response_1.clone()));

    let response_2 =
        new_attachments_inventory_response(vec![(0, vec![1, 1, 1]), (1, vec![0, 0, 0])]);
    responses.insert(peer_url_2.clone(), Some(response_2.clone()));

    let response_3 =
        new_attachments_inventory_response(vec![(0, vec![0, 1, 1]), (1, vec![1, 0, 0])]);
    responses.insert(peer_url_3.clone(), Some(response_3.clone()));
    responses.insert(peer_url_4, None);

    inventories_results
        .succeeded
        .insert(request_1, Some(response_1));
    inventories_results
        .succeeded
        .insert(request_2, Some(response_2));
    inventories_results
        .succeeded
        .insert(request_3, Some(response_3));
    inventories_results.succeeded.insert(request_4, None);

    let context = context.extend_with_inventories(&mut inventories_results);

    let mut attachments_requests = context.get_prioritized_attachments_requests();

    let request = attachments_requests.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    // Attachment 4 is the rarest resource
    assert_eq!(
        request_type.request_path(),
        format!("/v2/attachments/{}", attachment_4.hash())
    );
    // Peer 1 is the only peer showing Attachment 4 as being available in its inventory
    assert_eq!(request.get_url(), &peer_url_3);

    let request = attachments_requests.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    // Attachment 1 is the 2nd rarest resource
    assert_eq!(
        request_type.request_path(),
        format!("/v2/attachments/{}", attachment_1.hash())
    );
    // Both Peer 1 and Peer 2 could serve Attachment 1, but Peer 1 has a better history
    assert_eq!(request.get_url(), &peer_url_1);

    // The 2 last requests can be served by Peer 1, 2 and 3, but will be served in random
    // order by Peer 1 (best score).
    let request = attachments_requests.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    assert_eq!(request.get_url(), &peer_url_1);

    let request = attachments_requests.pop().unwrap();
    let request_type = request.make_request_type(localhost.clone());
    assert_eq!(request.get_url(), &peer_url_1);
}

#[test]
fn test_keep_uninstantiated_attachments() {
    let bns_contract_id = boot_code_id("bns", false);
    let pox_contract_id = boot_code_id("pox", false);

    let mut contracts = HashSet::new();
    contracts.insert(bns_contract_id.clone());

    let atlas_config = AtlasConfig {
        contracts,
        attachments_max_size: 16,
        max_uninstantiated_attachments: 10,
        uninstantiated_attachments_expire_after: 10,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    assert_eq!(
        atlas_db.should_keep_attachment(&pox_contract_id, &new_attachment_from("facade02")),
        false
    );

    assert_eq!(
        atlas_db.should_keep_attachment(&bns_contract_id, &new_attachment_from("facade02")),
        true
    );

    assert_eq!(
        atlas_db.should_keep_attachment(
            &bns_contract_id,
            &new_attachment_from("facadefacadefacade02")
        ),
        false
    );
}

#[test]
fn schema_2_migration() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 10,
        uninstantiated_attachments_expire_after: 0,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let atlas_db = AtlasDB::connect_memory_db_v1(atlas_config.clone()).unwrap();
    let conn = atlas_db.conn;

    let attachments = [
        AttachmentInstance {
            // content_hash, index_block_hash, and txid must contain hex letters!
            //  because their fields are declared `STRING`, if you supply all numerals,
            //  sqlite assigns the field a REAL affinity (instead of TEXT)
            content_hash: Hash160([0xa0; 20]),
            attachment_index: 1,
            stacks_block_height: 1,
            index_block_hash: StacksBlockId([0xb1; 32]),
            metadata: "".into(),
            contract_id: QualifiedContractIdentifier::transient(),
            tx_id: Txid([0x2f; 32]),
            canonical_stacks_tip_height: None,
        },
        AttachmentInstance {
            content_hash: Hash160([0x00; 20]),
            attachment_index: 1,
            stacks_block_height: 1,
            index_block_hash: StacksBlockId([0x0a; 32]),
            metadata: "".into(),
            contract_id: QualifiedContractIdentifier::transient(),
            tx_id: Txid([0x0b; 32]),
            canonical_stacks_tip_height: None,
        },
    ];

    for attachment in attachments.iter() {
        // need to manually insert data, because the insertion routine in the codebase
        //  sets `status` which doesn't exist in v1
        conn.execute(
            "INSERT OR REPLACE INTO attachment_instances (
               content_hash, created_at, index_block_hash,
               attachment_index, block_height, is_available,
                metadata, contract_id, tx_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                attachment.content_hash,
                0,
                attachment.index_block_hash,
                attachment.attachment_index,
                u64_to_sql(attachment.stacks_block_height).unwrap(),
                true,
                attachment.metadata,
                attachment.contract_id.to_string(),
                attachment.tx_id,
            ],
        )
        .unwrap();
    }

    // perform the migration and unwrap() to assert that it runs okay
    let atlas_db = AtlasDB::connect_with_sqlconn(atlas_config, conn).unwrap();

    let mut attachments_fetched_a0 = atlas_db
        .find_all_attachment_instances(&Hash160([0xa0; 20]))
        .unwrap();
    assert_eq!(
        attachments_fetched_a0.len(),
        1,
        "Should have one attachment instance marked 'checked' with hash `0xa0a0a0..`"
    );

    let attachment_a0 = attachments_fetched_a0.pop().unwrap();
    assert_eq!(&attachment_a0, &attachments[0]);

    let mut attachments_fetched_00 = atlas_db
        .find_all_attachment_instances(&Hash160([0x00; 20]))
        .unwrap();
    assert_eq!(
        attachments_fetched_00.len(),
        1,
        "Should have one attachment instance marked 'checked' with hash `0x000000..`"
    );

    let attachment_00 = attachments_fetched_00.pop().unwrap();
    assert_eq!(&attachment_00, &attachments[1]);

    assert_eq!(
        atlas_db.queued_attachments().unwrap().len(),
        0,
        "Should have no attachment instance marked 'queued'"
    );
}

#[test]
fn test_evict_k_oldest_uninstantiated_attachments() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 10,
        uninstantiated_attachments_expire_after: 0,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let mut atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade00"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 1);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade01"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 2);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade02"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 3);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade02"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 3);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade03"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 4);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade04"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 5);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade05"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 6);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade06"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 7);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade07"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 8);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade08"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 9);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade09"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade10"))
        .unwrap();
    // We reached `max_uninstantiated_attachments`. Eviction should start kicking in
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);
    // The latest attachment inserted should be available
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade10").hash())
            .unwrap()
            .is_some(),
        true
    );
    // The first attachment inserted should be gone
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade00").hash())
            .unwrap()
            .is_none(),
        true
    );
    // The second attachment inserted should be available
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade01").hash())
            .unwrap()
            .is_some(),
        true
    );

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade11"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade12"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade13"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade14"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade15"))
        .unwrap();
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);
    // The 5th attachment inserted should be gone
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade05").hash())
            .unwrap()
            .is_none(),
        true
    );
    // The 6th attachment inserted should be available
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade06").hash())
            .unwrap()
            .is_some(),
        true
    );
    // The latest attachment inserted should be available
    assert_eq!(
        atlas_db
            .find_uninstantiated_attachment(&new_attachment_from("facade15").hash())
            .unwrap()
            .is_some(),
        true
    );
}

#[test]
fn test_evict_expired_uninstantiated_attachments() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 100,
        uninstantiated_attachments_expire_after: 10,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let mut atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade00"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade01"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade02"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade03"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade04"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade05"))
        .unwrap();
    thread::sleep(time::Duration::from_secs(11));
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade06"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade07"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade08"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade09"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade10"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade11"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade12"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade13"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade14"))
        .unwrap();
    atlas_db
        .insert_uninstantiated_attachment(&new_attachment_from("facade15"))
        .unwrap();
    // Count before eviction should be 16
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 16);
    atlas_db.evict_expired_uninstantiated_attachments().unwrap();
    // Count after eviction should be 10
    assert_eq!(atlas_db.count_uninstantiated_attachments().unwrap(), 10);
}

#[test]
fn test_evict_expired_unresolved_attachment_instances() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 100,
        uninstantiated_attachments_expire_after: 200,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };
    let mut atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    // Insert some uninstantiated attachments
    let uninstantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade11"), 0, 1),
        new_attachment_instance_from(&new_attachment_from("facade12"), 1, 1),
        new_attachment_instance_from(&new_attachment_from("facade13"), 2, 1),
        new_attachment_instance_from(&new_attachment_from("facade14"), 3, 1),
        new_attachment_instance_from(&new_attachment_from("facade15"), 4, 1),
        new_attachment_instance_from(&new_attachment_from("facade16"), 5, 1),
        new_attachment_instance_from(&new_attachment_from("facade17"), 6, 1),
        new_attachment_instance_from(&new_attachment_from("facade18"), 7, 1),
    ];
    for attachment_instance in uninstantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, false)
            .unwrap();
    }

    // Insert some instanciated attachments
    let instantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade21"), 8, 1),
        new_attachment_instance_from(&new_attachment_from("facade22"), 9, 1),
        new_attachment_instance_from(&new_attachment_from("facade23"), 10, 1),
        new_attachment_instance_from(&new_attachment_from("facade24"), 11, 1),
    ];
    for attachment_instance in instantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, true)
            .unwrap();
    }

    thread::sleep(time::Duration::from_secs(11));

    // Insert more uninstanciated attachments
    let uninstantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade31"), 12, 1),
        new_attachment_instance_from(&new_attachment_from("facade32"), 13, 1),
        new_attachment_instance_from(&new_attachment_from("facade33"), 14, 1),
    ];
    for attachment_instance in uninstantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, false)
            .unwrap();
    }

    // Count before eviction should be 11
    assert_eq!(
        atlas_db.count_unresolved_attachment_instances().unwrap(),
        11
    );
    atlas_db
        .evict_expired_unresolved_attachment_instances()
        .unwrap();
    // Count after eviction should be 3
    assert_eq!(atlas_db.count_unresolved_attachment_instances().unwrap(), 3);
}

#[test]
fn test_get_minmax_heights_atlasdb() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 100,
        uninstantiated_attachments_expire_after: 10,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    // Calling get_minmax_heights_window_for_page_index on a blank db should return an error,
    // not be crashing.
    let res = atlas_db
        .get_minmax_heights_window_for_page_index(0)
        .unwrap_err();
}

#[test]
fn test_bit_vectors() {
    let atlas_config = AtlasConfig {
        contracts: HashSet::new(),
        attachments_max_size: 1024,
        max_uninstantiated_attachments: 100,
        uninstantiated_attachments_expire_after: 10,
        unresolved_attachment_instances_expire_after: 10,
        genesis_attachments: None,
    };

    let mut atlas_db = AtlasDB::connect_memory(atlas_config).unwrap();

    // Insert some uninstantiated attachments
    let uninstantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade11"), 0, 1),
        new_attachment_instance_from(&new_attachment_from("facade12"), 1, 1),
        new_attachment_instance_from(&new_attachment_from("facade13"), 2, 1),
        new_attachment_instance_from(&new_attachment_from("facade14"), 3, 1),
    ];
    for attachment_instance in uninstantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, false)
            .unwrap();
    }
    let block_id_1 = uninstantiated_attachment_instances[0].index_block_hash;
    let bit_vector = atlas_db
        .get_attachments_available_at_page_index(0, &block_id_1)
        .unwrap();
    assert_eq!(bit_vector, [0x00; 64]);

    let uninstantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade15"), 4, 1),
        new_attachment_instance_from(&new_attachment_from("facade16"), 5, 1),
        new_attachment_instance_from(&new_attachment_from("facade17"), 6, 1),
        new_attachment_instance_from(&new_attachment_from("facade18"), 7, 1),
    ];
    for attachment_instance in uninstantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, false)
            .unwrap();
    }
    let bit_vector = atlas_db
        .get_attachments_available_at_page_index(0, &block_id_1)
        .unwrap();
    assert_eq!(bit_vector, [0x00; 64]);

    let instantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade21"), 8, 1),
        new_attachment_instance_from(&new_attachment_from("facade22"), 9, 1),
        new_attachment_instance_from(&new_attachment_from("facade23"), 10, 1),
        new_attachment_instance_from(&new_attachment_from("facade24"), 11, 1),
    ];
    for attachment_instance in instantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, true)
            .unwrap();
    }

    let bit_vector = atlas_db
        .get_attachments_available_at_page_index(0, &block_id_1)
        .unwrap();
    let mut expected = [0x00; 64];
    expected[8] = 1;
    expected[9] = 1;
    expected[10] = 1;
    expected[11] = 1;
    assert_eq!(bit_vector, expected);

    println!("1: {:?}", bit_vector);

    // Insert some instanciated attachments at block 2
    let instantiated_attachment_instances = [
        new_attachment_instance_from(&new_attachment_from("facade31"), 12, 2),
        new_attachment_instance_from(&new_attachment_from("facade32"), 13, 2),
        new_attachment_instance_from(&new_attachment_from("facade33"), 14, 2),
        new_attachment_instance_from(&new_attachment_from("facade34"), 15, 2),
    ];
    let block_id_2 = instantiated_attachment_instances[0].index_block_hash;
    for attachment_instance in instantiated_attachment_instances.iter() {
        atlas_db
            .queue_attachment_instance(attachment_instance)
            .unwrap();
        atlas_db
            .mark_attachment_instance_checked(attachment_instance, true)
            .unwrap();
    }

    let bit_vector = atlas_db
        .get_attachments_available_at_page_index(0, &block_id_1)
        .unwrap();
    assert_eq!(bit_vector, expected);

    let bit_vector = atlas_db
        .get_attachments_available_at_page_index(0, &block_id_2)
        .unwrap();
    let mut expected = [0x00; 64];
    expected[12] = 1;
    expected[13] = 1;
    expected[14] = 1;
    expected[15] = 1;
    assert_eq!(bit_vector, expected);
}

#[test]
fn test_attachments_inventory_requests_hashing() {
    let mut requests = HashMap::new();

    let attachments_inventory_1_request =
        new_attachments_inventory_request("http://localhost:20443", vec![0, 1], 1, 0, 0);
    requests.insert(attachments_inventory_1_request.key(), 1);

    let attachments_inventory_2_request =
        new_attachments_inventory_request("http://localhost:30443", vec![0, 1], 1, 2, 1);
    requests.insert(attachments_inventory_2_request.key(), 2);

    let attachments_inventory_3_request =
        new_attachments_inventory_request("http://localhost:40443", vec![0, 1], 1, 2, 2);
    requests.insert(attachments_inventory_3_request.key(), 3);

    let attachments_inventory_4_request =
        new_attachments_inventory_request("http://localhost:50443", vec![0, 1], 1, 4, 4);
    requests.insert(attachments_inventory_4_request.key(), 4);

    println!("{:?}", requests);
}
