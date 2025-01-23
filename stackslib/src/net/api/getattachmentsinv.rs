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

use std::collections::HashSet;
use std::io::{Read, Write};

use regex::{Captures, Regex};
use stacks_common::types::chainstate::{ConsensusHash, StacksBlockId};
use stacks_common::types::net::PeerHost;
use url::form_urlencoded;

use crate::net::atlas::{
    AttachmentPage, GetAttachmentsInvResponse, MAX_ATTACHMENT_INV_PAGES_PER_REQUEST,
};
use crate::net::http::{
    parse_json, Error, HttpBadRequest, HttpNotFound, HttpRequest, HttpRequestContents,
    HttpRequestPreamble, HttpResponse, HttpResponseContents, HttpResponsePayload,
    HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    HttpPreambleExtensions, RPCRequestHandler, StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::{Error as NetError, StacksNodeState};

#[derive(Clone)]
pub struct RPCGetAttachmentsInvRequestHandler {
    pub index_block_hash: Option<StacksBlockId>,
    pub page_indexes: Option<Vec<u32>>,
}

impl RPCGetAttachmentsInvRequestHandler {
    pub fn new() -> Self {
        Self {
            index_block_hash: None,
            page_indexes: None,
        }
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCGetAttachmentsInvRequestHandler {
    fn verb(&self) -> &'static str {
        "GET"
    }

    fn path_regex(&self) -> Regex {
        Regex::new("^/v2/attachments/inv$").unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v2/attachments/inv"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        _body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        if preamble.get_content_length() != 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected 0-length body".to_string(),
            ));
        }

        let query_str = if let Some(qs) = query {
            qs
        } else {
            return Err(Error::DecodeError(
                "Invalid Http request: expecting index_block_hash and pages_indexes".to_string(),
            ));
        };

        let mut index_block_hash = None;
        let mut page_indexes = HashSet::new();

        // expect index_block_hash= and page_indexes=
        for (key, value) in form_urlencoded::parse(query_str.as_bytes()) {
            if key == "index_block_hash" {
                index_block_hash = StacksBlockId::from_hex(&value).ok();
            } else if key == "pages_indexes" {
                let pages_indexes_value = value.to_string();
                for entry in pages_indexes_value.split(',') {
                    if let Ok(page_index) = entry.parse::<u32>() {
                        page_indexes.insert(page_index);
                    }
                }
            }
        }

        let index_block_hash = if let Some(ibh) = index_block_hash {
            ibh
        } else {
            return Err(Error::DecodeError(
                "Invalid Http request: expecting index_block_hash".to_string(),
            ));
        };

        if page_indexes.is_empty() {
            return Err(Error::DecodeError(
                "Invalid Http request: expecting pages_indexes".to_string(),
            ));
        }

        let mut page_index_list: Vec<u32> = page_indexes.into_iter().collect();
        page_index_list.sort();

        self.index_block_hash = Some(index_block_hash);
        self.page_indexes = Some(page_index_list);

        Ok(HttpRequestContents::new().query_string(query))
    }
}

impl RPCRequestHandler for RPCGetAttachmentsInvRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.index_block_hash = None;
        self.page_indexes = None;
    }

    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let index_block_hash = self
            .index_block_hash
            .take()
            .ok_or(NetError::SendError("Missing `index_block_hash`".into()))?;
        let page_indexes = self
            .page_indexes
            .take()
            .ok_or(NetError::SendError("Missing `page_indexes`".into()))?;

        // We are receiving a list of page indexes with a chain tip hash.
        // The amount of pages_indexes is capped by MAX_ATTACHMENT_INV_PAGES_PER_REQUEST (8)
        // Pages sizes are controlled by the constant ATTACHMENTS_INV_PAGE_SIZE (8), which
        // means that a `GET v2/attachments/inv` request can be requesting for a 64 bit vector
        // at once.
        // Since clients can be asking for non-consecutive pages indexes (1, 5_000, 10_000, ...),
        // we will be handling each page index separately.
        // We could also add the notion of "budget" so that a client could only get a limited number
        // of pages when they are spanning over many blocks.
        if page_indexes.len() > MAX_ATTACHMENT_INV_PAGES_PER_REQUEST {
            let msg = format!(
                "Number of attachment inv pages is limited by {} per request",
                MAX_ATTACHMENT_INV_PAGES_PER_REQUEST
            );
            warn!("{msg}");
            return StacksHttpResponse::new_error(&preamble, &HttpBadRequest::new(msg))
                .try_into_contents()
                .map_err(NetError::from);
        }
        if page_indexes.is_empty() {
            let msg = "Page indexes missing".to_string();
            warn!("{msg}");
            return StacksHttpResponse::new_error(&preamble, &HttpBadRequest::new(msg))
                .try_into_contents()
                .map_err(NetError::from);
        }

        let mut pages = vec![];

        for page_index in page_indexes.iter() {
            let page_res =
                node.with_node_state(|network, _sortdb, _chainstate, _mempool, _rpc_args| {
                    match network
                        .get_atlasdb()
                        .get_attachments_available_at_page_index(*page_index, &index_block_hash)
                    {
                        Ok(inventory) => Ok(AttachmentPage {
                            inventory,
                            index: *page_index,
                        }),
                        Err(e) => {
                            let msg = format!("Unable to read Atlas DB - {}", e);
                            warn!("{}", msg);
                            Err(msg)
                        }
                    }
                });

            match page_res {
                Ok(page) => {
                    pages.push(page);
                }
                Err(msg) => {
                    return StacksHttpResponse::new_error(&preamble, &HttpNotFound::new(msg))
                        .try_into_contents()
                        .map_err(NetError::from);
                }
            }
        }

        let content = GetAttachmentsInvResponse {
            block_id: index_block_hash.clone(),
            pages,
        };

        let mut preamble = HttpResponsePreamble::ok_json(&preamble);
        preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
        let body = HttpResponseContents::try_from_json(&content)?;
        Ok((preamble, body))
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCGetAttachmentsInvRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let pages: GetAttachmentsInvResponse = parse_json(preamble, body)?;
        Ok(HttpResponsePayload::try_from_json(pages)?)
    }
}

impl StacksHttpRequest {
    /// Make a new request for attachment inventory page
    pub fn new_getattachmentsinv(
        host: PeerHost,
        index_block_hash: StacksBlockId,
        page_indexes: HashSet<u32>,
    ) -> StacksHttpRequest {
        let page_list: Vec<String> = page_indexes.into_iter().map(|i| format!("{}", i)).collect();
        StacksHttpRequest::new_for_peer(
            host,
            "GET".into(),
            "/v2/attachments/inv".into(),
            HttpRequestContents::new()
                .query_arg("index_block_hash".into(), format!("{}", &index_block_hash))
                .query_arg("pages_indexes".into(), page_list[..].join(",")),
        )
        .expect("FATAL: failed to construct request from infallible data")
    }
}

impl StacksHttpResponse {
    pub fn decode_atlas_attachments_inv_response(
        self,
    ) -> Result<GetAttachmentsInvResponse, NetError> {
        let contents = self.get_http_payload_ok()?;
        let contents_json: serde_json::Value = contents.try_into()?;
        let resp: GetAttachmentsInvResponse = serde_json::from_value(contents_json)
            .map_err(|_e| NetError::DeserializeError("Failed to load from JSON".to_string()))?;
        Ok(resp)
    }
}
