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

use std::io::Read;
use std::net::SocketAddr;
use std::str::FromStr;
use std::{fmt, io};

use stacks_common::codec::{read_next, Error as CodecError, StacksMessageCodec, MAX_MESSAGE_LEN};
use stacks_common::types::net::PeerHost;
use stacks_common::util::chunked_encoding::*;
use stacks_common::util::retry::BoundReader;

use crate::net::http::{
    Error, HttpContentType, HttpRequestContents, HttpResponseContents, HttpResponsePreamble,
};

/// HTTP version (1.0 or 1.1)
#[derive(Debug, Clone, PartialEq, Copy, Hash)]
#[repr(u8)]
pub enum HttpVersion {
    Http10 = 0x10,
    Http11 = 0x11,
}

/// HTTP headers that we really care about
#[derive(Debug, Clone, PartialEq)]
pub enum HttpReservedHeader {
    ContentLength(u32),
    ContentType(HttpContentType),
    Host(PeerHost),
}

impl HttpReservedHeader {
    pub fn is_reserved(header: &str) -> bool {
        let hdr = header.to_string();
        match hdr.as_str() {
            "content-length" | "content-type" | "host" => true,
            _ => false,
        }
    }

    pub fn try_from_str(header: &str, value: &str) -> Option<HttpReservedHeader> {
        let hdr = header.to_string().to_lowercase();
        match hdr.as_str() {
            "content-length" => match value.parse::<u32>() {
                Ok(cl) => Some(HttpReservedHeader::ContentLength(cl)),
                Err(_) => None,
            },
            "content-type" => match value.parse::<HttpContentType>() {
                Ok(ct) => Some(HttpReservedHeader::ContentType(ct)),
                Err(_) => None,
            },
            "host" => match value.parse::<PeerHost>() {
                Ok(ph) => Some(HttpReservedHeader::Host(ph)),
                Err(_) => None,
            },
            _ => None,
        }
    }
}

/// Maximum size of all of the HTTP headers in a request or response
pub const HTTP_PREAMBLE_MAX_ENCODED_SIZE: u32 = 4096;
/// Maximum number of headers in an HTTP request or response
pub const HTTP_PREAMBLE_MAX_NUM_HEADERS: usize = 64;

/// Helper function to parse a SIP-003 bytestream.  The first 4 bytes are a big-endian length prefix
pub fn parse_bytestream<R: Read, T: StacksMessageCodec>(
    preamble: &HttpResponsePreamble,
    mut body: &[u8],
) -> Result<T, Error> {
    // content-type has to be Bytes
    if preamble.content_type != HttpContentType::Bytes {
        return Err(Error::DecodeError(
            "Invalid content-type: expected application/octet-stream".to_string(),
        ));
    }

    let item: T = read_next(&mut body)?;
    Ok(item)
}

/// Helper function to decode an HTTP response preamble and its request body (as an `fd`) into a
/// JSON object
pub fn parse_json<T: serde::de::DeserializeOwned>(
    preamble: &HttpResponsePreamble,
    body: &[u8],
) -> Result<T, Error> {
    // content-type has to be JSON
    if preamble.content_type != HttpContentType::JSON {
        return Err(Error::DecodeError(
            "Invalid content-type: expected application/json".to_string(),
        ));
    }

    let item_result: Result<T, serde_json::Error> = serde_json::from_slice(body);
    item_result.map_err(|e| {
        if e.is_eof() {
            Error::UnderflowError("Not enough bytes to parse JSON".to_string())
        } else {
            Error::DecodeError(format!("Failed to parse JSON: {:?}", &e))
        }
    })
}

/// Helper function to read a raw bytestream
pub fn parse_raw_bytes(
    preamble: &HttpResponsePreamble,
    body: &[u8],
    max_len: u64,
    expected_content_type: HttpContentType,
) -> Result<Vec<u8>, Error> {
    if preamble.content_type != expected_content_type {
        return Err(Error::DecodeError(format!(
            "Invalid content-type: expected {}",
            expected_content_type
        )));
    }
    if (body.len() as u64) < max_len {
        let buf = body.to_vec();
        Ok(buf)
    } else {
        let buf = body[0..(max_len as usize)].to_vec();
        Ok(buf)
    }
}

/// Helper function to read `application/octet-stream` content
pub fn parse_bytes(
    preamble: &HttpResponsePreamble,
    body: &[u8],
    max_len: u64,
) -> Result<Vec<u8>, Error> {
    parse_raw_bytes(preamble, body, max_len, HttpContentType::Bytes)
}
