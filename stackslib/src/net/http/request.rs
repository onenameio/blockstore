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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};

use percent_encoding::percent_decode_str;
use rand::{thread_rng, Rng};
use regex::{Captures, Regex};
use serde_json;
use stacks_common::codec::{write_next, Error as CodecError, StacksMessageCodec};
use stacks_common::deps_common::httparse;
use stacks_common::types::net::PeerHost;
use url::form_urlencoded;

use crate::net::http::common::{
    HttpReservedHeader, HTTP_PREAMBLE_MAX_ENCODED_SIZE, HTTP_PREAMBLE_MAX_NUM_HEADERS,
};
use crate::net::http::{
    default_accept_header, write_headers, Error, HttpContentType, HttpResponseContents,
    HttpResponsePreamble, HttpVersion,
};

/// HTTP request preamble.  This captures "control plane" data for an HTTP request, and contains
/// everything of use to us from the HTTP requests's headers.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequestPreamble {
    /// HTTP version (1.0 or 1.1)
    pub version: HttpVersion,
    /// HTTP verb
    pub verb: String,
    /// Fully-qualified HTTP request path, including query string
    pub path_and_query_str: String,
    /// `Host:` value
    pub host: PeerHost,
    /// `Content-Type:` value, if given.  Not all requests need this.
    pub content_type: Option<HttpContentType>,
    /// `Content-Length:` value, if given.  Not all requests need this.
    pub content_length: Option<u32>,
    /// true if `Connection: keep-alive` was set
    pub keep_alive: bool,
    /// Other headers that were not consumed in parsing
    pub headers: BTreeMap<String, String>,
}

impl HttpRequestPreamble {
    pub fn new(
        version: HttpVersion,
        verb: String,
        path_and_query_str: String,
        hostname: String,
        port: u16,
        keep_alive: bool,
    ) -> HttpRequestPreamble {
        HttpRequestPreamble {
            version,
            verb,
            path_and_query_str,
            host: PeerHost::from_host_port(hostname, port),
            content_type: None,
            content_length: None,
            keep_alive,
            headers: BTreeMap::new(),
        }
    }

    /// chain constructor for content type
    pub fn with_content_type(mut self, content_type: HttpContentType) -> Self {
        self.set_content_type(content_type);
        self
    }

    /// chain constructor for content length
    pub fn with_content_length(mut self, content_length: u32) -> Self {
        self.set_content_length(content_length);
        self
    }

    /// Create a request destined for another Stacks node.
    /// Stacks nodes support HTTP/1.1 and keep-alive
    pub fn new_for_peer(
        peerhost: PeerHost,
        verb: String,
        path_and_query_str: String,
    ) -> HttpRequestPreamble {
        HttpRequestPreamble {
            version: HttpVersion::Http11,
            verb,
            path_and_query_str,
            host: peerhost,
            content_type: None,
            content_length: None,
            keep_alive: true,
            headers: BTreeMap::new(),
        }
    }

    /// Test helper to construct an HTTP request preamble from headers
    #[cfg(test)]
    pub fn from_headers(
        version: HttpVersion,
        verb: String,
        path_and_query_str: String,
        hostname: String,
        port: u16,
        keep_alive: bool,
        mut keys: Vec<String>,
        values: Vec<String>,
    ) -> HttpRequestPreamble {
        assert_eq!(keys.len(), values.len());
        let mut req = HttpRequestPreamble::new(
            version,
            verb,
            path_and_query_str,
            hostname,
            port,
            keep_alive,
        );

        for (k, v) in keys.drain(..).zip(values) {
            req.add_header(k, v);
        }
        req
    }

    /// Add a header to the given request.  If it's a reserved header, then handle it accordingly
    /// by setting the special-purpose field in the premable.  Otherwise, put it into
    /// `self.headers`.
    pub fn add_header(&mut self, key: String, value: String) {
        let hdr = key.to_lowercase();
        if HttpReservedHeader::is_reserved(&hdr) {
            match HttpReservedHeader::try_from_str(&hdr, &value) {
                Some(h) => match h {
                    HttpReservedHeader::Host(ph) => {
                        self.host = ph;
                        return;
                    }
                    HttpReservedHeader::ContentType(ct) => {
                        self.content_type = Some(ct);
                        return;
                    }
                    HttpReservedHeader::ContentLength(len) => {
                        self.content_length = Some(len);
                        return;
                    }
                },
                None => {
                    return;
                }
            }
        }

        self.headers.insert(hdr, value);
    }

    /// Remove a header.
    /// Return true if removed, false if not.
    /// Will be false if this is a reserved header
    pub fn remove_header(&mut self, key: String) -> bool {
        let hdr = key.to_lowercase();
        if HttpReservedHeader::is_reserved(&hdr) {
            // these cannot be removed
            return false;
        }
        self.headers.remove(&key);
        return true;
    }

    /// Get an owned copy of a header if it exists
    pub fn get_header(&self, key: String) -> Option<String> {
        let hdr = key.to_lowercase();
        match hdr.as_str() {
            "host" => {
                return Some(format!("{}", &self.host));
            }
            "content-type" => {
                return self.content_type.clone().map(|ct| format!("{}", &ct));
            }
            "content-length" => {
                return self.content_length.clone().map(|cl| format!("{}", &cl));
            }
            _ => {
                return self.headers.get(&hdr).cloned();
            }
        }
    }

    /// Content-Length for this request.
    /// If there is no valid Content-Length header, then
    /// the Content-Length is 0
    pub fn get_content_length(&self) -> u32 {
        self.content_length.unwrap_or(0)
    }

    /// Set the content-length for this request
    pub fn set_content_length(&mut self, len: u32) {
        self.content_length = Some(len);
    }

    /// Set the content-type for this request
    pub fn set_content_type(&mut self, content_type: HttpContentType) {
        self.content_type = Some(content_type)
    }

    /// Write this out
    pub fn send<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        self.consensus_serialize(fd).map_err(|e| e.into())
    }
}

/// Read from a stream until we see '\r\n\r\n', with the purpose of reading a HTTP preamble.
/// It's gonna be important here that R does some bufferring, since this reads byte by byte.
/// EOF if we read 0 bytes.
fn read_to_crlf2<R: Read>(fd: &mut R) -> Result<Vec<u8>, CodecError> {
    let mut ret = Vec::with_capacity(HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize);
    while ret.len() < HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize {
        let mut b = [0u8];
        fd.read_exact(&mut b).map_err(CodecError::ReadError)?;
        ret.push(b[0]);

        if ret.len() > 4 {
            let last_4 = &ret[(ret.len() - 4)..ret.len()];

            // '\r\n\r\n' is [0x0d, 0x0a, 0x0d, 0x0a]
            if last_4 == &[0x0d, 0x0a, 0x0d, 0x0a] {
                break;
            }
        }
    }
    Ok(ret)
}

impl StacksMessageCodec for HttpRequestPreamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        // "$verb $path HTTP/1.${version}\r\n"
        fd.write_all(self.verb.as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all(" ".as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all(self.path_and_query_str.as_bytes())
            .map_err(CodecError::WriteError)?;

        match self.version {
            HttpVersion::Http10 => {
                fd.write_all(" HTTP/1.0\r\n".as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
            HttpVersion::Http11 => {
                fd.write_all(" HTTP/1.1\r\n".as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
        }

        // "User-Agent: $agent\r\nHost: $host\r\n"
        fd.write_all("User-Agent: stacks/3.0\r\nHost: ".as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all(format!("{}", self.host).as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all("\r\n".as_bytes())
            .map_err(CodecError::WriteError)?;

        // content-type
        match self.content_type {
            Some(ref c) => {
                fd.write_all("Content-Type: ".as_bytes())
                    .map_err(CodecError::WriteError)?;
                fd.write_all(c.to_string().as_str().as_bytes())
                    .map_err(CodecError::WriteError)?;
                fd.write_all("\r\n".as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
            None => {}
        }

        // content-length
        match self.content_length {
            Some(l) => {
                fd.write_all("Content-Length: ".as_bytes())
                    .map_err(CodecError::WriteError)?;
                fd.write_all(format!("{}", l).as_bytes())
                    .map_err(CodecError::WriteError)?;
                fd.write_all("\r\n".as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
            None => {}
        }

        // keep-alive
        match self.version {
            HttpVersion::Http10 => {
                if self.keep_alive {
                    fd.write_all("Connection: keep-alive\r\n".as_bytes())
                        .map_err(CodecError::WriteError)?;
                }
            }
            HttpVersion::Http11 => {
                if !self.keep_alive {
                    fd.write_all("Connection: close\r\n".as_bytes())
                        .map_err(CodecError::WriteError)?;
                }
            }
        }

        fd.write_all(default_accept_header().as_bytes())
            .map_err(CodecError::WriteError)?;

        // other headers
        write_headers(fd, &self.headers)?;

        // end-of-headers
        fd.write_all("\r\n".as_bytes())
            .map_err(CodecError::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HttpRequestPreamble, CodecError> {
        // realistically, there won't be more than HTTP_PREAMBLE_MAX_NUM_HEADERS headers
        let mut headers = [httparse::EMPTY_HEADER; HTTP_PREAMBLE_MAX_NUM_HEADERS];
        let mut req = httparse::Request::new(&mut headers);

        let buf_read = read_to_crlf2(fd)?;

        // consume request
        match req.parse(&buf_read).map_err(|e| {
            CodecError::DeserializeError(format!("Failed to parse HTTP request: {:?}", &e))
        })? {
            httparse::Status::Partial => {
                // partial
                return Err(CodecError::UnderflowError(
                    "Not enough bytes to form a HTTP request preamble".to_string(),
                ));
            }
            httparse::Status::Complete(_) => {
                // consumed all headers.  body_offset points to the start of the request body
                let version = match req
                    .version
                    .ok_or(CodecError::DeserializeError("No HTTP version".to_string()))?
                {
                    0 => HttpVersion::Http10,
                    1 => HttpVersion::Http11,
                    _ => {
                        return Err(CodecError::DeserializeError(
                            "Invalid HTTP version".to_string(),
                        ));
                    }
                };

                let verb = req
                    .method
                    .ok_or(CodecError::DeserializeError("No HTTP method".to_string()))?
                    .to_string();
                let path_and_query_str = req
                    .path
                    .ok_or(CodecError::DeserializeError("No HTTP path".to_string()))?
                    .to_string();

                let mut peerhost = None;
                let mut content_type = None;
                let mut content_length = None;
                let mut keep_alive = match version {
                    HttpVersion::Http10 => false,
                    HttpVersion::Http11 => true,
                };

                let mut headers: BTreeMap<String, String> = BTreeMap::new();
                let mut seen_headers: HashSet<String> = HashSet::new();

                for i in 0..req.headers.len() {
                    let value = String::from_utf8(req.headers[i].value.to_vec()).map_err(|_e| {
                        CodecError::DeserializeError(
                            "Invalid HTTP header value: not utf-8".to_string(),
                        )
                    })?;
                    if !value.is_ascii() {
                        return Err(CodecError::DeserializeError(
                            "Invalid HTTP request: header value is not ASCII-US".to_string(),
                        ));
                    }
                    if value.len() > HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize {
                        return Err(CodecError::DeserializeError(
                            "Invalid HTTP request: header value is too big".to_string(),
                        ));
                    }

                    let key = req.headers[i].name.to_string().to_lowercase();

                    if seen_headers.contains(&key) {
                        return Err(CodecError::DeserializeError(format!(
                            "Invalid HTTP request: duplicate header \"{}\"",
                            key
                        )));
                    }
                    seen_headers.insert(key.clone());

                    if key == "host" {
                        peerhost = match value.parse::<PeerHost>() {
                            Ok(ph) => Some(ph),
                            Err(_) => None,
                        };
                    } else if key == "content-type" {
                        // parse
                        let ctype = value.to_lowercase().parse::<HttpContentType>()?;
                        content_type = Some(ctype);
                    } else if key == "content-length" {
                        // parse
                        content_length = match value.parse::<u32>() {
                            Ok(len) => Some(len),
                            Err(_) => None,
                        };
                    } else if key == "connection" {
                        // parse
                        if value.to_lowercase() == "close" {
                            keep_alive = false;
                        } else if value.to_lowercase() == "keep-alive" {
                            keep_alive = true;
                        } else {
                            return Err(CodecError::DeserializeError(
                                "Inavlid HTTP request: invalid Connection: header".to_string(),
                            ));
                        }
                    } else {
                        headers.insert(key, value);
                    }
                }

                if peerhost.is_none() {
                    return Err(CodecError::DeserializeError(
                        "Missing Host header".to_string(),
                    ));
                };

                Ok(HttpRequestPreamble {
                    version,
                    verb,
                    path_and_query_str,
                    host: peerhost.unwrap(),
                    content_type,
                    content_length,
                    keep_alive,
                    headers,
                })
            }
        }
    }
}

/// Http request bodies that can be consumed
#[derive(Debug, Clone, PartialEq)]
pub enum HttpRequestPayload {
    /// No body
    Empty,
    /// JSON body
    JSON(serde_json::Value),
    /// Bytes body
    Bytes(Vec<u8>),
    /// Text body
    Text(String),
}

impl HttpRequestPayload {
    /// Deduce the content type
    pub fn content_type(&self) -> Option<HttpContentType> {
        match self {
            Self::Empty => None,
            Self::JSON(..) => Some(HttpContentType::JSON),
            Self::Bytes(..) => Some(HttpContentType::Bytes),
            Self::Text(..) => Some(HttpContentType::Text),
        }
    }

    /// Deduce the content length.
    /// This can fail if we're sending a JSON payload and it cannot be encoded (which itself
    /// indicates a bug in the caller).
    pub fn content_length(&self) -> Result<u32, Error> {
        match self {
            Self::Empty => Ok(0),
            Self::JSON(ref val) => {
                let bytes = serde_json::to_vec(val)?;
                Ok(bytes.len() as u32)
            }
            Self::Bytes(ref val) => Ok(val.len() as u32),
            Self::Text(ref val) => Ok(val.as_str().as_bytes().len() as u32),
        }
    }

    /// Write this payload to a given Write instance
    pub fn send<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        match self {
            Self::Empty => Ok(()),
            Self::JSON(ref value) => serde_json::to_writer(fd, value).map_err(Error::JsonError),
            Self::Bytes(ref value) => fd.write_all(value).map_err(Error::WriteError),
            Self::Text(ref value) => fd.write_all(value.as_bytes()).map_err(Error::WriteError),
        }
    }
}

/// Http request contents.  This is "data plane" stuff -- all the app-specific data that the client
/// sends -- the request path, query string, and body.  The request handler constructs this when
/// decoding an inbound HTTP request.  The instance will then be fed into the corresponding
/// HTTP response handler.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRequestContents {
    /// payload consumed from the connection buffer
    payload: HttpRequestPayload,
    /// arguments extracted from the path that are useful to this request
    path_args: HashMap<String, String>,
    /// query string arguments from the path that are useful to this request
    query_args: HashMap<String, String>,
    /// parsed data from the request, used by the caller
    parsed_data: HashMap<String, serde_json::Value>,
}

impl HttpRequestContents {
    pub fn new() -> Self {
        Self {
            payload: HttpRequestPayload::Empty,
            path_args: HashMap::new(),
            query_args: HashMap::new(),
            parsed_data: HashMap::new(),
        }
    }

    /// Decode the query string
    fn parse_qs(query: Option<&str>) -> HashMap<String, String> {
        query
            .map(|query_string| {
                let mut kv = HashMap::new();
                for (key, value) in form_urlencoded::parse(query_string.as_bytes()) {
                    kv.insert(key.to_string(), value.to_string());
                }
                kv
            })
            .unwrap_or(HashMap::new())
    }

    /// chain constructor -- add a query strings' values to the existing values, and also
    pub fn query_string(mut self, qs: Option<&str>) -> Self {
        let new_kv = Self::parse_qs(qs);
        self.query_args.extend(new_kv);
        self
    }

    /// chain constructor -- set the payload to JSON
    pub fn payload_json(mut self, value: serde_json::Value) -> Self {
        self.payload = HttpRequestPayload::JSON(value);
        self
    }

    /// chain constructor -- set the payload to bytes
    pub fn payload_bytes(mut self, value: Vec<u8>) -> Self {
        self.payload = HttpRequestPayload::Bytes(value);
        self
    }

    /// chain consturctor -- set the payload to text
    pub fn payload_text(mut self, value: String) -> Self {
        self.payload = HttpRequestPayload::Text(value);
        self
    }

    /// chain constructor -- set the payload to SIP-003 bytestream
    pub fn payload_stacks<T: StacksMessageCodec>(mut self, payload: &T) -> Self {
        self.payload = HttpRequestPayload::Bytes(payload.serialize_to_vec());
        self
    }

    /// chain constructor -- add a path argument
    pub fn path_arg(mut self, key: String, value: String) -> Self {
        self.path_args.insert(key, value);
        self
    }

    /// chain constructor -- add a query argument.
    pub fn query_arg(mut self, key: String, value: String) -> Self {
        self.query_args.insert(key, value);
        self
    }

    /// chain constructor -- add a parsed datum
    pub fn parsed_data(mut self, key: String, value: serde_json::Value) -> Self {
        self.parsed_data.insert(key, value);
        self
    }

    /// Directly ref the inner path args
    pub fn get_path_args(&self) -> &HashMap<String, String> {
        &self.path_args
    }

    /// Directly ref the inner query args
    pub fn get_query_args(&self) -> &HashMap<String, String> {
        &self.query_args
    }

    /// Get a path argument
    pub fn get_path_arg(&self, key: &String) -> Option<&String> {
        self.path_args.get(key)
    }

    /// Get a query argument
    pub fn get_query_arg(&self, key: &str) -> Option<&String> {
        self.query_args.get(key)
    }

    /// Get a parsed datum
    pub fn get_parsed_data(&self, key: &String) -> Option<&serde_json::Value> {
        self.parsed_data.get(key)
    }

    /// Take a parsed data
    pub fn take_parsed_data(&mut self, key: &String) -> Option<serde_json::Value> {
        self.parsed_data.remove(key)
    }

    /// Take a query arg
    pub fn take_query_arg(&mut self, key: &String) -> Option<String> {
        self.query_args.remove(key)
    }

    /// Get the MIME type for this contents
    pub fn content_type(&self) -> Option<HttpContentType> {
        self.payload.content_type()
    }

    /// Get the length of this upload
    pub fn content_length(&self) -> Result<u32, Error> {
        self.payload.content_length()
    }

    /// Ref the internal payload
    pub fn get_payload(&self) -> &HttpRequestPayload {
        &self.payload
    }

    /// Destruct into internal payload
    pub fn into_payload(self) -> HttpRequestPayload {
        self.payload
    }

    /// Recover the full query string
    pub fn get_full_query_string(&self) -> String {
        let buf = "".to_string();
        let mut serializer = form_urlencoded::Serializer::new(buf);
        for (k, v) in self.query_args.iter() {
            serializer.append_pair(&k, &v);
        }
        serializer.finish()
    }
}

/// Work around Clone blanket implementations not being object-safe
pub trait HttpRequestClone {
    fn clone_box(&self) -> Box<dyn HttpRequest>;
}

impl<T> HttpRequestClone for T
where
    T: 'static + HttpRequest + Clone,
{
    fn clone_box(&self) -> Box<dyn HttpRequest> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn HttpRequest> {
    fn clone(&self) -> Box<dyn HttpRequest> {
        self.clone_box()
    }
}

/// Trait that every HTTP round-trip request type must implement
pub trait HttpRequest: Send + HttpRequestClone {
    /// What is the HTTP verb that this request honors?
    fn verb(&self) -> &'static str;
    /// What is the path regex that this request honors?
    fn path_regex(&self) -> Regex;
    /// Decode a request into the contents that this request handler cares about.
    fn try_parse_request(
        &mut self,
        request_preamble: &HttpRequestPreamble,
        captures: &Captures,
        query_str: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error>;
    /// Get identifier from finite set to be used in metrics
    fn metrics_identifier(&self) -> &str;
}
