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
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;
use std::time::SystemTime;

use stacks_common::codec::{Error as CodecError, StacksMessageCodec};
use stacks_common::deps_common::httparse;
use stacks_common::util::chunked_encoding::{
    HttpChunkedTransferWriter, HttpChunkedTransferWriterState,
};
use stacks_common::util::hash::to_hex;
use stacks_common::util::pipe::PipeWrite;
use {serde, serde_json};

use crate::net::http::common::{
    HttpReservedHeader, HTTP_PREAMBLE_MAX_ENCODED_SIZE, HTTP_PREAMBLE_MAX_NUM_HEADERS,
};
use crate::net::http::request::{HttpRequestContents, HttpRequestPreamble};
use crate::net::http::stream::HttpChunkGenerator;
use crate::net::http::{http_reason, write_headers, Error, HttpContentType, HttpVersion};

/// HTTP response preamble.  This captures all HTTP header information, but in a way that
/// certain fields that nodes rely on are guaranteed to have correct, sensible values.
/// The code calls this a "preamble" to be consistent with the Stacks protocol family system.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponsePreamble {
    /// HTTP version that was requested
    pub client_http_version: HttpVersion,
    /// HTTP status code
    pub status_code: u16,
    /// HTTP status code reason
    pub reason: String,
    /// true if `Connction: keep-alive` is present
    pub keep_alive: bool,
    /// Content-Length value, if given.  If it's not given, then the payload will be treated as
    /// chunk-encoded (and it had better have a `Transfer-Encoding: chunked` header)
    pub content_length: Option<u32>,
    /// Content-Type value.
    pub content_type: HttpContentType,
    /// Other headers we did not use
    pub headers: BTreeMap<String, String>,
}

pub struct HttpStreamState {
    encoder_state: Option<HttpChunkedTransferWriterState>,
    generator: Box<dyn HttpChunkGenerator>,
}

/// HTTP response body generated by the request handler.  It implements a means of streaming data from disk
/// or RAM into a socket buffer as space within it frees up.  Use one of the constructors below to
/// generate the response contents.
pub enum HttpResponseContents {
    Stream(HttpStreamState),
    RAM(Vec<u8>),
}

impl fmt::Debug for HttpResponseContents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(..) => write!(f, "HttpResponseContents::Stream(..)"),
            Self::RAM(ref bytes) => write!(f, "HttpResponseContents::RAM({})", to_hex(bytes)),
        }
    }
}

impl HttpResponseContents {
    /// Make response contents from a given stream cursor
    pub fn from_stream(generator: Box<dyn HttpChunkGenerator>) -> HttpResponseContents {
        let chunk_size = generator.hint_chunk_size();
        HttpResponseContents::Stream(HttpStreamState {
            generator,
            encoder_state: Some(HttpChunkedTransferWriterState::new(chunk_size)),
        })
    }

    /// Make response contents from a byte array
    pub fn from_ram(bytes: Vec<u8>) -> HttpResponseContents {
        assert!(bytes.len() < (u32::MAX as usize));
        HttpResponseContents::RAM(bytes)
    }

    /// Make response contents from a JSON value
    pub fn try_from_json<T: serde::ser::Serialize>(
        value: &T,
    ) -> Result<HttpResponseContents, Error> {
        Ok(Self::from_ram(serde_json::to_string(value)?.into_bytes()))
    }

    /// Deduce the proper content-length
    pub fn content_length(&self) -> Option<u32> {
        match self {
            Self::Stream(..) => None,
            Self::RAM(data) => Some(data.len() as u32),
        }
    }

    /// Write data for this to a pipe writer, which buffers it up.
    /// Return Ok(Some(..)) if there is mroe data to send.
    /// Once all data is sent, return Ok(None)
    #[cfg_attr(test, mutants::skip)]
    pub fn pipe_out(&mut self, fd: &mut PipeWrite) -> Result<u64, Error> {
        match self {
            HttpResponseContents::Stream(ref mut inner_stream) => {
                // write the next chunk
                let mut encoder_state = inner_stream
                    .encoder_state
                    .take()
                    .expect("FATAL: encoder state poisoned");
                let res = inner_stream
                    .generator
                    .stream_to(&mut encoder_state, fd)
                    .map_err(Error::WriteError);
                inner_stream.encoder_state = Some(encoder_state);
                res
            }
            HttpResponseContents::RAM(ref mut buf) => {
                // dump directly into the pipewrite
                // TODO: zero-copy?
                if !buf.is_empty() {
                    fd.write_all(&buf[..]).map_err(Error::WriteError)?;
                    buf.clear();
                }
                Ok(buf.len() as u64)
            }
        }
    }
}

impl From<Vec<u8>> for HttpResponseContents {
    fn from(data: Vec<u8>) -> Self {
        Self::RAM(data)
    }
}

impl HttpResponsePreamble {
    pub fn new(
        client_http_version: HttpVersion,
        status_code: u16,
        reason: String,
        content_length_opt: Option<u32>,
        content_type: HttpContentType,
        keep_alive: bool,
    ) -> HttpResponsePreamble {
        HttpResponsePreamble {
            client_http_version,
            status_code,
            reason,
            keep_alive,
            content_length: content_length_opt,
            content_type,
            headers: BTreeMap::new(),
        }
    }

    pub fn from_http_request_preamble(
        preamble: &HttpRequestPreamble,
        status: u16,
        reason: &str,
        content_len_opt: Option<u32>,
        content_type: HttpContentType,
    ) -> HttpResponsePreamble {
        HttpResponsePreamble::new(
            preamble.version,
            status,
            reason.to_string(),
            content_len_opt,
            content_type,
            preamble.keep_alive,
        )
    }

    pub fn success_2xx_json(
        preamble: &HttpRequestPreamble,
        status_code: u16,
    ) -> HttpResponsePreamble {
        HttpResponsePreamble::new(
            preamble.version,
            status_code,
            http_reason(status_code).to_string(),
            None,
            HttpContentType::JSON,
            preamble.keep_alive,
        )
    }

    pub fn ok_json(preamble: &HttpRequestPreamble) -> HttpResponsePreamble {
        Self::success_2xx_json(preamble, 200)
    }

    pub fn accepted_json(preamble: &HttpRequestPreamble) -> HttpResponsePreamble {
        Self::success_2xx_json(preamble, 202)
    }

    pub fn raw_ok_json(version: HttpVersion, keep_alive: bool) -> HttpResponsePreamble {
        HttpResponsePreamble::new(
            version,
            200,
            "OK".to_string(),
            None,
            HttpContentType::JSON,
            keep_alive,
        )
    }

    pub fn error_bytes(code: u16, reason: &str) -> Self {
        HttpResponsePreamble::new(
            HttpVersion::Http11,
            code,
            reason.to_string(),
            None,
            HttpContentType::Bytes,
            false,
        )
    }

    pub fn error_json(code: u16, reason: &str) -> Self {
        HttpResponsePreamble::new(
            HttpVersion::Http11,
            code,
            reason.to_string(),
            None,
            HttpContentType::JSON,
            false,
        )
    }

    pub fn error_text(code: u16, reason: &str, message: &str) -> Self {
        HttpResponsePreamble::new(
            HttpVersion::Http11,
            code,
            reason.to_string(),
            Some(message.len() as u32),
            HttpContentType::Text,
            false,
        )
    }

    #[cfg(test)]
    pub fn from_headers(
        status_code: u16,
        reason: String,
        keep_alive: bool,
        content_length: Option<u32>,
        content_type: HttpContentType,
        keys: Vec<String>,
        values: Vec<String>,
    ) -> HttpResponsePreamble {
        assert_eq!(keys.len(), values.len());
        let mut res = HttpResponsePreamble::new(
            HttpVersion::Http11,
            status_code,
            reason,
            content_length,
            content_type,
            keep_alive,
        );

        for (k, v) in keys.into_iter().zip(values) {
            res.add_header(k, v);
        }
        res
    }

    /// Add a header.
    /// Reserved headers will not be directly added to self.headers.
    pub fn add_header(&mut self, key: String, value: String) {
        let hdr = key.to_lowercase();
        if HttpReservedHeader::is_reserved(&hdr) {
            match HttpReservedHeader::try_from_str(&hdr, &value) {
                Some(h) => match h {
                    HttpReservedHeader::ContentLength(cl) => {
                        self.content_length = Some(cl);
                        return;
                    }
                    HttpReservedHeader::ContentType(ct) => {
                        self.content_type = ct;
                        return;
                    }
                    HttpReservedHeader::Host(..) => {
                        // ignored
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
            "content-type" => {
                return Some(format!("{}", &self.content_type));
            }
            "content-length" => {
                return self.content_length.clone().map(|cl| format!("{}", &cl));
            }
            _ => {
                return self.headers.get(&hdr).cloned();
            }
        }
    }

    pub fn add_CORS_headers(&mut self) {
        self.headers
            .insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
    }

    // do we have Transfer-Encoding: chunked?
    pub fn is_chunked(&self) -> bool {
        self.content_length.is_none()
    }
}

/// Get an RFC 7231 date that represents the current time
fn rfc7231_now() -> String {
    let now = time::PrimitiveDateTime::from(SystemTime::now());
    now.format("%a, %b %-d %-Y %-H:%M:%S GMT")
}

/// Read from a stream until we see '\r\n\r\n', with the purpose of reading an HTTP preamble.
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

impl StacksMessageCodec for HttpResponsePreamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        fd.write_all("HTTP/1.1 ".as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all(format!("{} {}\r\n", self.status_code, self.reason).as_bytes())
            .map_err(CodecError::WriteError)?;

        if !self.headers.contains_key("server") {
            fd.write_all("Server: stacks/2.0\r\n".as_bytes())
                .map_err(CodecError::WriteError)?;
        }

        if !self.headers.contains_key("date") {
            fd.write_all("Date: ".as_bytes())
                .map_err(CodecError::WriteError)?;
            fd.write_all(rfc7231_now().as_bytes())
                .map_err(CodecError::WriteError)?;
            fd.write_all("\r\n".as_bytes())
                .map_err(CodecError::WriteError)?;
        }

        if !self.headers.contains_key("access-control-allow-origin") {
            fd.write_all("Access-Control-Allow-Origin: *\r\n".as_bytes())
                .map_err(CodecError::WriteError)?;
        }

        if !self.headers.contains_key("access-control-allow-headers") {
            fd.write_all("Access-Control-Allow-Headers: origin, content-type\r\n".as_bytes())
                .map_err(CodecError::WriteError)?;
        }

        if !self.headers.contains_key("access-control-allow-methods") {
            fd.write_all("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n".as_bytes())
                .map_err(CodecError::WriteError)?;
        }

        // content type (reserved header)
        fd.write_all("Content-Type: ".as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all(self.content_type.to_string().as_bytes())
            .map_err(CodecError::WriteError)?;
        fd.write_all("\r\n".as_bytes())
            .map_err(CodecError::WriteError)?;

        // content-length / transfer-encoding (reserved header)
        match self.content_length {
            Some(len) => {
                fd.write_all("Content-Length: ".as_bytes())
                    .map_err(CodecError::WriteError)?;
                fd.write_all(format!("{}\r\n", len).as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
            None => {
                fd.write_all("Transfer-Encoding: chunked\r\n".as_bytes())
                    .map_err(CodecError::WriteError)?;
            }
        }

        // connection (reserved header)
        match self.client_http_version {
            HttpVersion::Http10 => {
                // client expects explicit keep-alive
                if self.keep_alive {
                    fd.write_all("Connection: keep-alive\r\n".as_bytes())
                        .map_err(CodecError::WriteError)?;
                } else {
                    fd.write_all("Connection: close\r\n".as_bytes())
                        .map_err(CodecError::WriteError)?;
                }
            }
            HttpVersion::Http11 => {
                // only need "connection: close" if we're explicitly _not_ doing keep-alive
                if !self.keep_alive {
                    fd.write_all("Connection: close\r\n".as_bytes())
                        .map_err(CodecError::WriteError)?;
                }
            }
        }

        // other headers
        write_headers(fd, &self.headers)?;

        fd.write_all("\r\n".as_bytes())
            .map_err(CodecError::WriteError)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HttpResponsePreamble, CodecError> {
        // realistically, there won't be more than HTTP_PREAMBLE_MAX_NUM_HEADERS headers
        let mut headers = [httparse::EMPTY_HEADER; HTTP_PREAMBLE_MAX_NUM_HEADERS];
        let mut resp = httparse::Response::new(&mut headers);

        let buf_read = read_to_crlf2(fd)?;

        // consume response
        match resp.parse(&buf_read).map_err(|e| {
            CodecError::DeserializeError(format!("Failed to parse HTTP response: {:?}", &e))
        })? {
            httparse::Status::Partial => {
                // try again
                return Err(CodecError::UnderflowError(
                    "Not enough bytes to form a HTTP response preamble".to_string(),
                ));
            }
            httparse::Status::Complete(_) => {
                // consumed all headers.
                let http_version = resp
                    .version
                    .ok_or(CodecError::DeserializeError("No HTTP version".to_string()))?;
                let client_http_version = match http_version {
                    0 => HttpVersion::Http10,
                    1 => HttpVersion::Http11,
                    _ => {
                        return Err(CodecError::DeserializeError(
                            "Invalid HTTP version".to_string(),
                        ));
                    }
                };

                let status_code = resp.code.ok_or(CodecError::DeserializeError(
                    "No HTTP status code".to_string(),
                ))?;
                let reason = resp
                    .reason
                    .ok_or(CodecError::DeserializeError(
                        "No HTTP status reason".to_string(),
                    ))?
                    .to_string();

                let mut headers: BTreeMap<String, String> = BTreeMap::new();
                let mut seen_headers: HashSet<String> = HashSet::new();

                let mut content_type = None;
                let mut content_length = None;
                let mut chunked_encoding = false;
                let mut keep_alive = true;

                for i in 0..resp.headers.len() {
                    let value =
                        String::from_utf8(resp.headers[i].value.to_vec()).map_err(|_e| {
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

                    let key = resp.headers[i].name.to_string().to_lowercase();

                    if seen_headers.contains(&key) {
                        return Err(CodecError::DeserializeError(format!(
                            "Invalid HTTP request: duplicate header \"{}\"",
                            key
                        )));
                    }
                    seen_headers.insert(key.clone());

                    if key == "content-type" {
                        let ctype = value.to_lowercase().parse::<HttpContentType>()?;
                        content_type = Some(ctype);
                    } else if key == "content-length" {
                        let len = value.parse::<u32>().map_err(|_e| {
                            CodecError::DeserializeError(
                                "Invalid Content-Length header value".to_string(),
                            )
                        })?;
                        content_length = Some(len);
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
                    } else if key == "transfer-encoding" {
                        if value.to_lowercase() == "chunked" {
                            chunked_encoding = true;
                        } else {
                            return Err(CodecError::DeserializeError(format!(
                                "Unsupported transfer-encoding '{}'",
                                value
                            )));
                        }
                    } else {
                        headers.insert(key, value);
                    }
                }

                if content_length.is_some() && chunked_encoding {
                    return Err(CodecError::DeserializeError(
                        "Invalid HTTP response: incompatible transfer-encoding and content-length"
                            .to_string(),
                    ));
                }

                if content_length.is_none() && !chunked_encoding {
                    return Err(CodecError::DeserializeError(
                        "Invalid HTTP response: missing Content-Type, Content-Length".to_string(),
                    ));
                }

                Ok(HttpResponsePreamble {
                    client_http_version,
                    status_code,
                    reason,
                    keep_alive,
                    content_type: content_type.unwrap_or(HttpContentType::Bytes), // per the RFC
                    content_length,
                    headers,
                })
            }
        }
    }
}

/// HTTP response body that the receiver gets
#[derive(Debug, Clone, PartialEq)]
pub enum HttpResponsePayload {
    /// no HTTP body
    Empty,
    /// HTTP body is a JSON blob
    JSON(serde_json::Value),
    /// HTTP body is raw data
    Bytes(Vec<u8>),
    /// HTTP body is a UTF-8 String
    Text(String),
}

impl TryFrom<HttpResponsePayload> for HttpResponseContents {
    type Error = Error;
    fn try_from(payload: HttpResponsePayload) -> Result<HttpResponseContents, Error> {
        match payload {
            HttpResponsePayload::Empty => Ok(HttpResponseContents::from_ram(vec![])),
            HttpResponsePayload::JSON(value) => Ok(HttpResponseContents::from_ram(
                serde_json::to_string(&value)?.into_bytes(),
            )),
            HttpResponsePayload::Bytes(bytes) => Ok(HttpResponseContents::from_ram(bytes)),
            HttpResponsePayload::Text(string) => {
                Ok(HttpResponseContents::from_ram(string.into_bytes()))
            }
        }
    }
}

impl HttpResponsePayload {
    /// Try to make an HTTP payload from a JSON value
    pub fn try_from_json<T: serde::ser::Serialize>(obj: T) -> Result<HttpResponsePayload, Error> {
        Ok(Self::JSON(serde_json::to_value(&obj)?))
    }

    /// Try to calculate the content length
    pub fn try_content_length(&self) -> Option<u32> {
        match self {
            Self::Empty => Some(0),
            Self::JSON(value) => {
                let value_bytes = serde_json::to_vec(&value).ok()?;
                if value_bytes.len() > (u32::MAX as usize) {
                    return None;
                }
                Some(value_bytes.len() as u32)
            }
            Self::Bytes(value) => {
                if value.len() > (u32::MAX as usize) {
                    return None;
                }
                Some(value.len() as u32)
            }
            Self::Text(value) => {
                if value.as_bytes().len() > (u32::MAX as usize) {
                    return None;
                }
                Some(value.len() as u32)
            }
        }
    }

    /// Write this payload to a Write
    pub fn send<W: Write>(&self, fd: &mut W) -> Result<(), Error> {
        match self {
            Self::Empty => Ok(()),
            Self::JSON(value) => serde_json::to_writer(fd, &value).map_err(Error::JsonError),
            Self::Bytes(value) => fd.write_all(value).map_err(Error::WriteError),
            Self::Text(value) => fd.write_all(value.as_bytes()).map_err(Error::WriteError),
        }
    }

    /// Write this payload to a Write, but as a single HTTP chunk.
    /// This is here for the times where you've already sent the HTTP preamble while designating
    /// chunked-enoding, but you don't (yet) have a Streamer implementation for your body.
    ///
    /// You really should not use this in production.  It's mainly used in testing clients
    /// who use this library.
    pub fn send_chunked<W: Write>(&self, chunk_size: usize, fd: &mut W) -> Result<(), Error> {
        let mut bytes = vec![];
        match self {
            Self::Empty => (),
            Self::JSON(value) => {
                serde_json::to_writer(&mut bytes, &value).map_err(Error::JsonError)?
            }
            Self::Bytes(value) => bytes.extend_from_slice(&value[..]),
            Self::Text(value) => bytes.extend_from_slice(&value.as_bytes()[..]),
        }
        let mut encoded_bytes = vec![];
        {
            let mut encoder = HttpChunkedTransferWriterState::new(chunk_size);
            let mut chunker_fd =
                HttpChunkedTransferWriter::from_writer_state(&mut encoded_bytes, &mut encoder);
            chunker_fd.write_all(&bytes).map_err(Error::WriteError)?;
            chunker_fd.flush().map_err(Error::WriteError)?;
        }
        fd.write_all(&encoded_bytes).map_err(Error::WriteError)?;
        debug!("bytes: {:?}", &bytes);
        debug!("encoded: {:?}", &encoded_bytes);
        Ok(())
    }
}

/// Convert into the inner Bytes
impl TryInto<Vec<u8>> for HttpResponsePayload {
    type Error = Error;
    fn try_into(self) -> Result<Vec<u8>, Error> {
        match self {
            HttpResponsePayload::Empty => Ok(vec![]),
            HttpResponsePayload::Bytes(bytes) => Ok(bytes),
            _ => Err(Error::DecodeError("Http payload is not Bytes".to_string())),
        }
    }
}

/// Convert into the inner Text
impl TryInto<String> for HttpResponsePayload {
    type Error = Error;
    fn try_into(self) -> Result<String, Error> {
        match self {
            HttpResponsePayload::Empty => Ok("".to_string()),
            HttpResponsePayload::Text(s) => Ok(s),
            _ => Err(Error::DecodeError("Http payload is not Text".to_string())),
        }
    }
}

/// Convert into the inner JSON
impl TryInto<serde_json::Value> for HttpResponsePayload {
    type Error = Error;
    fn try_into(self) -> Result<serde_json::Value, Error> {
        match self {
            HttpResponsePayload::Empty => Ok(serde_json::Value::Null),
            HttpResponsePayload::JSON(j) => Ok(j),
            _ => Err(Error::DecodeError("Http payload is not JSON".to_string())),
        }
    }
}

/// Work around Clone blanket implementations not being object-safe
pub trait HttpResponseClone {
    fn clone_box(&self) -> Box<dyn HttpResponse>;
}

impl<T> HttpResponseClone for T
where
    T: 'static + HttpResponse + Clone,
{
    fn clone_box(&self) -> Box<dyn HttpResponse> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn HttpResponse> {
    fn clone(&self) -> Box<dyn HttpResponse> {
        self.clone_box()
    }
}

/// Trait to implement to decode an HTTP response
pub trait HttpResponse: Send + HttpResponseClone {
    /// Decode the incoming HTTP response into its MIME-typed body.
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error>;
}
