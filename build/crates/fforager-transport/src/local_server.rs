use crate::{ByteCredits, TransportError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_METADATA_BYTES: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct LocalProtocolServer {
    target: LocalHarnessTarget,
    request_rx: Receiver<CapturedRequest>,
    worker: JoinHandle<Result<(), String>>,
}

#[derive(Debug, Clone)]
pub struct LocalHarnessTarget {
    address: SocketAddr,
    authorization: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedRequest {
    pub request_line: String,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub connection_identity: String,
    pub wire_identity: String,
}

impl LocalProtocolServer {
    /// Starts one authenticated, one-request loopback proof server.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the listener, identity, or worker setup fails.
    pub fn spawn() -> Result<Self, TransportError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-BIND: {error}")))?;
        let address = listener
            .local_addr()
            .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-ADDR: {error}")))?;
        let authorization = format!("ff-local-harness-{}", address.port());
        let expected_authorization = authorization.clone();
        let (request_tx, request_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-ACCEPT: {error}"))?;
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-TIMEOUT: {error}"))?;
            stream
                .set_write_timeout(Some(IO_TIMEOUT))
                .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-TIMEOUT: {error}"))?;
            let request = read_request(&mut stream)?;
            if request.headers.get("x-ff-harness-authorization") != Some(&expected_authorization) {
                return Err("FF-TRANSPORT-E-HARNESS-AUTHORIZATION".to_owned());
            }
            let response = response_for(&request)?;
            request_tx
                .send(request)
                .map_err(|_| "FF-TRANSPORT-E-HARNESS-RECEIPT".to_owned())?;
            stream
                .write_all(&response)
                .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-WRITE: {error}"))
        });
        Ok(Self {
            target: LocalHarnessTarget {
                address,
                authorization,
            },
            request_rx,
            worker,
        })
    }

    #[must_use]
    pub fn target(&self) -> LocalHarnessTarget {
        self.target.clone()
    }

    /// Waits for the captured request and joins the server worker.
    ///
    /// # Errors
    ///
    /// Returns a transport error for a missing receipt, worker panic, timeout, or
    /// protocol failure.
    pub fn finish(self) -> Result<CapturedRequest, TransportError> {
        let request = self.request_rx.recv_timeout(IO_TIMEOUT).map_err(|error| {
            TransportError::Protocol(format!("FF-TRANSPORT-E-HARNESS-RECEIPT: {error}"))
        })?;
        self.worker
            .join()
            .map_err(|_| TransportError::Protocol("FF-TRANSPORT-E-HARNESS-PANIC".to_owned()))?
            .map_err(TransportError::Protocol)?;
        Ok(request)
    }
}

/// Executes one bounded HTTP/1.1 request through a private local harness target.
///
/// # Errors
///
/// Returns a transport error for an invalid target path or range, I/O failure,
/// malformed response, missing byte credit, or body bound violation.
pub fn execute_local(
    target: &LocalHarnessTarget,
    path_and_query: &str,
    range: Option<&str>,
    credits: &mut ByteCredits,
) -> Result<LocalResponse, TransportError> {
    if !path_and_query.starts_with('/')
        || path_and_query.len() > 4 * 1024
        || path_and_query.chars().any(char::is_control)
    {
        return Err(TransportError::Protocol(
            "FF-TRANSPORT-E-HARNESS-PATH".to_owned(),
        ));
    }
    let mut stream = TcpStream::connect_timeout(&target.address, IO_TIMEOUT)
        .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-CONNECT: {error}")))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-TIMEOUT: {error}")))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-TIMEOUT: {error}")))?;
    let mut request = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nX-FF-Harness-Authorization: {}\r\n",
        target.address.port(),
        target.authorization
    );
    if let Some(range) = range {
        if range.chars().any(char::is_control) || range.len() > 128 {
            return Err(TransportError::InvalidHeader(
                "FF-TRANSPORT-E-HARNESS-RANGE".to_owned(),
            ));
        }
        write!(request, "Range: {range}\r\n")
            .map_err(|error| TransportError::Protocol(format!("FF-TRANSPORT-E-FORMAT: {error}")))?;
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-HARNESS-WRITE: {error}")))?;
    read_response(&mut stream, credits, target.address)
}

fn read_request(stream: &mut TcpStream) -> Result<CapturedRequest, String> {
    let bytes = read_until_header_end(stream, MAX_REQUEST_BYTES)
        .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-READ: {error}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("FF-TRANSPORT-E-HARNESS-UTF8: {error}"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "FF-TRANSPORT-E-HARNESS-REQUEST-LINE".to_owned())?
        .to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "FF-TRANSPORT-E-HARNESS-HEADER".to_owned())?;
        let normalized = name.trim().to_ascii_lowercase();
        if headers
            .insert(normalized, value.trim().to_owned())
            .is_some()
        {
            return Err("FF-TRANSPORT-E-HARNESS-DUPLICATE-HEADER".to_owned());
        }
    }
    Ok(CapturedRequest {
        request_line,
        headers,
    })
}

fn response_for(request: &CapturedRequest) -> Result<Vec<u8>, String> {
    let path = request
        .request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "FF-TRANSPORT-E-HARNESS-TARGET".to_owned())?;
    let (status, reason, headers, body) = match path.split('?').next().unwrap_or(path) {
        "/ok" => (200, "OK", Vec::new(), b"ferric-transport".to_vec()),
        "/range" => {
            if request.headers.get("range").map(String::as_str) != Some("bytes=2-5") {
                return Err("FF-TRANSPORT-E-HARNESS-RANGE-EXPECTATION".to_owned());
            }
            (
                206,
                "Partial Content",
                vec![("Content-Range", "bytes 2-5/10")],
                b"2345".to_vec(),
            )
        }
        "/stream" => (200, "OK", Vec::new(), b"stream-one-stream-two".to_vec()),
        _ => (404, "Not Found", Vec::new(), b"not-found".to_vec()),
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    )
    .into_bytes();
    for (name, value) in headers {
        response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(&body);
    Ok(response)
}

fn read_response(
    stream: &mut TcpStream,
    credits: &mut ByteCredits,
    address: SocketAddr,
) -> Result<LocalResponse, TransportError> {
    let metadata = read_until_header_end(stream, MAX_RESPONSE_METADATA_BYTES)
        .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-RESPONSE-READ: {error}")))?;
    let metadata_text = std::str::from_utf8(&metadata).map_err(|error| {
        TransportError::Protocol(format!("FF-TRANSPORT-E-RESPONSE-UTF8: {error}"))
    })?;
    let mut lines = metadata_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| TransportError::Protocol("FF-TRANSPORT-E-STATUS-LINE".to_owned()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| TransportError::Protocol("FF-TRANSPORT-E-STATUS".to_owned()))?
        .parse::<u16>()
        .map_err(|error| TransportError::Protocol(format!("FF-TRANSPORT-E-STATUS: {error}")))?;
    let mut headers = BTreeMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| TransportError::Protocol("FF-TRANSPORT-E-RESPONSE-HEADER".to_owned()))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or_else(|| TransportError::Protocol("FF-TRANSPORT-E-CONTENT-LENGTH".to_owned()))?
        .parse::<usize>()
        .map_err(|error| {
            TransportError::Protocol(format!("FF-TRANSPORT-E-CONTENT-LENGTH: {error}"))
        })?;
    let mut body = vec![0_u8; content_length];
    let mut offset = 0;
    while offset < content_length {
        let read = stream
            .read(&mut body[offset..])
            .map_err(|error| TransportError::Io(format!("FF-TRANSPORT-E-BODY-READ: {error}")))?;
        if read == 0 {
            return Err(TransportError::Protocol(
                "FF-TRANSPORT-E-BODY-TRUNCATED".to_owned(),
            ));
        }
        let accepted = u64::try_from(read)
            .map_err(|error| TransportError::Protocol(format!("FF-TRANSPORT-E-SIZE: {error}")))?;
        credits.accept(accepted)?;
        offset += read;
    }
    Ok(LocalResponse {
        status,
        headers,
        body,
        connection_identity: format!("tcp://{address}"),
        wire_identity: "http/1.1-std-tcp-v1".to_owned(),
    })
}

fn read_until_header_end(stream: &mut TcpStream, maximum: usize) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while bytes.len() < maximum {
        let read = stream.read(&mut one)?;
        if read == 0 {
            break;
        }
        bytes.push(one[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "header terminator missing or bound exceeded",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_http_range_evidence_crosses_loopback_socket() {
        let server = LocalProtocolServer::spawn().expect("local server");
        let mut credits = ByteCredits::new(4);
        credits.grant(4).expect("credits");
        let response = execute_local(&server.target(), "/range", Some("bytes=2-5"), &mut credits)
            .expect("local response");
        let request = server.finish().expect("server receipt");
        assert_eq!(response.status, 206);
        assert_eq!(response.body, b"2345");
        assert_eq!(credits.accepted(), 4);
        assert_eq!(
            request.headers.get("range").map(String::as_str),
            Some("bytes=2-5")
        );
    }
}
