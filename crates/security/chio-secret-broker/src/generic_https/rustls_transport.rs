use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use zeroize::{Zeroize, Zeroizing};

use super::{PinnedHttpsRequest, PinnedHttpsTransport, RawHttpsResponse, MAX_RESPONSE_HEAD_BYTES};
use crate::protocol::{
    BrokerScheme, HeaderField, MAX_HEADER_COUNT, MAX_HEADER_NAME_BYTES, MAX_HEADER_VALUE_BYTES,
    MAX_WIRE_BYTES,
};
use crate::{BrokerError, Result};

const MAX_STATUS_LINE_BYTES: usize = 1_024;
const MAX_RESPONSE_HEADER_LINE_BYTES: usize = 8_384;
const MAX_CHUNK_LINE_BYTES: usize = 64;
const HTTP_READER_CAPACITY: usize = 8_192;

pub(crate) struct RustlsPinnedHttpsTransport {
    tls_config: Arc<ClientConfig>,
}

impl RustlsPinnedHttpsTransport {
    pub(crate) fn new() -> Result<Self> {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let builder =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .map_err(|_| {
                    BrokerError::Invariant("TLS protocol configuration failed".to_string())
                })?;
        let mut config = builder.with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls_config: Arc::new(config),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_tls_config(tls_config: Arc<ClientConfig>) -> Self {
        Self { tls_config }
    }
}

impl PinnedHttpsTransport for RustlsPinnedHttpsTransport {
    fn dispatch(&self, mut request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
        if request.scheme != BrokerScheme::Https {
            return Err(BrokerError::AuthorizationDenied(
                "production transport requires HTTPS".to_string(),
            ));
        }
        if request.redirects_allowed {
            return Err(BrokerError::AuthorizationDenied(
                "production transport refuses redirect-enabled requests".to_string(),
            ));
        }
        let timeout = Duration::from_millis(request.timeout_ms);
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| BrokerError::InvalidRequest("request deadline overflow".to_string()))?;
        let expected_peer = SocketAddr::new(request.pinned_address, request.port);
        let socket = TcpStream::connect_timeout(&expected_peer, timeout)
            .map_err(|_| BrokerError::Upstream("upstream connection failed".to_string()))?;
        let peer = socket
            .peer_addr()
            .map_err(|_| BrokerError::Upstream("upstream peer observation failed".to_string()))?;
        if peer != expected_peer {
            return Err(BrokerError::AuthorizationDenied(
                "connected peer does not match the pinned destination".to_string(),
            ));
        }
        let mut socket = DeadlineTcpStream { socket, deadline };
        let server_name = ServerName::try_from(request.original_hostname.clone())
            .map_err(|_| BrokerError::InvalidRequest("TLS server name is invalid".to_string()))?;
        let mut connection = ClientConnection::new(self.tls_config.clone(), server_name)
            .map_err(|_| BrokerError::Upstream("TLS session creation failed".to_string()))?;
        connection
            .complete_io(&mut socket)
            .map_err(|_| BrokerError::Upstream("TLS handshake failed".to_string()))?;
        if connection.is_handshaking()
            || connection
                .peer_certificates()
                .is_none_or(|certificates| certificates.is_empty())
            || connection
                .alpn_protocol()
                .is_some_and(|protocol| protocol != b"http/1.1")
        {
            return Err(BrokerError::Upstream(
                "TLS peer verification did not complete".to_string(),
            ));
        }
        let verified_tls_server_name = request.original_hostname.clone();
        let mut stream = StreamOwned::new(connection, socket);
        let mut request_head = build_request_head(&request)?;
        request.secret_headers.clear();
        stream
            .write_all(request_head.as_slice())
            .and_then(|()| stream.flush())
            .map_err(|_| BrokerError::Upstream("upstream request write failed".to_string()))?;
        request_head.zeroize();
        stream
            .write_all(&request.body)
            .and_then(|()| stream.flush())
            .map_err(|_| BrokerError::Upstream("upstream request body write failed".to_string()))?;

        let combined_limit = usize::try_from(request.response_limit_bytes).map_err(|_| {
            BrokerError::InvalidRequest("response limit exceeds platform size".to_string())
        })?;
        let mut reader = BufReader::with_capacity(HTTP_READER_CAPACITY, stream);
        let mut parsed = parse_http_response(&mut reader, &request.method, combined_limit)?;
        let observed_peer =
            reader.get_ref().sock.peer_addr().map_err(|_| {
                BrokerError::Upstream("upstream peer observation failed".to_string())
            })?;
        if observed_peer != expected_peer {
            return Err(BrokerError::AuthorizationDenied(
                "response peer does not match the pinned destination".to_string(),
            ));
        }
        Ok(RawHttpsResponse {
            status: parsed.status,
            headers: std::mem::take(&mut parsed.headers),
            decoded_body_chunks: vec![std::mem::take(&mut parsed.body)],
            response_head_bytes: parsed.response_head_bytes,
            connected_address: observed_peer.ip(),
            tls_server_name: verified_tls_server_name,
            redirected: (300..400).contains(&parsed.status),
        })
    }
}

struct DeadlineTcpStream {
    socket: TcpStream,
    deadline: Instant,
}

impl DeadlineTcpStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request deadline elapsed"))
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.flush()
    }
}

pub(super) fn build_request_head(request: &PinnedHttpsRequest) -> Result<Zeroizing<Vec<u8>>> {
    let mut head = Zeroizing::new(Vec::new());
    head.extend_from_slice(request.method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.path_and_query.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    if request.original_hostname.contains(':') {
        head.push(b'[');
        head.extend_from_slice(request.original_hostname.as_bytes());
        head.push(b']');
    } else {
        head.extend_from_slice(request.original_hostname.as_bytes());
    }
    if request.port != 443 {
        head.push(b':');
        head.extend_from_slice(request.port.to_string().as_bytes());
    }
    head.extend_from_slice(
        b"\r\nConnection: close\r\nAccept-Encoding: identity\r\nContent-Length: ",
    );
    head.extend_from_slice(request.body.len().to_string().as_bytes());
    head.extend_from_slice(b"\r\n");
    for header in &request.caller_headers {
        append_header(&mut head, &header.name, &header.value)?;
    }
    for header in &request.secret_headers {
        append_header(&mut head, header.name(), header.value())?;
    }
    head.extend_from_slice(b"\r\n");
    if head.len() > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "HTTP request head exceeds the wire limit".to_string(),
        ));
    }
    Ok(head)
}

fn append_header(head: &mut Vec<u8>, name: &str, value: &[u8]) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_HEADER_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || value.len() > MAX_HEADER_VALUE_BYTES
        || value
            .iter()
            .any(|byte| !matches!(*byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
    {
        return Err(BrokerError::InvalidRequest(
            "outbound HTTP header is invalid".to_string(),
        ));
    }
    head.extend_from_slice(name.as_bytes());
    head.extend_from_slice(b": ");
    head.extend_from_slice(value);
    head.extend_from_slice(b"\r\n");
    Ok(())
}

struct ParsedHeader {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

struct ParsedHttpResponse {
    status: u16,
    headers: Vec<HeaderField>,
    body: Vec<u8>,
    response_head_bytes: usize,
}

impl Drop for ParsedHttpResponse {
    fn drop(&mut self) {
        for header in &mut self.headers {
            header.value.zeroize();
        }
        self.body.zeroize();
    }
}

fn parse_http_response(
    reader: &mut impl Read,
    request_method: &str,
    combined_limit: usize,
) -> Result<ParsedHttpResponse> {
    let head_limit = combined_limit.min(MAX_RESPONSE_HEAD_BYTES);
    if head_limit < 16 {
        return Err(BrokerError::ResponseRejected(
            "response limit cannot contain a valid HTTP response head".to_string(),
        ));
    }
    let status_line = read_crlf_line(reader, MAX_STATUS_LINE_BYTES.min(head_limit - 4))?;
    let status = parse_status_line(status_line.as_slice())?;
    let mut response_head_bytes = status_line
        .len()
        .checked_add(2)
        .ok_or_else(|| BrokerError::ResponseRejected("response head size overflow".to_string()))?;
    let mut headers = Vec::new();
    loop {
        let remaining = head_limit.checked_sub(response_head_bytes).ok_or_else(|| {
            BrokerError::ResponseRejected(
                "response head exceeds the signed combined byte limit".to_string(),
            )
        })?;
        if remaining < 2 {
            return Err(BrokerError::ResponseRejected(
                "response head exceeds the signed combined byte limit".to_string(),
            ));
        }
        let line = read_crlf_line(reader, MAX_RESPONSE_HEADER_LINE_BYTES.min(remaining - 2))?;
        response_head_bytes = response_head_bytes
            .checked_add(line.len())
            .and_then(|total| total.checked_add(2))
            .ok_or_else(|| {
                BrokerError::ResponseRejected("response head size overflow".to_string())
            })?;
        if response_head_bytes > head_limit {
            return Err(BrokerError::ResponseRejected(
                "response head exceeds the signed combined byte limit".to_string(),
            ));
        }
        if line.is_empty() {
            break;
        }
        if line
            .first()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
        {
            return Err(BrokerError::ResponseRejected(
                "obsolete folded response headers are forbidden".to_string(),
            ));
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(BrokerError::ResponseRejected(
                "upstream response has too many headers".to_string(),
            ));
        }
        let separator = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            BrokerError::ResponseRejected("upstream response header is malformed".to_string())
        })?;
        let name = std::str::from_utf8(&line[..separator]).map_err(|_| {
            BrokerError::ResponseRejected("upstream response header name is invalid".to_string())
        })?;
        let value = trim_optional_whitespace(&line[separator + 1..]);
        let field = HeaderField::normalized(name, value).map_err(|_| {
            BrokerError::ResponseRejected("upstream response header is invalid".to_string())
        })?;
        headers.push(ParsedHeader {
            name: field.name,
            value: Zeroizing::new(field.value),
        });
    }

    let framing = response_framing(&headers)?;
    let body_limit = combined_limit - response_head_bytes;
    let redirected = (300..400).contains(&status);
    let body_forbidden = status == 204 || status == 205;
    let no_body = request_method == "HEAD" || body_forbidden || redirected;
    let body = if no_body {
        if framing.transfer_chunked
            || (body_forbidden && framing.content_length.is_some_and(|length| length != 0))
        {
            return Err(BrokerError::ResponseRejected(
                "body-free response cannot declare a body".to_string(),
            ));
        }
        Vec::new()
    } else if framing.transfer_chunked {
        read_chunked_body(reader, body_limit)?
    } else if let Some(length) = framing.content_length {
        read_fixed_body(reader, length, body_limit)?
    } else {
        return Err(BrokerError::ResponseRejected(
            "upstream response has no supported body framing".to_string(),
        ));
    };
    let headers = headers
        .into_iter()
        .map(|header| HeaderField {
            name: header.name,
            value: header.value.to_vec(),
        })
        .collect();
    Ok(ParsedHttpResponse {
        status,
        headers,
        body,
        response_head_bytes,
    })
}

fn parse_status_line(line: &[u8]) -> Result<u16> {
    if line.len() < 12
        || &line[..9] != b"HTTP/1.1 "
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || (line.len() > 12 && line[12] != b' ')
        || line.get(13..).is_some_and(|reason| {
            !reason
                .iter()
                .all(|byte| matches!(*byte, b'\t' | b' '..=b'~'))
        })
    {
        return Err(BrokerError::ResponseRejected(
            "upstream HTTP status line is invalid".to_string(),
        ));
    }
    let status = u16::from(line[9] - b'0') * 100
        + u16::from(line[10] - b'0') * 10
        + u16::from(line[11] - b'0');
    if !(200..=599).contains(&status) {
        return Err(BrokerError::ResponseRejected(
            "informational or invalid HTTP status is unsupported".to_string(),
        ));
    }
    Ok(status)
}

struct ResponseFraming {
    content_length: Option<usize>,
    transfer_chunked: bool,
}

fn response_framing(headers: &[ParsedHeader]) -> Result<ResponseFraming> {
    let mut content_length = None;
    let mut transfer_chunked = false;
    for header in headers {
        match header.name.as_str() {
            "content-length" => {
                if content_length.is_some() {
                    return Err(BrokerError::ResponseRejected(
                        "duplicate content length is forbidden".to_string(),
                    ));
                }
                let text = std::str::from_utf8(header.value.as_slice()).map_err(|_| {
                    BrokerError::ResponseRejected("content length is invalid".to_string())
                })?;
                if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(BrokerError::ResponseRejected(
                        "content length is invalid".to_string(),
                    ));
                }
                content_length = Some(text.parse::<usize>().map_err(|_| {
                    BrokerError::ResponseRejected("content length overflows".to_string())
                })?);
            }
            "transfer-encoding" => {
                if transfer_chunked || !header.value.as_slice().eq_ignore_ascii_case(b"chunked") {
                    return Err(BrokerError::ResponseRejected(
                        "unsupported transfer coding".to_string(),
                    ));
                }
                transfer_chunked = true;
            }
            "content-encoding" => {
                return Err(BrokerError::ResponseRejected(
                    "compressed upstream responses are unsupported".to_string(),
                ))
            }
            "trailer" => {
                return Err(BrokerError::ResponseRejected(
                    "response trailers are unsupported".to_string(),
                ))
            }
            _ => {}
        }
    }
    if content_length.is_some() && transfer_chunked {
        return Err(BrokerError::ResponseRejected(
            "content length and transfer encoding cannot be combined".to_string(),
        ));
    }
    Ok(ResponseFraming {
        content_length,
        transfer_chunked,
    })
}

fn read_fixed_body(reader: &mut impl Read, length: usize, body_limit: usize) -> Result<Vec<u8>> {
    if length > body_limit {
        return Err(BrokerError::ResponseRejected(
            "response headers and decoded body exceed the signed combined byte limit".to_string(),
        ));
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    read_exact_response(reader, body.as_mut_slice())?;
    Ok(body.to_vec())
}

fn read_chunked_body(reader: &mut impl Read, body_limit: usize) -> Result<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::new());
    loop {
        let line = read_crlf_line(reader, MAX_CHUNK_LINE_BYTES)?;
        if line.is_empty()
            || line.contains(&b';')
            || line.len() > 16
            || !line.iter().all(u8::is_ascii_hexdigit)
        {
            return Err(BrokerError::ResponseRejected(
                "chunk size line is invalid".to_string(),
            ));
        }
        let text = std::str::from_utf8(line.as_slice())
            .map_err(|_| BrokerError::ResponseRejected("chunk size line is invalid".to_string()))?;
        let length = usize::from_str_radix(text, 16)
            .map_err(|_| BrokerError::ResponseRejected("chunk size overflows".to_string()))?;
        if length == 0 {
            let trailer_end = read_crlf_line(reader, MAX_RESPONSE_HEADER_LINE_BYTES)?;
            if !trailer_end.is_empty() {
                return Err(BrokerError::ResponseRejected(
                    "response trailers are unsupported".to_string(),
                ));
            }
            break;
        }
        let new_length = body.len().checked_add(length).ok_or_else(|| {
            BrokerError::ResponseRejected("decoded response size overflow".to_string())
        })?;
        if new_length > body_limit {
            return Err(BrokerError::ResponseRejected(
                "response headers and decoded body exceed the signed combined byte limit"
                    .to_string(),
            ));
        }
        let previous = body.len();
        body.resize(new_length, 0);
        read_exact_response(reader, &mut body[previous..])?;
        let mut terminator = [0_u8; 2];
        read_exact_response(reader, &mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(BrokerError::ResponseRejected(
                "chunk terminator is invalid".to_string(),
            ));
        }
    }
    Ok(body.to_vec())
}

fn read_crlf_line(reader: &mut impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let mut byte = [0_u8; 1];
        read_exact_response(reader, &mut byte)?;
        if byte[0] == b'\n' {
            if line.last() != Some(&b'\r') {
                return Err(BrokerError::ResponseRejected(
                    "HTTP line does not use CRLF".to_string(),
                ));
            }
            line.pop();
            if line.len() > maximum {
                return Err(BrokerError::ResponseRejected(
                    "HTTP response line exceeds its bound".to_string(),
                ));
            }
            return Ok(line);
        }
        line.push(byte[0]);
        if line.len() > maximum.saturating_add(1) {
            return Err(BrokerError::ResponseRejected(
                "HTTP response line exceeds its bound".to_string(),
            ));
        }
    }
}

fn read_exact_response(reader: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    reader
        .read_exact(buffer)
        .map_err(|_| BrokerError::Upstream("upstream response read failed".to_string()))
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use chio_test_support::prelude::*;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, TcpListener};
    use std::sync::mpsc;
    use std::thread;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::backend::SecretMaterial;
    use crate::generic_https::{DestinationResolver, GenericHttpsExecutor, NetworkPolicy};
    use crate::protocol::{
        BrokerDestination, BrokerRequest, CallerOptions, RedirectPolicy, RequestConstraints,
    };
    use crate::provider::{CredentialPlacement, GenericCredentialProvider};

    #[test]
    fn strict_parser_accepts_only_fixed_or_plain_chunked_bodies() {
        let fixed = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-test: one\r\n\r\nhello";
        let parsed = parse_http_response(&mut Cursor::new(fixed), "GET", 64).test_expect("fixed");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hello");
        assert_eq!(parsed.response_head_bytes, fixed.len() - parsed.body.len());

        let chunked = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n";
        let parsed =
            parse_http_response(&mut Cursor::new(chunked), "GET", 64).test_expect("chunked");
        assert_eq!(parsed.body, b"hello");
        assert_eq!(
            parsed.response_head_bytes,
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n".len()
        );

        for rejected in [
            b"HTTP/1.1 200 OK\r\ncontent-length: 1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n"
                .as_slice(),
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, chunked\r\n\r\n0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nx-one: value\r\n folded\r\ncontent-length: 0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\nbody".as_slice(),
        ] {
            assert!(parse_http_response(&mut Cursor::new(rejected), "GET", 128).is_err());
        }
    }

    #[test]
    fn strict_parser_applies_one_combined_header_and_decoded_body_budget() {
        let head = b"HTTP/1.1 200 OK\r\nx-budget: 12345678\r\ncontent-length: 4\r\n\r\n";
        let response = [head.as_slice(), b"body"].concat();
        assert!(parse_http_response(&mut Cursor::new(&response), "GET", head.len() + 4).is_ok());
        assert!(parse_http_response(&mut Cursor::new(&response), "GET", head.len() + 3).is_err());

        let chunked_head = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
        let chunked = [chunked_head.as_slice(), b"4\r\nbody\r\n0\r\n\r\n"].concat();
        assert!(
            parse_http_response(&mut Cursor::new(&chunked), "GET", chunked_head.len() + 4).is_ok()
        );
        assert!(
            parse_http_response(&mut Cursor::new(&chunked), "GET", chunked_head.len() + 3).is_err()
        );
    }

    #[test]
    fn one_response_head_overhead_byte_crosses_the_signed_limit() {
        let short = b"HTTP/1.1 204 OK\r\n\r\n";
        let long = b"HTTP/1.1 204  OK\r\n\r\n";
        assert!(parse_http_response(&mut Cursor::new(short), "GET", short.len()).is_ok());
        assert!(parse_http_response(&mut Cursor::new(long), "GET", short.len()).is_err());
    }

    #[test]
    fn informational_and_body_bearing_reset_content_statuses_fail_closed() {
        let informational = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert!(
            parse_http_response(&mut Cursor::new(informational), "GET", informational.len())
                .is_err()
        );
        let reset_with_body = b"HTTP/1.1 205 Reset Content\r\ncontent-length: 1\r\n\r\nx";
        assert!(parse_http_response(
            &mut Cursor::new(reset_with_body),
            "GET",
            reset_with_body.len()
        )
        .is_err());
    }

    struct StaticResolver(IpAddr);

    impl DestinationResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(vec![self.0])
        }
    }

    struct LocalTlsServer {
        address: SocketAddr,
        client_config: Arc<ClientConfig>,
        observed_request: mpsc::Receiver<Vec<u8>>,
        thread: thread::JoinHandle<()>,
    }

    enum ServerBehavior {
        Respond(Vec<u8>),
        Delay(Duration),
        Truncate(Vec<u8>),
    }

    fn local_tls_server(behavior: ServerBehavior) -> LocalTlsServer {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()]).test_expect("certificate");
        let certificate: CertificateDer<'static> = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
        let builder =
            ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .test_expect("server protocols");
        let mut server_config = builder
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .test_expect("server certificate");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let mut roots = RootCertStore::empty();
        roots.add(certificate).test_expect("test root");
        let builder =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .test_expect("client protocols");
        let mut client_config = builder.with_root_certificates(roots).with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).test_expect("listener");
        let address = listener.local_addr().test_expect("listener address");
        let (sender, receiver) = mpsc::channel();
        let server_config = Arc::new(server_config);
        let thread = thread::spawn(move || {
            let (socket, _) = listener.accept().test_expect("accept");
            let connection =
                ServerConnection::new(server_config).test_expect("server TLS connection");
            let mut stream = StreamOwned::new(connection, socket);
            let mut request = read_request_head(&mut stream).test_expect("request head");
            let mut request_body = [0_u8; 4];
            stream
                .read_exact(&mut request_body)
                .test_expect("request body");
            request.extend_from_slice(&request_body);
            sender.send(request).test_expect("observed request");
            match behavior {
                ServerBehavior::Respond(response) => {
                    stream.write_all(&response).test_expect("response");
                    stream.flush().test_expect("response flush");
                }
                ServerBehavior::Delay(duration) => thread::sleep(duration),
                ServerBehavior::Truncate(response) => {
                    stream
                        .write_all(&response)
                        .test_expect("truncated response");
                    stream.flush().test_expect("truncated response flush");
                }
            }
        });
        LocalTlsServer {
            address,
            client_config: Arc::new(client_config),
            observed_request: receiver,
            thread,
        }
    }

    fn read_request_head(reader: &mut impl Read) -> io::Result<Vec<u8>> {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while request.len() <= MAX_WIRE_BYTES {
            reader.read_exact(&mut byte)?;
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                return Ok(request);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "test request head exceeded bound",
        ))
    }

    fn request_and_constraints(port: u16, timeout_ms: u64) -> (BrokerRequest, RequestConstraints) {
        let request = BrokerRequest {
            destination: BrokerDestination::parse(
                &format!("https://localhost:{port}/v1"),
                "POST",
                false,
            )
            .test_expect("destination"),
            headers: Vec::new(),
            body: b"body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms,
                streaming: false,
                response_limit_bytes: 256,
            },
        };
        let constraints = RequestConstraints {
            allowed_caller_headers: Vec::new(),
            provider_owned_headers: vec!["authorization".to_string()],
            maximum_body_bytes: request.body.len() as u64,
            required_body_sha256: hex::encode(Sha256::digest(&request.body)),
            required_preview_sha256: None,
            redirect_policy: RedirectPolicy::Disabled,
            maximum_response_bytes: 256,
            streaming_allowed: false,
            maximum_timeout_ms: timeout_ms,
        };
        (request, constraints)
    }

    fn provider() -> GenericCredentialProvider {
        GenericCredentialProvider::new(
            "generic-bearer".to_string(),
            1,
            CredentialPlacement::BearerAuthorization,
        )
        .test_expect("provider")
    }

    fn local_executor(server: &LocalTlsServer) -> GenericHttpsExecutor {
        GenericHttpsExecutor::new(
            Arc::new(StaticResolver(server.address.ip())),
            Arc::new(RustlsPinnedHttpsTransport::with_tls_config(
                server.client_config.clone(),
            )),
            NetworkPolicy {
                allow_loopback_test: true,
                allow_exact_address: None,
            },
        )
    }

    #[test]
    fn local_tls_transport_pins_peer_verifies_original_name_and_injects_only_upstream() {
        let server = local_tls_server(ServerBehavior::Respond(
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok".to_vec(),
        ));
        let canary = b"direct-rustls-auth-canary-9813";
        let credential = SecretMaterial::new(canary.to_vec());
        let (request, constraints) = request_and_constraints(server.address.port(), 2_000);
        let executor = local_executor(&server);
        let prepared = executor
            .prepare(&provider(), &request, &constraints, &credential)
            .test_expect("prepare");
        let (_, _, body) = executor
            .dispatch(prepared, &constraints, &credential)
            .test_expect("dispatch");
        assert_eq!(body, b"ok");
        let observed = server
            .observed_request
            .recv_timeout(Duration::from_secs(1))
            .test_expect("observed request");
        assert!(observed
            .windows(canary.len())
            .any(|candidate| candidate == canary));
        server.thread.join().test_expect("server thread");
    }

    #[test]
    fn timeout_and_upstream_cancellation_diagnostics_redact_seeded_canaries() {
        let canary = b"direct-rustls-diagnostic-canary-7712";
        for behavior in [
            ServerBehavior::Delay(Duration::from_millis(750)),
            ServerBehavior::Truncate(
                b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\n\r\ndirect-rustls-diagnostic-canary-7712"
                    .to_vec(),
            ),
        ] {
            let server = local_tls_server(behavior);
            let credential = SecretMaterial::new(canary.to_vec());
            let (request, constraints) = request_and_constraints(server.address.port(), 250);
            let executor = local_executor(&server);
            let prepared = executor
                .prepare(&provider(), &request, &constraints, &credential)
                .test_expect("prepare");
            let error = executor
                .dispatch(prepared, &constraints, &credential)
                .test_expect_err("timeout or cancellation must fail closed");
            let diagnostic = format!(
                "{} {:?} {}",
                error,
                error,
                error.diagnostic_code()
            );
            assert!(!diagnostic.contains(std::str::from_utf8(canary).test_expect("canary UTF-8")));
            assert_eq!(error.diagnostic_code(), "upstream");
            let observed = server
                .observed_request
                .recv_timeout(Duration::from_secs(1))
                .test_expect("observed request");
            assert!(observed
                .windows(canary.len())
                .any(|candidate| candidate == canary));
            server.thread.join().test_expect("server thread");
        }
    }
}
