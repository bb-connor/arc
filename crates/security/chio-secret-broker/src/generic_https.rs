use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::backend::SecretMaterial;
use crate::proof::{body_digest, caller_header_digest, caller_option_digest, RequestProof};
use crate::protocol::{
    BrokerRequest, BrokerScheme, HeaderField, RequestConstraints, MAX_HEADER_COUNT,
};
use crate::provider::{rejects_forbidden_caller_header, PreparedProviderRequest, ProviderAdapter};
use crate::{BrokerError, Result};

const MAX_RESOLVED_ADDRESSES: usize = 16;
pub(super) const MAX_RESPONSE_HEAD_BYTES: usize = 16_384;

mod rustls_transport;

pub(crate) use rustls_transport::RustlsPinnedHttpsTransport;

pub(crate) trait DestinationResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>>;
}

pub(crate) struct PinnedHttpsRequest {
    scheme: BrokerScheme,
    original_hostname: String,
    pinned_address: IpAddr,
    port: u16,
    method: String,
    path_and_query: String,
    caller_headers: Vec<HeaderField>,
    secret_headers: Vec<crate::provider::SecretHeader>,
    body: Vec<u8>,
    timeout_ms: u64,
    response_limit_bytes: u64,
    redirects_allowed: bool,
}

impl PinnedHttpsRequest {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn original_hostname(&self) -> &str {
        &self.original_hostname
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn pinned_address(&self) -> IpAddr {
        self.pinned_address
    }

    #[cfg(test)]
    pub(crate) fn secret_headers(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.secret_headers
            .iter()
            .map(|header| (header.name(), header.value()))
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn redirects_allowed(&self) -> bool {
        self.redirects_allowed
    }
}

pub(crate) struct RawHttpsResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<HeaderField>,
    pub(crate) decoded_body_chunks: Vec<Vec<u8>>,
    /// Exact HTTP status line, header lines, and terminating CRLF bytes consumed on the wire.
    pub(crate) response_head_bytes: usize,
    pub(crate) connected_address: IpAddr,
    pub(crate) tls_server_name: String,
    pub(crate) redirected: bool,
}

impl Drop for RawHttpsResponse {
    fn drop(&mut self) {
        for header in &mut self.headers {
            header.value.zeroize();
        }
        for chunk in &mut self.decoded_body_chunks {
            chunk.zeroize();
        }
    }
}

pub(crate) trait PinnedHttpsTransport: Send + Sync {
    fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetworkPolicy {
    pub(crate) allow_loopback_test: bool,
    pub(crate) allow_exact_address: Option<IpAddr>,
}

impl NetworkPolicy {
    #[must_use]
    pub(crate) const fn production() -> Self {
        Self {
            allow_loopback_test: false,
            allow_exact_address: None,
        }
    }
}

/// Secret-bearing transport selection is fixed for production callers.
///
/// This example used to compile when arbitrary resolver and transport injection
/// was public. It must remain a compile failure so an external caller cannot
/// route credential-bearing requests through a transport of its choice.
///
/// ```compile_fail
/// use std::net::IpAddr;
/// use std::sync::Arc;
/// use chio_secret_broker::generic_https::{
///     DestinationResolver, GenericHttpsExecutor, NetworkPolicy, PinnedHttpsRequest,
///     PinnedHttpsTransport, RawHttpsResponse,
/// };
/// use chio_secret_broker::{BrokerError, Result};
///
/// struct AlternateResolver;
///
/// impl DestinationResolver for AlternateResolver {
///     fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
///         Ok(vec!["93.184.216.34".parse().expect("public address")])
///     }
/// }
///
/// struct AlternateTransport;
///
/// impl PinnedHttpsTransport for AlternateTransport {
///     fn dispatch(&self, _request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
///         Err(BrokerError::Upstream("alternate transport selected".to_string()))
///     }
/// }
///
/// let _executor = GenericHttpsExecutor::new(
///     Arc::new(AlternateResolver),
///     Arc::new(AlternateTransport),
///     NetworkPolicy::production(),
/// );
/// ```
pub struct GenericHttpsExecutor {
    resolver: Arc<dyn DestinationResolver>,
    transport: Arc<dyn PinnedHttpsTransport>,
    network_policy: NetworkPolicy,
}

impl GenericHttpsExecutor {
    /// Construct the only production executor, with system DNS, direct pinned
    /// rustls transport, and the production network policy.
    pub fn production() -> Result<Self> {
        Ok(Self {
            resolver: Arc::new(SystemDestinationResolver),
            transport: Arc::new(RustlsPinnedHttpsTransport::new()?),
            network_policy: NetworkPolicy::production(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        resolver: Arc<dyn DestinationResolver>,
        transport: Arc<dyn PinnedHttpsTransport>,
        network_policy: NetworkPolicy,
    ) -> Self {
        Self {
            resolver,
            transport,
            network_policy,
        }
    }

    pub(crate) fn preflight(
        &self,
        request: &BrokerRequest,
        constraints: &RequestConstraints,
        proof: &RequestProof,
    ) -> Result<()> {
        validate_request_before_secret_use(request, constraints)?;
        if proof.body.body_sha256 != body_digest(&request.body)
            || proof.body.caller_headers_sha256 != caller_header_digest(&request.headers)?
            || proof.body.caller_options_sha256 != caller_option_digest(&request.options)?
        {
            return Err(BrokerError::AuthorizationDenied(
                "request changed after proof verification".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        provider: &dyn ProviderAdapter,
        request: &BrokerRequest,
        constraints: &RequestConstraints,
        credential: &SecretMaterial,
    ) -> Result<PreparedProviderRequest> {
        validate_request_before_secret_use(request, constraints)?;
        provider.prepare(request, constraints, credential)
    }

    pub(crate) fn dispatch(
        &self,
        prepared: PreparedProviderRequest,
        constraints: &RequestConstraints,
        credential: &SecretMaterial,
    ) -> Result<(u16, Vec<HeaderField>, Vec<u8>)> {
        let destination = &prepared.caller.destination;
        let literal_address = destination.normalized_host.parse::<IpAddr>().ok();
        if literal_address.is_some() && literal_address != self.network_policy.allow_exact_address {
            return Err(BrokerError::AuthorizationDenied(
                "IP-literal destinations require a matching exact exception".to_string(),
            ));
        }
        let resolved = if let Some(address) = literal_address {
            vec![address]
        } else {
            self.resolver
                .resolve(&destination.normalized_host, destination.explicit_port)
                .map_err(BrokerError::redacted)?
        };
        let pinned = validate_resolution(&resolved, self.network_policy)?;
        let outbound = PinnedHttpsRequest {
            scheme: destination.scheme,
            original_hostname: destination.normalized_host.clone(),
            pinned_address: pinned,
            port: destination.explicit_port,
            method: destination.method.clone(),
            path_and_query: destination.exact_path_and_query.clone(),
            caller_headers: prepared.caller.headers.clone(),
            secret_headers: prepared.secret_headers,
            body: prepared.caller.body.clone(),
            timeout_ms: prepared.caller.options.timeout_ms,
            response_limit_bytes: prepared.caller.options.response_limit_bytes,
            redirects_allowed: false,
        };
        let mut response = self
            .transport
            .dispatch(outbound)
            .map_err(BrokerError::redacted)?;
        if response.connected_address != pinned
            || response.tls_server_name != destination.normalized_host
        {
            return Err(BrokerError::Upstream(
                "transport did not preserve DNS pinning and original-host TLS".to_string(),
            ));
        }
        if response.redirected || (300..400).contains(&response.status) {
            return Err(BrokerError::ResponseRejected(
                "redirect responses are forbidden".to_string(),
            ));
        }
        if !(200..=599).contains(&response.status) {
            return Err(BrokerError::ResponseRejected(
                "upstream returned an informational or invalid HTTP status".to_string(),
            ));
        }
        let framing =
            validate_response_framing(&response.headers, &destination.method, response.status)?;
        let limit = usize::try_from(
            constraints
                .maximum_response_bytes
                .min(prepared.caller.options.response_limit_bytes),
        )
        .map_err(|_| BrokerError::InvalidRequest("response limit exceeds usize".to_string()))?;
        let minimum_head_bytes = minimum_response_head_bytes(&response.headers)?;
        if response.response_head_bytes < minimum_head_bytes
            || response.response_head_bytes > MAX_RESPONSE_HEAD_BYTES
            || response.response_head_bytes > limit
        {
            return Err(BrokerError::ResponseRejected(
                "response head violates the signed combined byte limit".to_string(),
            ));
        }
        let body_limit = limit - response.response_head_bytes;
        let mut decoded_body_bytes = 0_usize;
        for chunk in &response.decoded_body_chunks {
            decoded_body_bytes = decoded_body_bytes.checked_add(chunk.len()).ok_or_else(|| {
                BrokerError::ResponseRejected("response size overflow".to_string())
            })?;
            if decoded_body_bytes > body_limit {
                return Err(BrokerError::ResponseRejected(
                    "response headers and decoded body exceed the signed combined byte limit"
                        .to_string(),
                ));
            }
        }
        let mut body = Vec::with_capacity(decoded_body_bytes);
        for mut chunk in std::mem::take(&mut response.decoded_body_chunks) {
            body.extend_from_slice(&chunk);
            chunk.zeroize();
        }
        match framing {
            ResponseFraming::Fixed(expected) if body.len() != expected => {
                body.zeroize();
                return Err(BrokerError::ResponseRejected(
                    "decoded response length does not match content length".to_string(),
                ));
            }
            ResponseFraming::BodyFree if !body.is_empty() => {
                body.zeroize();
                return Err(BrokerError::ResponseRejected(
                    "body-free response contained decoded body bytes".to_string(),
                ));
            }
            ResponseFraming::Fixed(_) | ResponseFraming::Chunked | ResponseFraming::BodyFree => {}
        }
        let mut headers =
            match sanitize_response_headers(std::mem::take(&mut response.headers), credential) {
                Ok(headers) => headers,
                Err(error) => {
                    body.zeroize();
                    return Err(error);
                }
            };
        if contains_secret(&body, credential.as_bytes()) {
            body.zeroize();
            zeroize_header_values(&mut headers);
            return Err(BrokerError::ResponseRejected(
                "response body contains credential material".to_string(),
            ));
        }
        Ok((response.status, headers, body))
    }
}

#[derive(Debug, Default)]
pub(crate) struct SystemDestinationResolver;

impl DestinationResolver for SystemDestinationResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|_| BrokerError::Upstream("destination resolution failed".to_string()))?
            .map(|address| address.ip())
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect::<Vec<_>>();
        if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(BrokerError::AuthorizationDenied(
                "DNS resolution is empty or exceeds the address limit".to_string(),
            ));
        }
        Ok(addresses)
    }
}

fn validate_request_before_secret_use(
    request: &BrokerRequest,
    constraints: &RequestConstraints,
) -> Result<()> {
    request.validate_bounds()?;
    constraints.validate()?;
    let body_length = u64::try_from(request.body.len())
        .map_err(|_| BrokerError::InvalidRequest("request body length overflow".to_string()))?;
    if body_length > constraints.maximum_body_bytes
        || body_digest(&request.body) != constraints.required_body_sha256
        || request.options.timeout_ms > constraints.maximum_timeout_ms
        || request.options.response_limit_bytes > constraints.maximum_response_bytes
        || (request.options.streaming && !constraints.streaming_allowed)
        || request.approved_preview_sha256 != constraints.required_preview_sha256
    {
        return Err(BrokerError::AuthorizationDenied(
            "request body, preview, or caller options violate signed constraints".to_string(),
        ));
    }
    let allowed: BTreeSet<&str> = constraints
        .allowed_caller_headers
        .iter()
        .map(String::as_str)
        .collect();
    for header in &request.headers {
        if rejects_forbidden_caller_header(header)
            || !allowed.contains(header.name.as_str())
            || constraints
                .provider_owned_headers
                .binary_search(&header.name)
                .is_ok()
        {
            return Err(BrokerError::AuthorizationDenied(
                "caller supplied a forbidden or unlisted header".to_string(),
            ));
        }
    }
    let _ = caller_header_digest(&request.headers)?;
    let _ = caller_option_digest(&request.options)?;
    Ok(())
}

fn validate_resolution(addresses: &[IpAddr], policy: NetworkPolicy) -> Result<IpAddr> {
    if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(BrokerError::AuthorizationDenied(
            "DNS resolution is empty or oversized".to_string(),
        ));
    }
    let mut unique = BTreeSet::new();
    for address in addresses {
        if !unique.insert(*address) {
            continue;
        }
        if Some(*address) == policy.allow_exact_address {
            continue;
        }
        if is_restricted(*address, policy.allow_loopback_test) {
            return Err(BrokerError::AuthorizationDenied(
                "DNS resolved to a restricted address".to_string(),
            ));
        }
    }
    addresses
        .first()
        .copied()
        .ok_or_else(|| BrokerError::AuthorizationDenied("DNS resolution is empty".to_string()))
}

#[must_use]
pub fn is_restricted(address: IpAddr, allow_loopback_test: bool) -> bool {
    match address {
        IpAddr::V4(address) => restricted_v4(address, allow_loopback_test),
        IpAddr::V6(address) => restricted_v6(address, allow_loopback_test),
    }
}

fn restricted_v4(address: Ipv4Addr, allow_loopback_test: bool) -> bool {
    let octets = address.octets();
    (!allow_loopback_test && address.is_loopback())
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || address.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 224
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && octets[1] == 18)
        || (octets[0] == 198 && octets[1] == 19)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn restricted_v6(address: Ipv6Addr, allow_loopback_test: bool) -> bool {
    if address.is_loopback() {
        return !allow_loopback_test;
    }
    let segments = address.segments();
    let is_global_unicast_prefix = (segments[0] & 0xe000) == 0x2000;
    let is_teredo = segments[0] == 0x2001 && segments[1] == 0;
    let is_orchid =
        segments[0] == 0x2001 && (segments[1] == 0x0010 || (segments[1] & 0xfff0) == 0x0020);
    address.is_unspecified()
        || address.is_multicast()
        || !is_global_unicast_prefix
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || is_teredo
        || is_orchid
        || segments[0] == 0x2002
        || address
            .to_ipv4_mapped()
            .is_some_and(|mapped| restricted_v4(mapped, allow_loopback_test))
}

fn sanitize_response_headers(
    mut headers: Vec<HeaderField>,
    credential: &SecretMaterial,
) -> Result<Vec<HeaderField>> {
    if headers.len() > MAX_HEADER_COUNT {
        zeroize_header_values(&mut headers);
        return Err(BrokerError::ResponseRejected(
            "upstream response has too many headers".to_string(),
        ));
    }
    if headers
        .iter()
        .any(|header| contains_secret(&header.value, credential.as_bytes()))
    {
        zeroize_header_values(&mut headers);
        return Err(BrokerError::ResponseRejected(
            "response header contains credential material".to_string(),
        ));
    }
    let mut sanitized = Vec::new();
    let mut invalid_header = false;
    for original in &mut headers {
        let normalized = HeaderField::normalized(&original.name, &original.value);
        original.value.zeroize();
        let mut header = match normalized {
            Ok(header) => header,
            Err(_) => {
                invalid_header = true;
                break;
            }
        };
        if matches!(
            header.name.as_str(),
            "set-cookie" | "www-authenticate" | "proxy-authenticate" | "authorization"
        ) {
            header.value.zeroize();
            continue;
        }
        sanitized.push(header);
    }
    if invalid_header {
        zeroize_header_values(&mut headers);
        zeroize_header_values(&mut sanitized);
        return Err(BrokerError::ResponseRejected(
            "upstream response header is invalid".to_string(),
        ));
    }
    Ok(sanitized)
}

fn zeroize_header_values(headers: &mut [HeaderField]) {
    for header in headers {
        header.value.zeroize();
    }
}

fn minimum_response_head_bytes(headers: &[HeaderField]) -> Result<usize> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(BrokerError::ResponseRejected(
            "upstream response has too many headers".to_string(),
        ));
    }
    // "HTTP/1.1 " + three status digits + CRLF + final CRLF.
    headers.iter().try_fold(16_usize, |total, header| {
        let mut normalized =
            HeaderField::normalized(&header.name, &header.value).map_err(|_| {
                BrokerError::ResponseRejected("upstream response header is invalid".to_string())
            })?;
        let matches = normalized == *header;
        normalized.value.zeroize();
        if !matches {
            return Err(BrokerError::ResponseRejected(
                "upstream response header is not normalized".to_string(),
            ));
        }
        total
            .checked_add(header.name.len())
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_add(header.value.len()))
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| {
                BrokerError::ResponseRejected("response header size overflow".to_string())
            })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseFraming {
    Fixed(usize),
    Chunked,
    BodyFree,
}

fn validate_response_framing(
    headers: &[HeaderField],
    request_method: &str,
    status: u16,
) -> Result<ResponseFraming> {
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
                let text = std::str::from_utf8(&header.value).map_err(|_| {
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
                if transfer_chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(BrokerError::ResponseRejected(
                        "unsupported transfer coding".to_string(),
                    ));
                }
                transfer_chunked = true;
            }
            "content-encoding" => {
                return Err(BrokerError::ResponseRejected(
                    "compressed upstream responses are unsupported".to_string(),
                ));
            }
            "trailer" => {
                return Err(BrokerError::ResponseRejected(
                    "response trailers are unsupported".to_string(),
                ));
            }
            _ => {}
        }
    }
    if content_length.is_some() && transfer_chunked {
        return Err(BrokerError::ResponseRejected(
            "content length and transfer encoding cannot be combined".to_string(),
        ));
    }
    let body_forbidden = status == 204 || status == 205;
    if request_method == "HEAD" || body_forbidden {
        if transfer_chunked || (body_forbidden && content_length.is_some_and(|length| length != 0))
        {
            return Err(BrokerError::ResponseRejected(
                "body-free response cannot declare a body".to_string(),
            ));
        }
        return Ok(ResponseFraming::BodyFree);
    }
    match (content_length, transfer_chunked) {
        (Some(length), false) => Ok(ResponseFraming::Fixed(length)),
        (None, true) => Ok(ResponseFraming::Chunked),
        (None, false) => Err(BrokerError::ResponseRejected(
            "upstream response has no supported body framing".to_string(),
        )),
        (Some(_), true) => Err(BrokerError::ResponseRejected(
            "content length and transfer encoding cannot be combined".to_string(),
        )),
    }
}

fn contains_secret(haystack: &[u8], secret: &[u8]) -> bool {
    !secret.is_empty()
        && haystack
            .windows(secret.len())
            .any(|candidate| candidate == secret)
}

#[must_use]
pub(crate) fn response_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use crate::protocol::{BrokerDestination, CallerOptions, RedirectPolicy};
    use crate::provider::{CredentialPlacement, GenericCredentialProvider};

    use super::*;

    struct StaticResolver(Vec<IpAddr>);

    impl DestinationResolver for StaticResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    enum ResponseMode {
        Valid,
        Redirect,
        WrongAddress,
        WrongTlsName,
        Oversized,
        Canary,
        Timeout,
        UnderreportedHead,
    }

    struct StaticTransport(ResponseMode);

    impl PinnedHttpsTransport for StaticTransport {
        fn dispatch(&self, request: PinnedHttpsRequest) -> Result<RawHttpsResponse> {
            assert!(!request.redirects_allowed());
            if matches!(self.0, ResponseMode::Timeout) {
                return Err(BrokerError::Upstream("injected timeout".to_string()));
            }
            let connected_address = if matches!(self.0, ResponseMode::WrongAddress) {
                "1.1.1.1".parse().expect("address")
            } else {
                request.pinned_address()
            };
            let tls_server_name = if matches!(self.0, ResponseMode::WrongTlsName) {
                "attacker.example".to_string()
            } else {
                request.original_hostname().to_string()
            };
            let decoded_body_chunks = if matches!(self.0, ResponseMode::Oversized) {
                vec![vec![b'x'; 129]]
            } else if matches!(self.0, ResponseMode::Canary) {
                vec![b"unique-network-canary".to_vec()]
            } else {
                vec![b"response".to_vec()]
            };
            let status = if matches!(self.0, ResponseMode::Redirect) {
                302
            } else {
                200
            };
            let (headers, mut response_head_bytes) = if status == 302 {
                (Vec::new(), b"HTTP/1.1 302 Found\r\n\r\n".len())
            } else {
                let body_length = decoded_body_chunks.iter().map(Vec::len).sum::<usize>();
                let value = body_length.to_string();
                let header = HeaderField::normalized("content-length", value.as_bytes())
                    .expect("content length");
                let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {value}\r\n\r\n");
                (vec![header], head.len())
            };
            if matches!(self.0, ResponseMode::UnderreportedHead) {
                response_head_bytes = 16;
            }
            Ok(RawHttpsResponse {
                status,
                headers,
                decoded_body_chunks,
                response_head_bytes,
                connected_address,
                tls_server_name,
                redirected: false,
            })
        }
    }

    fn request_and_constraints() -> (BrokerRequest, RequestConstraints) {
        let request = BrokerRequest {
            destination: BrokerDestination::parse("https://example.com/v1", "POST", false)
                .expect("destination"),
            headers: Vec::new(),
            body: b"body".to_vec(),
            approved_preview_sha256: None,
            options: CallerOptions {
                timeout_ms: 100,
                streaming: false,
                response_limit_bytes: 128,
            },
        };
        let constraints = RequestConstraints {
            allowed_caller_headers: Vec::new(),
            provider_owned_headers: vec!["authorization".to_string()],
            maximum_body_bytes: 4,
            required_body_sha256: body_digest(&request.body),
            required_preview_sha256: None,
            redirect_policy: RedirectPolicy::Disabled,
            maximum_response_bytes: 128,
            streaming_allowed: false,
            maximum_timeout_ms: 100,
        };
        (request, constraints)
    }

    fn executor(mode: ResponseMode, addresses: Vec<IpAddr>) -> GenericHttpsExecutor {
        GenericHttpsExecutor::new(
            Arc::new(StaticResolver(addresses)),
            Arc::new(StaticTransport(mode)),
            NetworkPolicy::production(),
        )
    }

    fn provider() -> GenericCredentialProvider {
        GenericCredentialProvider::new(
            "generic-bearer".to_string(),
            1,
            CredentialPlacement::BearerAuthorization,
        )
        .expect("provider")
    }

    #[test]
    fn restricted_ranges_cover_ipv4_ipv6_and_mapped_forms() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2001::1",
            "2001:10::1",
            "2002::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                is_restricted(address.parse().expect("IP"), false),
                "{address}"
            );
        }
        assert!(!is_restricted("93.184.216.34".parse().expect("IP"), false));
        assert!(!is_restricted(
            "2606:4700:4700::1111".parse().expect("IP"),
            false
        ));
    }

    #[test]
    fn forbidden_headers_provider_collisions_body_preview_and_options_deny_before_secret_use() {
        let (request, constraints) = request_and_constraints();
        let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
        let executor = executor(
            ResponseMode::Valid,
            vec!["93.184.216.34".parse().expect("address")],
        );

        let mut forbidden = request.clone();
        forbidden.headers =
            vec![HeaderField::normalized("Authorization", b"caller").expect("forbidden header")];
        assert!(executor
            .prepare(&provider(), &forbidden, &constraints, &credential)
            .is_err());

        let mut body_changed = request.clone();
        body_changed.body.push(0);
        assert!(executor
            .prepare(&provider(), &body_changed, &constraints, &credential)
            .is_err());

        let mut option_changed = request.clone();
        option_changed.options.streaming = true;
        assert!(executor
            .prepare(&provider(), &option_changed, &constraints, &credential)
            .is_err());

        let mut collision = constraints;
        collision.provider_owned_headers = vec!["x-api-key".to_string()];
        assert!(executor
            .prepare(&provider(), &request, &collision, &credential)
            .is_err());
    }

    #[test]
    fn dns_rebinding_tls_redirect_size_timeout_and_canary_responses_fail_closed() {
        let public = "93.184.216.34".parse().expect("address");
        for mode in [
            ResponseMode::Redirect,
            ResponseMode::WrongAddress,
            ResponseMode::WrongTlsName,
            ResponseMode::Oversized,
            ResponseMode::Canary,
            ResponseMode::Timeout,
            ResponseMode::UnderreportedHead,
        ] {
            let (request, constraints) = request_and_constraints();
            let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
            let executor = executor(mode, vec![public]);
            let prepared = executor
                .prepare(&provider(), &request, &constraints, &credential)
                .expect("prepare");
            assert!(executor
                .dispatch(prepared, &constraints, &credential)
                .is_err());
        }

        let (request, constraints) = request_and_constraints();
        let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
        let restricted = executor(
            ResponseMode::Valid,
            vec!["127.0.0.1".parse().expect("address")],
        );
        let prepared = restricted
            .prepare(&provider(), &request, &constraints, &credential)
            .expect("prepare");
        assert!(restricted
            .dispatch(prepared, &constraints, &credential)
            .is_err());
    }

    #[test]
    fn ip_literal_requires_the_matching_exact_exception() {
        let (mut request, constraints) = request_and_constraints();
        request.destination = BrokerDestination::parse("https://93.184.216.34/v1", "POST", true)
            .expect("IP destination");
        let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
        let mismatched = GenericHttpsExecutor::new(
            Arc::new(StaticResolver(Vec::new())),
            Arc::new(StaticTransport(ResponseMode::Valid)),
            NetworkPolicy {
                allow_loopback_test: false,
                allow_exact_address: Some("1.1.1.1".parse().expect("address")),
            },
        );
        let prepared = mismatched
            .prepare(&provider(), &request, &constraints, &credential)
            .expect("prepare");
        assert!(mismatched
            .dispatch(prepared, &constraints, &credential)
            .is_err());

        let matching = GenericHttpsExecutor::new(
            Arc::new(StaticResolver(Vec::new())),
            Arc::new(StaticTransport(ResponseMode::Valid)),
            NetworkPolicy {
                allow_loopback_test: false,
                allow_exact_address: Some("93.184.216.34".parse().expect("address")),
            },
        );
        let prepared = matching
            .prepare(&provider(), &request, &constraints, &credential)
            .expect("prepare");
        matching
            .dispatch(prepared, &constraints, &credential)
            .expect("matching IP exception");
    }

    #[test]
    fn response_header_normalization_cannot_bypass_secret_header_stripping() {
        let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
        let stripped = sanitize_response_headers(
            vec![HeaderField {
                name: "Set-Cookie".to_string(),
                value: b"session=opaque".to_vec(),
            }],
            &credential,
        )
        .expect("sanitize");
        assert!(stripped.is_empty());

        assert!(sanitize_response_headers(
            vec![HeaderField {
                name: "x-response".to_string(),
                value: b"value\r\ninjected: true".to_vec(),
            }],
            &credential,
        )
        .is_err());
    }

    #[test]
    fn executor_counts_response_head_overhead_in_the_signed_combined_budget() {
        let public = "93.184.216.34".parse().expect("address");
        let credential = SecretMaterial::new(b"unique-network-canary".to_vec());
        let (mut request, mut constraints) = request_and_constraints();
        let response_head_bytes = b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\n".len() as u64;
        let response_body_bytes = b"response".len() as u64;
        request.options.response_limit_bytes = response_head_bytes + response_body_bytes;
        constraints.maximum_response_bytes = request.options.response_limit_bytes;
        let allowed = executor(ResponseMode::Valid, vec![public]);
        let prepared = allowed
            .prepare(&provider(), &request, &constraints, &credential)
            .expect("prepare");
        assert!(allowed
            .dispatch(prepared, &constraints, &credential)
            .is_ok());

        request.options.response_limit_bytes -= 1;
        constraints.maximum_response_bytes = request.options.response_limit_bytes;
        let denied = executor(ResponseMode::Valid, vec![public]);
        let prepared = denied
            .prepare(&provider(), &request, &constraints, &credential)
            .expect("prepare");
        assert!(denied
            .dispatch(prepared, &constraints, &credential)
            .is_err());
    }
}
