//! Typed HTTP egress contracts for substrate adapters.
//!
//! Kernel, guard, and adapter code paths that initiate outbound HTTP must
//! declare one of these contracts before a target URL is accepted. Missing or
//! malformed contract state fails closed.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// Typed egress policy that must be declared before substrate HTTP egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEgressContract {
    /// Tenant-scoped namespace used by callers to bind egress receipts and
    /// deployment policy to one authority domain.
    pub tenant_egress_namespace: String,
    /// Lowercase URL schemes allowed by this contract, for example `https`.
    #[serde(default)]
    pub allowed_schemes: BTreeSet<String>,
    /// Exact normalized URL authorities allowed by this contract.
    ///
    /// Domain authorities are lowercase. IPv6 authorities use brackets, for
    /// example `[2001:db8::10]:443`.
    #[serde(default)]
    pub allowed_authority_set: BTreeSet<String>,
    /// Reject loopback address literals and localhost names even if an
    /// authority entry was configured.
    pub deny_loopback: bool,
    /// Reject IPv4 and IPv6 link-local address literals.
    pub deny_link_local: bool,
    /// Reject IPv6 unique-local address literals.
    pub deny_ipv6_ula: bool,
    /// Maximum redirect hop count accepted for a request chain.
    pub max_redirect_chain: u8,
    /// Maximum response bytes accepted before the substrate must abort.
    pub max_response_bytes: u64,
}

/// A target URL that survived [`HttpEgressContract`] enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHttpEgressTarget {
    pub tenant_egress_namespace: String,
    pub scheme: String,
    pub authority: String,
}

/// Fail-closed reasons returned by HTTP egress contract enforcement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpEgressError {
    #[error("outbound HTTP egress requires a declared HttpEgressContract")]
    MissingContract,
    #[error("invalid HttpEgressContract: {0}")]
    InvalidContract(String),
    #[error("invalid egress URL: {0}")]
    InvalidUrl(String),
    #[error("egress URL is missing an authority")]
    MissingAuthority,
    #[error("egress URL must not include userinfo")]
    UserinfoDenied,
    #[error("scheme {scheme:?} is not allowed by the HttpEgressContract")]
    SchemeDenied { scheme: String },
    #[error("authority {authority:?} is not allowed by the HttpEgressContract")]
    AuthorityDenied { authority: String },
    #[error("loopback egress target denied: {host}")]
    LoopbackDenied { host: String },
    #[error("link-local egress target denied: {host}")]
    LinkLocalDenied { host: String },
    #[error("IPv6 unique-local egress target denied: {host}")]
    Ipv6UlaDenied { host: String },
    #[error("private network egress target denied: {host}")]
    PrivateNetworkDenied { host: String },
    #[error("failed to resolve egress target {host}: {details}")]
    DnsResolutionFailed { host: String, details: String },
    #[error("redirect chain length {observed} exceeds maximum {max}")]
    RedirectLimitExceeded { observed: u8, max: u8 },
    #[error("response size {observed} exceeds maximum {max}")]
    ResponseTooLarge { observed: u64, max: u64 },
}

impl HttpEgressContract {
    /// Enforce a required contract. `None` is a fail-closed denial.
    pub fn enforce_required(
        contract: Option<&Self>,
        target_url: &str,
        redirect_chain_len: u8,
        observed_response_bytes: Option<u64>,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let contract = contract.ok_or(HttpEgressError::MissingContract)?;
        contract.enforce_attempt(target_url, redirect_chain_len, observed_response_bytes)
    }

    /// Enforce target, redirect, and optional response-size bounds.
    pub fn enforce_attempt(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
        observed_response_bytes: Option<u64>,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        if let Some(observed) = observed_response_bytes {
            self.enforce_response_bytes(observed)?;
        }
        Ok(target)
    }

    /// Enforce target URL and redirect hop constraints.
    pub fn enforce_url(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.validate()?;
        if redirect_chain_len > self.max_redirect_chain {
            return Err(HttpEgressError::RedirectLimitExceeded {
                observed: redirect_chain_len,
                max: self.max_redirect_chain,
            });
        }

        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpEgressError::UserinfoDenied);
        }

        let scheme = url.scheme().to_ascii_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(HttpEgressError::SchemeDenied { scheme });
        }

        let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
        self.enforce_host_class(&host)?;

        let authority = normalized_url_authority(&url)?;
        if !self.authority_is_allowed(&url, &authority)? {
            return Err(HttpEgressError::AuthorityDenied { authority });
        }

        Ok(ValidatedHttpEgressTarget {
            tenant_egress_namespace: self.tenant_egress_namespace.trim().to_string(),
            scheme,
            authority,
        })
    }

    /// Enforce target URL, redirect hop constraints, and DNS post-resolution
    /// address-class denials for domain targets.
    pub fn enforce_url_with_dns(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        self.enforce_domain_resolution(&url)?;
        Ok(target)
    }

    /// Enforce the response-byte ceiling after headers or streaming counters
    /// expose the observed size.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        self.validate()?;
        if observed > self.max_response_bytes {
            return Err(HttpEgressError::ResponseTooLarge {
                observed,
                max: self.max_response_bytes,
            });
        }
        Ok(())
    }

    /// Validate the contract shape before use.
    pub fn validate(&self) -> Result<(), HttpEgressError> {
        if self.tenant_egress_namespace.trim().is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "tenant_egress_namespace must be non-empty".to_string(),
            ));
        }
        if self.allowed_schemes.is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "allowed_schemes must be non-empty".to_string(),
            ));
        }
        if self.allowed_authority_set.is_empty() {
            return Err(HttpEgressError::InvalidContract(
                "allowed_authority_set must be non-empty".to_string(),
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(HttpEgressError::InvalidContract(
                "max_response_bytes must be greater than zero".to_string(),
            ));
        }
        for scheme in &self.allowed_schemes {
            validate_scheme_token(scheme)?;
        }
        for authority in &self.allowed_authority_set {
            validate_authority_token(authority)?;
        }
        Ok(())
    }

    fn enforce_host_class(&self, host: &Host<&str>) -> Result<(), HttpEgressError> {
        match host {
            Host::Domain(domain) => {
                let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
                if self.deny_loopback
                    && matches!(normalized.as_str(), "localhost" | "localhost.localdomain")
                {
                    return Err(HttpEgressError::LoopbackDenied { host: normalized });
                }
            }
            Host::Ipv4(address) => self.enforce_ipv4_class(*address)?,
            Host::Ipv6(address) => self.enforce_ipv6_class(*address)?,
        }
        Ok(())
    }

    fn enforce_ipv4_class(&self, address: Ipv4Addr) -> Result<(), HttpEgressError> {
        if self.deny_loopback && address.is_loopback() {
            return Err(HttpEgressError::LoopbackDenied {
                host: address.to_string(),
            });
        }
        if self.deny_link_local && address.is_link_local() {
            return Err(HttpEgressError::LinkLocalDenied {
                host: address.to_string(),
            });
        }
        Ok(())
    }

    fn enforce_ipv6_class(&self, address: Ipv6Addr) -> Result<(), HttpEgressError> {
        if let Some(mapped) = address.to_ipv4_mapped() {
            return self.enforce_ipv4_class(mapped);
        }
        if self.deny_loopback && address.is_loopback() {
            return Err(HttpEgressError::LoopbackDenied {
                host: address.to_string(),
            });
        }
        if self.deny_link_local && is_ipv6_unicast_link_local(&address) {
            return Err(HttpEgressError::LinkLocalDenied {
                host: address.to_string(),
            });
        }
        if self.deny_ipv6_ula && is_ipv6_unique_local(&address) {
            return Err(HttpEgressError::Ipv6UlaDenied {
                host: address.to_string(),
            });
        }
        Ok(())
    }

    /// Enforce address-class denials after a domain has resolved to an IP.
    pub fn enforce_resolved_ip(&self, host: &str, address: IpAddr) -> Result<(), HttpEgressError> {
        match address {
            IpAddr::V4(address) => {
                self.enforce_ipv4_class(address)?;
                if address.is_private() {
                    return Err(HttpEgressError::PrivateNetworkDenied {
                        host: format!("{host} resolved to {address}"),
                    });
                }
            }
            IpAddr::V6(address) => {
                self.enforce_ipv6_class(address)?;
                if is_ipv6_unique_local(&address) {
                    return Err(HttpEgressError::PrivateNetworkDenied {
                        host: format!("{host} resolved to {address}"),
                    });
                }
            }
        }
        Ok(())
    }

    fn enforce_domain_resolution(&self, url: &Url) -> Result<(), HttpEgressError> {
        let Some(Host::Domain(domain)) = url.host() else {
            return Ok(());
        };
        let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
        if self.deny_loopback
            && matches!(normalized.as_str(), "localhost" | "localhost.localdomain")
        {
            return Err(HttpEgressError::LoopbackDenied { host: normalized });
        }
        let port = url.port_or_known_default().ok_or_else(|| {
            HttpEgressError::InvalidUrl(format!(
                "cannot resolve domain target `{normalized}` without a known port"
            ))
        })?;
        let resolved = (normalized.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| HttpEgressError::DnsResolutionFailed {
                host: normalized.clone(),
                details: error.to_string(),
            })?;
        let mut saw_address = false;
        for socket_addr in resolved {
            saw_address = true;
            self.enforce_resolved_ip(&normalized, socket_addr.ip())?;
        }
        if !saw_address {
            return Err(HttpEgressError::DnsResolutionFailed {
                host: normalized,
                details: "no addresses returned".to_string(),
            });
        }
        Ok(())
    }

    fn authority_is_allowed(&self, url: &Url, authority: &str) -> Result<bool, HttpEgressError> {
        if self.allowed_authority_set.contains(authority) {
            return Ok(true);
        }
        if let Some(default_port) = url.port_or_known_default() {
            let default_port_authority = format!("{authority}:{default_port}");
            return Ok(self.allowed_authority_set.contains(&default_port_authority));
        }
        Ok(false)
    }
}

#[cfg(all(test, feature = "reqwest-egress"))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod reqwest_egress_tests {
    use super::reqwest_helper::{client_builder_with_contract, send_with_contract};
    use super::{HttpEgressContract, HttpEgressError};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    fn authority(addr: SocketAddr) -> String {
        format!("{}:{}", addr.ip(), addr.port())
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    fn spawn_single_response_server<F>(
        response_for_request: F,
    ) -> (SocketAddr, Receiver<String>, JoinHandle<()>)
    where
        F: FnOnce(String) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("read local addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let request = read_http_request(&mut stream);
            tx.send(request.clone()).expect("send captured request");
            let response = response_for_request(request);
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });
        (addr, rx, handle)
    }

    #[tokio::test]
    async fn send_with_contract_validates_redirect_before_following() {
        let denied_target = "http://127.0.0.1:9/final";
        let (start_addr, _start_rx, start_handle) = spawn_single_response_server({
            let denied_target = denied_target.to_string();
            move |_| {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {denied_target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });
        let contract = HttpEgressContract::permissive_for_tests(&authority(start_addr));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/start", authority(start_addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("redirect target should be denied before follow");
        assert!(matches!(error, HttpEgressError::AuthorityDenied { .. }));
        start_handle.join().expect("join start server");
    }

    #[tokio::test]
    async fn send_with_contract_strips_sensitive_headers_on_cross_origin_redirect() {
        let (final_addr, final_rx, final_handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_string()
        });
        let final_url = format!("http://{}/final", authority(final_addr));
        let (start_addr, _start_rx, start_handle) = spawn_single_response_server({
            let final_url = final_url.clone();
            move |_| {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {final_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            }
        });

        let mut contract = HttpEgressContract::permissive_for_tests(&authority(start_addr));
        contract.allowed_authority_set.insert(authority(final_addr));
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/start", authority(start_addr)))
            .header(reqwest::header::AUTHORIZATION, "Bearer secret")
            .header(reqwest::header::COOKIE, "sid=secret")
            .build()
            .expect("build request");

        let response = send_with_contract(&contract, &client, request)
            .await
            .expect("follow redirect");
        assert_eq!(response.body(), b"ok");

        let final_request = final_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("capture final request");
        let final_request = final_request.to_ascii_lowercase();
        assert!(!final_request.contains("authorization:"));
        assert!(!final_request.contains("cookie:"));

        start_handle.join().expect("join start server");
        final_handle.join().expect("join final server");
    }

    #[tokio::test]
    async fn send_with_contract_denies_oversized_response_body() {
        let (addr, _rx, handle) = spawn_single_response_server(|_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nabcdef".to_string()
        });
        let mut contract = HttpEgressContract::permissive_for_tests(&authority(addr));
        contract.max_response_bytes = 5;
        let client = client_builder_with_contract(&contract)
            .build()
            .expect("build client");
        let request = client
            .get(format!("http://{}/body", authority(addr)))
            .build()
            .expect("build request");

        let error = send_with_contract(&contract, &client, request)
            .await
            .expect_err("oversized response should be rejected");
        assert!(matches!(
            error,
            HttpEgressError::ResponseTooLarge {
                observed: 6,
                max: 5
            }
        ));
        handle.join().expect("join server");
    }
}

fn validate_scheme_token(scheme: &str) -> Result<(), HttpEgressError> {
    let bytes = scheme.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_lowercase() {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed scheme {scheme:?}"
        )));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.'))
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed scheme {scheme:?}"
        )));
    }
    Ok(())
}

fn validate_authority_token(authority: &str) -> Result<(), HttpEgressError> {
    if authority.trim().is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority != authority.trim()
        || authority != authority.to_ascii_lowercase()
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}"
        )));
    }
    Ok(())
}

fn normalized_url_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
    let host = match host {
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn is_ipv6_unicast_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

/// Optional helper that pairs a `reqwest::Client` dispatch with
/// `HttpEgressContract` enforcement. Behind the `reqwest-egress` feature so
/// callers that already depend on `reqwest` get a single fail-closed entry
/// point and substrate adapters can keep their existing client builder.
#[cfg(feature = "reqwest-egress")]
pub mod reqwest_helper {
    use super::{HttpEgressContract, HttpEgressError};
    use reqwest::header::{
        HeaderMap, HeaderName, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, LOCATION,
        PROXY_AUTHORIZATION,
    };
    use reqwest::{Method, StatusCode, Url};
    use serde::de::DeserializeOwned;

    /// Response returned by [`send_with_contract`] after the full response body
    /// has been read under the contract byte ceiling.
    #[derive(Debug, Clone)]
    pub struct ContractResponse {
        status: StatusCode,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    impl ContractResponse {
        #[must_use]
        pub fn status(&self) -> StatusCode {
            self.status
        }

        #[must_use]
        pub fn url(&self) -> &Url {
            &self.url
        }

        #[must_use]
        pub fn headers(&self) -> &HeaderMap {
            &self.headers
        }

        #[must_use]
        pub fn body(&self) -> &[u8] {
            &self.body
        }

        pub async fn text(self) -> Result<String, std::string::FromUtf8Error> {
            String::from_utf8(self.body)
        }

        pub async fn json<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
            serde_json::from_slice(&self.body)
        }
    }

    /// Wrap a `reqwest::Client::execute` call with [`HttpEgressContract`]
    /// enforcement before each network hop and while reading the response body.
    /// The supplied client must be built with [`client_builder_with_contract`],
    /// which disables reqwest's automatic redirect following so this helper can
    /// validate each `Location` target before issuing the next request.
    pub async fn send_with_contract(
        contract: &HttpEgressContract,
        client: &reqwest::Client,
        request: reqwest::Request,
    ) -> Result<ContractResponse, HttpEgressError> {
        let mut request = request;
        let mut redirect_chain_len = 0_u8;

        loop {
            let request_url = request.url().clone();
            contract.enforce_url_with_dns(request_url.as_str(), redirect_chain_len)?;
            let reusable_request = request.try_clone();
            let request_method = request.method().clone();
            let request_headers = request.headers().clone();

            let response = client.execute(request).await.map_err(map_reqwest_error)?;
            if response.url() != &request_url {
                return Err(HttpEgressError::InvalidUrl(
                    "reqwest client followed a redirect internally; build it with client_builder_with_contract"
                        .to_string(),
                ));
            }

            let status = response.status();
            if is_redirect_status(status) {
                if let Some(location) = response.headers().get(LOCATION).cloned() {
                    if redirect_chain_len >= contract.max_redirect_chain {
                        return Err(HttpEgressError::RedirectLimitExceeded {
                            observed: redirect_chain_len.saturating_add(1),
                            max: contract.max_redirect_chain,
                        });
                    }
                    let location = location.to_str().map_err(|error| {
                        HttpEgressError::InvalidUrl(format!(
                            "invalid redirect Location header from {request_url}: {error}"
                        ))
                    })?;
                    let next_url = request_url.join(location).map_err(|error| {
                        HttpEgressError::InvalidUrl(format!(
                            "invalid redirect target `{location}` from {request_url}: {error}"
                        ))
                    })?;
                    let next_chain_len = redirect_chain_len.saturating_add(1);
                    contract.enforce_url_with_dns(next_url.as_str(), next_chain_len)?;
                    let cross_origin = !same_origin(&request_url, &next_url);
                    request = build_redirect_request(
                        client,
                        reusable_request,
                        request_method,
                        request_headers,
                        status,
                        next_url,
                        cross_origin,
                    )?;
                    redirect_chain_len = next_chain_len;
                    continue;
                }
            }

            return collect_capped_response(contract, response).await;
        }
    }

    fn is_redirect_status(status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        )
    }

    /// Build a `reqwest::ClientBuilder` whose redirect policy applies the
    /// supplied [`HttpEgressContract`] by disabling reqwest's automatic redirect
    /// handling. [`send_with_contract`] manually follows redirects after
    /// validating each hop and stripping sensitive headers on cross-origin hops.
    pub fn client_builder_with_contract(_contract: &HttpEgressContract) -> reqwest::ClientBuilder {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
    }

    fn build_redirect_request(
        client: &reqwest::Client,
        reusable_request: Option<reqwest::Request>,
        method: Method,
        headers: HeaderMap,
        status: StatusCode,
        next_url: Url,
        cross_origin: bool,
    ) -> Result<reqwest::Request, HttpEgressError> {
        let rewrite_to_get = status == StatusCode::SEE_OTHER && method != Method::HEAD
            || matches!(status, StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND)
                && method == Method::POST;
        if rewrite_to_get {
            let mut builder = client.request(Method::GET, next_url);
            for (name, value) in &headers {
                if should_drop_redirect_header(name, cross_origin, true) {
                    continue;
                }
                builder = builder.header(name, value);
            }
            return builder.build().map_err(map_reqwest_error);
        }

        let mut request = reusable_request.ok_or_else(|| {
            HttpEgressError::InvalidUrl(
                "redirect requires a cloneable request body to replay safely".to_string(),
            )
        })?;
        *request.url_mut() = next_url;
        strip_redirect_headers(request.headers_mut(), cross_origin, false);
        Ok(request)
    }

    fn should_drop_redirect_header(
        name: &HeaderName,
        cross_origin: bool,
        body_was_dropped: bool,
    ) -> bool {
        *name == HOST
            || body_was_dropped && (*name == CONTENT_LENGTH || *name == CONTENT_TYPE)
            || cross_origin && is_sensitive_request_header(name)
    }

    fn strip_redirect_headers(headers: &mut HeaderMap, cross_origin: bool, body_was_dropped: bool) {
        let names = headers.keys().cloned().collect::<Vec<_>>();
        for name in names {
            if should_drop_redirect_header(&name, cross_origin, body_was_dropped) {
                headers.remove(name);
            }
        }
    }

    fn is_sensitive_request_header(name: &HeaderName) -> bool {
        *name == AUTHORIZATION || *name == COOKIE || *name == PROXY_AUTHORIZATION
    }

    fn same_origin(left: &Url, right: &Url) -> bool {
        left.scheme() == right.scheme()
            && left.host_str().map(str::to_ascii_lowercase)
                == right.host_str().map(str::to_ascii_lowercase)
            && left.port_or_known_default() == right.port_or_known_default()
    }

    async fn collect_capped_response(
        contract: &HttpEgressContract,
        mut response: reqwest::Response,
    ) -> Result<ContractResponse, HttpEgressError> {
        if let Some(content_length) = response.content_length() {
            contract.enforce_response_bytes(content_length)?;
        }

        let status = response.status();
        let url = response.url().clone();
        let headers = response.headers().clone();
        let mut observed = 0_u64;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            observed = observed.checked_add(chunk.len() as u64).ok_or(
                HttpEgressError::ResponseTooLarge {
                    observed: u64::MAX,
                    max: contract.max_response_bytes,
                },
            )?;
            contract.enforce_response_bytes(observed)?;
            body.extend_from_slice(&chunk);
        }

        Ok(ContractResponse {
            status,
            url,
            headers,
            body,
        })
    }

    fn map_reqwest_error(err: reqwest::Error) -> HttpEgressError {
        let kind = if err.is_timeout() {
            "timeout"
        } else if err.is_connect() {
            "connect error"
        } else if err.is_request() {
            "request error"
        } else if err.is_body() {
            "body error"
        } else if err.is_decode() {
            "decode error"
        } else {
            "transport error"
        };
        HttpEgressError::InvalidUrl(format!("dispatch failed ({kind}): {err}"))
    }
}

#[cfg(feature = "reqwest-egress")]
#[allow(unused_imports)]
pub use reqwest_helper::{client_builder_with_contract, send_with_contract, ContractResponse};

impl HttpEgressContract {
    /// Construct a permissive contract suitable for tests that exercise a
    /// wiremock or other local loopback HTTP server. Production code MUST NOT
    /// use this; production always builds a contract from tenant-scoped
    /// substrate config.
    ///
    /// Loopback, link-local and IPv6 ULA denials are disabled so wiremock's
    /// `127.0.0.1:<port>` URL is accepted. Authority allow-list is wildcard
    /// per `allowed_authority_set` semantics: caller supplies the wiremock
    /// authority. Schemes default to `http` and `https`.
    pub fn permissive_for_tests(authority: &str) -> Self {
        let mut allowed_schemes = BTreeSet::new();
        allowed_schemes.insert("http".to_string());
        allowed_schemes.insert("https".to_string());
        let mut allowed_authority_set = BTreeSet::new();
        allowed_authority_set.insert(authority.to_ascii_lowercase());
        Self {
            tenant_egress_namespace: "tests".to_string(),
            allowed_schemes,
            allowed_authority_set,
            deny_loopback: false,
            deny_link_local: false,
            deny_ipv6_ula: false,
            max_redirect_chain: 4,
            max_response_bytes: 64 * 1024 * 1024,
        }
    }
}
