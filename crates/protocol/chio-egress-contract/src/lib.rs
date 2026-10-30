//! Typed HTTP egress contracts for substrate adapters.
//!
//! Kernel, guard, and adapter code paths that initiate outbound HTTP must
//! declare one of these contracts before a target URL is accepted. Missing or
//! malformed contract state fails closed.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

mod allowance;
pub use allowance::{
    private_network_allowance_digest, AllowanceScheme, EgressAllowanceSet, IpCidr,
    PrivateNetworkAllowance, PrivateNetworkAllowanceError, EMPTY_PRIVATE_NETWORK_ALLOWANCE_DIGEST,
    MIN_IPV4_ALLOWANCE_PREFIX, MIN_IPV6_ALLOWANCE_PREFIX, PRIVATE_NETWORK_ALLOWANCE_DIGEST_SCHEMA,
};

/// Typed egress policy that must be declared before substrate HTTP egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEgressContract {
    /// Tenant-scoped namespace used by callers to bind egress receipts and
    /// deployment policy to one authority domain.
    pub tenant_egress_namespace: String,
    /// Lowercase HTTP URL schemes allowed by this contract: `http` or `https`.
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
    /// Private destinations this contract may reach. Each entry pins one
    /// `host:port` to the CIDR every resolved address must fall inside.
    #[serde(default)]
    pub private_network_allowances: BTreeSet<PrivateNetworkAllowance>,
}

/// A target URL that survived [`HttpEgressContract`] enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedHttpEgressTarget {
    pub tenant_egress_namespace: String,
    pub scheme: String,
    pub authority: String,
}

/// Immutable egress contract that has passed shape validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedHttpEgressContract {
    contract: HttpEgressContract,
    tenant_egress_namespace: String,
}

/// Fail-closed reasons returned by HTTP egress contract enforcement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpEgressError {
    #[cfg(any(feature = "reqwest-egress", feature = "ureq-egress"))]
    #[error("urn:chio:error:transport:http-failed")]
    Transport(#[from] RequestFailure),
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
    #[error("invalid private network allowance: {0}")]
    InvalidAllowance(#[from] PrivateNetworkAllowanceError),
    #[error("{host}:{port} resolved to {address} outside its private network allowance")]
    PrivateNetworkAllowanceMismatch {
        host: String,
        port: u16,
        address: IpAddr,
    },
    #[error("{scheme} is not the scheme of the private network allowance for {host}:{port}")]
    PrivateNetworkAllowanceSchemeMismatch {
        host: String,
        port: u16,
        scheme: String,
    },
    #[error("cloud metadata egress target denied: {host}")]
    ReservedAddressDenied { host: String },
    #[error("loopback name resolved off host: {host}")]
    LoopbackNameResolvedOffHost { host: String },
}

/// Who chose a [`HttpEgressContract::single_endpoint`] URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointSource {
    /// The operator named the URL, for example on the command line. A
    /// loopback URL may use plaintext `http`.
    Operator,
    /// A remote party chose the URL. Only `https` to a non-loopback host is
    /// admitted.
    Remote,
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
        self.prepare()?
            .enforce_attempt(target_url, redirect_chain_len, observed_response_bytes)
    }

    /// Enforce target URL and redirect hop constraints.
    pub fn enforce_url(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.prepare()?.enforce_url(target_url, redirect_chain_len)
    }

    /// Enforce target URL, redirect hop constraints, and DNS safety.
    ///
    /// Literal IPs and localhost names are enforced directly. Domain names are
    /// resolved here and every resolved IP is checked against the address-class
    /// policy before the caller opens a socket.
    pub fn enforce_url_with_dns(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        self.prepare()?
            .enforce_url_with_dns(target_url, redirect_chain_len)
    }

    /// Enforce the response-byte ceiling after headers or streaming counters
    /// expose the observed size.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        self.prepare()?.enforce_response_bytes(observed)
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
        allowance::validate_allowances(
            &self.private_network_allowances,
            &self.allowed_schemes,
            &self.allowed_authority_set,
        )?;
        Ok(())
    }

    /// Digest of this contract's private network allowances.
    pub fn private_network_allowance_digest(&self) -> Result<String, HttpEgressError> {
        private_network_allowance_digest(&self.private_network_allowances)
    }

    /// Replace this contract's allowances with the entries of `allowances`
    /// that pin the `host:port` of one of its authorities. A bare authority
    /// stands for the default port of each scheme. An entry whose scheme the
    /// contract does not allow is kept so that validation refuses it. The
    /// result is checked when the contract is prepared.
    #[must_use]
    pub fn with_private_network_allowances(mut self, allowances: &EgressAllowanceSet) -> Self {
        let mut pinned = BTreeSet::new();
        for scheme in [AllowanceScheme::Https, AllowanceScheme::Http] {
            for authority in &self.allowed_authority_set {
                let Ok(url) = Url::parse(&format!("{}://{authority}/", scheme.as_str())) else {
                    continue;
                };
                let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
                    continue;
                };
                pinned.extend(allowances.for_endpoint(host, port));
            }
        }
        self.private_network_allowances = pinned;
        self
    }

    /// Validate this raw contract and return an immutable enforcement handle.
    pub fn prepare(&self) -> Result<PreparedHttpEgressContract, HttpEgressError> {
        self.validate()?;
        Ok(PreparedHttpEgressContract {
            contract: self.clone(),
            tenant_egress_namespace: self.tenant_egress_namespace.trim().to_string(),
        })
    }

    /// Validate that this contract can be used by the reqwest-backed
    /// dispatcher whose resolver enforces address-class policy at connect
    /// time.
    pub fn validate_dispatchable_with_pinned_dns(&self) -> Result<(), HttpEgressError> {
        self.validate()?;
        for authority in &self.allowed_authority_set {
            validate_dispatchable_authority(authority)?;
        }
        Ok(())
    }

    fn enforce_host_class(
        &self,
        host: &Host<&str>,
        port: Option<u16>,
    ) -> Result<(), HttpEgressError> {
        match host {
            Host::Domain(domain) => {
                let normalized = normalize_domain_name(domain);
                self.enforce_loopback_hostname(&normalized)?;
            }
            Host::Ipv4(address) => {
                let address = IpAddr::V4(*address);
                self.enforce_address(&address.to_string(), port, address, address.to_string())?;
            }
            Host::Ipv6(address) => {
                let address = IpAddr::V6(*address);
                let label = allowance::canonical_ip(address).to_string();
                self.enforce_address(&label, port, address, label.clone())?;
            }
        }
        Ok(())
    }

    fn enforce_loopback_hostname(&self, normalized: &str) -> Result<(), HttpEgressError> {
        if self.deny_loopback && is_loopback_name(normalized) {
            return Err(HttpEgressError::LoopbackDenied {
                host: normalized.to_string(),
            });
        }
        Ok(())
    }

    /// A host pinned for this port is dialed only under the scheme its
    /// allowance names.
    fn enforce_allowance_scheme(&self, url: &Url, scheme: &str) -> Result<(), HttpEgressError> {
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Ok(());
        };
        let host = allowance::allowance_host(host);
        match self
            .private_network_allowances
            .iter()
            .find(|entry| entry.host == host && entry.port == port)
        {
            Some(pin) if pin.scheme.as_str() != scheme => {
                Err(HttpEgressError::PrivateNetworkAllowanceSchemeMismatch {
                    host,
                    port,
                    scheme: scheme.to_string(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Enforce the contract on one address `host` resolved to. The port
    /// selects the private network allowance that pins `host`, if any.
    /// A loopback name such as `localhost` must resolve only to loopback.
    pub fn enforce_resolved_address(
        &self,
        host: &str,
        address: SocketAddr,
    ) -> Result<(), HttpEgressError> {
        let ip = allowance::canonical_ip(address.ip());
        if is_loopback_name(&normalize_domain_name(host)) && !ip.is_loopback() {
            return Err(HttpEgressError::LoopbackNameResolvedOffHost {
                host: format!("{host} resolved to {ip}"),
            });
        }
        self.enforce_address(
            host,
            Some(address.port()),
            ip,
            format!("{host} resolved to {ip}"),
        )
    }

    /// A host pinned by an allowance for this port must resolve inside the
    /// allowance CIDR, public answers included. Any other host falls to the
    /// address-class policy, and a cloud metadata address that policy would
    /// admit is still refused.
    fn enforce_address(
        &self,
        host: &str,
        port: Option<u16>,
        address: IpAddr,
        label: String,
    ) -> Result<(), HttpEgressError> {
        let address = allowance::canonical_ip(address);
        let host = allowance::allowance_host(host);
        if let Some(pin) = self
            .private_network_allowances
            .iter()
            .find(|entry| entry.host == host && Some(entry.port) == port)
        {
            if pin.cidr.contains(address) && allowance::is_unlockable_address(address) {
                return Ok(());
            }
            return Err(HttpEgressError::PrivateNetworkAllowanceMismatch {
                host,
                port: pin.port,
                address,
            });
        }
        let class = match address {
            IpAddr::V4(address) => classify_ipv4_address(&address),
            IpAddr::V6(address) => classify_ipv6_address(&address),
        };
        self.enforce_ip_address_class(label.clone(), class)?;
        if allowance::is_metadata_address(address) {
            return Err(HttpEgressError::ReservedAddressDenied { host: label });
        }
        Ok(())
    }

    fn enforce_ip_address_class(
        &self,
        host: String,
        class: IpAddressClass,
    ) -> Result<(), HttpEgressError> {
        match class {
            IpAddressClass::Global => Ok(()),
            IpAddressClass::Loopback => {
                if self.deny_loopback {
                    return Err(HttpEgressError::LoopbackDenied { host });
                }
                Ok(())
            }
            IpAddressClass::LinkLocal => {
                if self.deny_link_local {
                    return Err(HttpEgressError::LinkLocalDenied { host });
                }
                Ok(())
            }
            IpAddressClass::Ipv6Ula => {
                if self.deny_ipv6_ula {
                    return Err(HttpEgressError::Ipv6UlaDenied { host });
                }
                Ok(())
            }
            IpAddressClass::PrivateOrSpecialUse => {
                Err(HttpEgressError::PrivateNetworkDenied { host })
            }
        }
    }

    fn enforce_domain_resolution(&self, url: &Url) -> Result<(), HttpEgressError> {
        let Some(Host::Domain(domain)) = url.host() else {
            return Ok(());
        };
        let normalized = normalize_domain_name(domain);
        self.enforce_loopback_hostname(&normalized)?;
        let port = url.port_or_known_default().ok_or_else(|| {
            HttpEgressError::InvalidUrl(format!(
                "egress URL {url} has no explicit port or known default port"
            ))
        })?;
        let addrs = (normalized.as_str(), port)
            .to_socket_addrs()
            .map_err(|error| HttpEgressError::DnsResolutionFailed {
                host: normalized.clone(),
                details: error.to_string(),
            })?;
        let mut saw_addr = false;
        for addr in addrs {
            saw_addr = true;
            self.enforce_resolved_address(&normalized, addr)?;
        }
        if !saw_addr {
            return Err(HttpEgressError::DnsResolutionFailed {
                host: normalized,
                details: "resolver returned no addresses".to_string(),
            });
        }
        Ok(())
    }

    fn authority_is_allowed(&self, url: &Url, authority: &str) -> Result<bool, HttpEgressError> {
        if self.allowed_authority_set.contains(authority) {
            return Ok(true);
        }
        let host_authority = normalized_url_host_authority(url)?;
        if let Some(default_port) = url.port_or_known_default() {
            let default_port_authority = format!("{host_authority}:{default_port}");
            return Ok(self.allowed_authority_set.contains(&default_port_authority));
        }
        Ok(false)
    }

    #[cfg(feature = "reqwest-egress")]
    fn enforce_resolver_hostname(&self, host: &str) -> Result<(), HttpEgressError> {
        self.prepare()?.enforce_resolver_hostname(host)
    }
}

impl PreparedHttpEgressContract {
    /// Return the validated raw contract that backs this prepared handle.
    #[must_use]
    pub fn contract(&self) -> &HttpEgressContract {
        &self.contract
    }

    /// Return the normalized tenant namespace captured during preparation.
    #[must_use]
    pub fn tenant_egress_namespace(&self) -> &str {
        &self.tenant_egress_namespace
    }

    /// Return the prepared redirect-hop ceiling.
    #[must_use]
    pub fn max_redirect_chain(&self) -> u8 {
        self.contract.max_redirect_chain
    }

    /// Return the prepared response-byte ceiling.
    #[must_use]
    pub fn max_response_bytes(&self) -> u64 {
        self.contract.max_response_bytes
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
        if redirect_chain_len > self.contract.max_redirect_chain {
            return Err(HttpEgressError::RedirectLimitExceeded {
                observed: redirect_chain_len,
                max: self.contract.max_redirect_chain,
            });
        }

        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(HttpEgressError::UserinfoDenied);
        }

        let scheme = url.scheme().to_ascii_lowercase();
        if !self.contract.allowed_schemes.contains(&scheme) {
            return Err(HttpEgressError::SchemeDenied { scheme });
        }

        let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
        self.contract.enforce_allowance_scheme(&url, &scheme)?;
        self.contract
            .enforce_host_class(&host, url.port_or_known_default())?;

        let authority = normalized_url_authority(&url)?;
        if !self.contract.authority_is_allowed(&url, &authority)? {
            return Err(HttpEgressError::AuthorityDenied { authority });
        }

        Ok(ValidatedHttpEgressTarget {
            tenant_egress_namespace: self.tenant_egress_namespace.clone(),
            scheme,
            authority,
        })
    }

    /// Enforce target URL, redirect hop constraints, and DNS safety.
    pub fn enforce_url_with_dns(
        &self,
        target_url: &str,
        redirect_chain_len: u8,
    ) -> Result<ValidatedHttpEgressTarget, HttpEgressError> {
        let target = self.enforce_url(target_url, redirect_chain_len)?;
        let url = Url::parse(target_url)
            .map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        self.contract.enforce_domain_resolution(&url)?;
        Ok(target)
    }

    /// Enforce the response-byte ceiling.
    pub fn enforce_response_bytes(&self, observed: u64) -> Result<(), HttpEgressError> {
        if observed > self.contract.max_response_bytes {
            return Err(HttpEgressError::ResponseTooLarge {
                observed,
                max: self.contract.max_response_bytes,
            });
        }
        Ok(())
    }

    /// Validate that this prepared contract can be used by the reqwest-backed
    /// dispatcher whose resolver enforces address-class policy at connect time.
    pub fn validate_dispatchable_with_pinned_dns(&self) -> Result<(), HttpEgressError> {
        for authority in &self.contract.allowed_authority_set {
            validate_dispatchable_authority(authority)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "reqwest-egress", feature = "ureq-egress"))]
    fn enforce_resolver_hostname(&self, host: &str) -> Result<(), HttpEgressError> {
        self.validate_dispatchable_with_pinned_dns()?;
        let normalized = normalize_domain_name(host);
        if normalized.is_empty() {
            return Err(HttpEgressError::MissingAuthority);
        }
        self.contract.enforce_loopback_hostname(&normalized)?;
        for authority in &self.contract.allowed_authority_set {
            if normalized_authority_host(authority)? == normalized {
                return Ok(());
            }
        }
        Err(HttpEgressError::AuthorityDenied {
            authority: normalized,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "allowance_tests.rs"]
mod allowance_tests;

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
    if !matches!(scheme, "http" | "https") {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid HTTP egress scheme {scheme:?}; expected \"http\" or \"https\""
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
        || authority.ends_with(':')
    {
        return Err(HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}"
        )));
    }
    validate_dispatchable_authority(authority)?;
    let normalized = normalize_authority_token(authority)?;
    if normalized != authority {
        return Err(HttpEgressError::InvalidContract(format!(
            "allowed authority {authority:?} must be normalized as {normalized:?}"
        )));
    }
    Ok(())
}

fn validate_dispatchable_authority(authority: &str) -> Result<(), HttpEgressError> {
    let _ = normalized_authority_host(authority)?;
    Ok(())
}

fn normalize_authority_token(authority: &str) -> Result<String, HttpEgressError> {
    let parsed = Url::parse(&format!("http://{authority}/")).map_err(|error| {
        HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}: {error}"
        ))
    })?;
    let host = parsed.host().ok_or_else(|| {
        HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
    })?;
    let normalized_host = match host {
        Host::Domain(domain) => normalize_domain_name(domain),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    if authority_has_explicit_port(authority) {
        let port = parsed.port_or_known_default().ok_or_else(|| {
            HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
        })?;
        return Ok(format!("{normalized_host}:{port}"));
    }
    Ok(normalized_host)
}

fn authority_has_explicit_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        return authority
            .rsplit_once(']')
            .is_some_and(|(_, suffix)| suffix.starts_with(':'));
    }
    authority
        .rsplit_once(':')
        .is_some_and(|(host, _)| !host.contains(':'))
}

fn normalized_authority_host(authority: &str) -> Result<String, HttpEgressError> {
    let parsed = Url::parse(&format!("http://{authority}/")).map_err(|error| {
        HttpEgressError::InvalidContract(format!(
            "invalid allowed authority {authority:?}: {error}"
        ))
    })?;
    let host = parsed.host().ok_or_else(|| {
        HttpEgressError::InvalidContract(format!("invalid allowed authority {authority:?}"))
    })?;
    Ok(match host {
        Host::Domain(domain) => normalize_domain_name(domain),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn normalize_domain_name(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn is_loopback_name(normalized: &str) -> bool {
    matches!(normalized, "localhost" | "localhost.localdomain")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpAddressClass {
    Global,
    Loopback,
    LinkLocal,
    Ipv6Ula,
    PrivateOrSpecialUse,
}

fn classify_ipv4_address(address: &Ipv4Addr) -> IpAddressClass {
    if address.is_loopback() {
        return IpAddressClass::Loopback;
    }
    if address.is_link_local() {
        return IpAddressClass::LinkLocal;
    }
    if is_ipv4_private_or_special_use(address) {
        return IpAddressClass::PrivateOrSpecialUse;
    }
    IpAddressClass::Global
}

fn classify_ipv6_address(address: &Ipv6Addr) -> IpAddressClass {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return classify_ipv4_address(&mapped);
    }
    if address.is_loopback() {
        return IpAddressClass::Loopback;
    }
    if is_ipv6_unicast_link_local(address) {
        return IpAddressClass::LinkLocal;
    }
    if is_ipv6_unique_local(address) {
        return IpAddressClass::Ipv6Ula;
    }
    if is_ipv6_private_or_special_use(address) {
        return IpAddressClass::PrivateOrSpecialUse;
    }
    IpAddressClass::Global
}

fn normalized_url_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = normalized_url_host_authority(url)?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn normalized_url_host_authority(url: &Url) -> Result<String, HttpEgressError> {
    let host = url.host().ok_or(HttpEgressError::MissingAuthority)?;
    Ok(match host {
        Host::Domain(domain) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    })
}

fn is_ipv6_unicast_link_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xffc0 == 0xfe80
}

fn is_ipv6_unique_local(address: &Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

fn is_ipv4_private_or_special_use(address: &Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_broadcast()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

fn is_ipv6_private_or_special_use(address: &Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_ipv4_private_or_special_use(&mapped);
    }
    let segments = address.segments();
    address.is_unspecified()
        || address.is_multicast()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || embeds_ipv4_destination(&segments)
}

/// NAT64 (64:ff9b::/96, 64:ff9b:1::/48), IPv4-compatible (::/96), 6to4
/// (2002::/16) and Teredo (2001::/32) addresses deliver to an IPv4 host the
/// address classes above do not see, so they are refused without decoding.
fn embeds_ipv4_destination(segments: &[u16; 8]) -> bool {
    let nat64 = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && (segments[2] == 0x0001 || segments[2..6] == [0, 0, 0, 0]);
    let ipv4_compatible = segments[..6] == [0, 0, 0, 0, 0, 0];
    nat64 || ipv4_compatible || segments[0] == 0x2002 || (segments[0] == 0x2001 && segments[1] == 0)
}

/// Optional reqwest transport that dispatches only through a
/// `ContractClient` under `HttpEgressContract` enforcement. Behind the
/// `reqwest-egress` feature so callers that already depend on `reqwest` get
/// a single fail-closed entry point.
#[cfg(feature = "reqwest-egress")]
pub mod reqwest_helper;

#[cfg(any(feature = "reqwest-egress", feature = "ureq-egress"))]
mod transport_failure;
#[cfg(any(feature = "reqwest-egress", feature = "ureq-egress"))]
pub use transport_failure::RequestFailure;

/// Optional blocking ureq transport that dispatches only through a
/// `BlockingContractAgent` under `HttpEgressContract` enforcement.
#[cfg(feature = "ureq-egress")]
pub mod ureq_helper;

#[cfg(feature = "ureq-egress")]
pub use ureq_helper::{
    system_lookup, BlockingContractAgent, BlockingContractRequest, BlockingContractResponse,
    BlockingContractStream, BlockingContractTls, CappedBody, ClientIdentityPem, ContractLookup,
    InvalidTlsMaterial,
};

#[cfg(feature = "reqwest-egress")]
mod operator_readiness;
#[cfg(feature = "reqwest-egress")]
pub use operator_readiness::{OperatorReadinessError, OperatorReadinessProbe};

#[cfg(feature = "reqwest-egress")]
pub use reqwest_helper::{
    client_builder_with_contract, send_with_contract, ContractClient, ContractClientBuilder,
    ContractRequestBuilder, ContractResponse,
};

impl HttpEgressContract {
    /// Contract for the single endpoint `url` names: that URL's scheme and
    /// authority only, no redirects, and `max_response_bytes`. An
    /// [`EndpointSource::Operator`] URL may be `https`, or plaintext `http`
    /// to a loopback host; an [`EndpointSource::Remote`] URL must be `https`
    /// to a non-loopback host. Link-local, unique-local, private and
    /// special-use addresses are refused. `url` itself is enforced before the
    /// contract is returned, and resolved addresses are enforced at connect.
    pub fn single_endpoint(
        source: EndpointSource,
        tenant_egress_namespace: &str,
        url: &str,
        max_response_bytes: u64,
    ) -> Result<Self, HttpEgressError> {
        let parsed =
            Url::parse(url).map_err(|error| HttpEgressError::InvalidUrl(error.to_string()))?;
        let loopback_host = match parsed.host() {
            Some(Host::Domain(domain)) => is_loopback_name(&normalize_domain_name(domain)),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => return Err(HttpEgressError::MissingAuthority),
        };
        let loopback = source == EndpointSource::Operator && loopback_host;
        let scheme = parsed.scheme();
        if scheme != "https" && !(scheme == "http" && loopback) {
            return Err(HttpEgressError::SchemeDenied {
                scheme: scheme.to_owned(),
            });
        }
        let contract = Self {
            tenant_egress_namespace: tenant_egress_namespace.to_owned(),
            allowed_schemes: BTreeSet::from([scheme.to_owned()]),
            allowed_authority_set: BTreeSet::from([normalized_url_authority(&parsed)?]),
            deny_loopback: !loopback,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes,
            private_network_allowances: BTreeSet::new(),
        };
        contract.enforce_url(url, 0)?;
        Ok(contract)
    }

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
            private_network_allowances: BTreeSet::new(),
        }
    }
}
