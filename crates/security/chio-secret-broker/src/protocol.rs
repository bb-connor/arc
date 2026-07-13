use std::collections::BTreeSet;

use chio_core_types::{PublicKey, Signature, SigningAlgorithm};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::proof::RequestProof;
use crate::{validate_digest, validate_identifier, BrokerError, Result};

pub const BROKER_CAPABILITY_SCHEMA: &str = "chio.broker-capability.v1";
pub const BROKER_PROOF_SCHEMA: &str = "chio.broker-request-proof.v1";
pub const BROKER_EXECUTE_SCHEMA: &str = "chio.broker-execute.v1";
pub const BROKER_EVIDENCE_SCHEMA: &str = "chio.broker-execution-evidence.v1";
pub const MAX_WIRE_BYTES: usize = 1_048_576;
pub const MAX_BODY_BYTES: usize = 524_288;
pub const MAX_RESPONSE_BYTES: usize = 2_097_152;
pub const MAX_HEADER_COUNT: usize = 64;
pub const MAX_HEADER_NAME_BYTES: usize = 128;
pub const MAX_HEADER_VALUE_BYTES: usize = 8_192;
pub const MAX_NONCE_BYTES: usize = 128;
pub const MAX_IDENTIFIER_BYTES: usize = 512;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const MAX_PATH_AND_QUERY_BYTES: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRef {
    pub provider: String,
    pub credential_id: String,
    pub version: u64,
}

impl CredentialRef {
    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.provider, "credential provider", MAX_IDENTIFIER_BYTES)?;
        validate_identifier(&self.credential_id, "credential id", MAX_IDENTIFIER_BYTES)?;
        if self.version == 0 {
            return Err(BrokerError::InvalidRequest(
                "credential version must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrokerScheme {
    Https,
    Http,
}

impl BrokerScheme {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Http => "http",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDestination {
    pub scheme: BrokerScheme,
    pub normalized_host: String,
    pub explicit_port: u16,
    pub exact_path_and_query: String,
    pub method: String,
}

impl BrokerDestination {
    pub fn parse(input: &str, method: &str, allow_loopback_http: bool) -> Result<Self> {
        let url = Url::parse(input).map_err(|error| {
            BrokerError::InvalidRequest(format!("invalid destination: {error}"))
        })?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(BrokerError::InvalidRequest(
                "destination cannot contain userinfo or a fragment".to_string(),
            ));
        }
        let scheme = match url.scheme() {
            "https" => BrokerScheme::Https,
            "http" if allow_loopback_http => BrokerScheme::Http,
            _ => {
                return Err(BrokerError::InvalidRequest(
                    "destination must use HTTPS".to_string(),
                ))
            }
        };
        let host = url.host().ok_or_else(|| {
            BrokerError::InvalidRequest("destination host is missing".to_string())
        })?;
        let normalized_host = match host {
            Host::Domain(domain) => normalize_domain(domain)?,
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        let explicit_port = url.port_or_known_default().ok_or_else(|| {
            BrokerError::InvalidRequest("destination port is missing".to_string())
        })?;
        let mut exact_path_and_query = url.path().to_string();
        if exact_path_and_query.is_empty() {
            exact_path_and_query.push('/');
        }
        if let Some(query) = url.query() {
            exact_path_and_query.push('?');
            exact_path_and_query.push_str(query);
        }
        let method = normalize_method(method)?;
        let destination = Self {
            scheme,
            normalized_host,
            explicit_port,
            exact_path_and_query,
            method,
        };
        destination.validate(allow_loopback_http)?;
        Ok(destination)
    }

    pub fn validate(&self, allow_loopback_http: bool) -> Result<()> {
        if self.scheme == BrokerScheme::Http {
            let loopback = self
                .normalized_host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback());
            if !allow_loopback_http || !loopback {
                return Err(BrokerError::InvalidRequest(
                    "HTTP is available only for explicit IP-loopback tests".to_string(),
                ));
            }
        }
        if self.explicit_port == 0 {
            return Err(BrokerError::InvalidRequest(
                "destination port must be positive".to_string(),
            ));
        }
        if self.normalized_host != normalize_host(&self.normalized_host)? {
            return Err(BrokerError::InvalidRequest(
                "destination host is not normalized".to_string(),
            ));
        }
        if self.method != normalize_method(&self.method)? {
            return Err(BrokerError::InvalidRequest(
                "destination method is not normalized".to_string(),
            ));
        }
        let path_bytes = self.exact_path_and_query.as_bytes();
        if !self.exact_path_and_query.starts_with('/')
            || path_bytes.len() > MAX_PATH_AND_QUERY_BYTES
            || path_bytes
                .iter()
                .any(|byte| !matches!(*byte, b'!'..=b'~') || matches!(*byte, b'#' | b'\\'))
            || path_bytes.iter().enumerate().any(|(index, byte)| {
                *byte == b'%'
                    && (path_bytes
                        .get(index + 1)
                        .is_none_or(|next| !next.is_ascii_hexdigit())
                        || path_bytes
                            .get(index + 2)
                            .is_none_or(|next| !next.is_ascii_hexdigit()))
            })
        {
            return Err(BrokerError::InvalidRequest(
                "destination path and query are invalid".to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.normalized_host.contains(':') {
            format!("[{}]", self.normalized_host)
        } else {
            self.normalized_host.clone()
        };
        let default = matches!(
            (self.scheme, self.explicit_port),
            (BrokerScheme::Https, 443) | (BrokerScheme::Http, 80)
        );
        if default {
            host
        } else {
            format!("{host}:{}", self.explicit_port)
        }
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme.as_str(),
            self.authority(),
            self.exact_path_and_query
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeaderField {
    pub name: String,
    pub value: Vec<u8>,
}

impl HeaderField {
    pub fn normalized(name: &str, value: &[u8]) -> Result<Self> {
        if name.is_empty()
            || name.len() > MAX_HEADER_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(BrokerError::InvalidRequest(
                "header name is invalid".to_string(),
            ));
        }
        if value.len() > MAX_HEADER_VALUE_BYTES
            || value
                .iter()
                .any(|byte| !matches!(*byte, b'\t' | b' '..=b'~' | 0x80..=0xff))
        {
            return Err(BrokerError::InvalidRequest(
                "header value is invalid or oversized".to_string(),
            ));
        }
        Ok(Self {
            name: name.to_ascii_lowercase(),
            value: value.to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptConsumption {
    CaptureBeforeDispatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestConstraints {
    pub allowed_caller_headers: Vec<String>,
    pub provider_owned_headers: Vec<String>,
    pub maximum_body_bytes: u64,
    pub required_body_sha256: String,
    pub required_preview_sha256: Option<String>,
    pub redirect_policy: RedirectPolicy,
    /// Maximum exact HTTP response-head bytes plus decoded response-body bytes.
    pub maximum_response_bytes: u64,
    pub streaming_allowed: bool,
    pub maximum_timeout_ms: u64,
}

impl RequestConstraints {
    pub fn validate(&self) -> Result<()> {
        if self.maximum_body_bytes > MAX_BODY_BYTES as u64
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > MAX_RESPONSE_BYTES as u64
            || self.maximum_timeout_ms == 0
            || self.maximum_timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(BrokerError::InvalidRequest(
                "request constraint limit is invalid".to_string(),
            ));
        }
        validate_digest(&self.required_body_sha256, "required body digest")?;
        if let Some(preview) = &self.required_preview_sha256 {
            validate_digest(preview, "required preview digest")?;
        }
        validate_normalized_header_names(&self.allowed_caller_headers)?;
        validate_normalized_header_names(&self.provider_owned_headers)?;
        if self
            .allowed_caller_headers
            .iter()
            .any(|name| self.provider_owned_headers.binary_search(name).is_ok())
        {
            return Err(BrokerError::InvalidRequest(
                "caller and provider header sets overlap".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    PublicKey,
    LoopbackBearer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBinding {
    pub mode: ProofMode,
    pub caller_public_key: PublicKey,
    pub nonce_ttl_seconds: u64,
}

impl ProofBinding {
    pub fn validate(&self, production: bool) -> Result<()> {
        if self.nonce_ttl_seconds == 0 || self.nonce_ttl_seconds > 300 {
            return Err(BrokerError::InvalidRequest(
                "proof nonce lifetime must be between 1 and 300 seconds".to_string(),
            ));
        }
        if production && self.mode != ProofMode::PublicKey {
            return Err(BrokerError::AuthorizationDenied(
                "production requires public-key proof".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerCapabilityBody {
    pub schema: String,
    pub issuer: PublicKey,
    pub capability_id: String,
    pub parent_capability_id: String,
    pub subject: PublicKey,
    pub audience: String,
    pub issued_at_unix_seconds: u64,
    pub not_before_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub credential: CredentialRef,
    pub provider_adapter_id: String,
    pub provider_adapter_version: u32,
    pub destination: BrokerDestination,
    pub constraints: RequestConstraints,
    pub broker_quota_key_id: String,
    pub maximum_executions: u32,
    pub consumption: AttemptConsumption,
    pub revocation_id: String,
    pub proof: ProofBinding,
}

impl BrokerCapabilityBody {
    pub fn validate(&self, production: bool) -> Result<()> {
        if self.schema != BROKER_CAPABILITY_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "unsupported broker capability schema".to_string(),
            ));
        }
        for (value, label) in [
            (&self.capability_id, "broker capability id"),
            (&self.parent_capability_id, "parent capability id"),
            (&self.audience, "broker audience"),
            (&self.provider_adapter_id, "provider adapter id"),
            (&self.broker_quota_key_id, "broker quota key id"),
            (&self.revocation_id, "broker revocation id"),
        ] {
            validate_identifier(value, label, MAX_IDENTIFIER_BYTES)?;
        }
        if self.issued_at_unix_seconds > self.not_before_unix_seconds
            || self.not_before_unix_seconds >= self.expires_at_unix_seconds
            || self.maximum_executions == 0
            || self.provider_adapter_version == 0
            || self.subject != self.proof.caller_public_key
            || self.capability_id == self.parent_capability_id
            || self.revocation_id == self.capability_id
            || self.revocation_id == self.parent_capability_id
        {
            return Err(BrokerError::InvalidRequest(
                "broker capability identity, time, adapter, or execution bound is invalid"
                    .to_string(),
            ));
        }
        self.credential.validate()?;
        self.destination.validate(!production)?;
        self.constraints.validate()?;
        self.proof.validate(production)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedBrokerCapability {
    pub body: BrokerCapabilityBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallerOptions {
    pub timeout_ms: u64,
    pub streaming: bool,
    /// Caller ceiling for exact HTTP response-head bytes plus decoded response-body bytes.
    pub response_limit_bytes: u64,
}

impl CallerOptions {
    pub fn validate(&self) -> Result<()> {
        if self.timeout_ms == 0
            || self.timeout_ms > MAX_TIMEOUT_MS
            || self.response_limit_bytes == 0
            || self.response_limit_bytes > MAX_RESPONSE_BYTES as u64
        {
            return Err(BrokerError::InvalidRequest(
                "caller options exceed broker limits".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerRequest {
    pub destination: BrokerDestination,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
    pub approved_preview_sha256: Option<String>,
    pub options: CallerOptions,
}

impl BrokerRequest {
    pub fn validate_bounds(&self) -> Result<()> {
        self.destination.validate(true)?;
        self.options.validate()?;
        if self.body.len() > MAX_BODY_BYTES || self.headers.len() > MAX_HEADER_COUNT {
            return Err(BrokerError::InvalidRequest(
                "request body or header count exceeds broker limit".to_string(),
            ));
        }
        if let Some(preview) = &self.approved_preview_sha256 {
            validate_digest(preview, "approved preview digest")?;
        }
        let mut previous: Option<&str> = None;
        for header in &self.headers {
            let normalized = HeaderField::normalized(&header.name, &header.value)?;
            if normalized != *header {
                return Err(BrokerError::InvalidRequest(
                    "caller headers must use normalized comparison form".to_string(),
                ));
            }
            if previous.is_some_and(|name| name >= header.name.as_str()) {
                return Err(BrokerError::InvalidRequest(
                    "caller headers must be strictly sorted without duplicates".to_string(),
                ));
            }
            previous = Some(&header.name);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerExecuteRequest {
    pub schema: String,
    pub invocation_id: String,
    pub capability: SignedBrokerCapability,
    pub proof: RequestProof,
    pub request: BrokerRequest,
}

impl BrokerExecuteRequest {
    pub fn validate_bounds(&self) -> Result<()> {
        if self.schema != BROKER_EXECUTE_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "unsupported broker execute schema".to_string(),
            ));
        }
        validate_identifier(&self.invocation_id, "invocation id", MAX_IDENTIFIER_BYTES)?;
        self.request.validate_bounds()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerExecutionEvidence {
    pub schema: String,
    pub attempt_id: String,
    pub invocation_id: String,
    pub hold_id: String,
    pub request_digest: String,
    pub capability_digest: String,
    pub revocation_set_digest: String,
    pub budget_commit_index: u64,
    pub revocation_commit_index: u64,
    pub authority_commit_index: u64,
    pub leader_epoch: u64,
    pub upstream_status: u16,
    pub response_body_sha256: String,
}

impl BrokerExecutionEvidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_EVIDENCE_SCHEMA || !(100..=599).contains(&self.upstream_status) {
            return Err(BrokerError::InvalidRequest(
                "broker evidence schema or upstream status is invalid".to_string(),
            ));
        }
        for (value, label) in [
            (&self.attempt_id, "evidence attempt id"),
            (&self.invocation_id, "evidence invocation id"),
            (&self.hold_id, "evidence hold id"),
        ] {
            validate_identifier(value, label, MAX_IDENTIFIER_BYTES)?;
        }
        for (value, label) in [
            (&self.request_digest, "evidence request digest"),
            (&self.capability_digest, "evidence capability digest"),
            (
                &self.revocation_set_digest,
                "evidence revocation-set digest",
            ),
            (&self.response_body_sha256, "evidence response body digest"),
        ] {
            validate_digest(value, label)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerExecuteResponse {
    pub status: u16,
    pub headers: Vec<HeaderField>,
    pub body: Vec<u8>,
    pub evidence: BrokerExecutionEvidence,
    pub receipt_reference: String,
}

pub fn decode_execute_request(bytes: &[u8]) -> Result<BrokerExecuteRequest> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_BYTES {
        return Err(BrokerError::InvalidRequest(
            "broker execute frame is empty or oversized".to_string(),
        ));
    }
    let request: BrokerExecuteRequest = serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::InvalidRequest(format!("invalid execute frame: {error}")))?;
    request.validate_bounds()?;
    Ok(request)
}

pub fn normalize_headers(
    headers: impl IntoIterator<Item = HeaderField>,
) -> Result<Vec<HeaderField>> {
    let mut normalized = headers
        .into_iter()
        .map(|header| HeaderField::normalized(&header.name, &header.value))
        .collect::<Result<Vec<_>>>()?;
    normalized.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    if normalized
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(BrokerError::InvalidRequest(
            "duplicate normalized caller header".to_string(),
        ));
    }
    Ok(normalized)
}

pub fn normalize_header_names(names: impl IntoIterator<Item = String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    for name in names {
        normalized.push(HeaderField::normalized(&name, &[])?.name);
    }
    normalized.sort_unstable();
    normalized.dedup();
    validate_normalized_header_names(&normalized)?;
    Ok(normalized)
}

fn validate_normalized_header_names(names: &[String]) -> Result<()> {
    if names.len() > MAX_HEADER_COUNT {
        return Err(BrokerError::InvalidRequest(
            "header allowlist exceeds broker limit".to_string(),
        ));
    }
    let mut unique = BTreeSet::new();
    for name in names {
        let normalized = HeaderField::normalized(name, &[])?.name;
        if normalized != *name || !unique.insert(name) {
            return Err(BrokerError::InvalidRequest(
                "header names must be normalized, sorted, and unique".to_string(),
            ));
        }
    }
    if names.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(BrokerError::InvalidRequest(
            "header names must be strictly sorted".to_string(),
        ));
    }
    Ok(())
}

fn normalize_domain(domain: &str) -> Result<String> {
    let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(BrokerError::InvalidRequest(
            "destination domain is invalid".to_string(),
        ));
    }
    Ok(normalized)
}

fn normalize_host(host: &str) -> Result<String> {
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    normalize_domain(host)
}

fn normalize_method(method: &str) -> Result<String> {
    let normalized = method.to_ascii_uppercase();
    if !matches!(
        normalized.as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
    ) {
        return Err(BrokerError::InvalidRequest(
            "HTTP method is invalid".to_string(),
        ));
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_is_limited_to_explicit_ip_loopback_tests() {
        assert!(BrokerDestination::parse("http://127.0.0.1/v1", "POST", true).is_ok());
        assert!(BrokerDestination::parse("http://[::1]/v1", "POST", true).is_ok());
        assert!(BrokerDestination::parse("http://127.0.0.1/v1", "POST", false).is_err());
        assert!(BrokerDestination::parse("http://example.com/v1", "POST", true).is_err());
    }

    #[test]
    fn request_targets_and_methods_reject_ambiguous_transport_syntax() {
        assert!(BrokerDestination::parse("https://example.com/v1", "TRACE", false).is_err());
        let mut destination =
            BrokerDestination::parse("https://example.com/v1", "POST", false).expect("destination");
        destination.exact_path_and_query = "/v1\\admin".to_string();
        assert!(destination.validate(false).is_err());
        destination.exact_path_and_query = "/v1%0".to_string();
        assert!(destination.validate(false).is_err());
        destination.exact_path_and_query = "/v1 host".to_string();
        assert!(destination.validate(false).is_err());
    }
}
