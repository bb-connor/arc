//! Explicit trust in a sanitizing proxy, bound to both its socket peer and a dedicated secret.
use crate::{
    CliError, RemoteServeHttpConfig, CHIO_MTLS_THUMBPRINT_HEADER, CHIO_RUNTIME_ATTESTATION_HEADER,
};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{collections::BTreeSet, net::IpAddr, path::Path, sync::Arc};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const PROXY_AUTH: &str = "x-chio-proxy-authorization";
const MAX_IDENTITY_BYTES: usize = 256;

/// Trust is explicit and never inferred from Forwarded or X-Forwarded-For.
/// The proxy must overwrite identity headers and protect its connection to Chio.
#[derive(Clone)]
pub struct TrustedProxyConfig {
    peers: BTreeSet<IpAddr>,
    secret: Arc<Zeroizing<Vec<u8>>>,
}
impl std::fmt::Debug for TrustedProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedProxyConfig")
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}
impl TrustedProxyConfig {
    /// Read a dedicated private token file using the same bounded custody checks as signing keys.
    pub fn from_token_file(peers: Vec<IpAddr>, path: &Path) -> Result<Self, CliError> {
        let mut secret = chio_control_plane::read_private_signing_custody(path, 513)?;
        if secret.last() == Some(&b'\n') {
            secret.pop();
        }
        Self::new(peers, secret)
    }
    fn new(peers: Vec<IpAddr>, secret: Zeroizing<Vec<u8>>) -> Result<Self, CliError> {
        if peers.is_empty()
            || peers.iter().any(IpAddr::is_unspecified)
            || !(32..=512).contains(&secret.len())
            || !secret.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CliError::cli_other_error(
                "trusted proxy requires explicit peer IPs and a dedicated 32-512 byte ASCII token"
                    .to_string(),
            ));
        }
        Ok(Self {
            peers: peers.into_iter().collect(),
            secret: Arc::new(secret),
        })
    }
    pub(crate) fn validate_separation(
        &self,
        config: &RemoteServeHttpConfig,
    ) -> Result<(), CliError> {
        for token in [
            &config.auth_token,
            &config.admin_token,
            &config.control_token,
            &config.remote_authority_workload_token,
            &config.auth_introspection_client_secret,
        ]
        .into_iter()
        .flatten()
        {
            if bool::from(self.secret.as_slice().ct_eq(token.as_bytes())) {
                return Err(CliError::cli_other_error(
                    "trusted proxy token must be independent of other service credentials"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn fingerprint(&self) -> serde_json::Value {
        serde_json::json!({"peers":self.peers,"credential_sha256":crate::sha256_hex(self.secret.as_slice())})
    }
    fn authenticate(&self, request: &Request) -> Result<TransportIdentity, ProxyRejection> {
        let peer = request
            .extensions()
            .get::<ConnectInfo<chio_http_serve::CappedPeerAddr>>()
            .ok_or(ProxyRejection::Untrusted)?;
        if !self.peers.contains(&peer.0 .0.ip()) {
            return Err(ProxyRejection::Untrusted);
        }
        let token =
            single_header(request.headers(), PROXY_AUTH, 512)?.ok_or(ProxyRejection::Untrusted)?;
        if !bool::from(self.secret.as_slice().ct_eq(token.as_bytes())) {
            return Err(ProxyRejection::Untrusted);
        }
        Ok(TransportIdentity {
            mtls: single_header(
                request.headers(),
                CHIO_MTLS_THUMBPRINT_HEADER,
                MAX_IDENTITY_BYTES,
            )?
            .map(str::to_owned),
            attestation: single_header(
                request.headers(),
                CHIO_RUNTIME_ATTESTATION_HEADER,
                MAX_IDENTITY_BYTES,
            )?
            .map(str::to_owned),
        })
    }
}

#[derive(Clone)]
pub(crate) struct TransportIdentity {
    mtls: Option<String>,
    attestation: Option<String>,
}
impl TransportIdentity {
    pub(crate) fn mtls(&self) -> Option<&str> {
        self.mtls.as_deref()
    }
    pub(crate) fn attestation(&self) -> Option<&str> {
        self.attestation.as_deref()
    }
}

/// Carries provenance alongside the headers without exposing an identity constructor.
#[derive(Clone, Copy)]
pub(crate) struct SenderRequest<'a> {
    headers: &'a HeaderMap,
    transport: Option<&'a TransportIdentity>,
}
impl<'a> SenderRequest<'a> {
    pub(crate) fn from_request(request: &'a Request) -> Self {
        Self {
            headers: request.headers(),
            transport: request.extensions().get(),
        }
    }
    pub(crate) fn from_extension(
        headers: &'a HeaderMap,
        transport: Option<&'a TransportIdentity>,
    ) -> Self {
        Self { headers, transport }
    }
    pub(crate) fn transport(self) -> Option<&'a TransportIdentity> {
        self.transport
    }
}
impl<'a> From<&'a HeaderMap> for SenderRequest<'a> {
    fn from(headers: &'a HeaderMap) -> Self {
        Self {
            headers,
            transport: None,
        }
    }
}
impl std::ops::Deref for SenderRequest<'_> {
    type Target = HeaderMap;
    fn deref(&self) -> &Self::Target {
        self.headers
    }
}

#[derive(Debug, thiserror::Error)]
enum ProxyRejection {
    #[error("urn:chio:error:transport:untrusted-proxy")]
    Untrusted,
    #[error("urn:chio:error:transport:invalid-proxy-header")]
    Header(#[from] axum::http::header::ToStrError),
}
fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
    bound: usize,
) -> Result<Option<&'a str>, ProxyRejection> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ProxyRejection::Untrusted);
    }
    let value = value.to_str()?;
    if value.is_empty() || value.len() > bound || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(ProxyRejection::Untrusted);
    }
    Ok(Some(value))
}

pub(crate) async fn authenticate_proxy(
    State(config): State<Option<TrustedProxyConfig>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Clear any preexisting extension before admitting this network boundary.
    request.extensions_mut().remove::<TransportIdentity>();
    let claims_identity = [
        PROXY_AUTH,
        CHIO_MTLS_THUMBPRINT_HEADER,
        CHIO_RUNTIME_ATTESTATION_HEADER,
    ]
    .iter()
    .any(|name| request.headers().contains_key(*name));
    if claims_identity {
        let identity = match config
            .as_ref()
            .ok_or(ProxyRejection::Untrusted)
            .and_then(|config| config.authenticate(&request))
        {
            Ok(identity) => identity,
            Err(error) => {
                return crate::input::with_source(
                    (StatusCode::UNAUTHORIZED, error.to_string()).into_response(),
                    error,
                )
            }
        };
        request.extensions_mut().insert(identity);
    }
    for name in [
        PROXY_AUTH,
        CHIO_MTLS_THUMBPRINT_HEADER,
        CHIO_RUNTIME_ATTESTATION_HEADER,
    ] {
        request.headers_mut().remove(name);
    }
    next.run(request).await
}

#[cfg(test)]
#[path = "transport_identity_tests.rs"]
mod tests;
