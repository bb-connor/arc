use std::fmt;

use zeroize::Zeroizing;

use crate::backend::SecretMaterial;
use crate::protocol::{BrokerRequest, HeaderField, RequestConstraints};
use crate::{validate_identifier, BrokerError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialPlacement {
    BearerAuthorization,
    ApiKeyHeader,
}

pub(crate) struct SecretHeader {
    name: String,
    value: Zeroizing<Vec<u8>>,
}

impl SecretHeader {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl fmt::Debug for SecretHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

pub(crate) struct PreparedProviderRequest {
    pub(crate) caller: BrokerRequest,
    pub(crate) secret_headers: Vec<SecretHeader>,
}

impl fmt::Debug for PreparedProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedProviderRequest")
            .field("destination", &self.caller.destination)
            .field("caller_header_count", &self.caller.headers.len())
            .field("body_bytes", &self.caller.body.len())
            .field("secret_headers", &"<redacted>")
            .finish()
    }
}

pub(crate) trait ProviderAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn adapter_version(&self) -> u32;
    fn prepare(
        &self,
        request: &BrokerRequest,
        constraints: &RequestConstraints,
        credential: &SecretMaterial,
    ) -> Result<PreparedProviderRequest>;
}

pub struct GenericCredentialProvider {
    adapter_id: String,
    adapter_version: u32,
    placement: CredentialPlacement,
}

impl GenericCredentialProvider {
    pub fn new(
        adapter_id: String,
        adapter_version: u32,
        placement: CredentialPlacement,
    ) -> Result<Self> {
        validate_identifier(&adapter_id, "provider adapter id", 512)?;
        if adapter_version == 0 {
            return Err(BrokerError::InvalidRequest(
                "provider adapter identity is invalid".to_string(),
            ));
        }
        Ok(Self {
            adapter_id,
            adapter_version,
            placement,
        })
    }

    fn owned_header(&self) -> &'static str {
        match self.placement {
            CredentialPlacement::BearerAuthorization => "authorization",
            CredentialPlacement::ApiKeyHeader => "x-api-key",
        }
    }
}

impl ProviderAdapter for GenericCredentialProvider {
    fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    fn prepare(
        &self,
        request: &BrokerRequest,
        constraints: &RequestConstraints,
        credential: &SecretMaterial,
    ) -> Result<PreparedProviderRequest> {
        let owned = self.owned_header();
        if constraints.provider_owned_headers != [owned.to_string()] {
            return Err(BrokerError::AuthorizationDenied(
                "signed provider-owned header set does not match the adapter".to_string(),
            ));
        }
        if request.headers.iter().any(|header| header.name == owned) {
            return Err(BrokerError::AuthorizationDenied(
                "caller attempted to supply a provider-owned header".to_string(),
            ));
        }
        let mut value = Zeroizing::new(Vec::new());
        if self.placement == CredentialPlacement::BearerAuthorization {
            value.extend_from_slice(b"Bearer ");
        }
        value.extend_from_slice(credential.as_bytes());
        if credential
            .as_bytes()
            .iter()
            .any(|byte| !matches!(*byte, b'!'..=b'~'))
        {
            return Err(BrokerError::InvalidRequest(
                "credential cannot be represented by the reviewed provider scheme".to_string(),
            ));
        }
        Ok(PreparedProviderRequest {
            caller: request.clone(),
            secret_headers: vec![SecretHeader {
                name: owned.to_string(),
                value,
            }],
        })
    }
}

pub(crate) fn rejects_forbidden_caller_header(header: &HeaderField) -> bool {
    matches!(
        header.name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "host"
            | "content-length"
            | "accept-encoding"
            | "expect"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_request_debug_redacts_injected_header() {
        let provider = GenericCredentialProvider::new(
            "generic-bearer".to_string(),
            1,
            CredentialPlacement::BearerAuthorization,
        )
        .expect("provider");
        let request = BrokerRequest {
            destination: crate::protocol::BrokerDestination::parse(
                "https://example.com/",
                "GET",
                false,
            )
            .expect("destination"),
            headers: Vec::new(),
            body: Vec::new(),
            approved_preview_sha256: None,
            options: crate::protocol::CallerOptions {
                timeout_ms: 100,
                streaming: false,
                response_limit_bytes: 100,
            },
        };
        let constraints = RequestConstraints {
            allowed_caller_headers: Vec::new(),
            provider_owned_headers: vec!["authorization".to_string()],
            maximum_body_bytes: 0,
            required_body_sha256: crate::proof::body_digest(&[]),
            required_preview_sha256: None,
            redirect_policy: crate::protocol::RedirectPolicy::Disabled,
            maximum_response_bytes: 100,
            streaming_allowed: false,
            maximum_timeout_ms: 100,
        };
        let credential = SecretMaterial::new(b"unique-provider-canary".to_vec());
        let prepared = provider
            .prepare(&request, &constraints, &credential)
            .expect("prepare");
        assert!(!format!("{prepared:?}").contains("unique-provider-canary"));
    }
}
