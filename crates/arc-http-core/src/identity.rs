//! Caller identity and authentication method types.

use serde::{Deserialize, Serialize};

/// How the caller authenticated to the upstream API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthMethod {
    /// Bearer token (JWT or opaque).
    Bearer {
        /// SHA-256 hash of the token value (never store raw tokens).
        token_hash: String,
    },
    /// API key in a header or query parameter.
    ApiKey {
        /// Name of the header or query parameter carrying the key.
        key_name: String,
        /// SHA-256 hash of the key value.
        key_hash: String,
    },
    /// Session cookie.
    Cookie {
        /// Cookie name.
        cookie_name: String,
        /// SHA-256 hash of the cookie value.
        cookie_hash: String,
    },
    /// mTLS client certificate.
    MtlsCertificate {
        /// Subject DN from the client certificate.
        subject_dn: String,
        /// SHA-256 fingerprint of the certificate.
        fingerprint: String,
    },
    /// No authentication was presented.
    Anonymous,
}

/// The identity of the caller as extracted from the HTTP request.
/// This is protocol-agnostic -- the same type is used regardless of
/// whether the request came through a reverse proxy, framework middleware,
/// or sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerIdentity {
    /// Stable identifier for the caller (e.g., user ID, service account, agent ID).
    /// Extracted from the auth credential.
    pub subject: String,

    /// How the caller authenticated.
    pub auth_method: AuthMethod,

    /// Whether this identity has been verified (e.g., JWT signature checked,
    /// API key looked up). False means the identity was extracted but not
    /// cryptographically validated.
    #[serde(default)]
    pub verified: bool,

    /// Optional tenant or organization the caller belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,

    /// Optional agent identifier when the caller is an AI agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

impl CallerIdentity {
    /// Create an anonymous caller identity.
    #[must_use]
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_string(),
            auth_method: AuthMethod::Anonymous,
            verified: false,
            tenant: None,
            agent_id: None,
        }
    }

    /// Compute a stable hash of this identity for inclusion in receipts.
    /// Uses SHA-256 over the canonical JSON representation.
    pub fn identity_hash(&self) -> arc_core_types::Result<String> {
        let bytes = arc_core_types::canonical_json_bytes(self)?;
        Ok(arc_core_types::sha256_hex(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_identity() {
        let id = CallerIdentity::anonymous();
        assert_eq!(id.subject, "anonymous");
        assert!(!id.verified);
        assert!(matches!(id.auth_method, AuthMethod::Anonymous));
    }

    #[test]
    fn identity_hash_deterministic() {
        let id = CallerIdentity {
            subject: "user-123".to_string(),
            auth_method: AuthMethod::Bearer {
                token_hash: "abc123".to_string(),
            },
            verified: true,
            tenant: Some("acme".to_string()),
            agent_id: None,
        };
        let h1 = id.identity_hash().unwrap();
        let h2 = id.identity_hash().unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn serde_roundtrip() {
        let id = CallerIdentity {
            subject: "svc-agent".to_string(),
            auth_method: AuthMethod::ApiKey {
                key_name: "X-API-Key".to_string(),
                key_hash: "deadbeef".to_string(),
            },
            verified: true,
            tenant: None,
            agent_id: Some("agent-42".to_string()),
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: CallerIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.subject, "svc-agent");
        assert_eq!(back.agent_id.as_deref(), Some("agent-42"));
    }
}
