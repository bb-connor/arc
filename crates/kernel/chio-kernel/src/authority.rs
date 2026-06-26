use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence,
    scope::ChioScope,
    token::{
        window_scoped_capability_id, AttestationWindowId, CapabilityToken, CapabilityTokenBody,
    },
};
use chio_core::crypto::{Keypair, PublicKey};
use uuid::Uuid;

use crate::KernelError;

pub trait CapabilityAuthority: Send + Sync {
    fn authority_public_key(&self) -> PublicKey;

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.authority_public_key()]
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError>;

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        _runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability(subject, scope, ttl_seconds)
    }

    /// Mint a Pass capability token whose id is the deterministic, window-scoped
    /// `chiopass:<hash>` (see [`window_scoped_capability_id`]) instead of a fresh
    /// UUIDv7, so a Pass re-presented within the same attestation window maps to a
    /// single `(capability_id, grant_index = 0)` budget row and re-minting cannot
    /// reset the free-tier counter.
    ///
    /// This is a fail-closed default: an authority that does not issue Passes
    /// rejects the request, so no other `CapabilityAuthority` implementation can
    /// silently mint a non-canonical id. `LocalCapabilityAuthority` overrides it.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::CapabilityIssuanceFailed`] unconditionally in the
    /// default.
    fn issue_window_scoped_capability(
        &self,
        _subject: &PublicKey,
        _subject_did: &str,
        _scope: ChioScope,
        _window: &AttestationWindowId,
    ) -> Result<CapabilityToken, KernelError> {
        Err(KernelError::CapabilityIssuanceFailed(
            "window-scoped Pass issuance unsupported by this authority".to_string(),
        ))
    }
}

pub struct LocalCapabilityAuthority {
    keypair: Keypair,
}

impl LocalCapabilityAuthority {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl CapabilityAuthority for LocalCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let body = CapabilityTokenBody {
            id: format!("cap-{}", Uuid::now_v7()),
            issuer: self.keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
        };

        CapabilityToken::sign(body, &self.keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }

    /// Mint the canonical window-scoped Pass capability token. This is the choke
    /// point that replaces the UUIDv7 stamp in [`Self::issue_capability`] for the
    /// Pass path: `token.id` is the deterministic `chiopass:<hash>` derived from
    /// `(subject_did, window)`, the single metered grant is pinned at index 0, and
    /// `issued_at`/`expires_at` are pinned to the attestation-window boundaries so
    /// window expiry is the monthly reset.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::CapabilityIssuanceFailed`], fail-closed at every
    /// branch, on a malformed window, a scope that does not carry exactly one
    /// metered grant, a capability-id derivation failure, or a signing failure.
    fn issue_window_scoped_capability(
        &self,
        subject: &PublicKey,
        subject_did: &str,
        scope: ChioScope,
        window: &AttestationWindowId,
    ) -> Result<CapabilityToken, KernelError> {
        window
            .validate()
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        if scope.grants.len() != 1 {
            return Err(KernelError::CapabilityIssuanceFailed(
                "Pass scope must carry exactly one metered grant pinned at index 0".to_string(),
            ));
        }
        let id = window_scoped_capability_id(subject_did, window)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))?;
        let body = CapabilityTokenBody {
            id,
            issuer: self.keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: window.since,
            expires_at: window.until,
            delegation_chain: vec![],
        };
        CapabilityToken::sign(body, &self.keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub public_key: PublicKey,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustedKeySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub activated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_keys: Vec<AuthorityTrustedKeySnapshot>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare authority store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid authority seed: {0}")]
    Core(#[from] chio_core::error::Error),

    #[error("authority fence rejected mutation: {0}")]
    Fence(String),
}

#[cfg(test)]
mod m0_pass_mint_tests {
    use super::*;
    use chio_core::capability::scope::{ChioScope, ToolGrant};

    fn window() -> AttestationWindowId {
        AttestationWindowId {
            window_ym: "2026-06".to_string(),
            since: 1_780_704_000,
            until: 1_783_296_000,
        }
    }

    fn pass_scope() -> ChioScope {
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "chio.pass.compute".to_string(),
                tool_name: "run".to_string(),
                operations: vec![],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        }
    }

    #[test]
    fn mints_deterministic_window_scoped_pass() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let subject = Keypair::generate().public_key();
        let w = window();
        let a = authority
            .issue_window_scoped_capability(&subject, "did:chio:alice", pass_scope(), &w)
            .unwrap();
        assert!(a.id.starts_with("chiopass:"));
        assert_eq!(a.issued_at, w.since);
        assert_eq!(a.expires_at, w.until);
        assert!(a.verify_signature().unwrap());

        let b = authority
            .issue_window_scoped_capability(&subject, "did:chio:alice", pass_scope(), &w)
            .unwrap();
        assert_eq!(
            a.id, b.id,
            "a re-mint in the same window must reuse the id so charges hit one budget row"
        );
    }

    #[test]
    fn rejects_malformed_window() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let subject = Keypair::generate().public_key();
        let mut w = window();
        w.window_ym = String::new();
        assert!(authority
            .issue_window_scoped_capability(&subject, "did:chio:alice", pass_scope(), &w)
            .is_err());
    }

    #[test]
    fn rejects_scope_without_exactly_one_grant() {
        let authority = LocalCapabilityAuthority::new(Keypair::generate());
        let subject = Keypair::generate().public_key();
        assert!(authority
            .issue_window_scoped_capability(
                &subject,
                "did:chio:alice",
                ChioScope::default(),
                &window()
            )
            .is_err());
    }

    #[test]
    fn trait_default_is_fail_closed() {
        struct Stub(Keypair);
        impl CapabilityAuthority for Stub {
            fn authority_public_key(&self) -> PublicKey {
                self.0.public_key()
            }
            fn issue_capability(
                &self,
                _subject: &PublicKey,
                _scope: ChioScope,
                _ttl_seconds: u64,
            ) -> Result<CapabilityToken, KernelError> {
                Err(KernelError::CapabilityIssuanceFailed("stub".to_string()))
            }
        }
        let stub = Stub(Keypair::generate());
        let subject = Keypair::generate().public_key();
        assert!(stub
            .issue_window_scoped_capability(&subject, "did:chio:alice", pass_scope(), &window())
            .is_err());
    }
}
