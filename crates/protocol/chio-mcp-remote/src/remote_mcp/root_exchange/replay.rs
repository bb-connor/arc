//! Replay keys of the root exchange.

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::Sha256Digest;
use chio_core::Sha256State;

const REPLAY_KEY_DOMAIN: &[u8] = b"chio.root-exchange.replay-key.v1\0";

/// What a replay key is unique within.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplayNamespace {
    /// An identity-provider assertion of one anchor kind.
    Assertion(AnchorKind),
    /// A `private_key_jwt` client assertion.
    ClientAssertion,
    /// A local authorization code redeemed for its root; apart from the
    /// issued token's `jti`, which its one re-exchange spends.
    LocalAsIssue,
}

impl ReplayNamespace {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assertion(kind) => kind.as_str(),
            Self::ClientAssertion => "client_assertion",
            Self::LocalAsIssue => "chio_local_as_issue",
        }
    }
}

/// `(namespace, issuer, id)`: one use per key. Neither part holds a NUL,
/// so [`Self::digest`] is injective.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplayKey {
    namespace: ReplayNamespace,
    issuer: String,
    id: String,
}

/// Why a replay key cannot be formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayKeyError {
    #[error("replay key issuer for {} contains a NUL byte", .0.as_str())]
    IssuerContainsNul(ReplayNamespace),
    #[error("replay key id for {} contains a NUL byte", .0.as_str())]
    IdContainsNul(ReplayNamespace),
}

impl ReplayKeyError {
    #[must_use]
    pub const fn namespace(self) -> ReplayNamespace {
        match self {
            Self::IssuerContainsNul(namespace) | Self::IdContainsNul(namespace) => namespace,
        }
    }
}

impl ReplayKey {
    /// The key of `id` from `issuer` within `namespace`. A NUL in either
    /// part refuses.
    pub fn new(
        namespace: ReplayNamespace,
        issuer: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, ReplayKeyError> {
        let issuer = issuer.into();
        if issuer.contains('\0') {
            return Err(ReplayKeyError::IssuerContainsNul(namespace));
        }
        let id = id.into();
        if id.contains('\0') {
            return Err(ReplayKeyError::IdContainsNul(namespace));
        }
        Ok(Self {
            namespace,
            issuer,
            id,
        })
    }

    #[must_use]
    pub fn namespace(&self) -> ReplayNamespace {
        self.namespace
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `SHA-256(domain || namespace || 0x00 || issuer || 0x00 || id)`.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let mut state = Sha256State::new();
        state.update(REPLAY_KEY_DOMAIN);
        state.update(self.namespace.as_str().as_bytes());
        state.update(&[0]);
        state.update(self.issuer.as_bytes());
        state.update(&[0]);
        state.update(self.id.as_bytes());
        Sha256Digest::from_hash(state.finalize())
    }
}

/// Outcome of binding a replay key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayBinding {
    /// The key was unused and is now bound.
    Bound,
    /// The key is already bound and its retention has not ended.
    AlreadyBound,
}

/// Why a replay store could not bind a key. The adapter logs its backend
/// detail; none of it crosses this port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("replay store is unavailable")]
    Unavailable,
    #[error("replay store is busy")]
    Busy,
    #[error("replay store state is corrupt")]
    Corrupt,
}

/// Durable single-use replay keys. A binding is retained until
/// `retain_until` (Unix seconds); a store error denies the exchange.
pub trait ExchangeReplayStore: Send + Sync {
    fn bind(
        &self,
        key: &ReplayKey,
        retain_until: u64,
        now: u64,
    ) -> Result<ReplayBinding, ReplayStoreError>;
}
