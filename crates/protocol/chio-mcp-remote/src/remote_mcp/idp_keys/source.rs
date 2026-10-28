//! The pinned key set of one provider record.

use std::sync::Arc;

use chio_core::crypto::{sign_canonical_with_backend_for_identity, PublicKey, SigningBackend};
use chio_core::root_authority::idp_key_snapshot::IdpKeySnapshotSigningBody;
use chio_core::root_authority::{
    EnterpriseProviderIdentity, HttpsUrl, IdpKeySnapshot, IdpKeySnapshotFields, Jwk, JwsAlgorithm,
    KeySnapshotSource, ProviderRecordKind, RootAuthorityShapeError, Uri,
    CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};
use tokio::sync::Mutex;

use super::document::{admit_jwks_document, admit_keys, key_supports, JwksDocumentError};
use super::fetch::{JwksFetchError, JwksFetcher};

pub const DEFAULT_MIN_FETCH_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_SCHEDULED_REFRESH_SECS: u64 = 900;
const MAX_SCHEDULED_REFRESH_SECS: u64 = 86_400;

/// Fetch spacing and key-set lifetime for a fetched source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    min_fetch_interval_secs: u64,
    scheduled_refresh_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefreshPolicyError {
    #[error("JWKS fetch interval {0} s is below {DEFAULT_MIN_FETCH_INTERVAL_SECS} s")]
    FetchIntervalTooShort(u64),
    #[error("scheduled JWKS refresh {0} s is outside the fetch interval..={MAX_SCHEDULED_REFRESH_SECS} s")]
    ScheduledRefreshOutOfRange(u64),
}

impl RefreshPolicy {
    /// `min_fetch_interval_secs` is at least 60; `scheduled_refresh_secs` lies
    /// between it and one day.
    pub fn new(
        min_fetch_interval_secs: u64,
        scheduled_refresh_secs: u64,
    ) -> Result<Self, RefreshPolicyError> {
        if min_fetch_interval_secs < DEFAULT_MIN_FETCH_INTERVAL_SECS {
            return Err(RefreshPolicyError::FetchIntervalTooShort(
                min_fetch_interval_secs,
            ));
        }
        if !(min_fetch_interval_secs..=MAX_SCHEDULED_REFRESH_SECS).contains(&scheduled_refresh_secs)
        {
            return Err(RefreshPolicyError::ScheduledRefreshOutOfRange(
                scheduled_refresh_secs,
            ));
        }
        Ok(Self {
            min_fetch_interval_secs,
            scheduled_refresh_secs,
        })
    }

    #[must_use]
    pub const fn min_fetch_interval_secs(&self) -> u64 {
        self.min_fetch_interval_secs
    }

    #[must_use]
    pub const fn scheduled_refresh_secs(&self) -> u64 {
        self.scheduled_refresh_secs
    }
}

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            min_fetch_interval_secs: DEFAULT_MIN_FETCH_INTERVAL_SECS,
            scheduled_refresh_secs: DEFAULT_SCHEDULED_REFRESH_SECS,
        }
    }
}

/// The exchange signing backend and the exchange key it must sign as.
#[derive(Clone)]
pub struct ExchangeSigner {
    pub backend: Arc<dyn SigningBackend>,
    pub key: PublicKey,
}

impl ExchangeSigner {
    /// Sign a `chio.idp-key-snapshot.v1` over `keys` as observed at `observed_at`.
    fn sign_snapshot(
        &self,
        issuer: &Uri,
        source: &KeySnapshotSource,
        keys: Vec<Jwk>,
        observed_at: u64,
    ) -> Result<IdpKeySnapshot, KeyResolutionError> {
        let (outcome, _) = sign_canonical_with_backend_for_identity(
            self.backend.as_ref(),
            &self.key,
            &IdpKeySnapshotSigningBody {
                schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
                issuer,
                source,
                keys: &keys,
                observed_at,
                exchange_key: &self.key,
            },
        )
        .map_err(|_| SnapshotNotSigned)?;
        IdpKeySnapshot::new(IdpKeySnapshotFields {
            schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA.to_owned(),
            issuer: issuer.clone(),
            source: source.clone(),
            keys,
            observed_at,
            exchange_key: self.key.clone(),
            signature: outcome.signature,
        })
        .map_err(KeyResolutionError::SnapshotInvalid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("identity-provider key snapshot could not be signed by the exchange key")]
pub struct SnapshotNotSigned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("identity-provider key snapshot was not recorded")]
pub struct SnapshotNotRecorded;

/// Records each key-set change before the new set is used.
#[async_trait::async_trait]
pub trait KeySnapshotSink: Send + Sync {
    async fn record(&self, snapshot: &IdpKeySnapshot) -> Result<(), SnapshotNotRecorded>;
}

/// A key selected for one token, and the signed snapshot in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdpKey {
    pub key: Jwk,
    pub snapshot: Arc<IdpKeySnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyResolutionError {
    #[error("token `kid` is not in the pinned key set")]
    UnknownKid,
    #[error("pinned key declares a different `alg` than the token")]
    KeyAlgorithmMismatch,
    #[error("pinned key type cannot verify the token `alg`")]
    KeyTypeMismatch,
    #[error("no current key set and the next fetch is rate limited")]
    KeySetUnavailable,
    #[error(transparent)]
    Fetch(#[from] JwksFetchError),
    #[error(transparent)]
    Document(#[from] JwksDocumentError),
    #[error(transparent)]
    SnapshotNotSigned(#[from] SnapshotNotSigned),
    #[error("key snapshot is malformed: {0}")]
    SnapshotInvalid(RootAuthorityShapeError),
    #[error(transparent)]
    SnapshotNotRecorded(#[from] SnapshotNotRecorded),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdpKeySourceError {
    #[error("provider record is not an `oidc_jwks` record with one key source")]
    NotAJwksRecord,
    #[error(transparent)]
    Document(#[from] JwksDocumentError),
    #[error("provider id cannot name a registry key snapshot source: {0}")]
    UnrepresentableProviderId(RootAuthorityShapeError),
}

enum Origin {
    Fetched {
        url: HttpsUrl,
        fetcher: Arc<dyn JwksFetcher>,
    },
    Inline(Vec<Jwk>),
}

struct KeySet {
    snapshot: Arc<IdpKeySnapshot>,
    fetched_at: u64,
}

impl KeySet {
    fn find(&self, kid: &str) -> Option<&Jwk> {
        self.snapshot
            .keys
            .iter()
            .find(|key| key.kid.as_str() == kid)
    }
}

#[derive(Default)]
struct KeyState {
    current: Option<KeySet>,
    last_attempt: Option<u64>,
    /// The last refresh failed or was cancelled. No key resolves until a
    /// refresh succeeds and its set is recorded.
    refresh_failed: bool,
}

impl KeyState {
    /// `now`, raised to the last fetch attempt so that attempts and
    /// `observed_at` never move backwards for one source.
    fn not_before(&self, now: u64) -> u64 {
        self.last_attempt.map_or(now, |attempt| now.max(attempt))
    }
}

/// The keys of one provider record: fetched from its pinned `jwks_url`, or
/// fixed by its inline `jwks`. Hold one instance per issuer; the fetch rate
/// limit is per instance.
pub struct PinnedIdpKeys {
    issuer: Uri,
    source: KeySnapshotSource,
    origin: Origin,
    policy: RefreshPolicy,
    signer: ExchangeSigner,
    sink: Arc<dyn KeySnapshotSink>,
    state: Mutex<KeyState>,
}

impl PinnedIdpKeys {
    /// Build the key source a validated `oidc_jwks` provider record pins.
    /// Nothing is fetched or recorded until the first resolution.
    pub fn from_provider(
        identity: &EnterpriseProviderIdentity,
        fetcher: Arc<dyn JwksFetcher>,
        signer: ExchangeSigner,
        sink: Arc<dyn KeySnapshotSink>,
        policy: RefreshPolicy,
    ) -> Result<Self, IdpKeySourceError> {
        let (source, origin) = match (identity.kind, &identity.jwks_url, &identity.jwks) {
            (ProviderRecordKind::OidcJwks, Some(url), None) => (
                KeySnapshotSource::JwksUrl(url.clone()),
                Origin::Fetched {
                    url: url.clone(),
                    fetcher,
                },
            ),
            (ProviderRecordKind::OidcJwks, None, Some(inline)) => (
                KeySnapshotSource::parse(&format!("registry:{}", identity.provider_id))
                    .map_err(IdpKeySourceError::UnrepresentableProviderId)?,
                Origin::Inline(admit_keys(inline.keys.clone())?),
            ),
            _ => return Err(IdpKeySourceError::NotAJwksRecord),
        };
        Ok(Self {
            issuer: identity.issuer.clone(),
            source,
            origin,
            policy,
            signer,
            sink,
            state: Mutex::new(KeyState::default()),
        })
    }

    /// Select the key `kid` for a token signed with `alg` at `now` (Unix
    /// seconds). A stale set is refetched first; an unknown `kid` triggers at
    /// most one refetch.
    pub async fn resolve(
        &self,
        kid: &str,
        alg: JwsAlgorithm,
        now: u64,
    ) -> Result<ResolvedIdpKey, KeyResolutionError> {
        let mut state = self.state.lock().await;
        let now = state.not_before(now);
        let mut installed = false;
        if !self.is_current(&state, now) {
            if !self.may_fetch(&state, now) {
                return Err(KeyResolutionError::KeySetUnavailable);
            }
            self.install(&mut state, now).await?;
            installed = true;
        }
        let known = state
            .current
            .as_ref()
            .is_some_and(|set| set.find(kid).is_some());
        if !known {
            let fetched = matches!(self.origin, Origin::Fetched { .. });
            if installed || !fetched || !self.may_fetch(&state, now) {
                return Err(KeyResolutionError::UnknownKid);
            }
            self.install(&mut state, now).await?;
        }
        let set = state
            .current
            .as_ref()
            .ok_or(KeyResolutionError::KeySetUnavailable)?;
        let key = set.find(kid).ok_or(KeyResolutionError::UnknownKid)?;
        if key.alg.is_some_and(|key_alg| key_alg != alg) {
            return Err(KeyResolutionError::KeyAlgorithmMismatch);
        }
        if !key_supports(key, alg) {
            return Err(KeyResolutionError::KeyTypeMismatch);
        }
        Ok(ResolvedIdpKey {
            key: key.clone(),
            snapshot: Arc::clone(&set.snapshot),
        })
    }

    /// Run the scheduled refresh when the set has outlived
    /// `scheduled_refresh_secs`, so withdrawn keys leave the set.
    pub async fn refresh_if_due(&self, now: u64) -> Result<(), KeyResolutionError> {
        let mut state = self.state.lock().await;
        let now = state.not_before(now);
        if self.is_current(&state, now) {
            return Ok(());
        }
        if !self.may_fetch(&state, now) {
            return Err(KeyResolutionError::KeySetUnavailable);
        }
        self.install(&mut state, now).await
    }

    fn is_current(&self, state: &KeyState, now: u64) -> bool {
        if state.refresh_failed {
            return false;
        }
        match (&state.current, &self.origin) {
            (None, _) => false,
            (Some(_), Origin::Inline(_)) => true,
            (Some(set), Origin::Fetched { .. }) => {
                now < set
                    .fetched_at
                    .saturating_add(self.policy.scheduled_refresh_secs)
            }
        }
    }

    fn may_fetch(&self, state: &KeyState, now: u64) -> bool {
        state.last_attempt.is_none_or(|attempt| {
            now >= attempt.saturating_add(self.policy.min_fetch_interval_secs)
        })
    }

    /// Obtain the key set and install it; a changed set is signed and recorded first.
    async fn install(&self, state: &mut KeyState, now: u64) -> Result<(), KeyResolutionError> {
        state.last_attempt = Some(now);
        state.refresh_failed = true;
        let keys = match &self.origin {
            Origin::Fetched { url, fetcher } => admit_jwks_document(&fetcher.fetch(url).await?)?,
            Origin::Inline(keys) => keys.clone(),
        };
        if let Some(current) = state
            .current
            .as_mut()
            .filter(|set| set.snapshot.keys == keys)
        {
            current.fetched_at = now;
            state.refresh_failed = false;
            return Ok(());
        }
        let snapshot = self
            .signer
            .sign_snapshot(&self.issuer, &self.source, keys, now)?;
        self.sink.record(&snapshot).await?;
        state.current = Some(KeySet {
            snapshot: Arc::new(snapshot),
            fetched_at: now,
        });
        state.refresh_failed = false;
        Ok(())
    }
}
