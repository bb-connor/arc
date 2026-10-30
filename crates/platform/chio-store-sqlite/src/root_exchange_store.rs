//! Root exchange state under the serving authority.
//!
//! The exchange mints an anchored root in one immediate transaction behind the
//! serving fence: the revocation check, the replay binding, the root row with
//! its authorization projection, the context openings, the bearer mapping, the
//! retained policy, provider identity and key snapshot, and one event covered
//! by the global authority commit chain. A root is returned only from a
//! transaction that began on an anchor equal to the chain head, so a root the
//! anchor does not yet cover is never handed out.

use std::sync::Arc;

use chio_core::capability::token::CapabilityToken;
use chio_core::root_authority::{
    DelegationContext, EnterpriseProviderIdentity, IdpKeySnapshot, LoadedRootPolicy, SaltRef,
    Sha256Digest,
};
use chio_core::tenant_index::KeyedIndexValue;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::RevocationStoreError;
use rusqlite::{params, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::admission_operation_store::{authority_validation_time, verify_active_owner};
use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};
use crate::store_connection::{StoreConnection, StoreGuard};

mod bindings;
mod maintenance;
mod mint;
mod projection;
mod reads;
mod schema;
mod tenant_index;

pub use tenant_index::{RootTagInputs, RootTenantIndex};

pub(crate) use schema::{
    initialize_root_exchange_schema, projection_reference, verify_projection_coverage,
    verify_root_exchange_invariants, PROJECTION,
};

/// The refusal text for a stored tag generation the loaded key set lacks.
pub const TAG_GENERATION_MISSING: &str = "tenant index key does not match the state directory";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootExchangeStoreError {
    #[error("assertion replay")]
    AssertionReplay,
    #[error("anchored root is revoked by entry {entry_id}")]
    Revoked { entry_id: String },
    #[error("revocation check is unavailable: {0}")]
    RevocationCheckUnavailable(RevocationCheckError),
    #[error("anchored root row missing for {capability_id}")]
    AnchoredRootMissing { capability_id: String },
    #[error("anchored root {capability_id} differs from its authorization projection")]
    AnchoredRootTampered { capability_id: String },
    #[error("anchored root {capability_id} has expired")]
    AnchoredRootExpired { capability_id: String },
    #[error("anchored root {capability_id} was minted under another root policy")]
    RootPolicyChanged { capability_id: String },
    #[error("anchored root {capability_id} was minted under another provider identity")]
    ProviderIdentityChanged { capability_id: String },
    #[error("retained {kind} bytes differ from their digest")]
    RetainedDigestMismatch { kind: RetainedArtifact },
    #[error("retained {kind} {digest} is absent")]
    RetainedArtifactMissing {
        kind: RetainedArtifact,
        digest: Sha256Digest,
    },
    #[error("delegation context {digest} is absent")]
    DelegationContextMissing { digest: Sha256Digest },
    #[error("live replay binding {replay_key_digest} is missing before its retention ends")]
    ReplayBindingMissing { replay_key_digest: Sha256Digest },
    #[error("live replay binding {replay_key_digest} differs from its recorded binding")]
    ReplayBindingMismatch { replay_key_digest: Sha256Digest },
    #[error("live bearer mapping {token_digest} is missing before its retention ends")]
    BearerMappingMissing { token_digest: Sha256Digest },
    #[error("live bearer mapping {token_digest} differs from its recorded mapping")]
    BearerMappingMismatch { token_digest: Sha256Digest },
    #[error("root opening {salt_ref} of {capability_id} is erased")]
    RootOpeningErased {
        capability_id: String,
        salt_ref: String,
    },
    #[error("{TAG_GENERATION_MISSING}")]
    TagGenerationMissing { key_id: Sha256Digest },
    #[error("tenant index key generation {key_id} referenced by a revocation entry is not loaded")]
    RevocationTagGenerationMissing { key_id: Sha256Digest },
    #[error("tenant index key {key_id} is not loaded")]
    TenantIndexKeyUnknown { key_id: Sha256Digest },
    #[error("root tags do not verify")]
    TagMismatch,
    #[error("root tag input {field} contains NUL")]
    TagInputContainsNul { field: &'static str },
    #[error("invalid mint request: {0}")]
    InvalidMintRequest(MintRequestRefusal),
    /// The change may have committed: the commit or the anchor sync after it
    /// failed, or the owner is poisoned by such a failure. Never a definite
    /// refusal, and never retried as a fresh mint.
    #[error("root exchange outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("root exchange store is unavailable: {0}")]
    Unavailable(String),
    #[error("root exchange store invariant failed: {0}")]
    Invalid(String),
}

type Result<T> = std::result::Result<T, RootExchangeStoreError>;

/// Why a mint request's members disagree with each other. Checked before
/// any durable step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintRequestRefusal {
    #[error("root capability id")]
    RootCapabilityId,
    #[error("client id")]
    ClientId,
    #[error("root capability has a delegation chain")]
    DelegationChain,
    #[error("root issuer is not the exchange key")]
    IssuerNotExchangeKey,
    #[error("root issuer is not in the policy exchange keys")]
    IssuerNotInPolicy,
    #[error("root policy is not valid now")]
    PolicyNotValid,
    #[error("root policy has no matched rule")]
    UnknownRule,
    #[error("rule anchor kind differs from the context")]
    RuleKindMismatch,
    #[error("root scope does not canonicalize")]
    ScopeNotCanonical,
    #[error("root scope hash differs from the context")]
    ScopeHashMismatch,
    #[error("root is already expired")]
    RootExpired,
    #[error("replay retention is already past")]
    ReplayRetentionPast,
    #[error("replay retention ends before the root")]
    ReplayRetentionShort,
    #[error("provider identity does not canonicalize")]
    ProviderIdentityNotCanonical,
    #[error("provider identity differs from the context")]
    ProviderIdentityMismatch,
    #[error("provider identity presence differs from the anchor kind")]
    ProviderIdentityPresence,
    #[error("key snapshot does not canonicalize")]
    KeySnapshotNotCanonical,
    #[error("key snapshot differs from the context")]
    KeySnapshotMismatch,
    #[error("artifact digest differs from the context")]
    ArtifactMismatch,
    #[error("context artifact digest presence differs from the anchor kind")]
    ArtifactDigestPresence,
    #[error("replay namespace is not admitted for the anchor kind")]
    ReplayNamespaceKind,
    #[error("root tags span two key generations")]
    TagsSpanGenerations,
    #[error("root tags are not among the loaded generations")]
    TagsNotLoaded,
    #[error("bearer mapping retention ends before the root")]
    BearerRetentionShort,
    #[error("duplicate context opening")]
    DuplicateOpening,
    #[error("context openings differ from the committed values")]
    OpeningsMismatch,
    #[error("delegation context does not canonicalize")]
    ContextNotCanonical,
}

/// An artifact retained by its recomputed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedArtifact {
    RootPolicy,
    ProviderIdentity,
    KeySnapshot,
}

impl std::fmt::Display for RetainedArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RootPolicy => "root policy",
            Self::ProviderIdentity => "provider identity",
            Self::KeySnapshot => "key snapshot",
        })
    }
}

/// Why the store refuses to open. Every variant leaves the rows in place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootExchangeIntegrityError {
    #[error("anchored root {capability_id} has no global commit")]
    RootWithoutGlobalCommit { capability_id: String },
    #[error("anchored root {capability_id} differs from its authorization projection")]
    RootTampered { capability_id: String },
    #[error("live replay binding {replay_key_digest} is missing before its retention ends")]
    ReplayBindingMissing { replay_key_digest: Sha256Digest },
    #[error("live replay binding {replay_key_digest} differs from its recorded binding")]
    ReplayBindingMismatch { replay_key_digest: Sha256Digest },
    #[error("live bearer mapping {token_digest} is missing before its retention ends")]
    BearerMappingMissing { token_digest: Sha256Digest },
    #[error("live bearer mapping {token_digest} differs from its recorded mapping")]
    BearerMappingMismatch { token_digest: Sha256Digest },
    #[error("root opening of {capability_id} has no anchored root")]
    OpeningWithoutRoot { capability_id: String },
    #[error("root opening of {capability_id} is present after its recorded erasure")]
    ErasedOpeningPresent { capability_id: String },
    #[error("retained {kind} bytes differ from their digest")]
    RetainedDigestMismatch { kind: RetainedArtifact },
    #[error("root exchange store is unreadable: {0}")]
    Unreadable(String),
}

/// The keyed tags of one root. Both values are derived under one tenant
/// index key generation, so both carry the same `key_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootTags {
    pub subject: KeyedIndexValue,
    pub tenant: KeyedIndexValue,
}

impl RootTags {
    /// The generation both tags were derived under.
    #[must_use]
    pub fn key_id(&self) -> Sha256Digest {
        self.subject.key_id
    }
}

/// The salt of one committed delegation-context value.
#[derive(Clone, PartialEq, Eq)]
pub struct ContextOpening {
    pub salt_ref: SaltRef,
    pub salt: [u8; 32],
}

impl std::fmt::Debug for ContextOpening {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContextOpening")
            .field("salt_ref", &self.salt_ref)
            .finish_non_exhaustive()
    }
}

/// Bearer intake maps a token digest to the root it produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BearerMapping {
    pub token_digest: Sha256Digest,
    /// `max(root expires_at, token exp) + 60`.
    pub retain_until: u64,
}

/// The revocation targets of a root the mint transaction is about to issue
/// or recover. `tag_candidates` holds the root's tags under every loaded
/// generation, so an entry recorded under a retired generation still matches.
pub struct RevocationCandidate<'a> {
    pub capability_id: &'a str,
    pub root_policy_rule_id: &'a str,
    pub replay_key_digest: &'a Sha256Digest,
    pub tag_candidates: &'a [RootTags],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRevocationRefusal {
    Revoked { entry_id: String },
    Unavailable(RevocationCheckError),
}

/// The revocation store error behind an unavailable mint check, kept typed
/// so a caller can match on the store's variant. Two errors are equal when
/// they render the same text, so two variants with identical text compare
/// equal; callers that need the variant match on `store_error()`.
#[derive(Debug, Clone)]
pub struct RevocationCheckError(Arc<RevocationStoreError>);

impl RevocationCheckError {
    #[must_use]
    pub fn new(error: RevocationStoreError) -> Self {
        Self(Arc::new(error))
    }

    #[must_use]
    pub fn store_error(&self) -> &RevocationStoreError {
        &self.0
    }
}

impl PartialEq for RevocationCheckError {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_string() == other.0.to_string()
    }
}

impl Eq for RevocationCheckError {}

impl std::fmt::Display for RevocationCheckError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Revocation linearized with the mint: the check runs inside the mint
/// transaction, so no entry can commit between the check and the root.
pub trait MintRevocationCheck {
    fn refuse_revoked_root(
        &self,
        transaction: &Transaction<'_>,
        candidate: &RevocationCandidate<'_>,
    ) -> std::result::Result<(), MintRevocationRefusal>;
}

/// What a mint's replay key is unique within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintReplayNamespace {
    /// The anchor kind's own namespace: the presented assertion, token or
    /// request, and for `chio_local_as` the re-exchanged subject token `jti`.
    AnchorKind,
    /// A `chio_local_as` authorization-code issuance, keyed by
    /// SHA-256 of the code.
    LocalAsIssue,
}

/// Everything one mint binds. The exchange signs `root` before the call.
pub struct MintRequest<'a> {
    pub root: &'a CapabilityToken,
    pub context: &'a DelegationContext,
    /// The loaded root policy the root was minted under.
    pub root_policy: &'a LoadedRootPolicy,
    /// The provider record's identity for provider-backed kinds.
    pub provider_identity: Option<&'a EnterpriseProviderIdentity>,
    pub key_snapshot: Option<&'a IdpKeySnapshot>,
    pub tags: RootTags,
    pub tag_candidates: &'a [RootTags],
    /// The authenticated client, or `bearer_intake` for bearer tokens.
    pub client_id: &'a str,
    /// SHA-256 of the presented assertion or token.
    pub artifact_digest: Sha256Digest,
    pub replay_namespace: MintReplayNamespace,
    /// `exp + 60`, past which the replay key may bind again.
    pub replay_retain_until: u64,
    pub openings: &'a [ContextOpening],
    pub bearer: Option<BearerMapping>,
}

/// A stored root that passed the row check on read.
#[derive(Debug, Clone)]
pub struct StoredRoot {
    pub capability: CapabilityToken,
    pub context: DelegationContext,
    pub tags: RootTags,
    pub root_policy_digest: Sha256Digest,
    pub minted_at: u64,
}

#[derive(Debug, Clone)]
pub enum MintOutcome {
    Minted(StoredRoot),
    /// The live replay binding already names this root for the same client,
    /// artifact and request.
    Recovered(StoredRoot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpeningState {
    Present([u8; 32]),
    Erased,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextOpenings {
    Known(Vec<(String, OpeningState)>),
    Unknown,
}

#[derive(Debug, Clone)]
pub enum BearerLookup {
    Live(Box<StoredRoot>),
    Expired { capability_id: String },
    Unknown,
}

#[derive(Clone, Copy)]
enum Mutation {
    Mint,
    ClientAssertion,
    EraseOpenings,
    KeySnapshot,
    Prune,
}

impl Mutation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::ClientAssertion => "client_assertion",
            Self::EraseOpenings => "erase_openings",
            Self::KeySnapshot => "key_snapshot",
            Self::Prune => "prune",
        }
    }
}

/// One committed change: the event subject and the digest its global
/// commit references.
struct Change {
    mutation: Mutation,
    subject: String,
    digest: String,
    replay: Option<bindings::ReplayRecord>,
    bearer: Option<bindings::BearerRecord>,
}

/// Serving-bound root exchange store. Construct it with
/// [`crate::SqliteAuthorityStore::root_exchange_store`].
pub struct SqliteRootExchangeStore {
    connection: Arc<StoreConnection>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteRootExchangeStore {
    pub(crate) fn open_alongside(
        connection: Arc<StoreConnection>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    fn connection(&self) -> Result<StoreGuard<'_>> {
        self.connection
            .lock()
            .map_err(|error| RootExchangeStoreError::Unavailable(error.to_string()))
    }

    fn read_only<T>(&self, read: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&tx, &self.serving_owner, None).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(&tx)
            .map_err(owner_error)?;
        read(&tx)
    }

    /// A read that judges expiry at the authority validation time.
    fn read_at<T>(
        &self,
        trusted_now_unix_ms: u64,
        read: impl FnOnce(&Transaction<'_>, u64) -> Result<T>,
    ) -> Result<T> {
        self.read_only(|tx| {
            let now = authority_validation_time(tx, trusted_now_unix_ms, &self.serving_owner)
                .map_err(unavailable)?
                / 1000;
            read(tx, now)
        })
    }

    /// Run one fenced mutation. The closure returns the change to commit, or
    /// `None` to commit nothing. A change is one event and one global commit.
    /// The closure's value is returned only after the commit and the anchor
    /// sync succeed.
    fn mutate<T>(
        &self,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        apply: impl FnOnce(&Transaction<'_>, u64) -> Result<(T, Option<Change>)>,
    ) -> Result<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (value, changed) = self.stage(&tx, fence, trusted_now_unix_ms, apply)?;
        if !changed {
            return Ok(value);
        }
        tx.commit().map_err(|error| {
            owner_error(
                self.serving_owner
                    .outcome_unknown(format!("sqlite root exchange commit is unknown: {error}")),
            )
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        Ok(value)
    }

    /// The part of a mutation inside its transaction: the owner, anchor and
    /// clock checks, the change, and its event and global commit. The change
    /// sees the authority validation time, never earlier than the authority
    /// clock, so a request that waited cannot act on an expired root. Returns
    /// whether a change was staged.
    fn stage<T>(
        &self,
        tx: &Transaction<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        apply: impl FnOnce(&Transaction<'_>, u64) -> Result<(T, Option<Change>)>,
    ) -> Result<(T, bool)> {
        verify_active_owner(tx, &self.serving_owner, Some(fence)).map_err(unavailable)?;
        self.serving_owner
            .verify_authority_anchor(tx)
            .map_err(owner_error)?;
        let now = authority_validation_time(tx, trusted_now_unix_ms, &self.serving_owner)
            .map_err(unavailable)?
            / 1000;
        let (value, change) = apply(tx, now)?;
        let Some(change) = change else {
            return Ok((value, false));
        };
        let sequence = append_event(tx, &change, now)?;
        self.serving_owner
            .append_global_commit(
                tx,
                &format!("root_exchange_{}", change.mutation.as_str()),
                PROJECTION,
                schema::PROJECTION_KEY,
                sequence,
            )
            .map_err(owner_error)?;
        Ok((value, true))
    }
}

fn append_event(tx: &Transaction<'_>, change: &Change, now: u64) -> Result<u64> {
    let previous: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) FROM root_exchange_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let sequence = u64::try_from(previous)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("root exchange event sequence overflow"))?;
    tx.execute(
        "INSERT INTO root_exchange_events (sequence, mutation, subject, digest, occurred_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            sql_u64(sequence)?,
            change.mutation.as_str(),
            change.subject,
            change.digest,
            sql_u64(now)?
        ],
    )
    .map_err(sqlite_error)?;
    bindings::insert_records(tx, sequence, change.replay.as_ref(), change.bearer.as_ref())?;
    Ok(sequence)
}

/// The digest of a non-mint change: the domain, the mutation and its body.
fn change_digest(mutation: Mutation, body: &impl Serialize) -> Result<String> {
    let bytes = chio_core::canonical::canonical_json_bytes(&(
        "chio.root-exchange-change.v1",
        mutation.as_str(),
        body,
    ))
    .map_err(|error| invalid(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn digest_column(digest: &Sha256Digest) -> String {
    digest.to_bare_hex()
}

fn parse_digest_column(value: &str) -> Result<Sha256Digest> {
    let mut bytes = [0_u8; 32];
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("stored digest is not 64 lowercase hex"));
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|error| invalid(error.to_string()))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn canonical_blob(value: &impl Serialize) -> Result<Vec<u8>> {
    chio_core::canonical::canonical_json_bytes(value).map_err(|error| invalid(error.to_string()))
}

fn decode_blob<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
    bound: usize,
) -> Result<T> {
    chio_core::canonical::UntrustedJsonText::from_wire(bytes, bound)
        .and_then(|text| text.decode_canonical())
        .map_err(|error| invalid(error.to_string()))
}

fn sql_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| invalid("integer exceeds SQLite range"))
}

fn stored_u64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| invalid("stored integer is negative"))
}

fn sqlite_error(error: rusqlite::Error) -> RootExchangeStoreError {
    RootExchangeStoreError::Unavailable(error.to_string())
}

/// An outcome-unknown owner error stays outcome-unknown; any other is
/// unavailability.
fn owner_error(error: SqliteServingOwnerError) -> RootExchangeStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            RootExchangeStoreError::OutcomeUnknown(detail)
        }
        other => RootExchangeStoreError::Unavailable(other.to_string()),
    }
}

fn unavailable(error: impl std::fmt::Display) -> RootExchangeStoreError {
    RootExchangeStoreError::Unavailable(error.to_string())
}

fn invalid(detail: impl Into<String>) -> RootExchangeStoreError {
    RootExchangeStoreError::Invalid(detail.into())
}

pub(super) fn owner_invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../tests/root_exchange_support/mod.rs"]
pub(crate) mod support;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod binding_tests;
