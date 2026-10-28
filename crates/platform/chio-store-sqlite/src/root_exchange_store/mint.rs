//! The mint transaction and replay recovery.

use std::collections::BTreeSet;

use chio_core::capability::anchor::AnchorKind;
use chio_core::root_authority::{ClaimValue, Sha256Digest};
use chio_core::StoreMutationFence;
use rusqlite::{params, OptionalExtension, Transaction};

use super::projection::{insert_root_row, read_root_row, required_root, RootRow};
use super::reads::{retain_identity, retain_policy, retain_snapshot};
use super::{
    canonical_blob, digest_column, sql_u64, sqlite_error, stored_u64, Change, MintOutcome,
    MintRequest, MintRequestRefusal, MintRevocationCheck, MintRevocationRefusal, Mutation, Result,
    RevocationCandidate, RootExchangeStoreError, SqliteRootExchangeStore, StoredRoot,
};

impl SqliteRootExchangeStore {
    /// Mint or recover one anchored root. Every refusal rolls the whole
    /// transaction back, so no replay key is spent without its root.
    pub fn mint_anchored_root(
        &self,
        request: &MintRequest<'_>,
        revocation: &dyn MintRevocationCheck,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<MintOutcome> {
        let checked = check_request(request, trusted_now_unix_ms / 1000)?;
        self.mutate(fence, trusted_now_unix_ms, |tx, now| {
            if let Some(stored) = live_replay_root(tx, request, now)? {
                recover(tx, request, revocation, &stored, now)?;
                return Ok((MintOutcome::Recovered(stored), None));
            }
            if let Some(mapping) = request.bearer {
                if let Some(stored) = live_bearer_root(tx, &mapping.token_digest, now)? {
                    recover(tx, request, revocation, &stored, now)?;
                    return Ok((MintOutcome::Recovered(stored), None));
                }
            }
            refuse_revoked(
                tx,
                revocation,
                &request.root.id,
                checked.rule_id,
                &request.context.anchor.replay_key_digest,
                request,
            )?;
            let row = checked.row(request, now)?;
            bind_replay(tx, request, now)?;
            insert_root_row(tx, &row)?;
            insert_openings(tx, request, now)?;
            if let Some(mapping) = request.bearer {
                tx.execute(
                    "INSERT INTO root_exchange_bearer_tokens (token_digest, capability_id, retain_until)
                     VALUES (?1, ?2, ?3)",
                    params![
                        digest_column(&mapping.token_digest),
                        request.root.id,
                        sql_u64(mapping.retain_until)?
                    ],
                )
                .map_err(sqlite_error)?;
            }
            retain_policy(tx, request.root_policy.policy())?;
            if let Some(identity) = request.provider_identity {
                retain_identity(tx, identity)?;
            }
            if let Some(snapshot) = request.key_snapshot {
                retain_snapshot(tx, snapshot)?;
            }
            let stored = row.verify()?;
            let change = Change {
                mutation: Mutation::Mint,
                subject: row.capability_id.clone(),
                digest: digest_column(&row.authorization_projection_digest),
            };
            Ok((MintOutcome::Minted(stored), Some(change)))
        })
    }
}

struct CheckedRequest<'a> {
    rule_id: &'a str,
    policy_digest: Sha256Digest,
    context_digest: Sha256Digest,
    context_bytes: Vec<u8>,
    capability_bytes: Vec<u8>,
}

impl CheckedRequest<'_> {
    fn row(&self, request: &MintRequest<'_>, now: u64) -> Result<RootRow> {
        let context = request.context;
        let mut row = RootRow {
            capability_id: request.root.id.clone(),
            root_policy_rule_id: self.rule_id.to_owned(),
            tags: request.tags,
            replay_key_digest: context.anchor.replay_key_digest,
            replay_bound_at: now,
            client_id: request.client_id.to_owned(),
            artifact_digest: request.artifact_digest,
            request_digest: context.exchange.request_digest,
            expires_at: request.root.expires_at,
            anchor_kind: context.anchor.kind.as_str().to_owned(),
            holder: context.exchange.holder.as_str().to_owned(),
            root_policy_digest: self.policy_digest,
            provider_identity_digest: context.anchor.provider_identity_digest,
            key_snapshot_digest: context.anchor.key_snapshot_digest,
            context_digest: self.context_digest,
            delegation_context: self.context_bytes.clone(),
            root_capability: self.capability_bytes.clone(),
            minted_at: now,
            authorization_projection_digest: Sha256Digest::from_bytes([0; 32]),
        };
        row.authorization_projection_digest = row.projection_digest()?;
        Ok(row)
    }
}

fn refuse(refusal: MintRequestRefusal) -> RootExchangeStoreError {
    RootExchangeStoreError::InvalidMintRequest(refusal)
}

/// The request's members agree with each other before any durable step.
fn check_request<'a>(request: &MintRequest<'a>, now: u64) -> Result<CheckedRequest<'a>> {
    let root = request.root;
    let context = request.context;
    let anchor = &context.anchor;
    if root.id.is_empty() || root.id.len() > 256 || root.id.contains('\0') {
        return Err(refuse(MintRequestRefusal::RootCapabilityId));
    }
    if request.client_id.is_empty()
        || request.client_id.len() > 256
        || request.client_id.contains('\0')
    {
        return Err(refuse(MintRequestRefusal::ClientId));
    }
    if !root.delegation_chain.is_empty() {
        return Err(refuse(MintRequestRefusal::DelegationChain));
    }
    if root.issuer != context.exchange.exchange_key {
        return Err(refuse(MintRequestRefusal::IssuerNotExchangeKey));
    }
    if !request.root_policy.lists_exchange_key(&root.issuer) {
        return Err(refuse(MintRequestRefusal::IssuerNotInPolicy));
    }
    request
        .root_policy
        .check_valid_at(now)
        .map_err(|_| refuse(MintRequestRefusal::PolicyNotValid))?;
    let rule_id = context.root_policy_rule_id.as_str();
    let Some(rule) = request.root_policy.rule(&context.root_policy_rule_id) else {
        return Err(refuse(MintRequestRefusal::UnknownRule));
    };
    if rule.match_.anchor_kind != anchor.kind {
        return Err(refuse(MintRequestRefusal::RuleKindMismatch));
    }
    let scope_hash = Sha256Digest::of_scope(&root.scope)
        .map_err(|_| refuse(MintRequestRefusal::ScopeNotCanonical))?;
    if scope_hash != context.effective_root_scope_hash {
        return Err(refuse(MintRequestRefusal::ScopeHashMismatch));
    }
    if root.expires_at <= now || root.expires_at <= request.root.issued_at {
        return Err(refuse(MintRequestRefusal::RootExpired));
    }
    if request.replay_retain_until <= now {
        return Err(refuse(MintRequestRefusal::ReplayRetentionPast));
    }
    match (anchor.kind.is_provider_backed(), request.provider_identity) {
        (true, Some(identity)) => {
            let digest = identity
                .digest()
                .map_err(|_| refuse(MintRequestRefusal::ProviderIdentityNotCanonical))?;
            if anchor.provider_identity_digest != Some(digest) {
                return Err(refuse(MintRequestRefusal::ProviderIdentityMismatch));
            }
        }
        (false, None) if anchor.provider_identity_digest.is_none() => {}
        _ => return Err(refuse(MintRequestRefusal::ProviderIdentityPresence)),
    }
    let snapshot_digest = request
        .key_snapshot
        .map(|snapshot| snapshot.digest())
        .transpose()
        .map_err(|_| refuse(MintRequestRefusal::KeySnapshotNotCanonical))?;
    if snapshot_digest != anchor.key_snapshot_digest {
        return Err(refuse(MintRequestRefusal::KeySnapshotMismatch));
    }
    if anchor
        .artifact_digest
        .is_some_and(|digest| digest != request.artifact_digest)
    {
        return Err(refuse(MintRequestRefusal::ArtifactMismatch));
    }
    if !request.tag_candidates.contains(&request.tags) {
        return Err(refuse(MintRequestRefusal::TagsNotLoaded));
    }
    if request.tags.tenant.key_id != request.tags.subject.key_id {
        return Err(refuse(MintRequestRefusal::TagsSpanGenerations));
    }
    if let Some(mapping) = request.bearer {
        if mapping.retain_until < root.expires_at {
            return Err(refuse(MintRequestRefusal::BearerRetentionShort));
        }
    }
    check_openings(request)?;
    Ok(CheckedRequest {
        rule_id,
        policy_digest: *request.root_policy.digest(),
        context_digest: context
            .digest()
            .map_err(|_| refuse(MintRequestRefusal::ContextNotCanonical))?,
        context_bytes: canonical_blob(context)?,
        capability_bytes: canonical_blob(root)?,
    })
}

/// The openings are exactly one salt per committed context value.
fn check_openings(request: &MintRequest<'_>) -> Result<()> {
    let anchor = &request.context.anchor;
    let mut expected = BTreeSet::new();
    expected.insert(anchor.subject.salt_ref.as_str().to_owned());
    expected.insert(anchor.tenant.salt_ref.as_str().to_owned());
    for (_, value) in anchor.claims.entries() {
        if let Some(ClaimValue::Committed(commitment)) = value {
            expected.insert(commitment.salt_ref.as_str().to_owned());
        }
    }
    let mut supplied = BTreeSet::new();
    for opening in request.openings {
        if !supplied.insert(opening.salt_ref.as_str().to_owned()) {
            return Err(refuse(MintRequestRefusal::DuplicateOpening));
        }
    }
    if supplied != expected {
        return Err(refuse(MintRequestRefusal::OpeningsMismatch));
    }
    Ok(())
}

/// The root a live replay binding names, when it was minted for the same
/// client, artifact and request. Any other live binding is a replay. An
/// expired binding is deleted so the key binds again.
fn live_replay_root(
    tx: &Transaction<'_>,
    request: &MintRequest<'_>,
    now: u64,
) -> Result<Option<StoredRoot>> {
    let replay = digest_column(&request.context.anchor.replay_key_digest);
    let binding: Option<(i64, Option<String>)> = tx
        .query_row(
            "SELECT retain_until, capability_id FROM root_exchange_replay WHERE replay_key_digest = ?1",
            [&replay],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((retain_until, capability_id)) = binding else {
        return Ok(None);
    };
    if stored_u64(retain_until)? <= now {
        tx.execute(
            "DELETE FROM root_exchange_replay WHERE replay_key_digest = ?1",
            [&replay],
        )
        .map_err(sqlite_error)?;
        return Ok(None);
    }
    let capability_id = capability_id.ok_or(RootExchangeStoreError::AssertionReplay)?;
    let row = read_root_row(tx, &capability_id)?.ok_or_else(|| {
        RootExchangeStoreError::AnchoredRootMissing {
            capability_id: capability_id.clone(),
        }
    })?;
    let stored = row.verify()?;
    if row.client_id != request.client_id
        || row.artifact_digest != request.artifact_digest
        || row.request_digest != request.context.exchange.request_digest
    {
        return Err(RootExchangeStoreError::AssertionReplay);
    }
    Ok(Some(stored))
}

fn live_bearer_root(
    tx: &Transaction<'_>,
    token_digest: &Sha256Digest,
    now: u64,
) -> Result<Option<StoredRoot>> {
    let token = digest_column(token_digest);
    let mapped: Option<String> = tx
        .query_row(
            "SELECT capability_id FROM root_exchange_bearer_tokens WHERE token_digest = ?1",
            [&token],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(capability_id) = mapped else {
        return Ok(None);
    };
    let stored = required_root(tx, &capability_id)?;
    if stored.capability.expires_at > now {
        return Ok(Some(stored));
    }
    tx.execute(
        "DELETE FROM root_exchange_bearer_tokens WHERE token_digest = ?1",
        [&token],
    )
    .map_err(sqlite_error)?;
    Ok(None)
}

/// A recovered root passes the checks a fresh mint would.
fn recover(
    tx: &Transaction<'_>,
    request: &MintRequest<'_>,
    revocation: &dyn MintRevocationCheck,
    stored: &StoredRoot,
    now: u64,
) -> Result<()> {
    let capability_id = stored.capability.id.clone();
    if stored.capability.expires_at <= now {
        return Err(RootExchangeStoreError::AnchoredRootExpired { capability_id });
    }
    if stored.root_policy_digest != *request.root_policy.digest() {
        return Err(RootExchangeStoreError::RootPolicyChanged { capability_id });
    }
    let current = request
        .provider_identity
        .map(|identity| identity.digest())
        .transpose()
        .map_err(|_| refuse(MintRequestRefusal::ProviderIdentityNotCanonical))?;
    if stored.context.anchor.provider_identity_digest != current {
        return Err(RootExchangeStoreError::ProviderIdentityChanged { capability_id });
    }
    refuse_revoked(
        tx,
        revocation,
        &stored.capability.id,
        stored.context.root_policy_rule_id.as_str(),
        &stored.context.anchor.replay_key_digest,
        request,
    )
}

fn refuse_revoked(
    tx: &Transaction<'_>,
    revocation: &dyn MintRevocationCheck,
    capability_id: &str,
    rule_id: &str,
    replay_key_digest: &Sha256Digest,
    request: &MintRequest<'_>,
) -> Result<()> {
    let candidate = RevocationCandidate {
        capability_id,
        root_policy_rule_id: rule_id,
        replay_key_digest,
        tag_candidates: request.tag_candidates,
    };
    revocation
        .refuse_revoked_root(tx, &candidate)
        .map_err(|refusal| match refusal {
            MintRevocationRefusal::Revoked { entry_id } => {
                RootExchangeStoreError::Revoked { entry_id }
            }
            MintRevocationRefusal::Unavailable(detail) => {
                RootExchangeStoreError::RevocationCheckUnavailable(detail)
            }
        })
}

fn bind_replay(tx: &Transaction<'_>, request: &MintRequest<'_>, now: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO root_exchange_replay
             (replay_key_digest, namespace, bound_at, retain_until, capability_id)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            digest_column(&request.context.anchor.replay_key_digest),
            request.context.anchor.kind.as_str(),
            sql_u64(now)?,
            sql_u64(request.replay_retain_until)?,
            request.root.id,
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn insert_openings(tx: &Transaction<'_>, request: &MintRequest<'_>, now: u64) -> Result<()> {
    for opening in request.openings {
        let tombstone: Option<String> = tx
            .query_row(
                "SELECT state FROM root_exchange_openings WHERE capability_id = ?1 AND salt_ref = ?2",
                params![request.root.id, opening.salt_ref.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if tombstone.is_some() {
            return Err(RootExchangeStoreError::RootOpeningErased {
                capability_id: request.root.id.clone(),
                salt_ref: opening.salt_ref.as_str().to_owned(),
            });
        }
        tx.execute(
            "INSERT INTO root_exchange_openings (capability_id, salt_ref, state, salt, state_at)
             VALUES (?1, ?2, 'present', ?3, ?4)",
            params![
                request.root.id,
                opening.salt_ref.as_str(),
                opening.salt.as_slice(),
                sql_u64(now)?
            ],
        )
        .map_err(sqlite_error)?;
    }
    Ok(())
}
