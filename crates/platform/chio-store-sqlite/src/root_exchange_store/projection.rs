//! The anchored-root authorization projection and the row check every
//! authorizing, revoking, recovering or exporting read runs.

use chio_core::capability::token::CapabilityToken;
use chio_core::root_authority::{DelegationContext, Sha256Digest};
use chio_core::tenant_index::KeyedIndexValue;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use super::{
    canonical_blob, decode_blob, digest_column, parse_digest_column, sqlite_error, stored_u64,
    Result, RootTags, SqliteRootExchangeStoreError, StoredRoot,
};

pub(super) const PROJECTION_DOMAIN: &[u8] = b"chio.anchored-root-projection.v1\0";
pub(super) const CONTEXT_BOUND: usize = 65_536;
pub(super) const CAPABILITY_BOUND: usize = 65_536;

/// Every authorization column of a root row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RootRow {
    pub(super) capability_id: String,
    pub(super) root_policy_rule_id: String,
    pub(super) tags: RootTags,
    pub(super) replay_key_digest: Sha256Digest,
    pub(super) replay_bound_at: u64,
    pub(super) client_id: String,
    pub(super) artifact_digest: Sha256Digest,
    pub(super) request_digest: Sha256Digest,
    pub(super) expires_at: u64,
    pub(super) anchor_kind: String,
    pub(super) holder: String,
    pub(super) root_policy_digest: Sha256Digest,
    pub(super) provider_identity_digest: Option<Sha256Digest>,
    pub(super) key_snapshot_digest: Option<Sha256Digest>,
    pub(super) context_digest: Sha256Digest,
    pub(super) delegation_context: Vec<u8>,
    pub(super) root_capability: Vec<u8>,
    pub(super) minted_at: u64,
    pub(super) authorization_projection_digest: Sha256Digest,
}

#[derive(Serialize)]
struct Projection<'a> {
    capability_id: &'a str,
    root_policy_rule_id: &'a str,
    tag_key_id: String,
    subject_tag: String,
    tenant_tag: Option<String>,
    replay_key_digest: String,
    replay_bound_at: u64,
    client_id: &'a str,
    artifact_digest: String,
    request_digest: String,
    expires_at: u64,
    holder: &'a str,
    anchor_kind: &'a str,
    root_policy_digest: String,
    provider_identity_digest: Option<String>,
    key_snapshot_digest: Option<String>,
    context_digest: String,
    delegation_context_sha256: String,
    root_capability_sha256: String,
    minted_at: u64,
}

impl RootRow {
    /// `SHA-256("chio.anchored-root-projection.v1\0" || canonical_json(projection))`.
    pub(super) fn projection_digest(&self) -> Result<Sha256Digest> {
        let projection = Projection {
            capability_id: &self.capability_id,
            root_policy_rule_id: &self.root_policy_rule_id,
            tag_key_id: digest_column(&self.tags.key_id()),
            subject_tag: digest_column(&self.tags.subject.value),
            tenant_tag: self.tags.tenant.map(|tag| digest_column(&tag.value)),
            replay_key_digest: digest_column(&self.replay_key_digest),
            replay_bound_at: self.replay_bound_at,
            client_id: &self.client_id,
            artifact_digest: digest_column(&self.artifact_digest),
            request_digest: digest_column(&self.request_digest),
            expires_at: self.expires_at,
            holder: &self.holder,
            anchor_kind: &self.anchor_kind,
            root_policy_digest: digest_column(&self.root_policy_digest),
            provider_identity_digest: self.provider_identity_digest.as_ref().map(digest_column),
            key_snapshot_digest: self.key_snapshot_digest.as_ref().map(digest_column),
            context_digest: digest_column(&self.context_digest),
            delegation_context_sha256: chio_core::sha256_hex(&self.delegation_context),
            root_capability_sha256: chio_core::sha256_hex(&self.root_capability),
            minted_at: self.minted_at,
        };
        Ok(Sha256Digest::of_domain(
            PROJECTION_DOMAIN,
            &canonical_blob(&projection)?,
        ))
    }

    /// The row check: the projection recomputes, the blobs decode
    /// canonically, and the capability and context agree with the columns.
    pub(super) fn verify(&self) -> Result<StoredRoot> {
        let tampered = || SqliteRootExchangeStoreError::AnchoredRootTampered {
            capability_id: self.capability_id.clone(),
        };
        if self.projection_digest()? != self.authorization_projection_digest {
            return Err(tampered());
        }
        let capability: CapabilityToken =
            decode_blob(&self.root_capability, CAPABILITY_BOUND).map_err(|_| tampered())?;
        let context: DelegationContext =
            decode_blob(&self.delegation_context, CONTEXT_BOUND).map_err(|_| tampered())?;
        let scope_hash = Sha256Digest::of_scope(&capability.scope).map_err(|_| tampered())?;
        let agrees = capability.id == self.capability_id
            && capability.issuer == context.exchange.exchange_key
            && capability.expires_at == self.expires_at
            && capability.delegation_chain.is_empty()
            && scope_hash == context.effective_root_scope_hash
            && context.digest().map_err(|_| tampered())? == self.context_digest
            && context.root_policy_rule_id.as_str() == self.root_policy_rule_id
            && context.anchor.kind.as_str() == self.anchor_kind
            && context.exchange.holder.as_str() == self.holder
            && context.anchor.replay_key_digest == self.replay_key_digest
            && context.exchange.request_digest == self.request_digest
            && context.anchor.provider_identity_digest == self.provider_identity_digest
            && context.anchor.key_snapshot_digest == self.key_snapshot_digest
            && context
                .anchor
                .artifact_digest
                .is_none_or(|digest| digest == self.artifact_digest);
        if !agrees {
            return Err(tampered());
        }
        Ok(StoredRoot {
            capability,
            context,
            tags: self.tags,
            root_policy_digest: self.root_policy_digest,
            minted_at: self.minted_at,
        })
    }
}

const ROOT_COLUMNS: &str = "capability_id, root_policy_rule_id, tag_key_id, subject_tag, \
    tenant_tag, replay_key_digest, replay_bound_at, client_id, artifact_digest, request_digest, \
    expires_at, anchor_kind, holder, root_policy_digest, provider_identity_digest, \
    key_snapshot_digest, context_digest, delegation_context, root_capability, minted_at, \
    authorization_projection_digest";

type RawRoot = (
    (String, String, String, String, Option<String>, String, i64),
    (String, String, String, i64, String, String, String),
    (
        Option<String>,
        Option<String>,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        String,
    ),
);

fn raw_root(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRoot> {
    Ok((
        (
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ),
        (
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
        ),
        (
            row.get(14)?,
            row.get(15)?,
            row.get(16)?,
            row.get(17)?,
            row.get(18)?,
            row.get(19)?,
            row.get(20)?,
        ),
    ))
}

fn root_row(raw: RawRoot) -> Result<RootRow> {
    let (
        (capability_id, rule, key_id, subject_tag, tenant_tag, replay, replay_bound_at),
        (client_id, artifact, request, expires_at, anchor_kind, holder, policy),
        (provider, snapshot, context_digest, context, capability, minted_at, projection),
    ) = raw;
    Ok(RootRow {
        capability_id,
        root_policy_rule_id: rule,
        tags: {
            let key_id = parse_digest_column(&key_id)?;
            let keyed = |value: &str| -> Result<KeyedIndexValue> {
                Ok(KeyedIndexValue {
                    key_id,
                    value: parse_digest_column(value)?,
                })
            };
            RootTags {
                subject: keyed(&subject_tag)?,
                tenant: tenant_tag.as_deref().map(keyed).transpose()?,
            }
        },
        replay_key_digest: parse_digest_column(&replay)?,
        replay_bound_at: stored_u64(replay_bound_at)?,
        client_id,
        artifact_digest: parse_digest_column(&artifact)?,
        request_digest: parse_digest_column(&request)?,
        expires_at: stored_u64(expires_at)?,
        anchor_kind,
        holder,
        root_policy_digest: parse_digest_column(&policy)?,
        provider_identity_digest: provider.as_deref().map(parse_digest_column).transpose()?,
        key_snapshot_digest: snapshot.as_deref().map(parse_digest_column).transpose()?,
        context_digest: parse_digest_column(&context_digest)?,
        delegation_context: context,
        root_capability: capability,
        minted_at: stored_u64(minted_at)?,
        authorization_projection_digest: parse_digest_column(&projection)?,
    })
}

pub(super) fn read_root_row(
    connection: &Connection,
    capability_id: &str,
) -> Result<Option<RootRow>> {
    connection
        .query_row(
            &format!("SELECT {ROOT_COLUMNS} FROM root_exchange_roots WHERE capability_id = ?1"),
            [capability_id],
            raw_root,
        )
        .optional()
        .map_err(sqlite_error)?
        .map(root_row)
        .transpose()
}

pub(super) fn read_root_row_by_context(
    connection: &Connection,
    context_digest: &Sha256Digest,
) -> Result<Option<RootRow>> {
    connection
        .query_row(
            &format!("SELECT {ROOT_COLUMNS} FROM root_exchange_roots WHERE context_digest = ?1"),
            [digest_column(context_digest)],
            raw_root,
        )
        .optional()
        .map_err(sqlite_error)?
        .map(root_row)
        .transpose()
}

pub(super) fn all_root_rows(connection: &Connection) -> Result<Vec<RootRow>> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {ROOT_COLUMNS} FROM root_exchange_roots ORDER BY capability_id"
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], raw_root)
        .map_err(sqlite_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    rows.into_iter().map(root_row).collect()
}

/// The checked root for `capability_id`, or `AnchoredRootMissing`.
pub(super) fn required_root(connection: &Connection, capability_id: &str) -> Result<StoredRoot> {
    read_root_row(connection, capability_id)?
        .ok_or_else(|| SqliteRootExchangeStoreError::AnchoredRootMissing {
            capability_id: capability_id.to_owned(),
        })?
        .verify()
}

pub(super) fn insert_root_row(connection: &Connection, row: &RootRow) -> Result<()> {
    connection
        .execute(
            &format!(
                "INSERT INTO root_exchange_roots ({ROOT_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                         ?17, ?18, ?19, ?20, ?21)"
            ),
            rusqlite::params![
                row.capability_id,
                row.root_policy_rule_id,
                digest_column(&row.tags.key_id()),
                digest_column(&row.tags.subject.value),
                row.tags.tenant.map(|tag| digest_column(&tag.value)),
                digest_column(&row.replay_key_digest),
                super::sql_u64(row.replay_bound_at)?,
                row.client_id,
                digest_column(&row.artifact_digest),
                digest_column(&row.request_digest),
                super::sql_u64(row.expires_at)?,
                row.anchor_kind,
                row.holder,
                digest_column(&row.root_policy_digest),
                row.provider_identity_digest.as_ref().map(digest_column),
                row.key_snapshot_digest.as_ref().map(digest_column),
                digest_column(&row.context_digest),
                row.delegation_context,
                row.root_capability,
                super::sql_u64(row.minted_at)?,
                digest_column(&row.authorization_projection_digest),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
