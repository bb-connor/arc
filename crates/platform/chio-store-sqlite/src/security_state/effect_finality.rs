//! Immutable completed-removal identity, authenticated by the original journal.
// tenant-read-contract: security_response_effect_finality; class=tenant-predicate; principal=security-runtime

use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    ActionId, Digest32, EffectId, EffectOperation, EffectRequest, EffectResult, RecordId, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use super::{body_hash, decode_digest, sqlite_error, PortError, PortResult};

mod commands;
mod migration;
mod schema;

pub(super) use schema::{
    ensure_schema, objects_absent, preflight, revision as schema_revision, validate_schema,
};

const MAX_MARKER_BYTES: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    schema_version: u8,
    tenant_id: TenantId,
    effect_kind: ResponseEffectKind,
    effect_id: EffectId,
    action_id: ActionId,
    target: ResponseTarget,
    plan_hash: Digest32,
    contribution_hash: Digest32,
    plan_expires_at_unix_ms: u64,
    remove_idempotency_key: RecordId,
    request_body_hash: Digest32,
    result_body_hash: Digest32,
    snapshot_body_hash: Option<Digest32>,
}

struct VerifiedCommand {
    request: EffectRequest,
    result: EffectResult,
    request_hash: Digest32,
    result_hash: Digest32,
    snapshot_hash: Option<Digest32>,
}

fn kind_name(kind: ResponseEffectKind) -> PortResult<&'static str> {
    match kind {
        ResponseEffectKind::SuspendSession => Ok("suspend_session"),
        ResponseEffectKind::RestrictEgress => Ok("restrict_egress"),
        ResponseEffectKind::ThrottleSession => Ok("throttle_session"),
        ResponseEffectKind::SuspendCapabilitySet => Ok("suspend_capability_set"),
        ResponseEffectKind::FreezeIssuance => Ok("freeze_issuance"),
        ResponseEffectKind::EscalateAlert => Err(PortError::invalid_data()),
    }
}

impl Marker {
    fn from_command(command: &VerifiedCommand) -> PortResult<Self> {
        let request = &command.request;
        if request.operation != EffectOperation::Remove || command.result.applied {
            return Err(PortError::integrity_failure());
        }
        let marker = Self {
            schema_version: 1,
            tenant_id: request.tenant_id.clone(),
            effect_kind: request.effect_kind,
            effect_id: request.effect_id.clone(),
            action_id: request.action_id.clone(),
            target: request.target.clone(),
            plan_hash: request.plan_hash,
            contribution_hash: request.contribution_hash,
            plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
            remove_idempotency_key: request.idempotency_key.clone(),
            request_body_hash: command.request_hash,
            result_body_hash: command.result_hash,
            snapshot_body_hash: command.snapshot_hash,
        };
        marker.validate()?;
        Ok(marker)
    }

    fn validate(&self) -> PortResult<()> {
        kind_name(self.effect_kind).map_err(|_| PortError::integrity_failure())?;
        if self.schema_version != 1
            || !self.effect_kind.accepts_target(&self.target)
            || self.plan_hash == Digest32::new([0; 32])
            || self.contribution_hash == Digest32::new([0; 32])
            || self.plan_expires_at_unix_ms == 0
            || !self
                .remove_idempotency_key
                .as_str()
                .starts_with("response_effect_command:")
            || self.request_body_hash == Digest32::new([0; 32])
            || self.result_body_hash == Digest32::new([0; 32])
            || (self.effect_kind == ResponseEffectKind::RestrictEgress)
                != self.snapshot_body_hash.is_none()
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.effect_kind == other.effect_kind
            && self.effect_id == other.effect_id
            && self.action_id == other.action_id
            && self.target == other.target
            && self.plan_hash == other.plan_hash
            && self.contribution_hash == other.contribution_hash
            && self.plan_expires_at_unix_ms == other.plan_expires_at_unix_ms
    }
}

fn load_marker(
    connection: &Connection,
    tenant: &TenantId,
    kind: ResponseEffectKind,
    effect: &EffectId,
) -> PortResult<Option<Marker>> {
    let row: Option<(String, String, Vec<u8>, Vec<u8>)> = connection.query_row(
        "SELECT action_id, remove_idempotency_key, marker_body, marker_body_hash \
         FROM security_response_effect_finality WHERE tenant_id = ?1 AND effect_kind = ?2 AND effect_id = ?3",
        params![tenant.as_str(), kind_name(kind)?, effect.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((action, key, bytes, hash)) = row else {
        return Ok(None);
    };
    if bytes.is_empty()
        || bytes.len() > MAX_MARKER_BYTES
        || body_hash(&bytes) != *decode_digest(hash)?.as_bytes()
    {
        return Err(PortError::integrity_failure());
    }
    let marker: Marker =
        chio_core::canonical::UntrustedJsonText::from_wire(&bytes, MAX_MARKER_BYTES)
            .and_then(|input| input.decode_signed())
            .map_err(|_| PortError::integrity_failure())?;
    marker.validate()?;
    if canonical_json_bytes(&marker).map_err(|_| PortError::integrity_failure())? != bytes
        || marker.tenant_id != *tenant
        || marker.effect_kind != kind
        || marker.effect_id != *effect
        || marker.action_id.as_str() != action
        || marker.remove_idempotency_key.as_str() != key
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(marker))
}

fn verified_marker(
    connection: &Connection,
    tenant: &TenantId,
    kind: ResponseEffectKind,
    effect: &EffectId,
) -> PortResult<Option<Marker>> {
    let Some(marker) = load_marker(connection, tenant, kind, effect)? else {
        return Ok(None);
    };
    let command = commands::load(
        connection,
        kind,
        tenant.as_str(),
        marker.remove_idempotency_key.as_str(),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    if Marker::from_command(&command)? != marker {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(marker))
}

pub(super) fn check_apply(connection: &Connection, request: &EffectRequest) -> PortResult<()> {
    if request.operation != EffectOperation::Apply {
        return Err(PortError::invalid_data());
    }
    if verified_marker(
        connection,
        &request.tenant_id,
        request.effect_kind,
        &request.effect_id,
    )?
    .is_some()
    {
        return Err(PortError::conflict());
    }
    Ok(())
}

pub(super) fn record_remove(
    transaction: &Transaction<'_>,
    request: &EffectRequest,
) -> PortResult<()> {
    let command = commands::load(
        transaction,
        request.effect_kind,
        request.tenant_id.as_str(),
        request.idempotency_key.as_str(),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    if command.request != *request {
        return Err(PortError::integrity_failure());
    }
    persist_first(transaction, &Marker::from_command(&command)?)
}

fn persist_first(connection: &Connection, marker: &Marker) -> PortResult<()> {
    if let Some(existing) = verified_marker(
        connection,
        &marker.tenant_id,
        marker.effect_kind,
        &marker.effect_id,
    )? {
        return if existing.same_identity(marker) {
            Ok(())
        } else {
            Err(PortError::integrity_failure())
        };
    }
    let bytes = canonical_json_bytes(marker).map_err(|_| PortError::integrity_failure())?;
    if bytes.len() > MAX_MARKER_BYTES {
        return Err(PortError::integrity_failure());
    }
    connection.execute(
        "INSERT INTO security_response_effect_finality (tenant_id, effect_kind, effect_id, action_id, remove_idempotency_key, marker_body, marker_body_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![marker.tenant_id.as_str(), kind_name(marker.effect_kind)?, marker.effect_id.as_str(), marker.action_id.as_str(), marker.remove_idempotency_key.as_str(), &bytes, body_hash(&bytes).as_slice()],
    ).map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn validate_ready(connection: &Connection, kind: ResponseEffectKind) -> PortResult<()> {
    validate_schema(connection)?;
    migration::verify_kind_coverage(connection, kind)
}

pub(super) fn migrate_legacy(connection: &Connection) -> PortResult<()> {
    migration::backfill(connection)
}

pub(super) fn completed_capability_remove(
    connection: &Connection,
    query: &chio_security_types::ports::EffectResultQuery,
) -> PortResult<Option<chio_security_types::ports::CapabilitySetSuspensionCommand>> {
    if query.effect_kind != ResponseEffectKind::SuspendCapabilitySet
        || query.operation != EffectOperation::Apply
    {
        return Err(PortError::invalid_data());
    }
    let Some(marker) = load_marker(
        connection,
        &query.tenant_id,
        query.effect_kind,
        &query.effect_id,
    )?
    else {
        return Ok(None);
    };
    let command = super::capability_set_suspension::load_command(
        connection,
        query.tenant_id.as_str(),
        marker.remove_idempotency_key.as_str(),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    super::capability_set_suspension::validate_stored_command(&command)?;
    let projection = commands::project(
        command.request.clone(),
        command.result.clone(),
        Some(
            canonical_json_bytes(&command.resulting_snapshot)
                .map_err(|_| PortError::integrity_failure())?,
        ),
    )?;
    if Marker::from_command(&projection)? != marker
        || marker.action_id != query.action_id
        || marker.target != query.target
        || marker.plan_hash != query.plan_hash
        || marker.plan_expires_at_unix_ms != query.plan_expires_at_unix_ms
        || marker.contribution_hash != query.contribution_hash
    {
        return Err(PortError::integrity_failure());
    }
    Ok(Some(command))
}

pub(super) fn completed_freeze_remove(
    connection: &Connection,
    key: &chio_security_types::ports::IssuanceFreezeKey,
    action: &ActionId,
    effect: &EffectId,
    plan_hash: Digest32,
) -> PortResult<Option<chio_security_types::ports::IssuanceFreezeCommand>> {
    let Some(marker) = load_marker(
        connection,
        &key.tenant_id,
        ResponseEffectKind::FreezeIssuance,
        effect,
    )?
    else {
        return Ok(None);
    };
    let command = super::issuance_freeze::load_finality_command(
        connection,
        key.tenant_id.as_str(),
        marker.remove_idempotency_key.as_str(),
    )?
    .ok_or_else(PortError::integrity_failure)?;
    let projection = commands::project(
        command.request.clone(),
        command.result.clone(),
        Some(
            canonical_json_bytes(&command.resulting_snapshot)
                .map_err(|_| PortError::integrity_failure())?,
        ),
    )?;
    if Marker::from_command(&projection)? != marker {
        return Err(PortError::integrity_failure());
    }
    if marker.action_id != *action
        || marker.plan_hash != plan_hash
        || marker.target
            != (ResponseTarget::Lineage {
                lineage_id: key.lineage_id.clone(),
            })
    {
        return Ok(None);
    }
    Ok(Some(command))
}
