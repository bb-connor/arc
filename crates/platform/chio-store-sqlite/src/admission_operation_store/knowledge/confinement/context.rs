//! Context derivation has no caller-selected lineage or epoch override.
use super::*;
use chio_kernel::SecurityInvocationContextV1;
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};

pub(super) fn make(
    profile: &NativeKnowledgeInstallationV1,
    child: &CapabilityToken,
    lineage: &IsolationLineageId,
    epoch: &ProtectedText<128>,
) -> Result<SecurityInvocationContext, AdmissionOperationStoreError> {
    Ok(SecurityInvocationContext::v1(
        SecurityInvocationContextV1::new(
            TenantId::new(profile.scope.tenant_id.as_str()).map_err(refused)?,
            SessionId::new(profile.producer_context.as_v1().session_id().as_str())
                .map_err(refused)?,
            chio_security_types::PrincipalId::new(child.subject.to_hex()).map_err(refused)?,
            IsolationEpochId::new(epoch.as_str()).map_err(refused)?,
            LineageId::new(lineage.as_str()).map_err(refused)?,
            1,
        ),
    ))
}
pub(super) fn validate_delegation(
    parent: &CapabilityToken,
    child: &CapabilityToken,
) -> Result<(), AdmissionOperationStoreError> {
    use chio_core::capability::attenuation::{scope_hash, validate_attenuation};
    if !parent.scope.authorizes_delegation()
        || !parent.verify_signature().map_err(refused)?
        || !child.verify_signature().map_err(refused)?
    {
        return Err(refused("delegation signature"));
    }
    validate_attenuation(&parent.scope, &child.scope).map_err(refused)?;
    let (last, prefix) = child
        .delegation_chain
        .split_last()
        .ok_or_else(|| refused("delegation hop"))?;
    if child.issuer != parent.issuer
        || child.issued_at < parent.issued_at
        || child.expires_at > parent.expires_at
        || child.issued_at >= child.expires_at
        || protected::encode(&child.aggregate_invocation_budget)?
            != protected::encode(&parent.aggregate_invocation_budget)?
        || child.budget_share_bps.unwrap_or(10_000) > parent.budget_share_bps.unwrap_or(10_000)
        || protected::encode(&prefix)? != protected::encode(&parent.delegation_chain)?
        || last.capability_id != parent.id
        || last.delegator != parent.subject
        || last.delegatee != child.subject
        || last.scope_hash.as_ref() != Some(&scope_hash(&parent.scope).map_err(refused)?)
        || !last.verify_signature().map_err(refused)?
    {
        return Err(refused("delegation binding"));
    }
    Ok(())
}
fn live(
    tx: &Connection,
    cap: &CapabilityToken,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    cap.validate_time(now / 1000).map_err(refused)?;
    for id in std::iter::once(cap.id.as_str()).chain(
        cap.delegation_chain
            .iter()
            .map(|v| v.capability_id.as_str()),
    ) {
        let revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(sqlite_error)?;
        if revoked {
            return Err(refused("retained capability revoked"));
        }
    }
    Ok(())
}
pub(super) fn verify_retained(
    tx: &Connection,
    record: &BoundaryRecord,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let deployment = protected::deployment_tx(tx, &record.reservation.boundary.scope)?;
    if !deployment.actors.as_slice().iter().any(|a| {
        a.subject == record.initiator.subject
            && a.principal == record.initiating_principal
            && a.permissions
                .as_slice()
                .contains(&RecoveryPermission::ConfinedLaunch)
    }) {
        return Err(refused("initiator assignment changed"));
    }
    live(tx, &record.initiator, now)?;
    live(tx, &record.parent_capability, now)?;
    live(tx, &record.child_capability, now)
}

pub(super) fn require_unobserved_principal(
    tx: &Connection,
    profile: &NativeKnowledgeInstallationV1,
    child: &CapabilityToken,
) -> Result<(), AdmissionOperationStoreError> {
    // A new epoch is not evidence that a principal has never observed data.
    // Match the native authority and tenant, deliberately across all epochs.
    let observed: bool = tx
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM security_participant_state_principal_flow_state
                WHERE security_authority_id=?1 AND tenant_id=?2 AND principal_id=?3
                UNION ALL
                SELECT 1 FROM security_participant_state_isolation_epochs
                WHERE security_authority_id=?1 AND tenant_id=?2 AND principal_id=?3
                UNION ALL
                SELECT 1 FROM security_participant_state_flow_contexts
                WHERE security_authority_id=?1 AND tenant_id=?2 AND principal_id=?3
            )",
            rusqlite::params![
                profile.native_authority.security_authority_id().as_str(),
                profile.scope.tenant_id.as_str(),
                child.subject.to_hex(),
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if observed {
        return Err(refused("child principal already observed"));
    }
    Ok(())
}

fn verify_attachment(
    tx: &Transaction<'_>,
    input: chio_kernel::admission_operation::ConfinedProcessAttachment<'_>,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if input.parent_lineage.is_empty() || input.parent_lineage.len() > 65 {
        return Err(refused("attachment ancestry"));
    }
    for capability in input.parent_lineage {
        if identity::whole_token(tx, capability)?.is_some() {
            return Err(refused("nested confined attachment"));
        }
    }
    let Some(record) = identity::whole_token(tx, input.child_capability)? else {
        return Ok(());
    };
    let boundary = &record.reservation.boundary;
    if identity::root_scope(tx, input.runtime, input.root_process)?.as_ref()
        != Some(&boundary.scope)
        || input.parent_process != boundary.scope.process_id.as_str()
        || input.child_process != boundary.child.as_str()
        || input.parent_lineage.len() != 1
        || capability_digest(&input.parent_lineage[0])? != boundary.parent_capability
        || now >= boundary.deadline_unix_ms.get()
        || !matches!(
            record.reservation.state,
            IsolationStateV1::Reserved
                | IsolationStateV1::LaunchPrepared
                | IsolationStateV1::EnforcedRunning
        )
    {
        return Err(refused("reserved confined attachment"));
    }
    let profile = super::super::installation(tx, &boundary.scope)?;
    validate_current(tx, &record, &profile, now)
}

pub(in crate::admission_operation_store) fn resolve(
    tx: &Transaction<'_>,
    runtime: &str,
    root_process: &str,
    process: &str,
    lineage: &[CapabilityToken],
    now: u64,
) -> Result<Option<SecurityInvocationContext>, AdmissionOperationStoreError> {
    // The process journal supports a root plus 64 ordinary descendants. Scan
    // that complete bounded ancestry before deciding confinement is absent.
    if lineage.is_empty() || lineage.len() > 65 {
        return Err(refused("ancestry bound"));
    }
    let selected = identity::root_scope(tx, runtime, root_process)?;
    for (index, capability) in lineage.iter().enumerate().rev() {
        let scoped = selected
            .as_ref()
            .map(|scope| identity::scoped_token(tx, scope, capability))
            .transpose()?
            .flatten();
        let retained = match scoped {
            Some(record) => Some(record),
            None => identity::whole_token(tx, capability)?,
        };
        let Some(record) = retained else {
            continue;
        };
        let boundary = &record.reservation.boundary;
        if selected.as_ref() != Some(&boundary.scope)
            || root_process != boundary.scope.process_id.as_str()
            || process != boundary.child.as_str()
            || runtime != boundary.parent.runtime.as_str()
            || lineage.len() != 2
            || index != 1
            || capability_digest(&lineage[0])? != boundary.parent_capability
        {
            return Err(refused("confined process binding"));
        }
        let profile = super::super::installation(tx, &boundary.scope)?;
        validate_current(tx, &record, &profile, now)?;
        if now >= boundary.deadline_unix_ms.get()
            || record.reservation.state != IsolationStateV1::EnforcedRunning
            || record.observation_release.is_none()
        {
            return Err(refused("confined context unavailable"));
        }
        validate_delegation(&lineage[0], capability)?;
        for cap in lineage {
            live(tx, cap, now)?;
        }
        return make(
            &profile,
            capability,
            &boundary.lineage,
            &boundary.isolation_epoch,
        )
        .map(Some);
    }
    Ok(None)
}

impl SqliteAdmissionOperationStore {
    pub fn verify_confined_process_attachment(
        &self,
        input: chio_kernel::admission_operation::ConfinedProcessAttachment<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        verify_attachment(&tx, input, now)?;
        tx.commit().map_err(sqlite_error)
    }

    pub fn confined_process_context(
        &self,
        runtime: &str,
        root_process: &str,
        process: &str,
        lineage: &[CapabilityToken],
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<SecurityInvocationContext>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let result = resolve(&tx, runtime, root_process, process, lineage, now)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}
