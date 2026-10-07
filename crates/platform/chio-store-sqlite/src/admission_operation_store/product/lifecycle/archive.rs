//! Queue retirement preserves immutable source records and their artifact pins.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchivedReport {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    id: EvidenceRef,
    digest: CommandDigest,
    archiver: PrincipalId,
    archiver_subject: PublicKey,
    archived_at_unix_ms: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArchivedProposal {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    id: ReviewId,
    digest: CanonicalPayloadDigest,
    report_id: EvidenceRef,
    report_digest: CommandDigest,
    archiver: PrincipalId,
    archiver_subject: PublicKey,
    archived_at_unix_ms: SafeInteger,
}

pub(super) fn report_disposition(
    tx: &Connection,
    report: &StoredDecisionReportV1,
) -> Result<Option<ArchivedReport>, AdmissionOperationStoreError> {
    let scope = &report.report.scope;
    let value = disposition::<ArchivedReport>(
        tx,
        scope,
        &terminal_key(scope, "archived-report", report.id.as_str())?,
    )?;
    if value.as_ref().is_some_and(|old| {
        old.scope != *scope
            || old.id != report.id
            || old.digest != report.digest
            || old.archived_at_unix_ms < report.submitted_at_unix_ms
    }) {
        return Err(refused("archived report identity"));
    }
    Ok(value)
}

pub(super) fn proposal_disposition(
    tx: &Connection,
    proposal: &StoredPolicyMaintenanceProposalV1,
) -> Result<Option<ArchivedProposal>, AdmissionOperationStoreError> {
    let scope = &proposal.proposal.scope;
    let value = disposition::<ArchivedProposal>(
        tx,
        scope,
        &terminal_key(
            scope,
            "archived-proposal",
            proposal.proposal.proposal_id.as_str(),
        )?,
    )?;
    if let Some(old) = &value {
        let report = stored_report(tx, scope, &proposal.proposal.report_id)?;
        if old.scope != *scope
            || old.id != proposal.proposal.proposal_id
            || old.digest != proposal.digest
            || old.report_id != report.id
            || old.report_digest != report.digest
            || old.archived_at_unix_ms < proposal.submitted_at_unix_ms
        {
            return Err(refused("archived proposal identity"));
        }
    }
    Ok(value)
}

impl SqliteAdmissionOperationStore {
    /// Current Maintain and the current evidence audience retire one active
    /// review slot. Every report, proposal and artifact pin remains retained.
    pub fn archive_decision_report(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reader: Option<&AuthenticatedRecoveryActor>,
        id: &EvidenceRef,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<StoredDecisionReportV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Maintain {
                return Err(refused("report archive permission"));
            }
            let report = stored_report(tx, actor.scope(), id)?;
            let current = reports::label(tx, actor, reader, profile, &report.report, now)?;
            require_clearance(
                actor,
                profile,
                &current.join_restrictions(&report.label).map_err(refused)?,
            )?;
            if report_disposition(tx, &report)?.is_some() {
                return Ok(report);
            }
            inventory::require_no_active_proposal(tx, &report)?;
            if !report_released(tx, actor.scope(), id)? {
                inventory::retire_report(tx, &self.serving_owner, &report)?;
            }
            let terminal = ArchivedReport {
                domain_version: VersionV1,
                scope: actor.scope().clone(),
                id: id.clone(),
                digest: report.digest,
                archiver: actor.principal().clone(),
                archiver_subject: actor.capability().subject.clone(),
                archived_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            };
            save(
                tx,
                &self.serving_owner,
                actor.scope(),
                &terminal_key(actor.scope(), "archived-report", id.as_str())?,
                &terminal,
            )?;
            Ok(report)
        })
    }

    /// Proposal archival releases its exact active dependency and slot once.
    /// It grants no policy application, artifact release or collection authority.
    pub fn archive_policy_maintenance(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reader: &AuthenticatedRecoveryActor,
        id: &ReviewId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<StoredPolicyMaintenanceProposalV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Maintain {
                return Err(refused("proposal archive permission"));
            }
            let proposal = stored_proposal(tx, actor.scope(), id)?;
            let current = proposals::label(tx, actor, reader, profile, &proposal.proposal, now)?;
            require_clearance(
                actor,
                profile,
                &current
                    .join_restrictions(&proposal.label)
                    .map_err(refused)?,
            )?;
            if proposal_disposition(tx, &proposal)?.is_some() {
                return Ok(proposal);
            }
            if !proposal_released(tx, actor.scope(), id)? {
                inventory::retire_proposal(tx, &self.serving_owner, &proposal)?;
            }
            let report = stored_report(tx, actor.scope(), &proposal.proposal.report_id)?;
            let terminal = ArchivedProposal {
                domain_version: VersionV1,
                scope: actor.scope().clone(),
                id: id.clone(),
                digest: proposal.digest,
                report_id: report.id,
                report_digest: report.digest,
                archiver: actor.principal().clone(),
                archiver_subject: actor.capability().subject.clone(),
                archived_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            };
            save(
                tx,
                &self.serving_owner,
                actor.scope(),
                &terminal_key(actor.scope(), "archived-proposal", id.as_str())?,
                &terminal,
            )?;
            Ok(proposal)
        })
    }

    /// Evidence reclamation has its own retention and authenticated reference
    /// ownership contract. Queue archival cannot release any artifact bytes.
    pub fn reclaim_archived_policy_evidence(
        &self,
        _actor: &AuthenticatedRecoveryActor,
        _reader: &AuthenticatedRecoveryActor,
        _id: &ReviewId,
        _fence: &StoreMutationFence,
        _now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        Err(refused(
            "terminal proposal evidence reclamation unavailable",
        ))
    }
}
