use super::super::knowledge::references::ProductEvidenceOwner;
use super::reference_intake::{ProductReferenceWriter, VerifiedProductReferenceIntake};
use super::*;
use chio_kernel::recovery::RecoveryCommandPortError;

pub(super) fn key(
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "product-report:{}:{}",
        protected::scope_key(scope)?,
        id.as_str()
    ))
}
pub(super) fn label(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reader: Option<&AuthenticatedRecoveryActor>,
    profile: &RecoveryDeploymentV1,
    report: &DecisionReportV1,
    now: u64,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    if report.scope != *actor.scope() {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let workflow = protected::workflow_tx(tx, actor.scope(), &report.workflow_id)?;
    let source = workflow
        .action
        .as_ref()
        .map(|action| action.authorization_requirements.source_label.clone())
        .unwrap_or(InformationLabel::Top);
    let mut label = current_label(tx, profile)?
        .join_restrictions(&source)
        .map_err(refused)?;
    if !report.attachments.as_slice().is_empty() {
        require_reader(tx, actor, reader, profile, now)?;
    }
    for reference in report.attachments.as_slice() {
        label = join_attachment(tx, actor.scope(), label, reference)?;
    }
    require_clearance(actor, profile, &label)?;
    Ok(label)
}
impl SqliteAdmissionOperationStore {
    /// Stable identity is resolved before stale revision checks, after live authorization.
    pub fn submit_decision_report(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reader: Option<&AuthenticatedRecoveryActor>,
        command: &CommandId,
        report: &DecisionReportV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<StoredDecisionReportV1, RecoveryCommandPortError> {
        report.validate().map_err(refused)?;
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Report || report.scope != *actor.scope() {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied.into());
            }
            let id = EvidenceRef::new(&format!(
                "report:{}",
                sha256_hex(&protected::encode(&(
                    actor.scope(),
                    actor.principal(),
                    command
                ))?)
            ))
            .map_err(refused)?;
            let key = key(actor.scope(), &id)?;
            let digest =
                CommandDigest::from_bytes(hash(RecoveryDigestDomain::DecisionReport, report)?);
            if let Some(old) = load::<StoredDecisionReportV1>(tx, &key)? {
                let current = label(tx, actor, reader, profile, &old.report, now)?;
                require_clearance(
                    actor,
                    profile,
                    &current.join_restrictions(&old.label).map_err(refused)?,
                )?;
                if old.digest != digest {
                    return Err(RecoveryCommandPortError::Conflict);
                }
                require_product_evidence_owners(
                    tx,
                    &ProductEvidenceOwner::Report {
                        scope: actor.scope().clone(),
                        id: old.id.clone(),
                        digest: old.digest,
                    },
                )?;
                return Ok(old);
            }
            require_finite_intake_audience(actor, profile)?;
            let label = label(tx, actor, reader, profile, report, now)?;
            if protected::workflow_tx(tx, actor.scope(), &report.workflow_id)?.revision
                != report.expected_revision
            {
                return Err(RecoveryCommandPortError::Conflict);
            }
            let value = StoredDecisionReportV1 {
                id,
                digest,
                report: report.clone(),
                reporter: actor.principal().clone(),
                reporter_subject: actor.capability().subject.clone(),
                label,
                // Free-form reporter input has no integrity endorsement. The
                // whole body commits every attachment/provenance dependency.
                influence: ArtifactInfluenceV1 {
                    commitment: CanonicalPayloadDigest::from_bytes(*digest.as_bytes()),
                    externally_influenced: true,
                    unknown: true,
                },
                submitted_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            };
            let writer =
                ProductReferenceWriter::new(tx, &self.serving_owner, actor, reader, profile, now);
            let intake = VerifiedProductReferenceIntake::report(writer, command, &value)?;
            let evidence_owner = intake.owner().clone();
            let reserved =
                protected::reserve_product_reference_intake(tx, &self.serving_owner, intake)?;
            lifecycle::inventory::reserve_report(
                tx,
                &self.serving_owner,
                actor.scope(),
                &value.id,
                digest,
            )?;
            save(tx, &self.serving_owner, actor.scope(), &key, &value)?;
            if let Some(reserved) = reserved {
                super::super::knowledge::retain_product_evidence(
                    tx,
                    &self.serving_owner,
                    evidence_owner,
                    reserved,
                )?;
            }
            Ok(value)
        })
    }
    pub fn read_decision_report(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reader: Option<&AuthenticatedRecoveryActor>,
        id: &EvidenceRef,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<StoredDecisionReportV1, AdmissionOperationStoreError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Inspect {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            let value = selected_report(tx, actor.scope(), id)?;
            let current = label(tx, actor, reader, profile, &value.report, now)?;
            require_clearance(
                actor,
                profile,
                &current.join_restrictions(&value.label).map_err(refused)?,
            )?;
            Ok(value)
        })
    }
}
