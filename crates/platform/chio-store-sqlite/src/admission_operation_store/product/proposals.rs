use super::super::knowledge::references::ProductEvidenceOwner;
use super::reference_intake::{ProductReferenceWriter, VerifiedProductReferenceIntake};
use super::*;
use chio_kernel::recovery::RecoveryCommandPortError;

pub(super) fn label(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    reader: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    proposal: &PolicyMaintenanceProposalV1,
    now: u64,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    if proposal.scope != *actor.scope() {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    require_reader(tx, actor, Some(reader), profile, now)?;
    let report = stored_report(tx, actor.scope(), &proposal.report_id)?;
    let mut label = current_label(tx, profile)?
        .join_restrictions(&report.label)
        .map_err(refused)?;
    for reference in report.report.attachments.as_slice() {
        label = join_attachment(tx, actor.scope(), label, reference)?;
    }
    for case in proposal
        .benign_trajectories
        .as_slice()
        .iter()
        .chain(proposal.adversarial_trajectories.as_slice())
    {
        label = join_attachment(tx, actor.scope(), label, &case.artifact)?;
    }
    require_clearance(actor, profile, &label)?;
    Ok(label)
}

impl SqliteAdmissionOperationStore {
    pub fn propose_policy_maintenance(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reader: &AuthenticatedRecoveryActor,
        proposal: &PolicyMaintenanceProposalV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<StoredPolicyMaintenanceProposalV1, RecoveryCommandPortError> {
        proposal.validate().map_err(refused)?;
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            if actor.permission() != RecoveryPermission::Maintain
                || proposal.scope != *actor.scope()
            {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied.into());
            }
            let report = selected_report(tx, actor.scope(), &proposal.report_id)?;
            let label = label(tx, actor, reader, profile, proposal, now)?;
            let digest = CanonicalPayloadDigest::from_bytes(hash(
                RecoveryDigestDomain::PolicyMaintenanceProposal,
                proposal,
            )?);
            let key = proposal_key(actor.scope(), &proposal.proposal_id)?;
            if let Some(old) = load::<StoredPolicyMaintenanceProposalV1>(tx, &key)? {
                require_clearance(
                    actor,
                    profile,
                    &label.join_restrictions(&old.label).map_err(refused)?,
                )?;
                if old.digest != digest {
                    return Err(RecoveryCommandPortError::Conflict);
                }
                require_product_evidence_owners(
                    tx,
                    &ProductEvidenceOwner::Proposal {
                        scope: actor.scope().clone(),
                        id: old.proposal.proposal_id.clone(),
                        digest: old.digest,
                    },
                )?;
                return Ok(old);
            }
            require_finite_intake_audience(actor, profile)?;
            let current =
                super::super::semantic::installation(tx, actor.scope())?.policy_basis()?;
            if current.policy != proposal.base_policy
                || current.deployment != proposal.base_deployment
            {
                return Err(RecoveryCommandPortError::Conflict);
            }
            let value = StoredPolicyMaintenanceProposalV1 {
                proposal: proposal.clone(),
                digest,
                maintainer: actor.principal().clone(),
                maintainer_subject: actor.capability().subject.clone(),
                label,
                influence: ArtifactInfluenceV1 {
                    commitment: digest,
                    externally_influenced: true,
                    unknown: true,
                },
                submitted_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            };
            let writer = ProductReferenceWriter::new(
                tx,
                &self.serving_owner,
                actor,
                Some(reader),
                profile,
                now,
            );
            let intake = VerifiedProductReferenceIntake::proposal(writer, &value)?;
            let evidence_owner = intake.owner().clone();
            let reserved =
                protected::reserve_product_reference_intake(tx, &self.serving_owner, intake)?;
            lifecycle::inventory::reserve_proposal(
                tx,
                &self.serving_owner,
                proposal,
                digest,
                &report,
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
}
