//! Immutable product bodies prove complete evidence sets, never retirement authority.
use super::super::knowledge::references::ProductEvidenceOwner;
use super::*;

/// Derive every declared artifact from the authenticated immutable source. A
/// caller cannot reserve only a selected first attachment of this source.
pub(in crate::admission_operation_store) fn product_evidence_source(
    tx: &Connection,
    owner: &ProductEvidenceOwner,
) -> Result<
    (
        protected::ProtectedSourceReference,
        Vec<ArtifactVersionRefV1>,
    ),
    AdmissionOperationStoreError,
> {
    let (scope, key, references) = match owner {
        ProductEvidenceOwner::Report { scope, id, digest } => {
            let report = stored_report(tx, scope, id)?;
            report.report.validate().map_err(refused)?;
            if report.digest != *digest {
                return Err(refused("product report evidence ownership"));
            }
            let mut references = Vec::new();
            for reference in report.report.attachments.as_slice() {
                if !references.contains(reference) {
                    references.push(reference.clone());
                }
            }
            (scope, reports::key(scope, id)?, references)
        }
        ProductEvidenceOwner::Proposal { scope, id, digest } => {
            let proposal = stored_proposal(tx, scope, id)?;
            proposal.proposal.validate().map_err(refused)?;
            if proposal.digest != *digest {
                return Err(refused("product proposal evidence ownership"));
            }
            let mut references = Vec::new();
            // The closed body has at most 16 benign and 16 adversarial cases.
            // Full governed-reference equality includes provenance and scope.
            for case in proposal
                .proposal
                .benign_trajectories
                .as_slice()
                .iter()
                .chain(proposal.proposal.adversarial_trajectories.as_slice())
            {
                if !references.contains(&case.artifact) {
                    references.push(case.artifact.clone());
                }
            }
            (scope, proposal_key(scope, id)?, references)
        }
    };
    for reference in &references {
        if reference.scope.authority_domain != scope.authority_domain
            || reference.scope.tenant_id != scope.tenant_id
        {
            return Err(refused("product evidence authority changed"));
        }
    }
    let source = protected::source_reference(tx, &key)?;
    let (namespace, request): (Option<String>, Option<String>) = tx
        .query_row(
            "SELECT native_namespace,native_request FROM main.admission_operation_recovery_records WHERE record_key=?1",
            [&key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if namespace.is_some()
        || request.is_some()
        || source.scope_key() != protected::scope_key(scope)?
        || source.kind() != "command"
        || source.version() != 1
    {
        return Err(refused("immutable product evidence source changed"));
    }
    Ok((source, references))
}

pub(in crate::admission_operation_store) fn verify_product_evidence_source(
    tx: &Connection,
    owner: &ProductEvidenceOwner,
    reference: &ArtifactVersionRefV1,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let (source, references) = product_evidence_source(tx, owner)?;
    if !references.contains(reference) {
        return Err(refused("artifact is not declared by its product source"));
    }
    Ok(source)
}

/// Exact immutable replay observes its retained complete owner set without
/// allocating another owner or appending a replacement for missing custody.
pub(super) fn require_product_evidence_owners(
    tx: &Connection,
    owner: &ProductEvidenceOwner,
) -> Result<(), AdmissionOperationStoreError> {
    use super::super::knowledge::references::{
        require_active_reference_owner, require_retired_reference_owner, ReferenceOwner,
        SourceAnchor,
    };
    let (source, references) = product_evidence_source(tx, owner)?;
    if references.is_empty() {
        return Ok(());
    }
    let anchor = SourceAnchor::capture(&source);
    let terminal = match owner {
        ProductEvidenceOwner::Proposal { .. } => {
            super::evidence_reclamation::product_reclamation_source(tx, owner)?
        }
        ProductEvidenceOwner::Report { .. } => None,
    };
    let owner = ReferenceOwner::from(owner.clone());
    for reference in &references {
        if let Some(terminal) = &terminal {
            if terminal.references() != references.as_slice()
                || SourceAnchor::capture(terminal.original()) != anchor
            {
                return Err(refused("reclaimed Proposal changed its complete owner set"));
            }
            require_retired_reference_owner(
                tx,
                reference,
                &owner,
                &anchor,
                &SourceAnchor::capture(terminal.terminal()),
            )?;
        } else {
            require_active_reference_owner(tx, reference, &owner, &anchor)?;
        }
    }
    Ok(())
}
