//! Native terminal dispositions preserve evidence and release only active work.
use super::super::semantic::NativePolicyChangeReceiptV1;
use super::*;
mod archive;
pub(super) mod inventory;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProductWorkKind {
    Report,
    Proposal,
}

impl ProductWorkKind {
    pub(super) fn quota_name(self) -> &'static str {
        match self {
            Self::Report => "reports",
            Self::Proposal => "proposals",
        }
    }

    pub(super) fn ceiling(self) -> u64 {
        match self {
            Self::Report => 64,
            Self::Proposal => 16,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedProposalDisposition {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    proposal_id: ReviewId,
    proposal_digest: CanonicalPayloadDigest,
    report_id: EvidenceRef,
    receipt: NativePolicyChangeReceiptV1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedReportDisposition {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    report_id: EvidenceRef,
    report_digest: CommandDigest,
    proposal_id: ReviewId,
    proposal_digest: CanonicalPayloadDigest,
    receipt: NativePolicyChangeReceiptV1,
}

pub(super) fn archived_proposal_source(
    tx: &Connection,
    proposal: &StoredPolicyMaintenanceProposalV1,
) -> Result<Option<(protected::ProtectedSourceReference, u64)>, AdmissionOperationStoreError> {
    archive::proposal_archive_source(tx, proposal)
}

pub(super) fn quota_key(
    scope: &RecoveryScopeV1,
    kind: ProductWorkKind,
) -> Result<(String, String), AdmissionOperationStoreError> {
    // Preserve the existing aggregate tenant/domain identity and stored bytes.
    let domain = sha256_hex(&protected::encode(&(
        &scope.tenant_id,
        &scope.authority_domain,
    ))?);
    Ok((
        format!("product-quota:{}:{domain}", kind.quota_name()),
        domain,
    ))
}

fn release_active_quota(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    kind: ProductWorkKind,
) -> Result<(), AdmissionOperationStoreError> {
    let (key, domain) = quota_key(scope, kind)?;
    let row = protected::raw(tx, &key)?.ok_or_else(|| refused("active product quota"))?;
    if row.scope != domain || row.kind != "command" || row.version == 0 {
        return Err(refused("active product quota custody"));
    }
    let count: SafeInteger = protected::decode(&row.payload)?;
    if count.get() > kind.ceiling() {
        return Err(refused("active product quota bound"));
    }
    let remaining = count
        .get()
        .checked_sub(1)
        .ok_or_else(|| refused("active product quota underflow"))?;
    protected::save(
        tx,
        owner,
        &key,
        &domain,
        "command",
        &protected::encode(&SafeInteger::new(remaining).map_err(refused)?)?,
        None,
    )
}

fn disposition<T: serde::de::DeserializeOwned + Serialize>(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    key: &str,
) -> Result<Option<T>, AdmissionOperationStoreError> {
    let Some(row) = protected::raw_checked(tx, key)? else {
        return Ok(None);
    };
    protected::source_reference(tx, key)?;
    if row.scope != protected::scope_key(scope)? || row.kind != "command" || row.version == 0 {
        return Err(refused("product terminal custody"));
    }
    protected::decode(&row.payload).map(Some)
}

fn terminal_key(
    scope: &RecoveryScopeV1,
    category: &str,
    id: &str,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "product-disposition:{category}:{}:{id}",
        protected::scope_key(scope)?
    ))
}

fn proposal_released(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    id: &ReviewId,
) -> Result<bool, AdmissionOperationStoreError> {
    let proposal = stored_proposal(tx, scope, id)?;
    let archived = archive::proposal_disposition(tx, &proposal)?.is_some();
    let applied = disposition::<AppliedProposalDisposition>(
        tx,
        scope,
        &terminal_key(scope, "proposal", id.as_str())?,
    )?;
    if let Some(old) = &applied {
        if old.scope != *scope
            || old.proposal_id != *id
            || old.proposal_digest != proposal.digest
            || old.report_id != proposal.proposal.report_id
            || old.receipt != application_receipt(tx, scope, &proposal)?
        {
            return Err(refused("applied proposal terminal identity"));
        }
    }
    Ok(archived || applied.is_some())
}

fn report_released(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
) -> Result<bool, AdmissionOperationStoreError> {
    let report = stored_report(tx, scope, id)?;
    let archived = archive::report_disposition(tx, &report)?.is_some();
    let reviewed = disposition::<ReviewedReportDisposition>(
        tx,
        scope,
        &terminal_key(scope, "report", id.as_str())?,
    )?;
    if let Some(old) = &reviewed {
        let proposal = stored_proposal(tx, scope, &old.proposal_id)?;
        if old.scope != *scope
            || old.report_id != *id
            || old.report_digest != report.digest
            || old.proposal_digest != proposal.digest
            || proposal.proposal.report_id != *id
            || old.receipt != application_receipt(tx, scope, &proposal)?
        {
            return Err(refused("reviewed report terminal identity"));
        }
    }
    Ok(archived || reviewed.is_some())
}

fn application_receipt(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    proposal: &StoredPolicyMaintenanceProposalV1,
) -> Result<NativePolicyChangeReceiptV1, AdmissionOperationStoreError> {
    let receipt = super::super::semantic::policy_application_receipt(
        tx,
        scope,
        &proposal.proposal.proposal_id,
    )?
    .ok_or_else(|| refused("independent policy application"))?;
    if receipt.proposal_id != proposal.proposal.proposal_id
        || receipt.target_policy != proposal.proposal.target_policy
        || receipt.generation.get() == 0
        || receipt.applied_at_unix_ms.get() < proposal.submitted_at_unix_ms.get()
    {
        return Err(refused("policy application binding"));
    }
    Ok(receipt)
}

/// Called only after the independent operator application has been saved in
/// this same fenced transaction. No receipt, attachment, report or proposal is
/// removed, and an exact native application replay never calls this hook.
pub(in crate::admission_operation_store) fn complete_policy_review(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    proposal_id: &ReviewId,
    report_id: &EvidenceRef,
) -> Result<(), AdmissionOperationStoreError> {
    verify_active_owner(tx, owner, Some(&owner.fence))?;
    let proposal = stored_proposal(tx, scope, proposal_id)?;
    if proposal.proposal.report_id != *report_id {
        return Err(refused("review report dependency"));
    }
    let report = stored_report(tx, scope, report_id)?;
    let receipt = application_receipt(tx, scope, &proposal)?;
    let current = super::super::semantic::installation(tx, scope)?.policy_basis()?;
    if current.deployment != receipt.target_deployment
        || current.policy != receipt.target_policy
        || current.generation != receipt.generation
        || receipt.applied_at_unix_ms.get() < report.submitted_at_unix_ms.get()
    {
        return Err(refused("completed review target"));
    }
    let scoped_key = protected::scope_key(scope)?;
    let proposal_key = format!(
        "product-disposition:proposal:{scoped_key}:{}",
        proposal_id.as_str()
    );
    let proposed = AppliedProposalDisposition {
        domain_version: VersionV1,
        scope: scope.clone(),
        proposal_id: proposal_id.clone(),
        proposal_digest: proposal.digest,
        report_id: report_id.clone(),
        receipt: receipt.clone(),
    };
    if let Some(old) = disposition::<AppliedProposalDisposition>(tx, scope, &proposal_key)? {
        if old != proposed {
            return Err(refused("proposal terminal identity reused"));
        }
    } else {
        if !proposal_released(tx, scope, proposal_id)? {
            inventory::retire_proposal(tx, owner, &proposal)?;
        }
        save(tx, owner, scope, &proposal_key, &proposed)?;
    }

    let report_key = format!(
        "product-disposition:report:{scoped_key}:{}",
        report_id.as_str()
    );
    if let Some(old) = disposition::<ReviewedReportDisposition>(tx, scope, &report_key)? {
        let old_proposal = stored_proposal(tx, scope, &old.proposal_id)?;
        let old_receipt = application_receipt(tx, scope, &old_proposal)?;
        if old.scope != *scope
            || old.report_id != *report_id
            || old.report_digest != report.digest
            || old.proposal_digest != old_proposal.digest
            || old_proposal.proposal.report_id != *report_id
            || old.receipt != old_receipt
        {
            return Err(refused("report terminal identity reused"));
        }
    } else {
        if !report_released(tx, scope, report_id)? {
            inventory::retire_report(tx, owner, &report)?;
        }
        save(
            tx,
            owner,
            scope,
            &report_key,
            &ReviewedReportDisposition {
                domain_version: VersionV1,
                scope: scope.clone(),
                report_id: report_id.clone(),
                report_digest: report.digest,
                proposal_id: proposal_id.clone(),
                proposal_digest: proposal.digest,
                receipt,
            },
        )?;
    }
    Ok(())
}
