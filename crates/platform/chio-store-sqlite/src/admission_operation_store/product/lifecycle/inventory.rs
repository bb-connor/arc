//! Bounded active review ownership is independent of immutable evidence history.
use super::*;
use std::collections::BTreeSet;

const LEGACY_RECORD_BOUND: usize = 256;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportOwner {
    scope: RecoveryScopeV1,
    id: EvidenceRef,
    digest: CommandDigest,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposalOwner {
    scope: RecoveryScopeV1,
    id: ReviewId,
    digest: CanonicalPayloadDigest,
    report_id: EvidenceRef,
    report_digest: CommandDigest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveInventory {
    domain_version: VersionV1,
    authority_domain: AuthorityDomainId,
    tenant_id: RecoveryTenantId,
    reports: BoundedList<ReportOwner, 64>,
    proposals: BoundedList<ProposalOwner, 16>,
}

fn key(scope: &RecoveryScopeV1) -> Result<(String, String), AdmissionOperationStoreError> {
    let (_, domain) = quota_key(scope, ProductWorkKind::Report)?;
    Ok((
        format!("product-disposition:active-inventory:{domain}"),
        domain,
    ))
}

fn same_domain(left: &RecoveryScopeV1, right: &RecoveryScopeV1) -> bool {
    left.authority_domain == right.authority_domain && left.tenant_id == right.tenant_id
}

fn quota(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    kind: ProductWorkKind,
) -> Result<u64, AdmissionOperationStoreError> {
    let (key, domain) = quota_key(scope, kind)?;
    let Some(row) = protected::raw_checked(tx, &key)? else {
        return Ok(0);
    };
    protected::source_reference(tx, &key)?;
    if row.scope != domain || row.kind != "command" || row.version == 0 {
        return Err(refused("active product quota custody"));
    }
    let count: SafeInteger = protected::decode(&row.payload)?;
    if count.get() > kind.ceiling() {
        return Err(refused("active product quota bound"));
    }
    Ok(count.get())
}

fn validate(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    value: &ActiveInventory,
) -> Result<(), AdmissionOperationStoreError> {
    if value.authority_domain != scope.authority_domain || value.tenant_id != scope.tenant_id {
        return Err(refused("active product domain"));
    }
    let mut report_keys = BTreeSet::new();
    for entry in value.reports.as_slice() {
        if !same_domain(&entry.scope, scope)
            || !report_keys.insert(reports::key(&entry.scope, &entry.id)?)
            || stored_report(tx, &entry.scope, &entry.id)?.digest != entry.digest
            || report_released(tx, &entry.scope, &entry.id)?
        {
            return Err(refused("active report ownership"));
        }
    }
    let mut proposal_keys = BTreeSet::new();
    for entry in value.proposals.as_slice() {
        let proposal = stored_proposal(tx, &entry.scope, &entry.id)?;
        if !same_domain(&entry.scope, scope)
            || !proposal_keys.insert(proposal_key(&entry.scope, &entry.id)?)
            || proposal.digest != entry.digest
            || proposal.proposal.report_id != entry.report_id
            || stored_report(tx, &entry.scope, &entry.report_id)?.digest != entry.report_digest
            || proposal_released(tx, &entry.scope, &entry.id)?
        {
            return Err(refused("active proposal ownership"));
        }
    }
    if quota(tx, scope, ProductWorkKind::Report)? != value.reports.as_slice().len() as u64
        || quota(tx, scope, ProductWorkKind::Proposal)? != value.proposals.as_slice().len() as u64
    {
        return Err(refused("active product quota differs from ownership"));
    }
    Ok(())
}

fn legacy_keys(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    kind: ProductWorkKind,
) -> Result<Vec<String>, AdmissionOperationStoreError> {
    let (pattern, authority_path, tenant_path) = match kind {
        ProductWorkKind::Report => (
            "product-report:*",
            "$.report.scope.authority_domain",
            "$.report.scope.tenant_id",
        ),
        ProductWorkKind::Proposal => (
            "product-proposal:*",
            "$.proposal.scope.authority_domain",
            "$.proposal.scope.tenant_id",
        ),
    };
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB ?1
           AND json_extract(payload,?2)=?3 AND json_extract(payload,?4)=?5
         ORDER BY record_key LIMIT ?6",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![
                pattern,
                authority_path,
                scope.authority_domain.as_str(),
                tenant_path,
                scope.tenant_id.as_str(),
                (LEGACY_RECORD_BOUND + 1) as i64,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?;
    let keys = rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?;
    if keys.len() > LEGACY_RECORD_BOUND {
        return Err(refused(
            "legacy product inventory requires explicit bounded migration",
        ));
    }
    Ok(keys)
}

fn bootstrap(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
) -> Result<ActiveInventory, AdmissionOperationStoreError> {
    let empty = ActiveInventory {
        domain_version: VersionV1,
        authority_domain: scope.authority_domain.clone(),
        tenant_id: scope.tenant_id.clone(),
        reports: BoundedList::new(Vec::new()).map_err(refused)?,
        proposals: BoundedList::new(Vec::new()).map_err(refused)?,
    };
    let (report_quota, _) = quota_key(scope, ProductWorkKind::Report)?;
    let (proposal_quota, _) = quota_key(scope, ProductWorkKind::Proposal)?;
    if protected::raw_checked(tx, &report_quota)?.is_none()
        && protected::raw_checked(tx, &proposal_quota)?.is_none()
    {
        // Native admission persists its aggregate ownership before every source
        // record. Pristine absence of both counters cannot have admitted work;
        // retained counter history is rejected by raw_checked independently.
        return Ok(empty);
    }
    // Genuine older product queues admitted at most 64 reports and 16 proposals.
    // A bounded authenticated import accommodates retained terminal records but
    // never silently resets a counter or treats a missing projection as empty.
    let mut report_owners = Vec::new();
    for key in legacy_keys(tx, scope, ProductWorkKind::Report)? {
        let retained: StoredDecisionReportV1 =
            load(tx, &key)?.ok_or_else(|| refused("legacy report disappeared"))?;
        if !same_domain(scope, &retained.report.scope)
            || reports::key(&retained.report.scope, &retained.id)? != key
        {
            return Err(refused("legacy report identity"));
        }
        let retained = stored_report(tx, &retained.report.scope, &retained.id)?;
        if !report_released(tx, &retained.report.scope, &retained.id)? {
            report_owners.push(ReportOwner {
                scope: retained.report.scope,
                id: retained.id,
                digest: retained.digest,
            });
        }
    }
    let mut proposal_owners = Vec::new();
    for key in legacy_keys(tx, scope, ProductWorkKind::Proposal)? {
        let retained: StoredPolicyMaintenanceProposalV1 =
            load(tx, &key)?.ok_or_else(|| refused("legacy proposal disappeared"))?;
        if !same_domain(scope, &retained.proposal.scope)
            || proposal_key(&retained.proposal.scope, &retained.proposal.proposal_id)? != key
        {
            return Err(refused("legacy proposal identity"));
        }
        let retained =
            stored_proposal(tx, &retained.proposal.scope, &retained.proposal.proposal_id)?;
        if !proposal_released(tx, &retained.proposal.scope, &retained.proposal.proposal_id)? {
            let report = stored_report(tx, &retained.proposal.scope, &retained.proposal.report_id)?;
            proposal_owners.push(ProposalOwner {
                scope: retained.proposal.scope,
                id: retained.proposal.proposal_id,
                digest: retained.digest,
                report_id: retained.proposal.report_id,
                report_digest: report.digest,
            });
        }
    }
    let value = ActiveInventory {
        domain_version: VersionV1,
        authority_domain: scope.authority_domain.clone(),
        tenant_id: scope.tenant_id.clone(),
        reports: BoundedList::new(report_owners).map_err(refused)?,
        proposals: BoundedList::new(proposal_owners).map_err(refused)?,
    };
    validate(tx, scope, &value)?;
    Ok(value)
}

fn read(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
) -> Result<ActiveInventory, AdmissionOperationStoreError> {
    let (key, domain) = key(scope)?;
    let value = if let Some(row) = protected::raw_checked(tx, &key)? {
        protected::source_reference(tx, &key)?;
        if row.scope != domain || row.kind != "command" || row.version == 0 {
            return Err(refused("active product inventory custody"));
        }
        protected::decode(&row.payload)?
    } else {
        bootstrap(tx, scope)?
    };
    validate(tx, scope, &value)?;
    Ok(value)
}

fn write(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    value: &ActiveInventory,
) -> Result<(), AdmissionOperationStoreError> {
    let (key, domain) = key(scope)?;
    protected::save(
        tx,
        owner,
        &key,
        &domain,
        "command",
        &protected::encode(value)?,
        None,
    )
}

pub(in crate::admission_operation_store::product) fn reserve_report(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    id: &EvidenceRef,
    digest: CommandDigest,
) -> Result<(), AdmissionOperationStoreError> {
    let mut value = read(tx, scope)?;
    if value
        .reports
        .as_slice()
        .iter()
        .any(|entry| entry.scope == *scope && entry.id == *id)
    {
        return Err(refused("active report identity reused"));
    }
    let mut entries = value.reports.as_slice().to_vec();
    entries.push(ReportOwner {
        scope: scope.clone(),
        id: id.clone(),
        digest,
    });
    value.reports = BoundedList::new(entries).map_err(refused)?;
    reserve_quota(tx, owner, scope, ProductWorkKind::Report)?;
    write(tx, owner, scope, &value)
}

pub(in crate::admission_operation_store::product) fn reserve_proposal(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proposal: &PolicyMaintenanceProposalV1,
    digest: CanonicalPayloadDigest,
    report: &StoredDecisionReportV1,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = &proposal.scope;
    let mut value = read(tx, scope)?;
    if value
        .proposals
        .as_slice()
        .iter()
        .any(|entry| entry.scope == *scope && entry.id == proposal.proposal_id)
    {
        return Err(refused("active proposal identity reused"));
    }
    let mut entries = value.proposals.as_slice().to_vec();
    entries.push(ProposalOwner {
        scope: scope.clone(),
        id: proposal.proposal_id.clone(),
        digest,
        report_id: report.id.clone(),
        report_digest: report.digest,
    });
    value.proposals = BoundedList::new(entries).map_err(refused)?;
    reserve_quota(tx, owner, scope, ProductWorkKind::Proposal)?;
    write(tx, owner, scope, &value)
}

pub(super) fn retire_report(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    report: &StoredDecisionReportV1,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = &report.report.scope;
    let mut value = read(tx, scope)?;
    let expected = ReportOwner {
        scope: scope.clone(),
        id: report.id.clone(),
        digest: report.digest,
    };
    if !value.reports.as_slice().contains(&expected) {
        return Err(refused("active report owner missing"));
    }
    value.reports = BoundedList::new(
        value
            .reports
            .as_slice()
            .iter()
            .filter(|entry| **entry != expected)
            .cloned()
            .collect(),
    )
    .map_err(refused)?;
    release_active_quota(tx, owner, scope, ProductWorkKind::Report)?;
    write(tx, owner, scope, &value)
}

pub(super) fn retire_proposal(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proposal: &StoredPolicyMaintenanceProposalV1,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = &proposal.proposal.scope;
    let mut value = read(tx, scope)?;
    let expected = ProposalOwner {
        scope: scope.clone(),
        id: proposal.proposal.proposal_id.clone(),
        digest: proposal.digest,
        report_id: proposal.proposal.report_id.clone(),
        report_digest: stored_report(tx, scope, &proposal.proposal.report_id)?.digest,
    };
    if !value.proposals.as_slice().contains(&expected) {
        return Err(refused("active proposal owner missing"));
    }
    value.proposals = BoundedList::new(
        value
            .proposals
            .as_slice()
            .iter()
            .filter(|entry| **entry != expected)
            .cloned()
            .collect(),
    )
    .map_err(refused)?;
    release_active_quota(tx, owner, scope, ProductWorkKind::Proposal)?;
    write(tx, owner, scope, &value)
}

pub(super) fn require_no_active_proposal(
    tx: &Transaction<'_>,
    report: &StoredDecisionReportV1,
) -> Result<(), AdmissionOperationStoreError> {
    let value = read(tx, &report.report.scope)?;
    if value.proposals.as_slice().iter().any(|entry| {
        entry.scope == report.report.scope
            && entry.report_id == report.id
            && entry.report_digest == report.digest
    }) {
        return Err(refused("report still owns active proposal evidence"));
    }
    Ok(())
}
