use super::*;

pub(crate) fn unix_timestamp_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn settlement_reconciliation_state_text(
    state: SettlementReconciliationState,
) -> &'static str {
    match state {
        SettlementReconciliationState::Open => "open",
        SettlementReconciliationState::Reconciled => "reconciled",
        SettlementReconciliationState::Ignored => "ignored",
        SettlementReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_settlement_reconciliation_state(
    value: &str,
) -> Result<SettlementReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn metered_billing_reconciliation_state_text(
    state: MeteredBillingReconciliationState,
) -> &'static str {
    match state {
        MeteredBillingReconciliationState::Open => "open",
        MeteredBillingReconciliationState::Reconciled => "reconciled",
        MeteredBillingReconciliationState::Ignored => "ignored",
        MeteredBillingReconciliationState::RetryScheduled => "retry_scheduled",
    }
}

pub(crate) fn parse_metered_billing_reconciliation_state(
    value: &str,
) -> Result<MeteredBillingReconciliationState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn underwriting_decision_outcome_label(
    outcome: UnderwritingDecisionOutcome,
) -> &'static str {
    match outcome {
        UnderwritingDecisionOutcome::Approve => "approve",
        UnderwritingDecisionOutcome::ReduceCeiling => "reduce_ceiling",
        UnderwritingDecisionOutcome::StepUp => "step_up",
        UnderwritingDecisionOutcome::Deny => "deny",
    }
}

pub(crate) fn underwriting_lifecycle_state_label(
    state: UnderwritingDecisionLifecycleState,
) -> &'static str {
    match state {
        UnderwritingDecisionLifecycleState::Active => "active",
        UnderwritingDecisionLifecycleState::Superseded => "superseded",
    }
}

pub(crate) fn underwriting_review_state_label(
    state: arc_kernel::UnderwritingReviewState,
) -> &'static str {
    match state {
        arc_kernel::UnderwritingReviewState::Approved => "approved",
        arc_kernel::UnderwritingReviewState::ManualReviewRequired => "manual_review_required",
        arc_kernel::UnderwritingReviewState::Denied => "denied",
    }
}

pub(crate) fn underwriting_risk_class_label(
    class: arc_kernel::UnderwritingRiskClass,
) -> &'static str {
    match class {
        arc_kernel::UnderwritingRiskClass::Baseline => "baseline",
        arc_kernel::UnderwritingRiskClass::Guarded => "guarded",
        arc_kernel::UnderwritingRiskClass::Elevated => "elevated",
        arc_kernel::UnderwritingRiskClass::Critical => "critical",
    }
}

pub(crate) fn underwriting_appeal_status_label(status: UnderwritingAppealStatus) -> &'static str {
    match status {
        UnderwritingAppealStatus::Open => "open",
        UnderwritingAppealStatus::Accepted => "accepted",
        UnderwritingAppealStatus::Rejected => "rejected",
    }
}

pub(crate) fn credit_facility_disposition_label(
    disposition: CreditFacilityDisposition,
) -> &'static str {
    match disposition {
        CreditFacilityDisposition::Grant => "grant",
        CreditFacilityDisposition::ManualReview => "manual_review",
        CreditFacilityDisposition::Deny => "deny",
    }
}

pub(crate) fn credit_facility_lifecycle_state_label(
    state: CreditFacilityLifecycleState,
) -> &'static str {
    match state {
        CreditFacilityLifecycleState::Active => "active",
        CreditFacilityLifecycleState::Superseded => "superseded",
        CreditFacilityLifecycleState::Denied => "denied",
        CreditFacilityLifecycleState::Expired => "expired",
    }
}

pub(crate) fn credit_bond_disposition_label(disposition: CreditBondDisposition) -> &'static str {
    match disposition {
        CreditBondDisposition::Lock => "lock",
        CreditBondDisposition::Hold => "hold",
        CreditBondDisposition::Release => "release",
        CreditBondDisposition::Impair => "impair",
    }
}

pub(crate) fn credit_bond_lifecycle_state_label(state: CreditBondLifecycleState) -> &'static str {
    match state {
        CreditBondLifecycleState::Active => "active",
        CreditBondLifecycleState::Superseded => "superseded",
        CreditBondLifecycleState::Released => "released",
        CreditBondLifecycleState::Impaired => "impaired",
        CreditBondLifecycleState::Expired => "expired",
    }
}

pub(crate) fn liability_provider_lifecycle_state_label(
    state: LiabilityProviderLifecycleState,
) -> &'static str {
    match state {
        LiabilityProviderLifecycleState::Active => "active",
        LiabilityProviderLifecycleState::Suspended => "suspended",
        LiabilityProviderLifecycleState::Superseded => "superseded",
        LiabilityProviderLifecycleState::Retired => "retired",
    }
}

pub(crate) fn credit_loss_lifecycle_event_kind_label(
    kind: CreditLossLifecycleEventKind,
) -> &'static str {
    match kind {
        CreditLossLifecycleEventKind::Delinquency => "delinquency",
        CreditLossLifecycleEventKind::Recovery => "recovery",
        CreditLossLifecycleEventKind::ReserveRelease => "reserve_release",
        CreditLossLifecycleEventKind::ReserveSlash => "reserve_slash",
        CreditLossLifecycleEventKind::WriteOff => "write_off",
    }
}

pub(crate) fn parse_underwriting_lifecycle_state(
    value: &str,
) -> Result<UnderwritingDecisionLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_facility_lifecycle_state(
    value: &str,
) -> Result<CreditFacilityLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_credit_bond_lifecycle_state(
    value: &str,
) -> Result<CreditBondLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn parse_liability_provider_lifecycle_state(
    value: &str,
) -> Result<LiabilityProviderLifecycleState, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn liability_quote_disposition_label(
    disposition: &LiabilityQuoteDisposition,
) -> &'static str {
    match disposition {
        LiabilityQuoteDisposition::Quoted => "quoted",
        LiabilityQuoteDisposition::Declined => "declined",
    }
}

pub(crate) fn liability_auto_bind_disposition_label(
    disposition: &LiabilityAutoBindDisposition,
) -> &'static str {
    match disposition {
        LiabilityAutoBindDisposition::AutoBound => "auto_bound",
        LiabilityAutoBindDisposition::ManualReview => "manual_review",
        LiabilityAutoBindDisposition::Denied => "denied",
    }
}

pub(crate) fn query_underwriting_appeal(
    tx: &rusqlite::Transaction<'_>,
    appeal_id: &str,
) -> Result<Option<UnderwritingAppealRecord>, ReceiptStoreError> {
    let row = tx
        .query_row(
            "SELECT decision_id, requested_by, reason, status, note, created_at, updated_at,
                resolved_by, replacement_decision_id
         FROM underwriting_appeals
         WHERE appeal_id = ?1",
            params![appeal_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)?;

    row.map(
        |(
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        )| {
            Ok(UnderwritingAppealRecord {
                schema: arc_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
                appeal_id: appeal_id.to_string(),
                decision_id,
                requested_by,
                reason,
                status: parse_underwriting_appeal_status(&status)?,
                note,
                created_at: created_at.max(0) as u64,
                updated_at: updated_at.max(0) as u64,
                resolved_by,
                replacement_decision_id,
            })
        },
    )
    .transpose()
}

pub(crate) fn parse_underwriting_appeal_status(
    value: &str,
) -> Result<UnderwritingAppealStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn load_underwriting_appeal_rows(
    connection: &Connection,
) -> Result<Vec<UnderwritingAppealRecord>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT appeal_id, decision_id, requested_by, reason, status, note, created_at,
                updated_at, resolved_by, replacement_decision_id
         FROM underwriting_appeals
         ORDER BY updated_at DESC, appeal_id DESC",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, i64>(6)?,
            row.get::<_, i64>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    rows.map(|row| {
        let (
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status,
            note,
            created_at,
            updated_at,
            resolved_by,
            replacement_decision_id,
        ) = row?;
        Ok(UnderwritingAppealRecord {
            schema: arc_kernel::UNDERWRITING_APPEAL_SCHEMA.to_string(),
            appeal_id,
            decision_id,
            requested_by,
            reason,
            status: parse_underwriting_appeal_status(&status)?,
            note,
            created_at: created_at.max(0) as u64,
            updated_at: updated_at.max(0) as u64,
            resolved_by,
            replacement_decision_id,
        })
    })
    .collect()
}

pub(crate) fn underwriting_decision_matches_query(
    decision: &SignedUnderwritingDecision,
    lifecycle_state: UnderwritingDecisionLifecycleState,
    latest_appeal_status: Option<UnderwritingAppealStatus>,
    query: &UnderwritingDecisionQuery,
) -> bool {
    let filters = &decision.body.evaluation.input.filters;
    let decision_id_matches = query
        .decision_id
        .as_deref()
        .is_none_or(|decision_id| decision.body.decision_id == decision_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let outcome_matches = query
        .outcome
        .is_none_or(|outcome| decision.body.evaluation.outcome == outcome);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let appeal_matches = query
        .appeal_status
        .is_none_or(|status| latest_appeal_status == Some(status));

    decision_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && outcome_matches
        && lifecycle_matches
        && appeal_matches
}

pub(crate) fn effective_credit_facility_lifecycle_state(
    facility: &SignedCreditFacility,
    persisted: CreditFacilityLifecycleState,
    now: u64,
) -> CreditFacilityLifecycleState {
    if persisted == CreditFacilityLifecycleState::Active && facility.body.expires_at <= now {
        CreditFacilityLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn effective_credit_bond_lifecycle_state(
    bond: &SignedCreditBond,
    persisted: CreditBondLifecycleState,
    now: u64,
) -> CreditBondLifecycleState {
    if persisted == CreditBondLifecycleState::Active && bond.body.expires_at <= now {
        CreditBondLifecycleState::Expired
    } else {
        persisted
    }
}

pub(crate) fn credit_facility_matches_query(
    facility: &SignedCreditFacility,
    lifecycle_state: CreditFacilityLifecycleState,
    query: &CreditFacilityListQuery,
) -> bool {
    let filters = &facility.body.report.filters;
    let facility_id_matches = query
        .facility_id
        .as_deref()
        .is_none_or(|facility_id| facility.body.facility_id == facility_id);
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| facility.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn credit_bond_matches_query(
    bond: &SignedCreditBond,
    lifecycle_state: CreditBondLifecycleState,
    query: &CreditBondListQuery,
) -> bool {
    let filters = &bond.body.report.filters;
    let bond_id_matches = query
        .bond_id
        .as_deref()
        .is_none_or(|bond_id| bond.body.bond_id == bond_id);
    let facility_id_matches = query.facility_id.as_deref().is_none_or(|facility_id| {
        bond.body.report.latest_facility_id.as_deref() == Some(facility_id)
    });
    let capability_matches = query
        .capability_id
        .as_deref()
        .is_none_or(|capability_id| filters.capability_id.as_deref() == Some(capability_id));
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| filters.agent_subject.as_deref() == Some(subject));
    let tool_server_matches = query
        .tool_server
        .as_deref()
        .is_none_or(|tool_server| filters.tool_server.as_deref() == Some(tool_server));
    let tool_name_matches = query
        .tool_name
        .as_deref()
        .is_none_or(|tool_name| filters.tool_name.as_deref() == Some(tool_name));
    let disposition_matches = query
        .disposition
        .is_none_or(|disposition| bond.body.report.disposition == disposition);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);

    bond_id_matches
        && facility_id_matches
        && capability_matches
        && subject_matches
        && tool_server_matches
        && tool_name_matches
        && disposition_matches
        && lifecycle_matches
}

pub(crate) fn liability_provider_matches_query(
    provider: &SignedLiabilityProvider,
    lifecycle_state: LiabilityProviderLifecycleState,
    query: &LiabilityProviderListQuery,
) -> bool {
    let report = &provider.body.report;
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| report.provider_id == provider_id);
    let lifecycle_matches = query
        .lifecycle_state
        .is_none_or(|state| lifecycle_state == state);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        report
            .policies
            .iter()
            .any(|policy| policy.jurisdiction.eq_ignore_ascii_case(jurisdiction))
    });
    let coverage_matches = query.coverage_class.is_none_or(|coverage_class| {
        report
            .policies
            .iter()
            .any(|policy| policy.coverage_classes.contains(&coverage_class))
    });
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        report.policies.iter().any(|policy| {
            policy
                .supported_currencies
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(currency))
        })
    });

    provider_id_matches
        && lifecycle_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_provider_policy_matches_resolution(
    policy: &arc_kernel::LiabilityJurisdictionPolicy,
    query: &LiabilityProviderResolutionQuery,
) -> bool {
    policy
        .jurisdiction
        .eq_ignore_ascii_case(&query.jurisdiction)
        && policy.coverage_classes.contains(&query.coverage_class)
        && policy
            .supported_currencies
            .iter()
            .any(|currency| currency.eq_ignore_ascii_case(&query.currency))
}

pub(crate) fn liability_market_workflow_matches_query(
    quote_request: &SignedLiabilityQuoteRequest,
    query: &LiabilityMarketWorkflowQuery,
) -> bool {
    let request = &quote_request.body;
    let quote_request_id_matches = query
        .quote_request_id
        .as_deref()
        .is_none_or(|quote_request_id| request.quote_request_id == quote_request_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| request.provider_policy.provider_id == provider_id);
    let subject_matches = query
        .agent_subject
        .as_deref()
        .is_none_or(|subject| request.risk_package.body.subject_key == subject);
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        request
            .provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let coverage_matches = query
        .coverage_class
        .is_none_or(|coverage_class| request.provider_policy.coverage_class == coverage_class);
    let currency_matches = query.currency.as_deref().is_none_or(|currency| {
        request
            .requested_coverage_amount
            .currency
            .eq_ignore_ascii_case(currency)
    });

    quote_request_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && coverage_matches
        && currency_matches
}

pub(crate) fn liability_claim_workflow_matches_query(
    claim: &SignedLiabilityClaimPackage,
    query: &LiabilityClaimWorkflowQuery,
) -> bool {
    let claim_body = &claim.body;
    let provider_policy = &claim_body
        .bound_coverage
        .body
        .placement
        .body
        .quote_response
        .body
        .quote_request
        .body
        .provider_policy;
    let claim_id_matches = query
        .claim_id
        .as_deref()
        .is_none_or(|claim_id| claim_body.claim_id == claim_id);
    let provider_id_matches = query
        .provider_id
        .as_deref()
        .is_none_or(|provider_id| provider_policy.provider_id == provider_id);
    let subject_matches = query.agent_subject.as_deref().is_none_or(|subject| {
        claim_body
            .bound_coverage
            .body
            .placement
            .body
            .quote_response
            .body
            .quote_request
            .body
            .risk_package
            .body
            .subject_key
            == subject
    });
    let jurisdiction_matches = query.jurisdiction.as_deref().is_none_or(|jurisdiction| {
        provider_policy
            .jurisdiction
            .eq_ignore_ascii_case(jurisdiction)
    });
    let policy_number_matches = query
        .policy_number
        .as_deref()
        .is_none_or(|policy_number| claim_body.bound_coverage.body.policy_number == policy_number);

    claim_id_matches
        && provider_id_matches
        && subject_matches
        && jurisdiction_matches
        && policy_number_matches
}

pub(crate) fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

pub(crate) fn parse_settlement_status(value: &str) -> Result<SettlementStatus, ReceiptStoreError> {
    serde_json::from_str(&format!("\"{value}\"")).map_err(ReceiptStoreError::from)
}

pub(crate) fn settlement_reconciliation_action_required(
    settlement_status: SettlementStatus,
    reconciliation_state: SettlementReconciliationState,
) -> bool {
    matches!(
        settlement_status,
        SettlementStatus::Pending | SettlementStatus::Failed
    ) && !matches!(
        reconciliation_state,
        SettlementReconciliationState::Reconciled | SettlementReconciliationState::Ignored
    )
}

pub(crate) fn metered_billing_evidence_record_from_columns(
    adapter_kind: Option<String>,
    evidence_id: Option<String>,
    observed_units: Option<i64>,
    billed_cost_units: Option<i64>,
    billed_cost_currency: Option<String>,
    evidence_sha256: Option<String>,
    recorded_at: Option<i64>,
) -> Option<MeteredBillingEvidenceRecord> {
    let (
        Some(adapter_kind),
        Some(evidence_id),
        Some(observed_units),
        Some(billed_cost_units),
        Some(billed_cost_currency),
        Some(recorded_at),
    ) = (
        adapter_kind,
        evidence_id,
        observed_units,
        billed_cost_units,
        billed_cost_currency,
        recorded_at,
    )
    else {
        return None;
    };

    Some(MeteredBillingEvidenceRecord {
        usage_evidence: arc_core::receipt::MeteredUsageEvidenceReceiptMetadata {
            evidence_kind: adapter_kind,
            evidence_id,
            observed_units: observed_units.max(0) as u64,
            evidence_sha256,
        },
        billed_cost: arc_core::capability::MonetaryAmount {
            units: billed_cost_units.max(0) as u64,
            currency: billed_cost_currency,
        },
        recorded_at: recorded_at.max(0) as u64,
    })
}

pub(crate) struct MeteredBillingReconciliationAnalysis {
    pub(crate) evidence_missing: bool,
    pub(crate) exceeds_quoted_units: bool,
    pub(crate) exceeds_max_billed_units: bool,
    pub(crate) exceeds_quoted_cost: bool,
    pub(crate) financial_mismatch: bool,
    pub(crate) action_required: bool,
}

pub(crate) fn analyze_metered_billing_reconciliation(
    metered: &arc_core::receipt::MeteredBillingReceiptMetadata,
    financial: Option<&FinancialReceiptMetadata>,
    evidence: Option<&MeteredBillingEvidenceRecord>,
    reconciliation_state: MeteredBillingReconciliationState,
) -> MeteredBillingReconciliationAnalysis {
    let evidence_missing = evidence.is_none();
    let exceeds_quoted_units = evidence
        .is_some_and(|record| record.usage_evidence.observed_units > metered.quote.quoted_units);
    let exceeds_max_billed_units = evidence.is_some_and(|record| {
        metered
            .max_billed_units
            .is_some_and(|max_units| record.usage_evidence.observed_units > max_units)
    });
    let exceeds_quoted_cost = evidence.is_some_and(|record| {
        record.billed_cost.currency != metered.quote.quoted_cost.currency
            || record.billed_cost.units > metered.quote.quoted_cost.units
    });
    let financial_mismatch = evidence.is_some_and(|record| {
        financial.is_some_and(|financial| {
            record.billed_cost.currency != financial.currency
                || record.billed_cost.units != financial.cost_charged
        })
    });
    let action_required = (evidence_missing
        || exceeds_quoted_units
        || exceeds_max_billed_units
        || exceeds_quoted_cost
        || financial_mismatch)
        && !matches!(
            reconciliation_state,
            MeteredBillingReconciliationState::Reconciled
                | MeteredBillingReconciliationState::Ignored
        );

    MeteredBillingReconciliationAnalysis {
        evidence_missing,
        exceeds_quoted_units,
        exceeds_max_billed_units,
        exceeds_quoted_cost,
        financial_mismatch,
        action_required,
    }
}

#[derive(Default)]
pub(crate) struct RootAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
    pub(crate) leaf_subjects: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct LeafAggregate {
    pub(crate) receipt_count: u64,
    pub(crate) total_cost_charged: u64,
    pub(crate) total_attempted_cost: u64,
    pub(crate) max_delegation_depth: u64,
}

#[derive(Default)]
pub(crate) struct ReceiptAttributionColumns {
    pub(crate) subject_key: Option<String>,
    pub(crate) issuer_key: Option<String>,
    pub(crate) grant_index: Option<u32>,
}

pub(crate) fn extract_receipt_attribution(receipt: &ArcReceipt) -> ReceiptAttributionColumns {
    let Some(metadata) = receipt.metadata.as_ref() else {
        return ReceiptAttributionColumns::default();
    };

    let attribution = metadata
        .get("attribution")
        .cloned()
        .and_then(|value| serde_json::from_value::<ReceiptAttributionMetadata>(value).ok());
    let grant_index = attribution
        .as_ref()
        .and_then(|value| value.grant_index)
        .or_else(|| {
            metadata
                .get("financial")
                .and_then(|value| value.get("grant_index"))
                .and_then(serde_json::Value::as_u64)
                .map(|value| value as u32)
        });

    ReceiptAttributionColumns {
        subject_key: attribution.as_ref().map(|value| value.subject_key.clone()),
        issuer_key: attribution.as_ref().map(|value| value.issuer_key.clone()),
        grant_index,
    }
}

pub(crate) fn extract_financial_metadata(receipt: &ArcReceipt) -> Option<FinancialReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .and_then(|value| serde_json::from_value::<FinancialReceiptMetadata>(value).ok())
}

pub(crate) fn extract_governed_transaction_metadata(
    receipt: &ArcReceipt,
) -> Option<GovernedTransactionReceiptMetadata> {
    receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .cloned()
        .and_then(|value| serde_json::from_value::<GovernedTransactionReceiptMetadata>(value).ok())
}

pub(crate) fn authorization_details_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> Vec<GovernedAuthorizationDetail> {
    let mut details = vec![GovernedAuthorizationDetail {
        detail_type: ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE.to_string(),
        locations: vec![governed.server_id.clone()],
        actions: vec![governed.tool_name.clone()],
        purpose: Some(governed.purpose.clone()),
        max_amount: governed.max_amount.clone(),
        commerce: None,
        metered_billing: None,
    }];

    if let Some(commerce) = governed.commerce.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: governed.max_amount.clone(),
            commerce: Some(GovernedAuthorizationCommerceDetail {
                seller: commerce.seller.clone(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
            }),
            metered_billing: None,
        });
    }

    if let Some(metered) = governed.metered_billing.as_ref() {
        details.push(GovernedAuthorizationDetail {
            detail_type: ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE.to_string(),
            locations: Vec::new(),
            actions: Vec::new(),
            purpose: None,
            max_amount: None,
            commerce: None,
            metered_billing: Some(GovernedAuthorizationMeteredBillingDetail {
                settlement_mode: metered.settlement_mode,
                provider: metered.quote.provider.clone(),
                quote_id: metered.quote.quote_id.clone(),
                billing_unit: metered.quote.billing_unit.clone(),
                quoted_units: metered.quote.quoted_units,
                quoted_cost: metered.quote.quoted_cost.clone(),
                max_billed_units: metered.max_billed_units,
            }),
        });
    }

    details
}

pub(crate) fn authorization_transaction_context_from_governed_metadata(
    governed: &GovernedTransactionReceiptMetadata,
) -> GovernedAuthorizationTransactionContext {
    GovernedAuthorizationTransactionContext {
        intent_id: governed.intent_id.clone(),
        intent_hash: governed.intent_hash.clone(),
        approval_token_id: governed
            .approval
            .as_ref()
            .map(|value| value.token_id.clone()),
        approval_approved: governed.approval.as_ref().map(|value| value.approved),
        approver_key: governed
            .approval
            .as_ref()
            .map(|value| value.approver_key.clone()),
        runtime_assurance_tier: governed.runtime_assurance.as_ref().map(|value| value.tier),
        runtime_assurance_schema: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.schema.clone()),
        runtime_assurance_verifier_family: governed
            .runtime_assurance
            .as_ref()
            .and_then(|value| value.verifier_family),
        runtime_assurance_verifier: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.verifier.clone()),
        runtime_assurance_evidence_sha256: governed
            .runtime_assurance
            .as_ref()
            .map(|value| value.evidence_sha256.clone()),
        call_chain: governed.call_chain.clone(),
        identity_assertion: None,
    }
}

pub(crate) fn resolve_sender_constraint_subject_key(
    receipt_id: &str,
    receipt_subject_key: Option<&str>,
    lineage_subject_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_subject_key, lineage_subject_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.subjectKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.subjectKey `{receipt_key}` does not match capability snapshot subject `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.subjectKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound subjectKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_issuer_key(
    receipt_id: &str,
    receipt_issuer_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
) -> Result<(String, String), ReceiptStoreError> {
    match (receipt_issuer_key, lineage_issuer_key) {
        (Some(receipt_key), Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            ensure_non_empty_profile_value(receipt_id, "capabilitySnapshot.issuerKey", lineage_key)?;
            if receipt_key != lineage_key {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    format!(
                        "senderConstraint.issuerKey `{receipt_key}` does not match capability snapshot issuer `{lineage_key}`"
                    ),
                ));
            }
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (Some(receipt_key), None) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", receipt_key)?;
            Ok((receipt_key.to_string(), "receipt_attribution".to_string()))
        }
        (None, Some(lineage_key)) => {
            ensure_non_empty_profile_value(receipt_id, "senderConstraint.issuerKey", lineage_key)?;
            Ok((lineage_key.to_string(), "capability_snapshot".to_string()))
        }
        (None, None) => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires a bound issuerKey from receipt attribution or capability snapshot",
        )),
    }
}

pub(crate) fn resolve_sender_constraint_grant(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
) -> Result<(u32, bool), ReceiptStoreError> {
    let grants_json = grants_json.ok_or_else(|| {
        invalid_arc_oauth_authorization_profile(
            receipt_id,
            "sender-constrained profile requires capability snapshot grants_json",
        )
    })?;
    let scope: ArcScope = serde_json::from_str(grants_json).map_err(|error| {
        invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("invalid capability snapshot grants_json: {error}"),
        )
    })?;

    if let Some(index) = grant_index {
        let grant = scope.grants.get(index as usize).ok_or_else(|| {
            invalid_arc_oauth_authorization_profile(
                receipt_id,
                format!("matched grant_index `{index}` is outside the capability scope"),
            )
        })?;
        if grant.server_id != tool_server || grant.tool_name != tool_name {
            return Err(invalid_arc_oauth_authorization_profile(
                receipt_id,
                format!(
                    "grant_index `{index}` resolves to {}/{} instead of {tool_server}/{tool_name}",
                    grant.server_id, grant.tool_name
                ),
            ));
        }
        return Ok((index, grant.dpop_required == Some(true)));
    }

    let mut matches = scope
        .grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| grant.server_id == tool_server && grant.tool_name == tool_name);
    let Some((index, grant)) = matches.next() else {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("capability snapshot does not contain a grant for {tool_server}/{tool_name}"),
        ));
    };
    if matches.next().is_some() {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!(
                "capability snapshot contains multiple grants for {tool_server}/{tool_name}; grant_index is required"
            ),
        ));
    }
    Ok((index as u32, grant.dpop_required == Some(true)))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn derive_authorization_sender_constraint(
    receipt_id: &str,
    tool_server: &str,
    tool_name: &str,
    receipt_subject_key: Option<&str>,
    receipt_issuer_key: Option<&str>,
    lineage_subject_key: Option<&str>,
    lineage_issuer_key: Option<&str>,
    grant_index: Option<u32>,
    grants_json: Option<&str>,
    transaction_context: &GovernedAuthorizationTransactionContext,
) -> Result<AuthorizationContextSenderConstraint, ReceiptStoreError> {
    let (subject_key, subject_key_source) = resolve_sender_constraint_subject_key(
        receipt_id,
        receipt_subject_key,
        lineage_subject_key,
    )?;
    let (issuer_key, issuer_key_source) =
        resolve_sender_constraint_issuer_key(receipt_id, receipt_issuer_key, lineage_issuer_key)?;
    let (matched_grant_index, proof_required) = resolve_sender_constraint_grant(
        receipt_id,
        tool_server,
        tool_name,
        grant_index,
        grants_json,
    )?;

    Ok(AuthorizationContextSenderConstraint {
        subject_key,
        subject_key_source,
        issuer_key,
        issuer_key_source,
        matched_grant_index,
        proof_required,
        proof_type: proof_required.then(|| ARC_OAUTH_SENDER_PROOF_ARC_DPOP.to_string()),
        proof_schema: proof_required.then(|| DPOP_SCHEMA.to_string()),
        runtime_assurance_bound: transaction_context.runtime_assurance_tier.is_some(),
        delegated_call_chain_bound: transaction_context.call_chain.is_some(),
    })
}

pub(crate) fn invalid_arc_oauth_authorization_profile(
    receipt_id: &str,
    detail: impl AsRef<str>,
) -> ReceiptStoreError {
    ReceiptStoreError::Canonical(format!(
        "receipt {receipt_id} violates ARC OAuth authorization profile: {}",
        detail.as_ref()
    ))
}

pub(crate) fn ensure_non_empty_profile_value(
    receipt_id: &str,
    field: &str,
    value: &str,
) -> Result<(), ReceiptStoreError> {
    if value.trim().is_empty() {
        return Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_arc_oauth_authorization_detail(
    receipt_id: &str,
    detail: &GovernedAuthorizationDetail,
) -> Result<bool, ReceiptStoreError> {
    match detail.detail_type.as_str() {
        ARC_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE => {
            if detail.locations.is_empty() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must include at least one location",
                ));
            }
            if detail.actions.is_empty() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must include at least one action",
                ));
            }
            for location in &detail.locations {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.locations[]",
                    location,
                )?;
            }
            for action in &detail.actions {
                ensure_non_empty_profile_value(
                    receipt_id,
                    "authorizationDetails.actions[]",
                    action,
                )?;
            }
            if detail.commerce.is_some() || detail.metered_billing.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_tool must not carry commerce or meteredBilling sidecars",
                ));
            }
            Ok(true)
        }
        ARC_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE => {
            let Some(commerce) = detail.commerce.as_ref() else {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_commerce must include commerce detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.seller",
                &commerce.seller,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.commerce.sharedPaymentTokenId",
                &commerce.shared_payment_token_id,
            )?;
            if detail.metered_billing.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_commerce must not carry meteredBilling detail",
                ));
            }
            Ok(false)
        }
        ARC_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE => {
            let Some(metered) = detail.metered_billing.as_ref() else {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_metered_billing must include meteredBilling detail",
                ));
            };
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.provider",
                &metered.provider,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.quoteId",
                &metered.quote_id,
            )?;
            ensure_non_empty_profile_value(
                receipt_id,
                "authorizationDetails.meteredBilling.billingUnit",
                &metered.billing_unit,
            )?;
            if detail.commerce.is_some() {
                return Err(invalid_arc_oauth_authorization_profile(
                    receipt_id,
                    "arc_governed_metered_billing must not carry commerce detail",
                ));
            }
            Ok(false)
        }
        unsupported => Err(invalid_arc_oauth_authorization_profile(
            receipt_id,
            format!("unsupported authorizationDetails.type `{unsupported}`"),
        )),
    }
}

pub(crate) fn validate_arc_oauth_authorization_row(
    row: &AuthorizationContextRow,
) -> Result<(), ReceiptStoreError> {
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentId",
        &row.transaction_context.intent_id,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "transactionContext.intentHash",
        &row.transaction_context.intent_hash,
    )?;

    let mut saw_tool_detail = false;
    for detail in &row.authorization_details {
        if validate_arc_oauth_authorization_detail(&row.receipt_id, detail)? {
            saw_tool_detail = true;
        }
    }
    if !saw_tool_detail {
        return Err(invalid_arc_oauth_authorization_profile(
            &row.receipt_id,
            "report must include one arc_governed_tool authorization detail",
        ));
    }

    if let Some(token_id) = row.transaction_context.approval_token_id.as_deref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approvalTokenId",
            token_id,
        )?;
        let approver_key = row
            .transaction_context
            .approver_key
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "approvalTokenId requires approverKey",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.approverKey",
            approver_key,
        )?;
        if row.transaction_context.approval_approved.is_none() {
            return Err(invalid_arc_oauth_authorization_profile(
                &row.receipt_id,
                "approvalTokenId requires approvalApproved",
            ));
        }
    }

    if let Some(call_chain) = row.transaction_context.call_chain.as_ref() {
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.chainId",
            &call_chain.chain_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.parentRequestId",
            &call_chain.parent_request_id,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.originSubject",
            &call_chain.origin_subject,
        )?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.callChain.delegatorSubject",
            &call_chain.delegator_subject,
        )?;
        if let Some(parent_receipt_id) = call_chain.parent_receipt_id.as_deref() {
            ensure_non_empty_profile_value(
                &row.receipt_id,
                "transactionContext.callChain.parentReceiptId",
                parent_receipt_id,
            )?;
        }
    }

    if row.transaction_context.runtime_assurance_tier.is_some() {
        let runtime_assurance_schema = row
            .transaction_context
            .runtime_assurance_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceSchema",
            runtime_assurance_schema,
        )?;
        row.transaction_context
            .runtime_assurance_verifier_family
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifierFamily",
                )
            })?;
        let runtime_assurance_verifier = row
            .transaction_context
            .runtime_assurance_verifier
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceVerifier",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceVerifier",
            runtime_assurance_verifier,
        )?;
        let runtime_assurance_evidence_sha256 = row
            .transaction_context
            .runtime_assurance_evidence_sha256
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "runtimeAssuranceTier requires runtimeAssuranceEvidenceSha256",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "transactionContext.runtimeAssuranceEvidenceSha256",
            runtime_assurance_evidence_sha256,
        )?;
    }

    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKey",
        &row.sender_constraint.subject_key,
    )?;
    if row.subject_key.as_deref() != Some(row.sender_constraint.subject_key.as_str()) {
        return Err(invalid_arc_oauth_authorization_profile(
            &row.receipt_id,
            "row subjectKey must match senderConstraint.subjectKey",
        ));
    }
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.subjectKeySource",
        &row.sender_constraint.subject_key_source,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKey",
        &row.sender_constraint.issuer_key,
    )?;
    ensure_non_empty_profile_value(
        &row.receipt_id,
        "senderConstraint.issuerKeySource",
        &row.sender_constraint.issuer_key_source,
    )?;
    if row.sender_constraint.proof_required {
        let proof_type = row.sender_constraint.proof_type.as_deref().ok_or_else(|| {
            invalid_arc_oauth_authorization_profile(
                &row.receipt_id,
                "proofRequired requires senderConstraint.proofType",
            )
        })?;
        ensure_non_empty_profile_value(&row.receipt_id, "senderConstraint.proofType", proof_type)?;
        let proof_schema = row
            .sender_constraint
            .proof_schema
            .as_deref()
            .ok_or_else(|| {
                invalid_arc_oauth_authorization_profile(
                    &row.receipt_id,
                    "proofRequired requires senderConstraint.proofSchema",
                )
            })?;
        ensure_non_empty_profile_value(
            &row.receipt_id,
            "senderConstraint.proofSchema",
            proof_schema,
        )?;
    }

    Ok(())
}

pub(crate) fn chain_is_complete(
    capability_id: &str,
    chain: &[arc_kernel::CapabilitySnapshot],
) -> bool {
    if chain.is_empty() {
        return false;
    }
    let Some(leaf) = chain.last() else {
        return false;
    };
    if leaf.capability_id != capability_id {
        return false;
    }
    if chain
        .first()
        .and_then(|snapshot| snapshot.parent_capability_id.as_ref())
        .is_some()
    {
        return false;
    }
    if chain.windows(2).any(|window| {
        window[1].parent_capability_id.as_deref() != Some(window[0].capability_id.as_str())
    }) {
        return false;
    }
    if leaf.parent_capability_id.is_some() && chain.len() == 1 {
        return false;
    }
    if leaf.delegation_depth as usize != chain.len().saturating_sub(1) {
        return false;
    }
    true
}

pub(crate) fn ratio_option(numerator: u64, denominator: u64) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

pub(crate) fn compliance_export_scope_note(
    query: &OperatorReportQuery,
    export_query: &EvidenceExportQuery,
) -> Option<String> {
    let mut notes = Vec::new();

    if !query.direct_evidence_export_supported() {
        notes.push(
            "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window".to_string(),
        );
    }

    match export_query.child_receipt_scope() {
        EvidenceChildReceiptScope::TimeWindowContextOnly => notes.push(
            "child receipts are included only as time-window context for this export scope".to_string(),
        ),
        EvidenceChildReceiptScope::OmittedNoJoinPath => notes.push(
            "child receipts are omitted for this export scope because no truthful capability/agent join exists yet".to_string(),
        ),
        EvidenceChildReceiptScope::FullQueryWindow => {}
    }

    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}

pub(crate) fn ensure_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare("PRAGMA table_info(arc_tool_receipts)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<Result<Vec<_>, _>>()?;

    if !columns.iter().any(|column| column == "subject_key") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN subject_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "issuer_key") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN issuer_key TEXT",
            [],
        )?;
    }
    if !columns.iter().any(|column| column == "grant_index") {
        connection.execute(
            "ALTER TABLE arc_tool_receipts ADD COLUMN grant_index INTEGER",
            [],
        )?;
    }

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_subject ON arc_tool_receipts(subject_key)",
        [],
    )?;
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_arc_tool_receipts_grant ON arc_tool_receipts(capability_id, grant_index)",
        [],
    )?;
    Ok(())
}

pub(crate) fn backfill_tool_receipt_attribution_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        UPDATE arc_tool_receipts
        SET grant_index = CAST(COALESCE(
            json_extract(raw_json, '$.metadata.attribution.grant_index'),
            json_extract(raw_json, '$.metadata.financial.grant_index')
        ) AS INTEGER)
        WHERE grant_index IS NULL
          AND COALESCE(
                json_extract(raw_json, '$.metadata.attribution.grant_index'),
                json_extract(raw_json, '$.metadata.financial.grant_index')
              ) IS NOT NULL;

        UPDATE arc_tool_receipts
        SET subject_key = COALESCE(
            subject_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.subject_key') AS TEXT),
            (SELECT cl.subject_key FROM capability_lineage cl WHERE cl.capability_id = arc_tool_receipts.capability_id)
        )
        WHERE subject_key IS NULL;

        UPDATE arc_tool_receipts
        SET issuer_key = COALESCE(
            issuer_key,
            CAST(json_extract(raw_json, '$.metadata.attribution.issuer_key') AS TEXT),
            (SELECT cl.issuer_key FROM capability_lineage cl WHERE cl.capability_id = arc_tool_receipts.capability_id)
        )
        WHERE issuer_key IS NULL;
        "#,
    )?;
    Ok(())
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::append_arc_receipt_returning_seq(self, receipt).map(|_| ())
    }

    fn append_arc_receipt_returning_seq(
        &mut self,
        receipt: &ArcReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        Ok(Some(SqliteReceiptStore::append_arc_receipt_returning_seq(
            self, receipt,
        )?))
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        SqliteReceiptStore::receipts_canonical_bytes_range(self, start_seq, end_seq)
    }

    fn store_checkpoint(&mut self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::store_checkpoint(self, checkpoint)
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn record_capability_snapshot(
        &mut self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot(self, token, parent_capability_id).map_err(
            |error| match error {
                arc_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                arc_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            },
        )
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        Some(self)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.query_credit_bonds(&CreditBondListQuery {
            bond_id: Some(bond_id.to_string()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(1),
        })
        .map(|report| report.bonds.into_iter().next())
    }

    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection.execute(
            r#"
            INSERT INTO arc_child_receipts (
                receipt_id,
                timestamp,
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                policy_hash,
                outcome_hash,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                receipt.timestamp,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                terminal_state_kind(&receipt.terminal_state),
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }
}

pub(crate) fn decision_kind(decision: &Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Deny { .. } => "deny",
        Decision::Cancelled { .. } => "cancelled",
        Decision::Incomplete { .. } => "incomplete",
    }
}

pub(crate) fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}
