use crate::{claim_failed, RiskComptrollerReport, RiskEvidenceRefKind, TransactionPassportError};

/// Validate references supplied by an infallible, already-typed lookup.
pub fn validate_risk_evidence_refs(
    report: &RiskComptrollerReport,
    mut contains_ref: impl FnMut(&str, RiskEvidenceRefKind) -> bool,
) -> Result<(), TransactionPassportError> {
    try_validate_risk_evidence_refs(report, |reference, kind| Ok(contains_ref(reference, kind)))
}

/// Preserve failures when a reference lookup decodes or authenticates evidence.
pub fn try_validate_risk_evidence_refs(
    report: &RiskComptrollerReport,
    mut contains_ref: impl FnMut(&str, RiskEvidenceRefKind) -> Result<bool, TransactionPassportError>,
) -> Result<(), TransactionPassportError> {
    for transition in &report.facility_lifecycle {
        if !contains_ref(
            &transition.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        )? {
            return Err(claim_failed("risk facility lifecycle authority missing"));
        }
        if !contains_ref(
            &transition.evidence_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        )? {
            return Err(claim_failed("risk facility lifecycle evidence missing"));
        }
    }
    if !contains_ref(
        &report.actuarial_evidence.evidence_ref,
        RiskEvidenceRefKind::SupportingEvidence,
    )? {
        return Err(claim_failed("risk actuarial evidence missing"));
    }
    let Some(premium) = report.premium.as_ref() else {
        return Err(claim_failed("risk premium binding missing"));
    };
    if !contains_ref(&premium.quote_ref, RiskEvidenceRefKind::SupportingEvidence)? {
        return Err(claim_failed("risk premium quote evidence missing"));
    }
    if let Some(observed_payment_ref) = premium.observed_payment_ref.as_ref() {
        if !contains_ref(
            observed_payment_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        )? {
            return Err(claim_failed("risk premium payment evidence missing"));
        }
    }
    if let Some(settlement_ref) = premium.settlement_ref.as_ref() {
        if !contains_ref(settlement_ref, RiskEvidenceRefKind::Settlement)? {
            return Err(claim_failed("risk premium settlement evidence missing"));
        }
    }
    let Some(capital) = report.capital_decomposition.as_ref() else {
        return Err(claim_failed("risk capital decomposition missing"));
    };
    if !contains_ref(&capital.source_ref, RiskEvidenceRefKind::AuthorityReceipt)? {
        return Err(claim_failed("risk capital source evidence missing"));
    }
    for entry in &report.reserve_ledger {
        if !contains_ref(
            &entry.receipt_ref,
            RiskEvidenceRefKind::ReserveLedgerReceipt,
        )? {
            return Err(claim_failed("risk reserve ledger receipt missing"));
        }
        if !contains_ref(&entry.settlement_ref, RiskEvidenceRefKind::Settlement)? {
            return Err(claim_failed("risk reserve ledger settlement missing"));
        }
        let Some(sanction_bridge) = entry.sanction_bridge.as_ref() else {
            continue;
        };
        if !contains_ref(
            &sanction_bridge.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        )? {
            return Err(claim_failed("risk market slash sanction authority missing"));
        }
        if !contains_ref(
            &sanction_bridge.evidence_ref,
            RiskEvidenceRefKind::SupportingEvidence,
        )? {
            return Err(claim_failed("risk market slash sanction evidence missing"));
        }
        if !contains_ref(
            &sanction_bridge.jurisdiction_ref,
            RiskEvidenceRefKind::Jurisdiction,
        )? {
            return Err(claim_failed("risk market slash jurisdiction missing"));
        }
    }
    for entry in &report.sanction_reserve_ledger {
        if !contains_ref(
            &entry.receipt_ref,
            RiskEvidenceRefKind::ReserveLedgerReceipt,
        )? {
            return Err(claim_failed("risk sanction reserve ledger receipt missing"));
        }
        if !contains_ref(&entry.settlement_ref, RiskEvidenceRefKind::Settlement)? {
            return Err(claim_failed(
                "risk sanction reserve ledger settlement missing",
            ));
        }
        if !contains_ref(
            &entry.authority_receipt_ref,
            RiskEvidenceRefKind::AuthorityReceipt,
        )? {
            return Err(claim_failed(
                "risk sanction reserve ledger authority missing",
            ));
        }
        if !contains_ref(&entry.evidence_ref, RiskEvidenceRefKind::SupportingEvidence)? {
            return Err(claim_failed(
                "risk sanction reserve ledger evidence missing",
            ));
        }
        if !contains_ref(&entry.jurisdiction_ref, RiskEvidenceRefKind::Jurisdiction)? {
            return Err(claim_failed(
                "risk sanction reserve ledger jurisdiction missing",
            ));
        }
    }
    Ok(())
}
