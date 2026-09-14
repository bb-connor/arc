use std::collections::BTreeSet;

use crate::types::{
    PresentationIntervalSource, PresentationWindow, PresentationWindowError,
    ResolvedPresentationInterval,
};
use crate::*;

use super::treaty_evidence::TreatyEvidenceReview;

pub(super) fn verify_treaty_dsse_evidence<S: RuntimeAdmissionStore>(
    store: &S,
    envelope: &chio_federation::bilateral_dsse::DsseEnvelope,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&(ReceiptLineageBundle, String)>,
    invocation: Option<&BilateralInvocation>,
) -> Result<(), ChioRuntimeError> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence could not be decoded",
        );
    };
    if statement.predicate_type
        != chio_federation::bilateral_dsse::PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
    {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is not a strict Chio predicate",
        );
    }
    let Some(policy_summary) = statement.predicate.policy_evaluation_summary.as_ref() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing policy evaluation summary",
        );
    };
    chio_federation::bilateral_dsse::validate_policy_evaluation_summary(policy_summary).map_err(
        |_| ChioRuntimeError::Rejected {
            code: "chio_treaty_unverified_required_evidence",
            detail: "bilateral DSSE policy evaluation summary is invalid".to_string(),
        },
    )?;
    if policy_summary.server_a_verdict.verdict != "allow" {
        return rejected(
            "chio_treaty_policy_denied",
            "bilateral DSSE policy evaluation summary is not allow",
        );
    }
    let Some(treaty) = statement.predicate.treaty_binding_ref.as_ref() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing treaty binding refs",
        );
    };
    let expected_consistency_model = bilateral_dsse_consistency_model(review.consistency_model)?;
    if treaty.treaty_id != review.treaty_scope.treaty_id
        || treaty.treaty_scope_sha256 != treaty_scope_sha256(review.treaty_scope)?
        || treaty.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || treaty.continuation_sha256 != review.continuation_sha256
        || treaty.action_class_id != review.action_class_id
        || treaty.consistency_model != expected_consistency_model
        || treaty.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE treaty binding does not match the requested dispatch",
        );
    }
    if statement
        .predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(treaty.request_sha256.as_str())
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE tool argument hash does not match the treaty request binding",
        );
    }
    if treaty.lease_refs != review.bundle.lease_id.iter().cloned().collect::<Vec<_>>() {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE lease refs do not match the verifier-owned admission bundle",
        );
    }
    if treaty.governance_refs
        != review
            .bundle
            .governance_receipt_id
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE governance refs do not match the verifier-owned admission bundle",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = treaty.signer_kernel_ids.iter().collect();
    if review.treaty_scope.participant_kernel_ids.len() != 2 || treaty.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE evidence requires exactly two treaty participants and signers",
        );
    }
    if participants != signers {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE signer set does not match treaty participants",
        );
    }
    let signer_a_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[0])?;
    let signer_b_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[1])?;
    if signer_a_public_key == signer_b_public_key {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE signer public keys are not independent",
        );
    }
    chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
        envelope,
        signer_a_public_key,
        signer_b_public_key,
    )
    .map_err(|_| ChioRuntimeError::Rejected {
        code: "chio_treaty_unverified_required_evidence",
        detail: "bilateral DSSE signature verification failed".to_string(),
    })?;
    let window = presentation_window(store, review, &statement.predicate)?;
    if let Some(lease) = statement.predicate.capability_lease_ref.as_ref() {
        let lease_window = window
            .for_counterparty(&lease.issuer, REQUIRED_LEASE_INTERVAL_SOURCES)
            .map_err(presentation_window_rejection)?;
        if lease.expires_at_unix_ms <= review.now_unix_ms
            || !lease_window.admits_expiry(lease.expires_at_unix_ms)
        {
            return rejected(
                "chio_treaty_unverified_required_evidence",
                &format!(
                    "bilateral DSSE capability lease expires at {}, outside the presentation \
                     window this receiver resolved for {} (not before {}, not after {})",
                    lease.expires_at_unix_ms,
                    lease.issuer,
                    lease_window.not_before_unix_ms(),
                    lease_window.not_after_unix_ms()
                ),
            );
        }
    }
    if let Some((bundle, bundle_sha256)) = lineage_bundle {
        if treaty.lineage_bundle_sha256 != bundle_sha256.as_str()
            || treaty.local_receipt_sha256 != bundle.root_receipt_sha256
            || treaty.remote_receipt_sha256 != bundle.leaf_receipt_sha256
        {
            return rejected(
                "chio_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match lineage bundle",
            );
        }
    }
    if let Some(invocation) = invocation {
        let invocation_consistency_model =
            bilateral_dsse_consistency_model(&invocation.consistency_model)?;
        if treaty.consistency_model != invocation_consistency_model
            || treaty.outcome_sha256 != invocation.outcome_sha256
            || treaty.local_receipt_sha256 != invocation.local_receipt_sha256
            || treaty.remote_receipt_sha256 != invocation.remote_receipt_sha256
            || treaty.signer_kernel_ids != invocation.signer_kernel_ids
        {
            return rejected(
                "chio_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match bilateral invocation",
            );
        }
    }
    Ok(())
}

/// The records this receiver requires to have resolved for the counterparty a
/// capability lease names before it will accept the lease that counterparty
/// co-signed. A required record that stops resolving between calls closes the
/// window for that counterparty and leaves the other counterparty's window
/// untouched.
const REQUIRED_LEASE_INTERVAL_SOURCES: &[PresentationIntervalSource] = &[
    PresentationIntervalSource::TreatyScope,
    PresentationIntervalSource::Continuation,
    PresentationIntervalSource::CapabilityLease,
];

/// The intervals this receiver resolved for itself while deciding this call.
///
/// Every reference must resolve independently of the statement. Missing or
/// revoked activation records deny instead of widening the intersection.
fn resolved_presentation_intervals<S: RuntimeAdmissionStore>(
    store: &S,
    review: &TreatyEvidenceReview<'_>,
    predicate: &chio_federation::bilateral_dsse::BilateralPredicate,
) -> Result<Vec<ResolvedPresentationInterval>, ChioRuntimeError> {
    let mut intervals = vec![
        ResolvedPresentationInterval::new(
            PresentationIntervalSource::TreatyScope,
            review.treaty_scope.participant_kernel_ids.clone(),
            review.treaty_scope.issued_at_unix_ms,
            review.treaty_scope.expires_at_unix_ms,
        )
        .map_err(presentation_window_rejection)?,
        ResolvedPresentationInterval::new(
            PresentationIntervalSource::Continuation,
            vec![
                review.continuation.source_kernel_id.clone(),
                review.continuation.target_kernel_id.clone(),
            ],
            review.continuation.issued_at_unix_ms,
            review.continuation.expires_at_unix_ms,
        )
        .map_err(presentation_window_rejection)?,
    ];

    if let Some(id) = review.bundle.lease_id.as_deref() {
        let record = store
            .treaty_capability_lease(id)?
            .ok_or_else(|| missing_record("capability lease"))?;
        let lease = predicate
            .capability_lease_ref
            .as_ref()
            .ok_or_else(|| missing_record("statement lease reference"))?;
        if record.lease.lease_id != id
            || lease.lease_id != id
            || record.lease.issuer != lease.issuer
            || record.lease.scope_digest != lease.scope_digest
            || record
                .lease
                .scope_digest
                .as_ref()
                .is_some_and(|scope| scope.alg != "sha256" || !crate::is_sha256_hex(&scope.value))
            || lease.expires_at_unix_ms > record.lease.expires_at_unix_ms
        {
            return rejected(
                "chio_treaty_unverified_required_evidence",
                "capability lease does not match its receiver-owned record",
            );
        }
        intervals.push(
            ResolvedPresentationInterval::new(
                PresentationIntervalSource::CapabilityLease,
                vec![record.lease.issuer],
                record.valid_from_unix_ms,
                record.lease.expires_at_unix_ms,
            )
            .map_err(presentation_window_rejection)?,
        );
    } else if predicate.capability_lease_ref.is_some() {
        return Err(missing_record("admission bundle lease reference"));
    }
    if let Some(id) = review.bundle.governance_receipt_id.as_deref() {
        let record = store
            .treaty_governance_receipt(id)?
            .ok_or_else(|| missing_record("governance receipt"))?;
        if record.receipt.receipt_id != id
            || predicate.governance_receipt_ref.as_ref() != Some(&record.receipt)
            || record.receipt.digest.alg != "sha256"
            || !crate::is_sha256_hex(&record.receipt.digest.value)
            || !review
                .treaty_scope
                .participant_kernel_ids
                .contains(&record.receipt.kernel_id)
        {
            return rejected(
                "chio_treaty_unverified_required_evidence",
                "governance reference does not match its receiver-owned record",
            );
        }
        intervals.push(
            ResolvedPresentationInterval::new(
                PresentationIntervalSource::GovernanceReceipt,
                vec![record.receipt.kernel_id],
                record.valid_from_unix_ms,
                record.valid_until_unix_ms,
            )
            .map_err(presentation_window_rejection)?,
        );
    } else if predicate.governance_receipt_ref.is_some() {
        return Err(missing_record("admission bundle governance reference"));
    }
    Ok(intervals)
}

fn missing_record(name: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_treaty_unverified_required_evidence",
        detail: format!("receiver could not resolve an active {name}"),
    }
}

/// The window in which this receiver accepts a co-signed statement, rebuilt on
/// every call from the records resolved for that call.
fn presentation_window<S: RuntimeAdmissionStore>(
    store: &S,
    review: &TreatyEvidenceReview<'_>,
    predicate: &chio_federation::bilateral_dsse::BilateralPredicate,
) -> Result<PresentationWindow, ChioRuntimeError> {
    let intervals = resolved_presentation_intervals(store, review, predicate)?;
    let window = PresentationWindow::intersect(intervals).map_err(presentation_window_rejection)?;
    if review.now_unix_ms < window.not_before_unix_ms()
        || review.now_unix_ms >= window.not_after_unix_ms()
    {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "dispatch time is outside the receiver-owned presentation window",
        );
    }
    Ok(window)
}

fn presentation_window_rejection(error: PresentationWindowError) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_treaty_unverified_required_evidence",
        detail: format!("bilateral DSSE presentation window is not open: {error}"),
    }
}

pub(super) fn treaty_participant_public_key<'a>(
    treaty_scope: &'a TreatyScope,
    kernel_id: &str,
) -> Result<&'a PublicKey, ChioRuntimeError> {
    let Some(index) = treaty_scope
        .participant_kernel_ids
        .iter()
        .position(|participant| participant == kernel_id)
    else {
        return rejected(
            "chio_treaty_missing_participant",
            "treaty participant public key is missing",
        );
    };
    treaty_scope
        .participant_public_keys
        .get(index)
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "chio_treaty_missing_participant",
            detail: "treaty participant public key is missing".to_string(),
        })
}
