//! Receipt-visible bindings for denied checked output and delivery mismatches.
use super::*;

pub(super) const DELIVERY_MISMATCH_REDACTION_DOMAIN: &[u8] =
    b"chio.delivery-mismatch.redacted.v1\0";

/// Produce the receipt-visible content binding for a delivery verdict.
///
/// A mismatch keeps the actual output and digest only in the durable outcome
/// store for privileged challenge handling. The public Deny receipt binds a
/// domain-separated redaction preimage keyed by the committed expected digest,
/// so neither its content hash, delivery-contract block, nor stream metadata
/// becomes a payload confirmation oracle. Replaying the same mismatch
/// reconstructs identical receipt bytes without requiring new randomness.
pub(super) fn receipt_visible_delivery_content(
    actual: &ReceiptContent,
    digest_mismatched: bool,
    expected_digest: Option<&str>,
) -> ReceiptContent {
    if digest_mismatched {
        let mut canonical_content = Vec::with_capacity(
            DELIVERY_MISMATCH_REDACTION_DOMAIN.len() + expected_digest.map_or(0, str::len),
        );
        canonical_content.extend_from_slice(DELIVERY_MISMATCH_REDACTION_DOMAIN);
        if let Some(expected_digest) = expected_digest {
            canonical_content.extend_from_slice(expected_digest.as_bytes());
        }
        return ReceiptContent {
            content_hash: sha256_hex(&canonical_content),
            metadata: None,
            canonical_content,
        };
    }
    ReceiptContent {
        content_hash: actual.content_hash.clone(),
        metadata: actual.metadata.clone(),
        canonical_content: actual.canonical_content.clone(),
    }
}

fn checked_output_decision() -> Decision {
    let denial = delivery_contract::output_guard_delivery_denial();
    Decision::Deny {
        reason: denial.message.to_owned(),
        guard: denial.guard.to_owned(),
    }
}

pub(super) fn retained_checked_output_denial(
    outcome: &ToolOutcomeRecordV1,
    resolved_output_digest: &str,
) -> Result<bool, KernelError> {
    let ResolvedToolOutcomeV1::Resolved {
        post_guard_decision_digest,
        ..
    } = outcome.disposition()
    else {
        return Ok(false);
    };
    let expected = admission_digest(
        "post_guard_decision_digest",
        &KernelOutputGuardDecision {
            schema: "chio.kernel-output-guard-decision.post-return.v1",
            resolved_output_digest,
            decision: &checked_output_decision(),
        },
    )?;
    Ok(post_guard_decision_digest == &expected)
}

pub(super) fn visible_terminal_content(
    actual: &ReceiptContent,
    evaluation: &delivery_contract::DeliveryEvaluation,
    expected_digest: Option<&str>,
) -> ReceiptContent {
    if evaluation.denial.as_ref().is_some_and(|denial| {
        denial.reason == crate::admission_operation::DeliveryDenialReason::OutputGuardRejected
    }) {
        let canonical_content =
            crate::admission_operation::OUTPUT_GUARD_REJECTION_REDACTION_DOMAIN.to_vec();
        return ReceiptContent {
            content_hash: sha256_hex(&canonical_content),
            metadata: None,
            canonical_content,
        };
    }
    receipt_visible_delivery_content(actual, evaluation.digest_mismatched, expected_digest)
}
