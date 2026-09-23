//! Signed response history still has to match the original physical capture.
use super::*;
use crate::receipt::{receipt_digest, sign_execution_receipt, validate_durable_completed_response};

pub(super) fn reject_signed_capture_substitutions(
    host: &host::NativeHost,
    operation_id: &chio_kernel::admission_operation::AdmissionOperationId,
    response: &BrokerExecuteResponse,
    signer: &Keypair,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let now = || -> std::result::Result<u64, Box<dyn std::error::Error>> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?)
    };
    host.reader.verify_completed_response(
        host.participant.as_ref(),
        operation_id,
        response,
        now()?,
    )?;
    for field in [
        "operation",
        "quota",
        "budget",
        "revocation",
        "authority",
        "leader",
        "revocation_set",
    ] {
        let mut changed = response.clone();
        let receipt = &mut changed.receipt.body;
        match field {
            "operation" => receipt.operation_id.push_str("-other"),
            "quota" => receipt.quotas[0].maximum_executions += 1,
            "budget" => receipt.evidence.budget_commit_index += 1,
            "revocation" => receipt.evidence.revocation_commit_index += 1,
            "authority" => receipt.evidence.authority_commit_index += 1,
            "leader" => receipt.evidence.leader_epoch += 1,
            _ => receipt.evidence.revocation_set_digest = "f".repeat(64),
        }
        changed.evidence = receipt.evidence.clone();
        changed.receipt =
            sign_execution_receipt(receipt.clone(), &Ed25519Backend::new(signer.clone()))?;
        changed.receipt_reference = format!(
            "broker-receipt-sha256-{}",
            receipt_digest(&changed.receipt)?
        );
        // This is valid signed broker evidence. Only the original native
        // operation and physical capture can reject the changed claim.
        validate_durable_completed_response(&changed, &signer.public_key())?;
        assert!(
            host.reader
                .verify_completed_response(
                    host.participant.as_ref(),
                    operation_id,
                    &changed,
                    now()?,
                )
                .is_err(),
            "accepted a signed {field} substitution"
        );
    }
    Ok(())
}
