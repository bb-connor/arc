//! Offline verification of a released launch without asserting its later outcome.

use std::io::Read;

use super::*;

fn bounded_text(path: &Path, limit: u64) -> Result<String, CliError> {
    let file = std::fs::File::open(path)?;
    require(file.metadata()?.is_file(), "input must be a regular file")?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    require(text.len() as u64 <= limit, "input exceeds size limit")?;
    Ok(text)
}

pub(crate) fn verify_native_start_file(
    policy_path: &Path,
    receipt_path: &Path,
    server_id: &str,
    trusted_policy_signer: &str,
    expected_receipt_id: &str,
    expected_target_sha256: &str,
) -> Result<(), CliError> {
    let key = chio_core::PublicKey::from_hex(trusted_policy_signer)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let policy_text = bounded_text(policy_path, MAX_CAGE_POLICY_BYTES as u64)?;
    let policy = decode_cage_policy(policy_path, policy_text.as_bytes(), &key)?;
    let receipt_key = chio_core::PublicKey::from_hex(&policy.receipt.trusted_signer_public_key)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let receipt = crate::receipt_verify::verify_original_receipt(
        &bounded_text(receipt_path, 8 * 1024 * 1024)?,
        &receipt_key,
    )?;
    let (_, body) =
        verify_policy_bound_enforcement(&policy_text, &receipt, server_id, &key)?;
    let full = body
        .enforcement_record
        .fully_enforced
        .as_ref()
        .ok_or_else(|| CliError::cli_other_error("missing full enforcement evidence"))?;
    require(
        receipt.id == expected_receipt_id
            && full.prepared.target_binding_digest == expected_target_sha256,
        "launch differs from selected receipt or expected target",
    )?;
    println!(
        "{}",
        serde_json::json!({
            "schema": "chio.native-start-verification.v1",
            "receipt_id": receipt.id,
            "server_id": server_id,
            "attempt_id": body.attempt_id,
            "process_id": full.prepared.process_id,
            "target_sha256": full.prepared.target_binding_digest,
            "trace_session_digest": full.prepared.trace_session_digest,
            "released_at_unix_ms": body.recorded_at_unix_ms,
            "checks": ["policy_signer_pin", "enforced_policy", "admitted_policy_binding", "signed_manifest",
                "receipt_signature", "receipt_semantics", "receipt_context",
                "execution_identity", "helper_binding", "target_binding", "selected_receipt"],
            "unchecked": ["live_pid_linkage", "target_death", "call_completion",
                "terminal_outcome", "log_inclusion"],
        })
    );
    Ok(())
}
