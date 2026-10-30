//! Checked optional nonce metadata and completed tool-error controls.

use super::*;

fn fixture(
    is_error: bool,
) -> Result<(Keypair, Box<CredentialCall>, Value), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("sessions.sqlite3");
    let _lease = crate::tests::acquire_test_session_store(&path);
    let keypair = Keypair::generate();
    let credential = super::super::tests::record();
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"write_file","arguments":{},"_meta":{"chioRequestId":"nonce-metadata"}}});
    let Ok(CallReservation::Pending(pending)) =
        reserve_at(&path, &keypair, &credential, &request, 100)
    else {
        return Err("pending reservation failed".into());
    };
    let message = super::super::tests::completed_response(
        &keypair,
        &pending,
        request["params"]["arguments"].clone(),
        is_error,
    )?;
    Ok((keypair, pending, message))
}

fn nonce(
    keypair: &Keypair,
    call: &CredentialCall,
    receipt: &ChioReceipt,
) -> Result<SignedExecutionNonce, Box<dyn std::error::Error>> {
    Ok(chio_kernel::mint_execution_nonce(
        &chio_core::crypto::Ed25519Backend::new(keypair.clone()),
        NonceBinding {
            subject_id: call.subject_key.clone(),
            request_id: call.request_id.clone(),
            capability_id: receipt.capability_id.clone(),
            tool_server: call.server_id.clone(),
            tool_name: call.tool_name.clone(),
            parameter_hash: call.parameter_hash.clone(),
        },
        &chio_kernel::ExecutionNonceConfig::default(),
        i64::try_from(receipt.timestamp)?,
    )?)
}

#[test]
fn verified_nonce_metadata_preserves_signed_tool_errors_and_drops_unsigned_nonce_members(
) -> Result<(), Box<dyn std::error::Error>> {
    for is_error in [false, true] {
        let (keypair, pending, mut message) = fixture(is_error)?;
        let receipt = verified_receipt(&keypair, &pending, &message).ok_or("verified receipt")?;
        let signed = nonce(&keypair, &pending, &receipt)?;
        message["result"]["_meta"]["chioExecutionNonce"] = serde_json::to_value(&signed)?;
        message["result"]["_meta"]["chioExecutionNonce"]["unsignedExtension"] =
            json!("nonce-extension-sentinel");
        let completed = verify(&keypair, &pending, &message).ok_or("verified result")?;
        assert_eq!(completed.message["result"]["isError"], is_error);
        assert_eq!(
            completed.message["result"]["_meta"]["chioExecutionNonce"],
            serde_json::to_value(signed)?
        );
        assert!(!completed
            .message
            .to_string()
            .contains("nonce-extension-sentinel"));
    }
    Ok(())
}

#[test]
fn optional_nonce_rejects_wrong_binding_issuer_and_operation_signature_domain(
) -> Result<(), Box<dyn std::error::Error>> {
    let (keypair, pending, mut original) = fixture(false)?;
    let receipt = verified_receipt(&keypair, &pending, &original).ok_or("verified receipt")?;
    let mut body = receipt.body();
    body.metadata.as_mut().ok_or("receipt metadata")?["admission_operation"]["operation_id"] =
        json!("01".repeat(32));
    let receipt = ChioReceipt::sign(body, &keypair)?;
    original["result"]["_meta"]["chioEvidence"]["receipt"] = serde_json::to_value(&receipt)?;
    let signed = nonce(&keypair, &pending, &receipt)?;
    let mut foreign_binding = signed.clone();
    foreign_binding.nonce.bound_to.request_id = "other-logical-call".into();
    foreign_binding.signature = keypair.sign_wrapped(
        EXECUTION_NONCE_SCHEMA,
        &chio_core::CanonicalBytes::from_serializable(&foreign_binding.nonce)?,
    )?;
    let mut foreign_issuer = signed.clone();
    foreign_issuer.signature = Keypair::generate().sign_wrapped(
        EXECUTION_NONCE_SCHEMA,
        &chio_core::CanonicalBytes::from_serializable(&foreign_issuer.nonce)?,
    )?;
    let mut wrong_domain = signed;
    wrong_domain.nonce.schema = OPERATION_EXECUTION_NONCE_SCHEMA.into();
    wrong_domain.signature = keypair.sign_wrapped(
        EXECUTION_NONCE_SCHEMA,
        &chio_core::CanonicalBytes::from_serializable(&wrong_domain.nonce)?,
    )?;
    for candidate in [foreign_binding, foreign_issuer, wrong_domain] {
        let mut message = original.clone();
        message["result"]["_meta"]["chioExecutionNonce"] = serde_json::to_value(candidate)?;
        let completed = verify(&keypair, &pending, &message).ok_or("verified tool output")?;
        assert!(completed.message["result"]["_meta"]
            .get("chioExecutionNonce")
            .is_none());
        assert_eq!(completed.message["result"]["isError"], false);
        assert_eq!(
            completed.message["result"]["content"],
            original["result"]["_meta"]["chioEvidence"]["output"]["content"]
        );
    }
    Ok(())
}

#[test]
fn nonce_window_uses_signed_admission_time_instead_of_the_timestamp_fallback(
) -> Result<(), Box<dyn std::error::Error>> {
    let (keypair, pending, original) = fixture(false)?;
    let receipt = verified_receipt(&keypair, &pending, &original).ok_or("verified receipt")?;
    let signed = nonce(&keypair, &pending, &receipt)?;
    for time in [signed.nonce.issued_at - 1, signed.nonce.expires_at] {
        let mut body = receipt.body();
        body.metadata.as_mut().ok_or("receipt metadata")?["admission_operation"]
            ["trusted_time_unix_ms"] = json!(u64::try_from(time)? * 1_000);
        let timed_receipt = ChioReceipt::sign(body, &keypair)?;
        let mut message = original.clone();
        message["result"]["_meta"]["chioEvidence"]["receipt"] =
            serde_json::to_value(timed_receipt)?;
        message["result"]["_meta"]["chioExecutionNonce"] = serde_json::to_value(&signed)?;
        let completed = verify(&keypair, &pending, &message).ok_or("verified timed output")?;
        assert!(completed.message["result"]["_meta"]
            .get("chioExecutionNonce")
            .is_none());
        assert_eq!(completed.message["result"]["isError"], false);
    }
    Ok(())
}

fn relabeled(
    decision: chio_core::receipt::decision::Decision,
) -> Result<(Keypair, Box<CredentialCall>, Value), Box<dyn std::error::Error>> {
    let (keypair, pending, mut message) = fixture(false)?;
    let receipt: ChioReceipt =
        serde_json::from_value(message["result"]["_meta"]["chioEvidence"]["receipt"].clone())?;
    let mut body = receipt.body();
    body.decision = Some(decision);
    body.content_hash = sha256_hex(&canonical_json_bytes(&Value::Null)?);
    let resigned = ChioReceipt::sign(body, &keypair)?;
    message["result"]["_meta"]["chioEvidence"] =
        json!({"receipt": resigned, "outputKind": "value", "output": null});
    Ok((keypair, pending, message))
}

#[test]
fn a_signed_denial_relabeled_as_a_value_output_is_rejected(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_core::receipt::decision::Decision;
    let (keypair, pending, message) = relabeled(Decision::Allow)?;
    assert!(verified_receipt(&keypair, &pending, &message).is_some());
    for decision in [
        Decision::Deny {
            reason: "denied".to_owned(),
            guard: "policy".to_owned(),
        },
        Decision::Cancelled {
            reason: "cancelled".to_owned(),
        },
        Decision::Incomplete {
            reason: "incomplete".to_owned(),
        },
    ] {
        let (keypair, pending, message) = relabeled(decision)?;
        assert!(verified_receipt(&keypair, &pending, &message).is_none());
        assert!(verify(&keypair, &pending, &message).is_none());
    }
    Ok(())
}
