//! Verify signed completion before projecting any caller-visible tool result.

use super::*;
use chio_core::receipt::body::ChioReceipt;
use chio_core::session::OperationTerminalState;
use chio_kernel::admission_operation::{
    verify_operation_execution_nonce_at, AdmissionOperationId, OPERATION_EXECUTION_NONCE_SCHEMA,
};
use chio_kernel::execution_nonce::{NonceBinding, SignedExecutionNonce, EXECUTION_NONCE_SCHEMA};

pub(super) struct CompletedResult {
    pub(super) receipt: ChioReceipt,
    pub(super) message: Value,
}

pub(super) fn verify(
    keypair: &Keypair,
    call: &CredentialCall,
    message: &Value,
) -> Option<CompletedResult> {
    let receipt = verified_receipt(keypair, call, message)?;
    let output = &message["result"]["_meta"]["chioEvidence"]["output"];
    let mut result = chio_mcp_adapter::edge::project_tool_result(output.clone());
    let meta = result
        .as_object_mut()?
        .entry("_meta")
        .or_insert_with(|| json!({}));
    if !meta.is_object() {
        *meta = json!({});
    }
    let meta = meta.as_object_mut()?;
    // Regenerate authority namespaces from verified material. Tool-supplied
    // namespaces and arbitrary unsigned worker extensions confer no authority.
    meta.remove("chioDelivery");
    meta.remove("chioExecutionNonce");
    meta.insert(
        "chio".into(),
        json!({
        "decision":"allow","receipt":&receipt,"receiptId":receipt.id,
        "terminalState":OperationTerminalState::Completed}),
    );
    meta.insert(
        "chioEvidence".into(),
        json!({
        "schema":"chio.mcp.execution-evidence.v1","requestId":call.request_id,
        "receipt":&receipt,"outputKind":"value","output":output,
        "terminalState":"completed"}),
    );
    if let Some(nonce) = verified_nonce(call, &receipt, message) {
        meta.insert(
            "chioExecutionNonce".into(),
            serde_json::to_value(nonce).ok()?,
        );
    }
    Some(CompletedResult {
        receipt,
        message: json!({"jsonrpc":"2.0","id":message["id"],"result":result}),
    })
}

fn verified_nonce(
    call: &CredentialCall,
    receipt: &ChioReceipt,
    message: &Value,
) -> Option<SignedExecutionNonce> {
    let value = message.pointer("/result/_meta/chioExecutionNonce")?;
    let encoded = input::encode_session(value).ok()?;
    let nonce: SignedExecutionNonce = decode_json(encoded.as_bytes(), MAX_AUTH_JSON_BYTES).ok()?;
    let expected = NonceBinding {
        subject_id: call.subject_key.clone(),
        request_id: call.request_id.clone(),
        capability_id: receipt.capability_id.clone(),
        tool_server: call.server_id.clone(),
        tool_name: call.tool_name.clone(),
        parameter_hash: call.parameter_hash.clone(),
    };
    let admission = receipt.metadata.as_ref()?.get("admission_operation")?;
    let now = match admission.get("trusted_time_unix_ms") {
        Some(value) => i64::try_from(value.as_u64()? / 1_000).ok()?,
        // Older signed receipts have only their signed timestamp. This fallback
        // verifies historical metadata and never establishes fresh authority.
        None => i64::try_from(receipt.timestamp).ok()?,
    };
    match nonce.nonce.schema.as_str() {
        OPERATION_EXECUTION_NONCE_SCHEMA => {
            let operation_id =
                AdmissionOperationId::from_persisted(admission.get("operation_id")?.as_str()?)
                    .ok()?;
            verify_operation_execution_nonce_at(
                &nonce,
                &operation_id,
                &receipt.kernel_key,
                &expected,
                now,
            )
            .ok()?;
        }
        EXECUTION_NONCE_SCHEMA => {
            if nonce.nonce.bound_to != expected
                || nonce.nonce.nonce_id.is_empty()
                || nonce.nonce.issued_at < 0
                || nonce.nonce.expires_at <= nonce.nonce.issued_at
                || now < nonce.nonce.issued_at
                || now >= nonce.nonce.expires_at
                || !receipt
                    .kernel_key
                    .verify_canonical_strict(&nonce.nonce, &nonce.signature)
                    .ok()?
            {
                return None;
            }
        }
        _ => return None,
    }
    Some(nonce)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
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
            keypair,
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
            let receipt =
                verified_receipt(&keypair, &pending, &message).ok_or("verified receipt")?;
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
        foreign_binding.signature = keypair.sign_canonical(&foreign_binding.nonce)?.0;
        let mut foreign_issuer = signed.clone();
        foreign_issuer.signature = Keypair::generate().sign_canonical(&foreign_issuer.nonce)?.0;
        let mut wrong_domain = signed;
        wrong_domain.nonce.schema = OPERATION_EXECUTION_NONCE_SCHEMA.into();
        wrong_domain.signature = keypair.sign_canonical(&wrong_domain.nonce)?.0;
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
}

pub(super) fn verified_receipt(
    keypair: &Keypair,
    call: &CredentialCall,
    message: &Value,
) -> Option<ChioReceipt> {
    let evidence = &message["result"]["_meta"]["chioEvidence"];
    let Ok(receipt) = serde_json::from_value::<chio_core::receipt::body::ChioReceipt>(
        evidence["receipt"].clone(),
    ) else {
        return None;
    };
    if receipt.kernel_key != keypair.public_key()
        || !matches!(receipt.verify_signature(), Ok(true))
        || receipt.decision != Some(chio_core::receipt::decision::Decision::Allow)
        || receipt.tool_server != call.server_id
        || receipt.tool_name != call.tool_name
        || receipt.action.parameter_hash != call.parameter_hash
        || !call.capability_ids.contains(&receipt.capability_id)
    {
        return None;
    }
    let Some(metadata) = receipt.metadata.as_ref() else {
        return None;
    };
    let admission = &metadata["admission_operation"];
    if metadata["receipt_context"]["request_id"] != call.request_id
        || metadata["attribution"]["subject_key"] != call.subject_key
        || admission["schema"] != "chio.admission-receipt.v1"
        || admission["request_id"] != call.request_id
        || admission["projected_state"] != "completed"
        || admission["projected_dispatch_state"] != "terminal"
        || !admission["tool_outcome_id"].is_string()
        || evidence["outputKind"] != "value"
    {
        return None;
    }
    // A terminal tool result can report failure. Acknowledge its verified delivery
    // without converting isError into success or treating it as an unknown dispatch.
    if !canonical_json_bytes(&evidence["output"])
        .is_ok_and(|bytes| sha256_hex(&bytes) == receipt.content_hash)
    {
        return None;
    }
    Some(receipt)
}
