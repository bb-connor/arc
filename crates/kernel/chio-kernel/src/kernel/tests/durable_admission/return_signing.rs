use super::*;

#[path = "return_signing/callbacks.rs"]
mod callbacks;

fn replace_receipt_authority(kernel: &mut ChioKernel) {
    let authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&Keypair::generate());
    kernel.signing_task = Arc::new(
        kernel
            .signing_task
            .reconfigured_with_backend(authority.backend.clone()),
    );
    kernel.signing_authority = authority;
}

#[test]
fn unfinished_return_cannot_be_signed_by_a_replacement_authority() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("frozen-signing-authority");
    let (mut admission, mut mutation) = pending_admission(&kernel, &request)?;
    let context = kernel.freeze_and_commit_durable_dispatch(
        &mut admission,
        &request.capability,
        &mut mutation,
        input(&request),
    )?;
    let original_key = kernel.receipt_signing_public_key();
    replace_receipt_authority(&mut kernel);
    assert_ne!(kernel.receipt_signing_public_key(), original_key);
    let returned = kernel.record_durable_tool_return(
        &mut admission,
        DurableToolReturnInput {
            request: &request,
            output: &ToolServerOutput::Value(serde_json::json!({"done": true})),
            reported_cost: None,
            context: &context,
            elapsed: Duration::ZERO,
            trusted_now_unix_ms: current_unix_timestamp_ms(),
        },
    )?;
    let result = kernel.finalize_durable_tool_return_with_security_release(
        &mut admission,
        &request,
        &returned,
        None,
    );
    assert!(
        result.is_err(),
        "unfinished return was signed by replacement authority"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    kernel.signing_authority =
        crate::kernel::signing_authority::KernelSigningAuthority::classical(&kernel.config.keypair);
    let recovered = kernel.finalize_durable_tool_return_with_security_release(
        &mut admission,
        &request,
        &returned,
        None,
    )?;
    assert_eq!(recovered.verdict, Verdict::Allow);
    assert_eq!(recovered.receipt.kernel_key, original_key);
    assert!(recovered.receipt.verify_signature()?);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn completed_replay_uses_original_signer_without_reinvocation() -> TestResult {
    completed_replay_retains_signer(false)
}

#[test]
fn nested_completed_replay_uses_original_signer_without_reinvocation() -> TestResult {
    completed_replay_retains_signer(true)
}

fn completed_replay_retains_signer(nested: bool) -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("retained-signing-authority");
    let response = if nested {
        let session = kernel.open_session("signing-parent".into(), Vec::new())?;
        kernel.activate_session(&session)?;
        let parent = make_operation_context(&session, "parent-request", "signing-parent");
        kernel.begin_session_request(&parent, OperationKind::ToolCall, true)?;
        kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut NoopNestedFlowClient,
            None,
        )?
    } else {
        kernel.evaluate_tool_call_blocking(&request)?
    };
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.verify_signature()?);
    let original_key = response.receipt.kernel_key.clone();
    replace_receipt_authority(&mut kernel);
    assert_ne!(kernel.receipt_signing_public_key(), original_key);
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_same_receipt(&replay.receipt, &response.receipt);
    assert_eq!(replay.output, response.output);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completed_replay_does_not_weaken_the_current_crypto_floor() -> TestResult {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("retained-signing-floor");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    kernel.signing_authority.floor = crate::KernelCryptoFloor::PqRequired;
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn raw_signing_identity_codec_rejects_omission_downgrade_and_invalid_floor() -> TestResult {
    let (kernel, request, store, _) = durable_admission_fixture("signing-codec");
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow);
    let raw = store
        .state
        .lock()
        .map_err(|_| "test lock")?
        .raw_outcome
        .clone()
        .ok_or("raw return")?;
    let blob = raw.canonical_blob()?;
    let decoded = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())?;
    let identity = decoded
        .receipt_signing_identity()
        .ok_or("frozen identity")?;
    assert_eq!(identity.public_key(), &response.receipt.kernel_key);
    assert_eq!(
        identity.crypto_floor(),
        kernel.receipt_signing_crypto_floor()
    );
    assert_eq!(decoded, raw);
    let original = serde_json::to_value(raw.to_persisted())?;
    for mutation in 0..5 {
        let mut value = original.clone();
        match mutation {
            0 => {
                value
                    .as_object_mut()
                    .ok_or("raw object")?
                    .remove("receipt_signing_identity");
            }
            1 => {
                value["schema"] = serde_json::json!(
                    crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA
                );
            }
            2 => {
                value["receipt_signing_identity"]["crypto_floor"] =
                    serde_json::json!("pq_required");
            }
            3 => {
                value["receipt_signing_identity"]["private_key"] =
                    serde_json::json!("not-permitted");
            }
            4 => {
                value
                    .as_object_mut()
                    .ok_or("raw object")?
                    .remove("request_canonical_json");
            }
            _ => return Err("unexpected mutation".into()),
        }
        assert!(
            RawInvocationOutcomeV1::from_canonical_bytes(
                &chio_core::canonical::canonical_json_bytes(&value)?,
            )
            .is_err(),
            "accepted mutation {mutation}"
        );
    }
    // Legacy bytes remain readable but never acquire a claimed frozen signer.
    let mut legacy = original;
    legacy["schema"] =
        serde_json::json!(crate::tool_outcome::RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA);
    legacy
        .as_object_mut()
        .ok_or("raw object")?
        .remove("receipt_signing_identity");
    let legacy = RawInvocationOutcomeV1::from_canonical_bytes(
        &chio_core::canonical::canonical_json_bytes(&legacy)?,
    )?;
    assert!(legacy.receipt_signing_identity().is_none());
    Ok(())
}
