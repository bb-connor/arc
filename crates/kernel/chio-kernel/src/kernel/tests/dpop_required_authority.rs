use super::*;
use crate::dpop::DpopError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn signed_authority_and_local_source_cannot_select_runtime_authority() -> TestResult {
    let mut kernel = make_kernel(make_config());
    kernel.set_dpop_replay_source(DpopNonceStore::new(8, Duration::from_secs(300))?)?;
    kernel.register_tool_server(Box::new(EchoServer::new("authority-server", vec!["read"])));
    let agent = make_keypair();
    let mut grant = make_grant("authority-server", "read");
    grant.dpop_required = Some(true);
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 3600);
    let mut request = make_request(
        "unselected-authority",
        &capability,
        "read",
        "authority-server",
    );
    request.dpop_proof = Some(DpopProof::sign(
        DpopProofBody {
            schema: DPOP_SCHEMA.into(),
            replay_authority: crate::dpop::test_authority(),
            capability_id: capability.id.clone(),
            tool_server: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            action_hash: sha256_hex(&canonical_json_bytes(&request.arguments)?),
            nonce: "unselected-authority-nonce".into(),
            issued_at: current_unix_timestamp(),
            agent_key: agent.public_key(),
        },
        &agent,
    )?);
    assert!(kernel.operation_owned_dpop_authority().is_none());
    assert!(matches!(
        kernel.verify_required_dpop_preview(&request, &capability),
        Err(KernelError::Dpop(DpopError::MissingAuthority))
    ));
    assert!(matches!(
        kernel.prepare_dispatch_credentials(
            &request,
            &capability,
            true,
            current_unix_timestamp(),
            false
        ),
        Err(KernelError::Dpop(DpopError::MissingAuthority))
    ));
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|value| value.pointer("/chio_kernel/rejection_code"))
            .and_then(serde_json::Value::as_str),
        Some(DpopError::MissingAuthority.code())
    );
    assert_eq!(
        kernel
            .dpop_nonce_store
            .as_ref()
            .ok_or("source")?
            .utilization()?
            .0,
        0
    );
    assert!(kernel.operation_owned_dpop_authority().is_none());
    Ok(())
}

#[test]
fn source_retirement_remains_explicit_without_enabling_dpop() -> TestResult {
    use crate::admission_operation::AdmissionIdentifier;
    use crate::dpop::replay_source::DpopReplaySourceBinding;
    let mut kernel = make_kernel(make_config());
    kernel.set_dpop_replay_source(DpopNonceStore::new(8, Duration::from_secs(300))?)?;
    let source = kernel.dpop_replay_source()?;
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "source-retirement")?,
        destination_authority_id: AdmissionIdentifier::try_new(
            "destination",
            "configured-destination",
        )?,
    })?;
    source.seal_exact(&snapshot)?;
    source.verify_exact(&snapshot)?;
    assert!(matches!(
        source.preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: AdmissionIdentifier::try_new("authority", "source-retirement")?,
            destination_authority_id: AdmissionIdentifier::try_new(
                "destination",
                "configured-destination"
            )?,
        }),
        Err(KernelError::DpopVerificationFailed(reason))
            if reason == "DPoP replay source: source is retired; replay mutations are forbidden"
    ));
    assert!(kernel.operation_owned_dpop_authority().is_none());
    Ok(())
}
