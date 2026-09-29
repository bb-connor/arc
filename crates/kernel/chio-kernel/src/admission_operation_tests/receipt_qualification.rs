use super::*;

#[test]
fn verified_projection_sidecars_reject_operation_substitution() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let context = projection_context(&operation);
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::CompensatedBeforeDispatch,
        identifier("incident_id", "incident-1"),
        digest("incident_digest", POLICY_HASH),
    )
    .expect("valid incident must bind to the operation snapshot");
    assert!(incident
        .validate_against(
            &operation,
            &context,
            AdmissionOperationState::CompensatedBeforeDispatch,
        )
        .is_ok());
    let mut substituted_time = context.clone();
    substituted_time.trusted_time_unix_ms += 1;
    assert_eq!(
        incident.validate_against(
            &operation,
            &substituted_time,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let mut substituted_coordinator = context.clone();
    substituted_coordinator.coordinator_lease_id =
        identifier("coordinator_lease_id", "coordinator-lease-other");
    assert_eq!(
        incident.validate_against(
            &operation,
            &substituted_coordinator,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    let other = AdmissionOperationV1::prepare(
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-other",
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        7,
    )
    .expect("other operation must prepare");
    assert_eq!(
        incident.validate_against(
            &other,
            &projection_context(&other),
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
}

#[test]
fn completed_projection_requires_exact_signed_admission_receipt_metadata() {
    let operation = finalizing_active_operation();
    let mut context = projection_context(&operation);
    context.trusted_time_unix_ms = 1_999;
    let kernel = Keypair::generate();
    let completed = |receipt: VerifiedAdmissionReceipt| {
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: context.clone(),
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
            channel_terminal: None,
        }))
    };
    let verify = |receipt| verify_completed_receipt(&operation, &context, receipt, &kernel, None);

    assert!(matches!(
        verify(signed_projection_receipt(&operation, None, &kernel)),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut substituted = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    substituted.request_id = identifier("request_id", "substituted-request");
    assert!(matches!(
        verify(signed_projection_receipt(
            &operation,
            Some(substituted),
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut substituted_time = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    substituted_time.trusted_time_unix_ms = 1_998;
    assert!(matches!(
        verify(signed_projection_receipt(
            &operation,
            Some(substituted_time),
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let exact_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    assert!(matches!(
        verify(signed_projection_receipt_with_tenant(
            &operation,
            Some(exact_metadata),
            None,
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let exact = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let exact = verify(signed_projection_receipt(&operation, Some(exact), &kernel))
        .expect("exact signed admission receipt must qualify");
    let exact = completed(exact);
    let terminal = operation
        .apply_terminal_projection(&exact, &full_projection_capabilities())
        .expect("exact signed admission metadata must terminalize");
    assert_eq!(terminal.state, AdmissionOperationState::Completed);
    assert_eq!(terminal.version, operation.version + 1);
}

#[test]
fn admission_receipt_qualification_pins_kernel_and_exact_signed_body() {
    let operation = finalizing_active_operation();
    let context = projection_context(&operation);
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = signed_projection_receipt(&operation, Some(metadata), &kernel);
    let qualify =
        |candidate| verify_completed_receipt(&operation, &context, candidate, &kernel, None);
    qualify(receipt.clone()).expect("exact kernel receipt must qualify");

    let rogue = Keypair::generate();
    let rogue_receipt = signed_projection_receipt(
        &operation,
        receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        &rogue,
    );
    assert!(matches!(
        qualify(rogue_receipt),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut invalid_id = receipt.clone();
    invalid_id.id = POLICY_HASH.to_string();
    assert!(matches!(
        qualify(invalid_id),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let resign = |mutate: fn(&mut ChioReceiptBody)| {
        let mut body = receipt.body();
        mutate(&mut body);
        ChioReceipt::sign(body, &kernel).expect("substituted test receipt must sign")
    };
    for substituted in [
        resign(|body| body.tool_server = "other-server".to_string()),
        resign(|body| body.tool_name = "other-tool".to_string()),
        resign(|body| {
            body.action = ToolCallAction::from_parameters(serde_json::json!({ "other": true }))
                .expect("alternate action must hash")
        }),
        resign(|body| body.content_hash = REQUEST_HASH.to_string()),
        resign(|body| body.capability_id = "other-capability".to_string()),
        resign(|body| body.policy_hash = REQUEST_HASH.to_string()),
        resign(|body| body.tenant_id = Some("other-tenant".to_string())),
        resign(|body| {
            body.decision = Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: "test".to_string(),
            })
        }),
    ] {
        assert!(matches!(
            qualify(substituted),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let invalid_parameter_hash = resign(|body| {
        body.action.parameter_hash = REQUEST_HASH.to_string();
    });
    assert!(matches!(
        VerifiedAdmissionReceipt::from_kernel_verified_for_test(
            invalid_parameter_hash,
            &kernel.public_key(),
            &Decision::Allow,
            TOOL_SERVER,
            TOOL_NAME,
            &digest("expected_parameter_hash", REQUEST_HASH),
            &digest("expected_content_hash", CONTENT_HASH),
            &operation,
            &context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let denied = resign(|body| {
        body.decision = Some(Decision::Deny {
            reason: "denied".to_string(),
            guard: "test".to_string(),
        });
    });
    assert!(matches!(
        VerifiedAdmissionReceipt::from_kernel_verified_for_test(
            denied,
            &kernel.public_key(),
            &Decision::Deny {
                reason: "denied".to_string(),
                guard: "test".to_string(),
            },
            TOOL_SERVER,
            TOOL_NAME,
            &digest("expected_parameter_hash", EMPTY_PARAMETER_HASH),
            &digest("expected_content_hash", CONTENT_HASH),
            &operation,
            &context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}
