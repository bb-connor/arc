use super::*;

// These are individually valid model operations, not authority-store mutations.
fn substitute_reference(fixture: &mut Fixture, field: &str) -> TestResult {
    let mut persisted = fixture.admission.operation.to_persisted();
    let mut attachments = serde_json::to_value(&persisted.attachments)?;
    let values = attachments.as_array_mut().ok_or("attachment array")?;
    let replacement = serde_json::json!({field: "a".repeat(64)});
    if let Some(value) = values.iter_mut().find(|value| value.get(field).is_some()) {
        *value = replacement;
    } else {
        values.push(replacement);
    }
    persisted.attachments = serde_json::from_value(attachments)?;
    fixture.admission.operation = AdmissionOperationV1::from_persisted(persisted)?;
    Ok(())
}

#[test]
fn frozen_participants_reject_changed_operation_references_in_live_context() -> TestResult {
    for field in [
        "ExecutionNonceIssuanceDigest",
        "ExecutionNoncePreflightDigest",
        "GovernedApprovalLedgerDigest",
        "DpopReplayLedgerDigest",
    ] {
        let mut fixture = fixture()?;
        let context = fixture.kernel.decode_caller_return_context(
            &fixture.admission,
            &fixture.frame,
            current_unix_timestamp_ms(),
        )?;
        substitute_reference(&mut fixture, field)?;
        let request = fixture
            .admission
            .retained_request
            .as_ref()
            .ok_or("original request")?
            .request_for_revalidation();
        assert!(
            context
                .validate_binding(&fixture.admission, request)
                .is_err(),
            "live context accepted substituted {field}"
        );
    }
    Ok(())
}

#[test]
fn frozen_participants_reject_changed_operation_references_in_caller_decode() -> TestResult {
    for field in [
        "ExecutionNonceIssuanceDigest",
        "ExecutionNoncePreflightDigest",
        "GovernedApprovalLedgerDigest",
        "DpopReplayLedgerDigest",
    ] {
        let mut fixture = fixture()?;
        substitute_reference(&mut fixture, field)?;
        assert!(
            fixture
                .kernel
                .decode_caller_return_context(
                    &fixture.admission,
                    &fixture.frame,
                    current_unix_timestamp_ms(),
                )
                .is_err(),
            "caller context accepted substituted {field}"
        );
    }
    Ok(())
}

#[test]
fn frozen_participants_require_every_reference_and_reject_substitution() -> TestResult {
    let fixture = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(fixture.frame.kernel_context_json())?;
    let references = original["participants"]
        .as_object()
        .ok_or("participant snapshot")?;
    assert_eq!(references.len(), 18);
    for (field, value) in references {
        for remove in [false, true] {
            let mut changed = original.clone();
            let participants = changed["participants"].as_object_mut().ok_or("snapshot")?;
            if remove {
                participants.remove(field);
            } else {
                let replacement = if field == "provider_attempt" {
                    let mut attempt = value.clone();
                    attempt["attempt_id"] = serde_json::json!("replacement-attempt");
                    attempt
                } else {
                    serde_json::json!("b".repeat(64))
                };
                participants.insert(field.clone(), replacement);
            }
            assert!(
                fixture
                    .kernel
                    .decode_caller_return_payload(
                        &fixture.admission,
                        &canonical_json_bytes(&changed)?,
                        current_unix_timestamp_ms(),
                    )
                    .is_err(),
                "accepted participant {field}, remove={remove}"
            );
        }
    }
    let mut changed = original;
    changed["participants"]["unrecognized_authority"] = serde_json::json!(true);
    assert!(fixture
        .kernel
        .decode_caller_return_payload(
            &fixture.admission,
            &canonical_json_bytes(&changed)?,
            current_unix_timestamp_ms(),
        )
        .is_err());
    Ok(())
}

#[test]
fn frozen_participants_preserve_legacy_absence_without_upgrading_custody() -> TestResult {
    let fixture = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(fixture.frame.kernel_context_json())?;
    let mut payload = original.clone();
    payload
        .as_object_mut()
        .ok_or("caller object")?
        .remove("participants");
    assert!(
        fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&payload)?,
                current_unix_timestamp_ms(),
            )
            .is_err(),
        "v3 cannot omit its participant snapshot"
    );
    for schema in [SIGNING_SCHEMA, LEGACY_SCHEMA] {
        payload["schema"] = serde_json::json!(schema);
        if schema == LEGACY_SCHEMA {
            payload
                .as_object_mut()
                .ok_or("caller object")?
                .remove("receipt_signing_identity");
        }
        let legacy = fixture.kernel.decode_caller_return_payload(
            &fixture.admission,
            &canonical_json_bytes(&payload)?,
            current_unix_timestamp_ms(),
        )?;
        assert!(legacy.participants.is_none());
        assert_eq!(
            legacy.receipt_signing_identity.is_some(),
            schema == SIGNING_SCHEMA
        );
        assert!(
            fixture
                .kernel
                .frame_caller_return_context(
                    &fixture.admission,
                    &legacy,
                    current_unix_timestamp_ms(),
                )
                .is_err(),
            "legacy context cannot be reissued as a complete v3 context"
        );
        let mut smuggled = payload.clone();
        smuggled["participants"] = original["participants"].clone();
        assert!(
            fixture
                .kernel
                .decode_caller_return_payload(
                    &fixture.admission,
                    &canonical_json_bytes(&smuggled)?,
                    current_unix_timestamp_ms(),
                )
                .is_err(),
            "{schema} cannot smuggle a participant snapshot"
        );
    }
    Ok(())
}
