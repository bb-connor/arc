// Signed but misbound claims cannot consume a use or reach the connector.
use super::*;

#[test]
fn native_declassification_rejects_missing_and_substituted_signed_claims() -> TestResult {
    for field in [
        "missing",
        "capability_id",
        "tenant_id",
        "subject_id",
        "agent_id",
        "session_id",
        "source_label_hash",
        "destination_id",
        "tool_name",
        "purpose",
        "request_hash",
        "authority_key_id",
        "issued_at_unix_seconds",
        "expires_at_unix_seconds",
    ] {
        let (mut fixture, authority) = profile(false, 300)?;
        if field == "missing" {
            fixture.request.declassification_grant = None;
        } else {
            let signed = fixture
                .request
                .declassification_grant
                .as_ref()
                .ok_or("grant")?;
            let mut value = serde_json::to_value(signed.body())?;
            let replacement = match field {
                "source_label_hash" => {
                    serde_json::to_value(information_label_hash(&InformationLabel::bottom())?)?
                }
                "request_hash" => serde_json::to_value(canonical_request_hash(
                    &CanonicalBody::new(b"{}".to_vec())?,
                )?)?,
                "expires_at_unix_seconds" => {
                    value["issued_at_unix_seconds"] = serde_json::json!(1);
                    serde_json::json!(2)
                }
                "issued_at_unix_seconds" => {
                    let now = now_ms()? / 1000;
                    value["expires_at_unix_seconds"] = serde_json::json!(now + 120);
                    serde_json::json!(now + 60)
                }
                _ => serde_json::json!("substituted"),
            };
            value[field] = replacement;
            fixture.request.declassification_grant = Some(SignedDeclassificationGrant::sign(
                serde_json::from_value(value)?,
                &authority,
            )?);
        }
        let response = fixture
            .kernel
            .evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "{field}: {:?}",
            response.reason
        );
        assert!(response.output.is_none(), "{field}");
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0, "{field}");
        let connection = rusqlite::Connection::open_with_flags(
            fixture._directory.path().join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let uses: i64 = connection.query_row(
            "SELECT COUNT(*) FROM security_participant_state_declassification_uses",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(uses, 0, "{field} consumed downgrade authority");
        if let Some(usage) = fixture
            .authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        {
            assert_eq!(usage.captured_invocations, 0, "{field}");
        }
    }
    Ok(())
}

#[test]
fn native_declassification_refuses_unselected_lifecycle_without_activation() -> TestResult {
    let (fixture, _) = configure(
        Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?,
        300,
    )?;
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(response.output.is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let connection = rusqlite::Connection::open_with_flags(
        fixture._directory.path().join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let uses: i64 = connection.query_row(
        "SELECT COUNT(*) FROM security_participant_state_declassification_uses",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(uses, 0);
    let lifecycle: (i64, i64, i64) = connection.query_row(
        "SELECT reconciliation_active, live_dispatch_sealed, compaction_active
         FROM security_participant_state_declassification_lifecycle WHERE security_authority_id = ?1",
        [fixture.binding.security_authority_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        lifecycle,
        (0, 0, 0),
        "dispatch activated an imported lifecycle"
    );
    let store = fixture.authority.admission_operation_store();
    let observation = store.observe_native_security_flow(
        &fixture.binding,
        &crate::security::adapters::flow_key(fixture.context.as_v1()),
        &fixture.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(
        observation
            .snapshot()
            .ok_or("committed taint")?
            .principal_label,
        restricted_label()
    );
    Ok(())
}
