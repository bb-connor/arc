use super::support::*;

fn underwriting_fixture() -> SignedUnderwritingDecision {
    signed_underwriting_decision_fixture(
        "signed-readback-subject",
        "signed-readback-decision",
        1_700_000_100,
        chio_kernel::UnderwritingDecisionOutcome::ReduceCeiling,
        chio_kernel::UnderwritingReviewState::Approved,
        chio_kernel::UnderwritingDecisionLifecycleState::Active,
        None,
        Some(usd(500)),
    )
}

fn replace_raw(store: &SqliteReceiptStore, table: &str, raw: &str) {
    // Table names are test constants; each fixture has exactly one row.
    assert_eq!(
        store
            .connection()
            .test_unwrap()
            .execute(&format!("UPDATE {table} SET raw_json = ?1"), [raw])
            .test_unwrap(),
        1
    );
}

#[test]
fn signed_readback_underwriting_rejects_precision_alias_before_verification() {
    let (_directory, path) = temp_db("signed-underwriting-alias").test_unwrap();
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let decision = underwriting_fixture();
    store.record_underwriting_decision(&decision).test_unwrap();
    let raw = serde_json::to_string(&decision).test_unwrap();
    assert!(raw.contains("0.8"));
    let aliased = raw.replacen("0.8", "0.80000000000000004", 1);
    // The old typed reader silently erased the extra precision and verified it.
    let decoded: SignedUnderwritingDecision = serde_json::from_str(&aliased).test_unwrap();
    assert!(decoded.verify_signature().test_unwrap());
    replace_raw(&store, "underwriting_decisions", &aliased);
    assert!(matches!(
        store.query_underwriting_decisions(&UnderwritingDecisionQuery::default()),
        Err(ReceiptStoreError::UntrustedInput(error)) if matches!(error.as_ref(), chio_core::canonical::UntrustedJsonError::SignedInput(chio_core::Error::CanonicalJson(reason)) if reason.contains("loses precision"))
    ));
}

#[test]
fn signed_readback_preserves_historical_encodings_and_full_width_premiums() {
    let (_directory, path) = temp_db("signed-underwriting-encoding").test_unwrap();
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let keypair = Keypair::from_seed(&[71; 32]);
    let original = underwriting_fixture();
    store.record_underwriting_decision(&original).test_unwrap();
    for units in [(1_u64 << 53) - 1, 1_u64 << 53, (1_u64 << 53) + 1, u64::MAX] {
        let mut body = original.body.clone();
        body.premium.quoted_amount = Some(usd(units));
        let signed = SignedExportEnvelope::sign(body, &keypair).test_unwrap();
        for raw in [
            serde_json::to_string(&signed).test_unwrap(),
            serde_json::to_string_pretty(&signed).test_unwrap(),
            String::from_utf8(canonical_json_bytes(&signed).test_unwrap()).test_unwrap(),
        ] {
            replace_raw(&store, "underwriting_decisions", &raw);
            let report = store
                .query_underwriting_decisions(&UnderwritingDecisionQuery::default())
                .test_unwrap();
            assert_eq!(report.summary.total_quoted_premium_units, units);
            assert_eq!(report.decisions[0].decision, signed);
        }
    }
}

#[test]
fn signed_readback_reports_reject_changed_signed_bodies() {
    let (_directory, path) = temp_db("signed-report-tamper").test_unwrap();
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut decision = underwriting_fixture();
    store.record_underwriting_decision(&decision).test_unwrap();
    decision.body.premium.quoted_amount = Some(usd(999_999));
    replace_raw(
        &store,
        "underwriting_decisions",
        &serde_json::to_string(&decision).test_unwrap(),
    );
    assert!(matches!(
        store.query_underwriting_decisions(&UnderwritingDecisionQuery::default()),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));

    let mut facility = signed_credit_facility_fixture(
        "subject",
        "facility",
        100,
        4_000_000_000,
        CreditFacilityDisposition::Grant,
        CreditFacilityLifecycleState::Active,
        None,
    );
    store.record_credit_facility(&facility).test_unwrap();
    facility.body.expires_at += 1;
    replace_raw(
        &store,
        "credit_facilities",
        &serde_json::to_string(&facility).test_unwrap(),
    );
    assert!(matches!(
        store.query_credit_facilities(&CreditFacilityListQuery::default()),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));
}

#[test]
fn signed_readback_provider_resolution_and_successor_reject_damaged_signature() {
    let (_directory, path) = temp_db("signed-provider-tamper").test_unwrap();
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut provider = signed_liability_provider(
        "provider-record",
        "carrier-alpha",
        100,
        LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let successor = signed_liability_provider(
        "provider-successor",
        "carrier-alpha",
        200,
        LiabilityProviderLifecycleState::Active,
        Some("provider-record"),
        true,
    );
    store.record_liability_provider(&provider).test_unwrap();
    // Preserve the body so a body-only predecessor comparison would accept it.
    provider.signature = successor.signature.clone();
    replace_raw(
        &store,
        "liability_providers",
        &serde_json::to_string(&provider).test_unwrap(),
    );
    let query = LiabilityProviderResolutionQuery {
        provider_id: "carrier-alpha".to_owned(),
        jurisdiction: "US-NY".to_owned(),
        coverage_class: chio_kernel::LiabilityCoverageClass::ToolExecution,
        currency: "USD".to_owned(),
    };
    assert!(matches!(
        store.resolve_liability_provider(&query),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));
    assert!(matches!(
        store.record_liability_provider(&successor),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));
    let rows: i64 = store
        .connection()
        .test_unwrap()
        .query_row("SELECT count(*) FROM liability_providers", [], |row| {
            row.get(0)
        })
        .test_unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn signed_readback_quote_workflow_rejects_corrupt_persisted_predecessor() {
    let (_directory, path) = temp_db("signed-quote-tamper").test_unwrap();
    let mut store = SqliteReceiptStore::open(&path).test_unwrap();
    let provider = signed_liability_provider(
        "provider-record",
        "carrier-alpha",
        100,
        LiabilityProviderLifecycleState::Active,
        None,
        true,
    );
    let mut request = signed_liability_quote_request("quote-request", &provider, "subject", "USD");
    let response = signed_liability_quote_response("quote-response", request.clone(), None);
    store.record_liability_provider(&provider).test_unwrap();
    store.record_liability_quote_request(&request).test_unwrap();
    request.signature = response.signature.clone();
    replace_raw(
        &store,
        "liability_quote_requests",
        &serde_json::to_string(&request).test_unwrap(),
    );
    assert!(matches!(
        store.record_liability_quote_response(&response),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));
    assert!(matches!(
        store.query_liability_market_workflows(&LiabilityMarketWorkflowQuery::default()),
        Err(ReceiptStoreError::Conflict(reason)) if reason.contains("signature verification failed")
    ));
    let rows: i64 = store
        .connection()
        .test_unwrap()
        .query_row(
            "SELECT count(*) FROM liability_quote_responses",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    assert_eq!(rows, 0);
}

fn lineage_fixture(child_id: &str) -> ReceiptLineageStatement {
    let keypair = Keypair::from_seed(&[72; 32]);
    ReceiptLineageStatement::sign(
        ReceiptLineageStatementBody::new(
            "signed-readback-lineage",
            ReceiptLineageEndpoints::new(
                "parent",
                child_id,
                RequestId::new("parent-request"),
                RequestId::new("child-request"),
                SessionAnchorReference::new("parent-anchor", "parent-hash"),
                SessionAnchorReference::new("child-anchor", "child-hash"),
            ),
            ReceiptLineageRelationKind::Continued,
            100,
            keypair.public_key(),
        ),
        &keypair,
    )
    .test_unwrap()
}

#[test]
fn signed_readback_lineage_verifies_signature_and_binds_requested_child() {
    let (_directory, path) = temp_db("signed-lineage-tamper").test_unwrap();
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let statement = lineage_fixture("child");
    store
        .record_session_anchor_record(
            "session",
            "child-anchor",
            "auth-context",
            90,
            None,
            &serde_json::json!({"schema": "chio.session_anchor.v1", "id": "child-anchor"}),
        )
        .test_unwrap();
    store
        .record_receipt_lineage_statement_record(
            "child",
            None,
            Some("session"),
            None,
            None,
            None,
            None,
            100,
            &serde_json::to_value(&statement).test_unwrap(),
        )
        .test_unwrap();
    assert_eq!(
        store.receipt_lineage_statement("child").test_unwrap(),
        Some(statement.clone())
    );
    assert_eq!(
        ReceiptStore::load_retained_receipt_lineage_statement(&store, "child").test_unwrap(),
        Some(statement.clone())
    );

    let mut damaged = statement;
    damaged.parent_receipt_id = "injected-parent".to_owned();
    for (replacement, cause) in [
        (damaged, "signature verification failed"),
        (
            lineage_fixture("other-child"),
            "does not match the requested child receipt",
        ),
    ] {
        replace_raw(
            &store,
            "receipt_lineage_statements",
            &serde_json::to_string(&replacement).test_unwrap(),
        );
        assert!(matches!(
            store.receipt_lineage_statement("child"),
            Err(ReceiptStoreError::Conflict(reason)) if reason.contains(cause)
        ));
        assert!(matches!(
            ReceiptStore::load_retained_receipt_lineage_statement(&store, "child"),
            Err(ReceiptStoreError::Conflict(reason)) if reason.contains(cause)
        ));
    }
}

#[test]
fn signed_readback_rejects_nested_duplicate_map_keys() {
    let keypair = Keypair::from_seed(&[73; 32]);
    let signed =
        SignedExportEnvelope::sign(serde_json::json!({"USD": 500}), &keypair).test_unwrap();
    let raw = serde_json::to_string(&signed).test_unwrap();
    let aliased = raw.replace(r#""USD":500"#, r#""USD":0,"USD":500"#);
    assert_ne!(raw, aliased);
    let erased: SignedExportEnvelope<serde_json::Value> =
        serde_json::from_str(&aliased).test_unwrap();
    assert!(erased.verify_signature().test_unwrap());
    assert!(matches!(
        decode_verified_signed_export::<serde_json::Value>(&aliased),
        Err(ReceiptStoreError::UntrustedInput(error)) if matches!(error.as_ref(), chio_core::canonical::UntrustedJsonError::SignedInput(chio_core::Error::CanonicalJson(reason)) if reason.contains("duplicate object key"))
    ));
}
