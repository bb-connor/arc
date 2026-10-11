use super::super::super::read_boundary::ReportReadLimits;
use super::*;

fn bounded_fixture() -> Fixture {
    populate(
        "bounded-report",
        ["agent-a", "agent-b", "agent-c"]
            .into_iter()
            .enumerate()
            .map(|(index, subject)| FixtureReceipt {
                capability_id: format!("cap-bounded-{index}"),
                subject_key: subject,
                tool_server: "shell",
                tool_name: "bash",
                decision: Decision::Allow,
                timestamp: DAY_SECS * (index as u64 + 1),
                financial: Some((11, Some(22))),
            })
            .collect(),
    )
}

#[test]
fn selected_reports_refuse_each_work_boundary_and_release_the_snapshot() {
    let fixture = bounded_fixture();
    let query = admin_query();
    let cost_query = CostAttributionQuery {
        limit: Some(1),
        read_context: query.read_context.clone(),
        ..CostAttributionQuery::default()
    };
    let raw_total: i64 = fixture
        .store
        .connection()
        .test_unwrap()
        .query_row(
            "SELECT SUM(octet_length(raw_json)) FROM chio_tool_receipts",
            [],
            |row| row.get(0),
        )
        .test_unwrap();
    for (limits, reason) in [
        (
            ReportReadLimits {
                rows: 2,
                ..ReportReadLimits::default()
            },
            "receipt",
        ),
        (
            ReportReadLimits {
                row_bytes: 32,
                ..ReportReadLimits::default()
            },
            "raw record byte limit",
        ),
        (
            ReportReadLimits {
                raw_bytes: u64::try_from(raw_total - 1).test_unwrap(),
                ..ReportReadLimits::default()
            },
            "aggregate raw source byte limit",
        ),
        (
            ReportReadLimits {
                decoded_bytes: 32,
                ..ReportReadLimits::default()
            },
            "decoded JSON text byte limit",
        ),
        (
            ReportReadLimits {
                groups: 1,
                ..ReportReadLimits::default()
            },
            "distinct group limit",
        ),
        (
            ReportReadLimits {
                sql_steps: 1000,
                ..ReportReadLimits::default()
            },
            "SQL work budget",
        ),
    ] {
        let analytics = fixture
            .store
            .receipt_analytics_with_read_limits(&query, limits, || Ok(()));
        assert!(
            matches!(&analytics, Err(ReceiptStoreError::ReadBoundary(message)) if message.contains(reason)),
            "analytics {reason}: {analytics:?}"
        );
        let attribution =
            fixture
                .store
                .cost_attribution_with_limits(&cost_query, limits, || Ok(()));
        assert!(
            matches!(&attribution, Err(ReceiptStoreError::ReadBoundary(message)) if message.contains(reason)),
            "attribution {reason}: {attribution:?}"
        );
        assert_eq!(
            fixture
                .store
                .query_receipt_analytics(&query)
                .test_unwrap()
                .summary
                .total_receipts,
            3
        );
        assert_eq!(
            fixture
                .store
                .query_cost_attribution_report(&cost_query)
                .test_unwrap()
                .summary
                .total_cost_charged,
            33
        );
    }
    let limits = ReportReadLimits {
        lineage_lookups: 0,
        ..ReportReadLimits::default()
    };
    let result = fixture
        .store
        .cost_attribution_with_limits(&cost_query, limits, || Ok(()));
    assert!(
        matches!(result, Err(ReceiptStoreError::ReadBoundary(message)) if message.contains("lineage lookup limit"))
    );
    let exact = ReportReadLimits {
        rows: 3,
        groups: 3,
        ..ReportReadLimits::default()
    };
    assert_eq!(
        fixture
            .store
            .receipt_analytics_with_read_limits(&query, exact, || Ok(()))
            .test_unwrap()
            .summary
            .total_cost_charged,
        33
    );
    assert_eq!(
        fixture
            .store
            .cost_attribution_with_limits(&cost_query, exact, || Ok(()))
            .test_unwrap()
            .summary
            .total_cost_charged,
        33
    );
}

#[test]
fn raw_length_metadata_is_read_before_fetching_a_large_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = bounded_fixture();
    let connection = fixture.store.connection()?;
    let column: i64 = connection.query_row(
        "SELECT cid FROM pragma_table_info('chio_tool_receipts') WHERE name = 'raw_json'",
        [],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare("EXPLAIN SELECT octet_length(raw_json), CASE WHEN octet_length(raw_json) <= 32 THEN raw_json END FROM chio_tool_receipts")?;
    let flags = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .filter_map(|row| match row {
            Ok((opcode, field, flags)) if opcode == "Column" && field == column => Some(Ok(flags)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        flags.first().copied(),
        Some(0xc0),
        "raw byte metadata must avoid payload loading: {flags:?}"
    );
    assert!(
        flags.contains(&0),
        "bounded CASE needs a payload read only on its allowed branch"
    );
    Ok(())
}

#[test]
fn report_count_totals_and_groups_share_the_production_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    for analytics in [false, true] {
        let fixture = bounded_fixture();
        let receipt = sign_fixture_receipt(
            90,
            &FixtureReceipt {
                capability_id: "cap-concurrent-report".into(),
                subject_key: "agent-concurrent",
                tool_server: "shell",
                tool_name: "bash",
                decision: Decision::Allow,
                timestamp: DAY_SECS,
                financial: Some((100, Some(200))),
            },
        );
        let append = || fixture.store.append_chio_receipt(&receipt);
        if analytics {
            let report = fixture.store.receipt_analytics_with_read_limits(
                &admin_query(),
                ReportReadLimits::default(),
                append,
            )?;
            assert_eq!(report.summary.total_receipts, 3);
            assert_eq!(report.summary.total_cost_charged, 33);
            assert_eq!(report.by_agent.len(), 3);
        } else {
            let report = fixture.store.cost_attribution_with_limits(
                &CostAttributionQuery {
                    read_context: admin_query().read_context,
                    ..CostAttributionQuery::default()
                },
                ReportReadLimits::default(),
                append,
            )?;
            assert_eq!(report.summary.matching_receipts, 3);
            assert_eq!(report.summary.total_cost_charged, 33);
            assert_eq!(report.receipts.len(), 3);
        }
        assert_eq!(
            fixture
                .store
                .query_receipt_analytics(&admin_query())?
                .summary
                .total_receipts,
            4
        );
    }
    Ok(())
}

#[test]
fn selected_integrity_preserves_legacy_null_lineage_fallback(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = bounded_fixture();
    // The signed body has no attribution and the receipt preceded its legacy
    // capability row. Stored NULL must retain the local COALESCE diagnostic.
    let mut body = sign_fixture_receipt(
        50,
        &FixtureReceipt {
            capability_id: "cap-legacy-null".into(),
            subject_key: "removed-before-signing",
            tool_server: "shell",
            tool_name: "bash",
            decision: Decision::Allow,
            timestamp: DAY_SECS,
            financial: Some((1, None)),
        },
    )
    .body();
    body.metadata
        .as_mut()
        .and_then(serde_json::Value::as_object_mut)
        .test_expect("metadata")
        .remove("attribution");
    let keypair = Keypair::from_seed(&[63; 32]);
    body.kernel_key = keypair.public_key();
    fixture
        .store
        .append_chio_receipt(&ChioReceipt::sign(body, &keypair)?)?;
    let external = Connection::open(&fixture.path)?;
    external.execute("INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance)
        VALUES ('cap-legacy-null', 'legacy-subject', 'legacy-issuer', 1, 100, '{}', 0, 'legacy_projection')", [])?;
    let report = fixture
        .store
        .query_receipt_analytics(&ReceiptAnalyticsQuery {
            agent_subject: Some("legacy-subject".into()),
            ..admin_query()
        })?;
    assert_eq!(report.summary.total_receipts, 1);
    assert_eq!(report.by_agent[0].subject_key, "legacy-subject");
    let limits = ReportReadLimits {
        lineage_lookups: 0,
        ..ReportReadLimits::default()
    };
    assert!(
        matches!(fixture.store.receipt_analytics_with_read_limits(&admin_query(), limits, || Ok(())), Err(ReceiptStoreError::ReadBoundary(message)) if message.contains("lineage lookup limit"))
    );
    Ok(())
}

#[test]
fn output_limit_does_not_hide_late_selected_projection_corruption(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = bounded_fixture();
    let external = Connection::open(&fixture.path)?;
    crate::receipt_store::support::drop_transparency_projection_guards(&external)?;
    external.execute(
        "UPDATE chio_tool_receipts SET decision_kind = 'deny' WHERE seq = 3",
        [],
    )?;
    crate::receipt_store::support::ensure_transparency_projection_guards(&external)?;
    let result = fixture
        .store
        .query_cost_attribution_report(&CostAttributionQuery {
            limit: Some(1),
            read_context: admin_query().read_context,
            ..CostAttributionQuery::default()
        });
    assert!(
        matches!(result, Err(ReceiptStoreError::Conflict(_))),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn oversized_filters_refuse_before_scope_cloning() {
    let fixture = bounded_fixture();
    let query = ReceiptAnalyticsQuery {
        tool_name: Some("x".repeat(9 * 1024 * 1024)),
        ..admin_query()
    };
    assert!(
        matches!(fixture.store.query_receipt_analytics(&query), Err(ReceiptStoreError::ReadBoundary(message)) if message == "report filter exceeds its raw byte limit")
    );
    let query = CostAttributionQuery {
        tool_name: query.tool_name,
        read_context: query.read_context,
        ..CostAttributionQuery::default()
    };
    assert!(
        matches!(fixture.store.query_cost_attribution_report(&query), Err(ReceiptStoreError::ReadBoundary(message)) if message == "report filter exceeds its raw byte limit")
    );
}

#[test]
fn signed_subject_grouping_does_not_multiply_receipts_through_unsigned_lineage(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = bounded_fixture();
    let external = Connection::open(&fixture.path)?;
    // Corruption control removes the original PK and duplicates the fallback.
    // Explicit signed attribution must not join that unsigned row at all.
    external.execute_batch(
        "ALTER TABLE capability_lineage RENAME TO original_lineage;
        CREATE TABLE capability_lineage AS SELECT * FROM original_lineage;",
    )?;
    for _ in 0..2 {
        external.execute("INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance)
            VALUES ('cap-bounded-0', 'unsigned-subject', 'unsigned-issuer', 1, 100, '{}', 0, 'legacy_projection')", [])?;
    }
    let report = fixture.store.query_receipt_analytics(&admin_query())?;
    assert_eq!(report.summary.total_cost_charged, 33);
    assert_eq!(
        report
            .by_agent
            .iter()
            .map(|group| group.metrics.total_cost_charged)
            .sum::<u64>(),
        33
    );
    Ok(())
}
