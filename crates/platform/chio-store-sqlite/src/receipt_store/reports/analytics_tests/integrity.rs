use super::*;
use crate::receipt_store::support::{
    drop_transparency_projection_guards, ensure_transparency_projection_guards,
};

#[test]
fn reports_reject_projection_drift_after_external_mutation_and_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    for column in ["cost_charged_be", "attempted_cost_be"] {
        for replacement in [None, Some(777_u64.to_be_bytes().to_vec())] {
            for reopen in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("receipts.db");
                let mut store = Some(SqliteReceiptStore::open(&path)?);
                let receipt = sign_fixture_receipt(
                    0,
                    &FixtureReceipt {
                        capability_id: "cap-integrity".to_owned(),
                        subject_key: "agent-integrity",
                        tool_server: "shell",
                        tool_name: "bash",
                        decision: Decision::Allow,
                        timestamp: DAY_SECS,
                        financial: Some((11, Some(22))),
                    },
                );
                store
                    .as_ref()
                    .test_expect("open store")
                    .append_chio_receipt(&receipt)?;
                let original = store
                    .as_ref()
                    .test_expect("open store")
                    .query_receipt_analytics(&admin_query())?;
                assert_eq!(original.summary.total_cost_charged, 11);
                assert_eq!(original.summary.total_attempted_cost, 22);
                if reopen {
                    drop(store.take());
                }
                let external = Connection::open(&path)?;
                drop_transparency_projection_guards(&external)?;
                let currency = if column == "cost_charged_be" && replacement.is_none() {
                    ", cost_currency = NULL"
                } else {
                    ""
                };
                external.execute(
                    &format!("UPDATE chio_tool_receipts SET {column} = ?1{currency}"),
                    [&replacement],
                )?;
                ensure_transparency_projection_guards(&external)?;
                drop(external);
                let store = match store {
                    Some(store) => store,
                    None => SqliteReceiptStore::open(&path)?,
                };
                let expected = format!(
                    "receipt analytics cost projection differs from signed receipt {}",
                    receipt.id
                );
                let outcome = store.query_receipt_analytics(&admin_query());
                assert!(
                    matches!(&outcome,
                        Err(ReceiptStoreError::Conflict(reason))
                            if reason == &expected
                    ),
                    "wrong result for altered {column} (reopened: {reopen}): {outcome:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn sparse_subject_queries_have_a_sql_work_budget() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = SqliteReceiptStore::open(directory.path().join("sparse.db"))?;
    let keypair = Keypair::from_seed(&[63; 32]);
    for index in 0..320 {
        let mut body = sign_fixture_receipt(
            index,
            &FixtureReceipt {
                capability_id: "cap-no-attribution".to_owned(),
                subject_key: "removed-before-signing",
                tool_server: "shell",
                tool_name: "bash",
                decision: Decision::Allow,
                timestamp: DAY_SECS,
                financial: Some((1, Some(2))),
            },
        )
        .body();
        body.metadata
            .as_mut()
            .and_then(serde_json::Value::as_object_mut)
            .test_expect("fixture metadata")
            .remove("attribution");
        body.kernel_key = keypair.public_key();
        store.append_chio_receipt(&ChioReceipt::sign(body, &keypair)?)?;
    }
    let query = ReceiptAnalyticsQuery {
        agent_subject: Some("no-matching-subject".to_owned()),
        ..admin_query()
    };
    let original = store.query_receipt_analytics(&query)?;
    assert_eq!(original.summary.total_receipts, 0);
    assert!(
        matches!(store.receipt_analytics_with_limits(&query, 8, 1_000),
            Err(ReceiptStoreError::ReadBoundary(reason))
                if reason == "receipt analytics report exhausted its SQL work budget"
        )
    );
    // The interrupted report must release its snapshot and progress callback.
    let retry = store.query_receipt_analytics(&query)?;
    assert_eq!(retry, original);
    Ok(())
}
