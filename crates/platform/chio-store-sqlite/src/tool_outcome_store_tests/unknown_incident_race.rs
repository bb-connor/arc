use super::*;
use chio_kernel::admission_operation::{
    verified_outcome_unknown_after_dispatch_projection, AdmissionProjectionContext,
    AdmissionTerminalReplay,
};
use chio_kernel::ReceiptStore;

#[test]
fn original_dispatch_incident_and_tool_return_mutually_refuse_the_losing_write() {
    for incident_first in [false, true] {
        let fixture = fixture();
        let begun_at = now_ms();
        let operation = committed(&fixture, "original-dispatch-mutual-refusal", begun_at);
        let at = begun_at + 20;
        let (blob, outcome) = returned_value(
            &operation,
            fixture.fence.clone(),
            at,
            serde_json::json!({"returned": true}),
            None,
        )
        .expect("valid return for the original dispatch");
        let lease = claim(&fixture, &operation, at);
        let context = AdmissionProjectionContext {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.binding().request_id().clone(),
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: at + 2,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: fixture.fence.clone(),
        };
        let receipt = crate::admission_operation_store::refusal_receipt(
            &operation,
            &context,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
            &chio_core::crypto::Keypair::generate(),
            &serde_json::json!({}),
        )
        .expect("bound refusal receipt");
        let incident =
            verified_outcome_unknown_after_dispatch_projection(&operation, context, receipt)
                .expect("verified original-dispatch incident");
        assert_eq!(
            incident.context().expected_operation_version,
            operation.version()
        );

        if incident_first {
            let terminal = fixture
                .operations
                .commit_admission_projection(&incident)
                .expect("the original incident commits first");
            assert_eq!(terminal.operation_id, *operation.binding().operation_id());
            assert_eq!(
                terminal.state,
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            );
            assert!(matches!(
                terminal.replay,
                AdmissionTerminalReplay::Receipt { .. }
            ));
        } else {
            let (stored, finalizing) = fixture
                .outcomes
                .record_tool_returned(&operation, &lease, &blob, &outcome, &fixture.fence, at + 1)
                .expect("the original return commits first")
                .into_parts();
            assert_eq!(stored.outcome_id(), outcome.outcome_id());
            assert_eq!(stored.raw_output_digest(), outcome.raw_output_digest());
            assert_eq!(finalizing.binding(), operation.binding());
            assert_eq!(finalizing.state(), AdmissionOperationState::Finalizing);
            assert!(finalizing.version() > incident.context().expected_operation_version);
        }

        let winner = fixture
            .operations
            .load_by_operation_id(operation.binding().operation_id())
            .expect("load authoritative winner")
            .expect("winner exists");
        let retained_outcome = fixture
            .outcomes
            .lookup_by_operation(operation.binding().operation_id())
            .expect("load retained outcome");
        let retained_raw = fixture
            .outcomes
            .load_raw_invocation_by_operation(operation.binding().operation_id())
            .expect("load retained raw return");
        let connection = Connection::open(&fixture.database).expect("independent history read");
        let before =
            crate::tests::authority_snapshot(&connection).expect("authority before losing write");
        let anchor = fixture
            .authority
            .anchor_generation()
            .expect("anchor before losing write");
        if incident_first {
            fixture
                .outcomes
                .record_tool_returned(&operation, &lease, &blob, &outcome, &fixture.fence, at + 3)
                .expect_err("a terminal incident cannot accept the competing return");
        } else {
            fixture
                .operations
                .commit_admission_projection(&incident)
                .expect_err("a stored return cannot be replaced by the stale incident");
        }
        assert_eq!(
            crate::tests::authority_snapshot(&connection).expect("authority after losing write"),
            before,
            "the losing successor must leave the authoritative history unchanged"
        );
        assert_eq!(
            fixture
                .authority
                .anchor_generation()
                .expect("retained anchor"),
            anchor
        );
        assert_eq!(
            fixture
                .operations
                .load_by_operation_id(operation.binding().operation_id())
                .expect("reload winner")
                .expect("retained winner"),
            winner
        );
        assert_eq!(
            fixture
                .outcomes
                .lookup_by_operation(operation.binding().operation_id())
                .expect("reload outcome"),
            retained_outcome
        );
        assert_eq!(
            fixture
                .outcomes
                .load_raw_invocation_by_operation(operation.binding().operation_id())
                .expect("reload raw return"),
            retained_raw
        );

        let counts: (i64, i64, i64, i64) = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM tool_outcome_blobs),
                    (SELECT COUNT(*) FROM tool_outcomes),
                    (SELECT COUNT(*) FROM admission_operation_terminal_records WHERE record_kind = 'incident'),
                    (SELECT COUNT(*) FROM admission_operation_terminal_records WHERE record_kind = 'receipt')",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).expect("independent artifact counts");
        assert_eq!(
            counts,
            if incident_first {
                (0, 0, 1, 1)
            } else {
                (1, 1, 0, 0)
            },
            "one original successor, with no orphan return or competing receipt"
        );
        assert_eq!(retained_outcome.is_none(), incident_first);
        assert_eq!(retained_raw.is_none(), incident_first);
        assert_eq!(winner.binding(), operation.binding());
        assert_eq!(winner.dispatch_commit(), operation.dispatch_commit());
    }
}
