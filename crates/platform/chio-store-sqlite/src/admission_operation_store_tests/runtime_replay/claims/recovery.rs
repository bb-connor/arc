use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantDisposition;

#[test]
fn reopened_history_recovers_exact_claim_and_retains_dispatch_disposition() -> TestResult {
    for dispatched in [false, true] {
        let fixture = fixture();
        let source = imported(&fixture, true)?;
        let (operation, lease) = setup(&fixture, "reopen-claim")?;
        let candidate = intent(
            &operation,
            &source,
            "lost-ack",
            &[(Kind::DestructiveLease, "resource")],
        )?;
        let (operation, reference) =
            fixture
                .store
                .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
        let operation = if dispatched {
            let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
            fixture
                .store
                .compare_and_swap(
                    &command(
                        &operation,
                        lease,
                        vec![],
                        AdmissionOperationState::DispatchCommitted,
                        None,
                    ),
                    now_ms(),
                )?
                .into_operation()
        } else {
            operation
        };
        let Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            fence,
        } = fixture;
        drop(store);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let store = authority.admission_operation_store();
        assert!(matches!(
            store.load_runtime_participant_history(
                operation.binding().operation_id(),
                &fence,
                now_ms()
            ),
            Err(AdmissionOperationStoreError::Fenced)
        ));
        assert!(matches!(
            store.load_runtime_participant_evidence(
                operation.binding().operation_id(),
                &fence,
                now_ms()
            ),
            Err(AdmissionOperationStoreError::Fenced)
        ));
        let fence = authority.mutation_fence();
        let (loaded, history) = store
            .load_runtime_participant_history(operation.binding().operation_id(), &fence, now_ms())?
            .ok_or("missing restored operation")?;
        assert_eq!(loaded, operation);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].reference, reference);
        assert_eq!(history[0].intent, candidate);
        let count = global_count(&store);
        let (exported, evidence) = store
            .load_runtime_participant_evidence(
                operation.binding().operation_id(),
                &fence,
                now_ms(),
            )?
            .ok_or("missing restored claim evidence")?;
        assert_eq!(exported, operation);
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].history, history[0]);
        evidence[0].verify()?;
        for field in ["expectationId", "requestBindingHash", "planDigest"] {
            let mut changed = evidence[0].clone();
            changed.claim["intent"][field] = serde_json::json!("a".repeat(64));
            assert!(changed.verify().is_err(), "accepted substituted {field}");
        }
        let mut changed = evidence[0].clone();
        changed.operation.version += 1;
        assert!(changed.verify().is_err());
        assert_eq!(
            global_count(&store),
            count,
            "export mutated the custody ledger"
        );
        assert_eq!(
            history[0].disposition,
            if dispatched {
                RuntimeParticipantDisposition::RetainedAfterDispatchCommit
            } else {
                RuntimeParticipantDisposition::ReservedBeforeDispatch
            }
        );
        let now = now_ms();
        let lease = store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant", "reopened-worker"),
            now,
            now + 10000,
            &fence,
        )?;
        let released =
            store.release_runtime_participants(&operation, &lease, &history[0].reference, now_ms());
        if dispatched {
            assert!(
                matches!(released, Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("after dispatch commitment"))
            );
        } else {
            released?;
            let (_, history) = store
                .load_runtime_participant_history(
                    operation.binding().operation_id(),
                    &fence,
                    now_ms(),
                )?
                .ok_or("missing released operation")?;
            assert_eq!(
                history[0].disposition,
                RuntimeParticipantDisposition::ReleasedBeforeDispatch
            );
            let (_, evidence) = store
                .load_runtime_participant_evidence(
                    operation.binding().operation_id(),
                    &fence,
                    now_ms(),
                )?
                .ok_or("missing released evidence")?;
            evidence[0].verify()?;
            assert_eq!(evidence[0].history, history[0]);
            assert!(store
                .claim_runtime_participants(&operation, &lease, &candidate, now_ms())
                .is_err());
        }
    }
    Ok(())
}
