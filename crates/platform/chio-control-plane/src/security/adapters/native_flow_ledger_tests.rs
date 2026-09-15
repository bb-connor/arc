use super::*;

/// Probe every lower-level capture route after actual ledger retention. No
/// historical preparation can replace the still-required dispatch authority.
pub(super) struct CaptureRefusalProbe {
    store: chio_store_sqlite::SqliteAdmissionOperationStore,
    budget: chio_store_sqlite::SqliteBudgetStore,
    fence: chio_kernel::admission_operation::StoreMutationFence,
    database: std::path::PathBuf,
}

impl CaptureRefusalProbe {
    pub(super) fn new(
        authority: &chio_store_sqlite::SqliteAuthorityStore,
        database: std::path::PathBuf,
    ) -> Self {
        Self {
            store: authority.admission_operation_store(),
            budget: authority.budget_store(),
            fence: authority.mutation_fence(),
            database,
        }
    }

    pub(super) fn verify(
        &self,
        kernel: &chio_kernel::ChioKernel,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        ledger: Option<&chio_kernel::admission_operation::NativeSecurityDispatchLedgerRecordV1>,
    ) -> TestResult {
        use chio_kernel::admission_operation::{
            AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationState,
            AdmissionOperationStore, QualifiedAdmissionOperationStoreExt,
        };
        use chio_kernel::budget_store::{BudgetCaptureInvocationRequest, BudgetEventAuthority};
        use chio_kernel::BudgetStore;
        let claimant = AdmissionIdentifier::try_new(
            "claimant",
            format!("kernel:{}", kernel.public_key().to_hex()),
        )?;
        for route in ["combined", "split", "generic"] {
            let now = now_ms()?;
            let lease = self.store.claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &claimant,
                now,
                now + 60_000,
                &self.fence,
            )?;
            let before = self.snapshot(operation)?;
            let capture = BudgetCaptureInvocationRequest {
                capability_id: operation.binding().capability_id().as_str().into(),
                grant_index: 0,
                hold_id: operation
                    .budget_hold_id()
                    .ok_or("physical hold")?
                    .as_str()
                    .into(),
                event_id: format!("ledger-refusal-{route}"),
                trusted_time: None,
                authority: Some(BudgetEventAuthority {
                    authority_id: self.fence.store_uuid.clone(),
                    lease_id: self.fence.lease_id.clone(),
                    lease_epoch: self.fence.owner_epoch,
                }),
            };
            let denied = match route {
                "combined" => self
                    .store
                    .capture_invocation_and_commit_dispatch(
                        operation,
                        &lease,
                        capture,
                        &self.fence,
                        now_ms()?,
                    )
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
                "split" => self
                    .budget
                    .capture_invocation_reservations(capture)
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
                _ => self
                    .store
                    .compare_and_swap(
                        &AdmissionOperationCommand::new(
                            operation.binding().operation_id().clone(),
                            operation.version(),
                            lease,
                            vec![],
                            Some(AdmissionOperationState::DispatchCommitted),
                            None,
                            None,
                        )?,
                        now_ms()?,
                    )
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
            };
            let error = denied
                .err()
                .ok_or("native capture unexpectedly succeeded")?;
            assert!(
                error.contains("native security dispatch custody is unsupported"),
                "{route}: {error}"
            );
            assert_eq!(self.snapshot(operation)?, before, "{route}");
            assert_eq!(
                self.store
                    .load_native_dispatch_ledger(
                        operation.binding().operation_id(),
                        &self.fence,
                        now_ms()?
                    )?
                    .as_ref(),
                ledger
            );
        }
        Ok(())
    }

    /// Keep the independent physical-store check covered after the producer
    /// begins rejecting bad grants before any egress mutation.
    pub(super) fn verify_invalid_ledger_grant(
        &self,
        kernel: &chio_kernel::ChioKernel,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
        request: &chio_kernel::ToolCallRequest,
        context: &chio_kernel::SecurityInvocationContext,
        custody: &NativeFlowCustody,
    ) -> TestResult {
        use chio_kernel::admission_operation::{
            AdmissionIdentifier, NativeSecurityDispatchLedgerContext, NativeSecurityEgressContext,
            QualifiedAdmissionOperationStoreExt,
        };
        let prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            request,
            context,
        )?;
        let now = now_ms()?;
        let lease = self.store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &AdmissionIdentifier::try_new(
                "claimant",
                format!("kernel:{}", kernel.public_key().to_hex()),
            )?,
            now,
            now + 60_000,
            &self.fence,
        )?;
        let before = self.snapshot(operation)?;
        let result =
            self.store
                .retain_native_dispatch_ledger(NativeSecurityDispatchLedgerContext {
                    custody: NativeSecurityEgressContext {
                        operation,
                        lease: &lease,
                        binding: prepared.observation().binding(),
                        security_context: prepared.security_context(),
                        request,
                        trusted_now_unix_ms: now_ms()?,
                    },
                    grant_index: 1,
                    policy_json: custody.policy_evidence().canonical_bytes(),
                });
        let error = result
            .err()
            .ok_or("physical journal accepted an unmatched grant")?;
        assert!(error.to_string().contains("unmatched grant"), "{error}");
        assert_eq!(self.snapshot(operation)?, before);
        assert_eq!(
            self.store
                .load_native_dispatch_ledger(
                    operation.binding().operation_id(),
                    &self.fence,
                    now_ms()?,
                )?
                .as_ref(),
            custody.dispatch_ledger()
        );
        Ok(())
    }

    fn snapshot(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationV1,
    ) -> TestResult<(Vec<u8>, i64, i64, i64)> {
        Ok(rusqlite::Connection::open(&self.database)?.query_row(
            "SELECT (SELECT operation_json FROM admission_operations WHERE operation_id = ?1),
                (SELECT COUNT(*) FROM authority_global_commits),
                (SELECT COUNT(*) FROM budget_mutation_events),
                (SELECT COUNT(*) FROM admission_operation_commits)",
            [operation.binding().operation_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?)
    }
}

#[test]
fn native_dispatch_ledger_retains_exact_policy_and_custody_after_compensation() -> TestResult {
    for egress in [false, true] {
        let mut fixture = public_fixture()?;
        fixture.request.arguments = serde_json::json!({"message": "ledger-private-payload"});
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            registry(egress, InformationLabel::bottom())?,
            classifier.clone(),
            Arc::new(Clock::default()),
            flow_config(),
        )?);
        let custody = fixture.run_with_dispatch_ledger(resolver, 0)??;
        let ledger = custody.dispatch_ledger().ok_or("durable dispatch ledger")?;
        let record: serde_json::Value = serde_json::from_slice(&ledger.canonical_record)?;
        assert_eq!(
            record["schema"],
            "chio.native-dispatch-preparation-ledger.v1"
        );
        assert_eq!(
            record["policy"],
            serde_json::from_slice::<serde_json::Value>(
                custody.policy_evidence().canonical_bytes()
            )?
        );
        assert_eq!(record["grant_index"], 0);
        assert_eq!(
            ledger.record_digest.as_str(),
            chio_core::sha256_hex(&ledger.canonical_record)
        );
        assert_eq!(ledger.operation_id, *custody.operation_id());
        assert_eq!(record["egress_acquisition"].is_null(), !egress);
        assert_eq!(record["egress_commitment"].is_null(), !egress);
        assert!(record["runtime"].is_null());
        assert!(record["approval"].is_null());
        assert!(record["dpop"].is_null());
        assert!(!std::str::from_utf8(&ledger.canonical_record)?.contains("ledger-private-payload"));
        assert!(!format!("{ledger:?}").contains("native-tenant"));
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
        let expected = ledger.clone();
        assert_eq!(
            fixture.reopen_dispatch_ledger(&expected.operation_id, |_| Ok(()))?,
            expected
        );
    }
    Ok(())
}

#[test]
fn native_dispatch_ledger_denies_unmatched_grant_without_retention() -> TestResult {
    for egress in [false, true] {
        let mut fixture = public_fixture()?;
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            registry(egress, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            Arc::new(Clock::default()),
            flow_config(),
        )?);
        let result = fixture.run_with_dispatch_ledger(resolver, 1)?;
        assert!(
            matches!(result, Err(NativeFlowError::Custody(ref error)) if error.to_string().contains("unmatched grant"))
        );
    }
    Ok(())
}

mod faults {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/security/adapters/native_flow_ledger_fault_tests.rs"
    ));
}
pub(super) use faults::{LedgerFailureProbe, WriteFault};

#[test]
fn native_dispatch_ledger_corruption_or_missing_global_coverage_denies_reopen() -> TestResult {
    for (mutation, reason) in [
        ("UPDATE admission_operation_native_dispatch_ledger SET canonical_record = CAST('{}' AS BLOB)", "missing field `schema`"),
        ("UPDATE admission_operation_native_dispatch_ledger SET canonical_record = zeroblob(1048577)", "native dispatch ledger record exceeds its physical bound"),
        ("DELETE FROM admission_operation_native_dispatch_ledger", "native dispatch ledger lost its exact global commitment"),
    ] {
        let mut fixture = public_fixture()?;
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(), registry(false, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()), Arc::new(Clock::default()), flow_config(),
        )?);
        let custody = fixture.run_with_dispatch_ledger(resolver, 0)??;
        let operation = custody.operation_id().clone();
        let result = fixture.reopen_dispatch_ledger(&operation, |connection| {
            connection.execute_batch("DROP TRIGGER admission_operation_native_dispatch_ledger_immutable; DROP TRIGGER admission_operation_native_dispatch_ledger_no_delete; PRAGMA ignore_check_constraints = ON;")?;
            connection.execute_batch(mutation)?;
            connection.execute_batch(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../chio-store-sqlite/src/admission_operation_native_dispatch_ledger.sql")))?;
            Ok(())
        });
        let error = result.err().ok_or("corrupted native ledger reopened")?;
        assert!(error.to_string().contains(reason), "{mutation}: {error}");
    }
    Ok(())
}
