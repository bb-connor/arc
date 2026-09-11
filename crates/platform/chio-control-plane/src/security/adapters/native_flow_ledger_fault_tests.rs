// Real SQLite failures after the kernel has confirmed both egress phases.
// No synthetic policy record or simulated physical store supplies this proof.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionOperationStore, AdmissionOperationV1, NativeSecurityEgressHistoryV1,
};

pub(in crate::security::adapters) use chio_store_sqlite::admission_operation_store::NativeDispatchLedgerTestFault as WriteFault;

pub(in crate::security::adapters) struct LedgerFailureProbe {
    store: chio_store_sqlite::SqliteAdmissionOperationStore,
    fence: chio_kernel::admission_operation::StoreMutationFence,
    database: std::path::PathBuf,
    fault: WriteFault,
    history: Mutex<Option<NativeSecurityEgressHistoryV1>>,
    capture: CaptureRefusalProbe,
}

impl LedgerFailureProbe {
    pub(in crate::security::adapters) fn new(
        authority: &chio_store_sqlite::SqliteAuthorityStore,
        database: std::path::PathBuf,
        fault: WriteFault,
    ) -> Self {
        Self {
            store: authority.admission_operation_store(),
            fence: authority.mutation_fence(),
            capture: CaptureRefusalProbe::new(authority, database.clone()),
            database,
            fault,
            history: Mutex::new(None),
        }
    }

    pub(in crate::security::adapters) fn install(&self) -> TestResult {
        self.store
            .inject_native_dispatch_ledger_failure_for_test(self.fault)?;
        Ok(())
    }

    pub(in crate::security::adapters) fn verify(
        &self,
        kernel: &chio_kernel::ChioKernel,
        operation: &AdmissionOperationV1,
        outcome: &Result<NativeFlowCustody, NativeFlowError>,
    ) -> TestResult {
        // Remove only this fixture's fault before compensation and reopen.
        self.store.clear_native_dispatch_ledger_failure_for_test()?;
        let connection = rusqlite::Connection::open(&self.database)?;
        let error = outcome
            .as_ref()
            .err()
            .ok_or("injected ledger write succeeded")?;
        assert!(
            error.to_string().contains("injected native ledger failure"),
            "{:?}: {error}",
            self.fault
        );
        let id = operation.binding().operation_id();
        let (current, history) = self
            .store
            .load_native_security_egress(id, &self.fence, now_ms()?)?
            .ok_or("partial egress operation")?;
        assert_eq!(&current, operation);
        let history = history.ok_or("successful egress must survive ledger error")?;
        assert!(history.commitment.is_some());
        assert!(self
            .store
            .load_native_dispatch_ledger(id, &self.fence, now_ms()?)?
            .is_none());
        let counts: (i64, i64, i64, String) = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM admission_operation_native_dispatch_ledger),
                    (SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'native_dispatch_ledger'),
                    (SELECT COUNT(*) FROM security_participant_egress_events WHERE operation_id = ?1),
                    (SELECT invocation_state FROM budget_authorization_holds WHERE operation_id = ?1)",
            [id.as_str()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        assert_eq!(counts, (0, 0, 2, "authorized".into()));
        *self
            .history
            .lock()
            .map_err(|_| "ledger failure history poisoned")? = Some(history);
        // Egress history without a journal also cannot unlock any capture path.
        self.capture.verify(kernel, operation, None)?;
        Ok(())
    }

    pub(in crate::security::adapters) fn history(
        &self,
    ) -> TestResult<NativeSecurityEgressHistoryV1> {
        self.history
            .lock()
            .map_err(|_| "ledger failure history poisoned")?
            .clone()
            .ok_or_else(|| "partial egress was not observed before compensation".into())
    }
}

#[test]
fn ledger_write_failures_preserve_committed_egress_through_compensation_and_reopen() -> TestResult {
    for fault in [
        WriteFault::BeforeRow,
        WriteFault::AfterRow,
        WriteFault::BeforeGlobalCommit,
        WriteFault::AfterGlobalCommit,
    ] {
        let mut fixture = public_fixture()?;
        let classifier = Arc::new(CountingEmptyClassifier::new());
        let resolver = Arc::new(NativeFlowResolver::new(
            fixture.binding.clone(),
            registry(true, InformationLabel::bottom())?,
            classifier.clone(),
            Arc::new(Clock::default()),
            flow_config(),
        )?);
        let result = fixture.run_ledger_write_fault(resolver, fault)?;
        assert!(
            matches!(result, Err(NativeFlowError::Custody(ref error)) if error.to_string().contains("injected native ledger failure")),
            "{fault:?}"
        );
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
        fixture.reopen_failed_dispatch_ledger()?;
    }
    Ok(())
}
