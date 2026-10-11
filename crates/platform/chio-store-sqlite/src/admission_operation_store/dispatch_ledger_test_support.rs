//! Default-off, fail-only cutpoints on the real serving-owner connection.
//! External connections cannot inject faults without tripping owner fencing.
use super::*;

/// Fixed abort points, never arbitrary SQL, replacement records or permissions.
#[derive(Clone, Copy, Debug)]
pub enum NativeDispatchLedgerTestFault {
    BeforeRow,
    AfterRow,
    BeforeGlobalCommit,
    AfterGlobalCommit,
}

/// Abort after earlier capture writes have actually executed in the same
/// transaction. Neither point simulates a post-commit acknowledgement failure.
#[derive(Clone, Copy, Debug)]
pub enum NativeDispatchCaptureTestFault {
    AfterBudgetCapture,
    AfterOperationCapture,
}

impl NativeDispatchCaptureTestFault {
    fn sql(self) -> &'static str {
        match self {
            Self::AfterBudgetCapture => "CREATE TEMP TRIGGER inject_native_capture_failure AFTER UPDATE OF invocation_state ON main.budget_authorization_holds WHEN NEW.invocation_state = 'captured' BEGIN SELECT RAISE(ABORT, 'injected native capture failure after budget write'); END",
            Self::AfterOperationCapture => "CREATE TEMP TRIGGER inject_native_capture_failure AFTER UPDATE OF state ON main.admission_operations WHEN NEW.state = 'dispatch_committed' BEGIN SELECT RAISE(ABORT, 'injected native capture failure after operation write'); END",
        }
    }
}

impl NativeDispatchLedgerTestFault {
    fn sql(self) -> &'static str {
        match self {
            Self::BeforeRow => "CREATE TEMP TRIGGER inject_native_ledger_failure BEFORE INSERT ON main.admission_operation_native_dispatch_ledger BEGIN SELECT RAISE(ABORT, 'injected native ledger failure'); END",
            Self::AfterRow => "CREATE TEMP TRIGGER inject_native_ledger_failure AFTER INSERT ON main.admission_operation_native_dispatch_ledger BEGIN SELECT RAISE(ABORT, 'injected native ledger failure'); END",
            Self::BeforeGlobalCommit => "CREATE TEMP TRIGGER inject_native_ledger_failure BEFORE INSERT ON main.authority_global_commits WHEN NEW.projection_kind = 'native_dispatch_ledger' BEGIN SELECT RAISE(ABORT, 'injected native ledger failure'); END",
            Self::AfterGlobalCommit => "CREATE TEMP TRIGGER inject_native_ledger_failure AFTER INSERT ON main.authority_global_commits WHEN NEW.projection_kind = 'native_dispatch_ledger' BEGIN SELECT RAISE(ABORT, 'injected native ledger failure'); END",
        }
    }
}

impl SqliteAdmissionOperationStore {
    pub fn inject_native_dispatch_capture_failure_for_test(
        &self,
        fault: NativeDispatchCaptureTestFault,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch(fault.sql())
            .map_err(sqlite_error)
    }

    pub fn clear_native_dispatch_capture_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TRIGGER temp.inject_native_capture_failure")
            .map_err(sqlite_error)
    }

    /// Install one connection-local abort point. An already armed point is an
    /// error. No table, anchor or serving-owner check is changed or bypassed.
    pub fn inject_native_dispatch_ledger_failure_for_test(
        &self,
        fault: NativeDispatchLedgerTestFault,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch(fault.sql())
            .map_err(sqlite_error)
    }

    /// Remove the exact test trigger before cleanup or another experiment.
    /// Connection teardown also discards this temporary trigger after a panic.
    pub fn clear_native_dispatch_ledger_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TRIGGER temp.inject_native_ledger_failure")
            .map_err(sqlite_error)
    }
}
