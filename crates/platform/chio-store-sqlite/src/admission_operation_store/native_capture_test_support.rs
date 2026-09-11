//! Default-off reply faults after real capture or readback, never replacement writes.
use super::*;
use chio_kernel::budget_store::{BudgetGuaranteeLevel, BudgetInvocationCaptureDecision};
use chio_kernel::AdmissionBudgetCapture;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeDispatchCaptureResponseTestFault {
    CaptureError,
    CapturePanic,
    CaptureOperation,
    CaptureReplay,
    CaptureHold,
    CaptureBinding,
    CaptureEvent,
    CaptureAuthority,
    CaptureCommitIndex,
    CaptureTimestamp,
    CaptureGuarantee,
    CaptureQuota,
    CaptureMissingQuota,
    CaptureCost,
    ReadMissing,
    ReadError,
    ReadPanic,
    ReadChanged,
}

impl NativeDispatchCaptureResponseTestFault {
    pub const ALL: [Self; 18] = [
        Self::CaptureError,
        Self::CapturePanic,
        Self::CaptureOperation,
        Self::CaptureReplay,
        Self::CaptureHold,
        Self::CaptureBinding,
        Self::CaptureEvent,
        Self::CaptureAuthority,
        Self::CaptureCommitIndex,
        Self::CaptureTimestamp,
        Self::CaptureGuarantee,
        Self::CaptureQuota,
        Self::CaptureMissingQuota,
        Self::CaptureCost,
        Self::ReadMissing,
        Self::ReadError,
        Self::ReadPanic,
        Self::ReadChanged,
    ];

    pub fn is_readback(self) -> bool {
        matches!(
            self,
            Self::ReadMissing | Self::ReadError | Self::ReadPanic | Self::ReadChanged
        )
    }
}

impl SqliteAdmissionOperationStore {
    /// Only the native capture reply is affected. No main table, persisted
    /// event, policy, owner fence or anchor is changed by this control.
    pub fn inject_native_capture_response_failure_for_test(
        &self,
        fault: NativeDispatchCaptureResponseTestFault,
    ) -> Result<(), AdmissionOperationStoreError> {
        let connection = self.connection()?;
        connection.execute_batch(
            "CREATE TEMP TABLE native_capture_response_test_fault (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), fault INTEGER NOT NULL)",
        ).map_err(sqlite_error)?;
        connection.execute(
            "INSERT INTO temp.native_capture_response_test_fault(singleton, fault) VALUES (1, ?1)",
            [fault as i64],
        ).map_err(sqlite_error)?;
        Ok(())
    }

    pub fn clear_native_capture_response_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TABLE temp.native_capture_response_test_fault")
            .map_err(sqlite_error)
    }

    fn native_capture_response_fault_for_test(
        &self,
    ) -> Result<Option<NativeDispatchCaptureResponseTestFault>, AdmissionOperationStoreError> {
        let connection = self.connection()?;
        let installed: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_capture_response_test_fault')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !installed {
            return Ok(None);
        }
        let code: i64 = connection
            .query_row(
                "SELECT fault FROM temp.native_capture_response_test_fault WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        NativeDispatchCaptureResponseTestFault::ALL
            .into_iter()
            .find(|fault| *fault as i64 == code)
            .map(Some)
            .ok_or_else(|| invariant("unknown native capture response test fault"))
    }

    /// Invoked only after the real transaction and anchor synchronization have
    /// succeeded. Panics occur after releasing the connection mutex.
    pub(super) fn native_capture_response_for_test(
        &self,
        original: &AdmissionOperationV1,
        mut capture: AdmissionBudgetCapture,
    ) -> Result<AdmissionBudgetCapture, AdmissionCaptureError> {
        use NativeDispatchCaptureResponseTestFault as Fault;
        let fault = self
            .native_capture_response_fault_for_test()
            .map_err(|error| AdmissionCaptureError::Unavailable(error.to_string()))?;
        match fault {
            None => return Ok(capture),
            Some(Fault::CaptureError) => {
                return Err(AdmissionCaptureError::OutcomeUnknown(
                    "injected native capture acknowledgement loss after commit".into(),
                ))
            }
            Some(Fault::CapturePanic) => panic!("injected native capture panic after commit"),
            Some(Fault::CaptureOperation) => {
                capture.operation = original.clone();
                return Ok(capture);
            }
            Some(Fault::CaptureReplay) => {
                capture.decision = match capture.decision {
                    BudgetInvocationCaptureDecision::Captured(mutation)
                    | BudgetInvocationCaptureDecision::AlreadyCaptured(mutation) => {
                        BudgetInvocationCaptureDecision::AlreadyCaptured(mutation)
                    }
                };
                return Ok(capture);
            }
            Some(fault) if fault.is_readback() => return Ok(capture),
            _ => {}
        }
        let BudgetInvocationCaptureDecision::Captured(mutation) = &mut capture.decision else {
            return Err(AdmissionCaptureError::Unavailable(
                "expected a real fresh native capture".into(),
            ));
        };
        match fault {
            Some(Fault::CaptureHold) => mutation.hold_id = Some("wrong-native-hold".into()),
            Some(Fault::CaptureBinding) => {
                let binding = mutation.admission_binding.as_mut().ok_or_else(|| {
                    AdmissionCaptureError::Unavailable(
                        "test requires a real admission binding".into(),
                    )
                })?;
                binding.operation_id = "0".repeat(64);
            }
            Some(Fault::CaptureEvent) => {
                mutation.metadata.event_id = Some("wrong-native-event".into())
            }
            Some(Fault::CaptureAuthority) => mutation.metadata.authority = None,
            Some(Fault::CaptureCommitIndex) => {
                mutation.metadata.budget_commit_index = mutation
                    .metadata
                    .budget_commit_index
                    .and_then(|index| index.checked_add(1))
            }
            Some(Fault::CaptureTimestamp) => {
                mutation.metadata.recorded_at_unix_seconds = mutation
                    .metadata
                    .recorded_at_unix_seconds
                    .and_then(|time| time.checked_add(1))
            }
            Some(Fault::CaptureGuarantee) => {
                mutation.metadata.guarantee_level = BudgetGuaranteeLevel::AdvisoryPosthoc
            }
            Some(Fault::CaptureQuota) => {
                let quota = mutation
                    .invocation_quota_usages
                    .first_mut()
                    .ok_or_else(|| {
                        AdmissionCaptureError::Unavailable("test requires a real quota".into())
                    })?;
                quota.quota.max_invocations =
                    quota.quota.max_invocations.checked_add(1).ok_or_else(|| {
                        AdmissionCaptureError::Unavailable("test quota overflow".into())
                    })?;
            }
            Some(Fault::CaptureMissingQuota) => mutation.invocation_quota_usages.clear(),
            Some(Fault::CaptureCost) => {
                mutation.exposure_units =
                    mutation.exposure_units.checked_add(1).ok_or_else(|| {
                        AdmissionCaptureError::Unavailable("test exposure overflow".into())
                    })?
            }
            _ => {
                return Err(AdmissionCaptureError::Unavailable(
                    "unhandled native capture response test fault".into(),
                ))
            }
        }
        Ok(capture)
    }

    /// Called after the read transaction and connection mutex have been dropped.
    pub(super) fn native_capture_readback_for_test(
        &self,
        mut capture: chio_kernel::AdmissionBudgetCapture,
    ) -> Result<Option<chio_kernel::AdmissionBudgetCapture>, AdmissionOperationStoreError> {
        use NativeDispatchCaptureResponseTestFault as Fault;
        match self.native_capture_response_fault_for_test()? {
            Some(Fault::ReadMissing) => return Ok(None),
            Some(Fault::ReadError) => {
                return Err(AdmissionOperationStoreError::Unavailable(
                    "injected native capture readback error after commit".into(),
                ))
            }
            Some(Fault::ReadPanic) => panic!("injected native capture readback panic after commit"),
            Some(Fault::ReadChanged) => {
                let BudgetInvocationCaptureDecision::Captured(mutation) = &mut capture.decision
                else {
                    return Err(invariant("test readback requires a real capture"));
                };
                mutation.exposure_units = mutation
                    .exposure_units
                    .checked_add(1)
                    .ok_or_else(|| invariant("test readback exposure overflow"))?;
            }
            _ => {}
        }
        Ok(Some(capture))
    }
}
