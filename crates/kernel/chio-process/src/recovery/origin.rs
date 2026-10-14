//! Exact original custody read independently of the process writer handle.
use crate::binding::complete_binding;
use crate::{digest, ProcessError, ProcessRuntime};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::recovery::{
    RecoveryOriginalRequestError, RecoveryOriginalRequestScope, RecoveryProcessOriginPort,
};
use chio_kernel::ToolCallRequest;
use chio_security_types::recovery::RecoveryScopeV1;

impl ProcessRuntime {
    fn verify_original_snapshot(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<(), RecoveryOriginalRequestError> {
        let check = || -> Result<(), ProcessError> {
            if self.store.is_poisoned() {
                return Err(ProcessError::StorePoisoned);
            }
            if expected_session != self.namespace
                || self
                    .security_profile
                    .as_ref()
                    .is_some_and(|profile| profile.tenant_id != scope.tenant_id.as_str())
            {
                return Err(ProcessError::Conflict);
            }
            let exact = digest(request)?;
            let bindings = [
                complete_binding(
                    &exact,
                    false,
                    self.routes.get(&request.server_id),
                    self.security_profile.as_ref(),
                )?,
                complete_binding(
                    &exact,
                    true,
                    self.routes.get(&request.server_id),
                    self.security_profile.as_ref(),
                )?,
            ];
            let key = self.original_snapshot.original_call_key(
                scope.process_id.as_str(),
                request,
                &bindings,
            )?;
            if request.request_id != self.request_id(scope.process_id.as_str(), &key)? {
                return Err(ProcessError::Conflict);
            }
            if self.store.is_poisoned() {
                return Err(ProcessError::StorePoisoned);
            }
            Ok(())
        };
        check().map_err(|error| match error {
            ProcessError::Conflict | ProcessError::NotFound(_) => {
                RecoveryOriginalRequestError::Refused
            }
            ProcessError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                RecoveryOriginalRequestError::Busy
            }
            ProcessError::Io(_) | ProcessError::Sqlite(_) => {
                RecoveryOriginalRequestError::Store(AdmissionOperationStoreError::Unavailable(
                    "original process journal is unavailable".into(),
                ))
            }
            _ => RecoveryOriginalRequestError::Store(AdmissionOperationStoreError::Invariant(
                "original process journal custody is invalid".into(),
            )),
        })
    }
}
impl RecoveryProcessOriginPort for ProcessRuntime {
    fn verify_original_request(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_original_snapshot(scope, request, expected_session)
            .map_err(|error| match error {
                RecoveryOriginalRequestError::Refused => AdmissionOperationStoreError::Invariant(
                    "recovery original process request refused".into(),
                ),
                RecoveryOriginalRequestError::Busy => AdmissionOperationStoreError::Unavailable(
                    "recovery process journal is busy".into(),
                ),
                RecoveryOriginalRequestError::Store(error) => error,
            })
    }
    fn original_request_scope(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError> {
        self.verify_original_snapshot(scope, request, expected_session)?;
        self.kernel
            .recovery_process_original_request_scope(scope, request)
    }
}
