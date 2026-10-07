//! Cache the exact trusted process proof before the setup writer begins.
use super::*;

/// A setup-local adapter; it grants no new namespace or execution authority.
/// Only the trusted process port can produce the cached opaque proof.
pub(super) struct PreparedSetupOriginalProcess {
    scope: RecoveryScopeV1,
    expected_session: Option<String>,
    result: Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError>,
}

impl PreparedSetupOriginalProcess {
    pub(super) fn prepare(
        process: &dyn RecoveryProcessOriginPort,
        scope: &RecoveryScopeV1,
        seed: &ToolCallRequest,
        deployment: Result<RecoveryDeploymentV1, AdmissionOperationStoreError>,
    ) -> Self {
        let mut expected_session = None;
        let result = (|| {
            let deployment = deployment?;
            let session = deployment.security_context.as_v1().session_id().as_str();
            expected_session = Some(session.to_owned());
            process.original_request_scope(scope, seed, session)
        })();
        Self {
            scope: scope.clone(),
            expected_session,
            result,
        }
    }
}

impl RecoveryProcessOriginPort for PreparedSetupOriginalProcess {
    fn verify_original_request(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.original_request_scope(scope, request, expected_session)
            .map(|_| ())
            .map_err(|error| original_custody_error(error.into()))
    }

    fn original_request_scope(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError> {
        let proof = self.result.as_ref().map_err(Clone::clone)?;
        if self.scope != *scope
            || self.expected_session.as_deref() != Some(expected_session)
            || !proof.matches(scope, request)
        {
            return Err(RecoveryOriginalRequestError::Refused);
        }
        Ok(proof.clone())
    }
}
