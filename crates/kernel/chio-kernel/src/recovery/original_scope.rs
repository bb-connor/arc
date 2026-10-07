//! Original content identity in the trusted process host's native namespace.
use super::{RecoveryDeploymentV1, RecoveryProcessOriginPort};
use crate::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, AuthenticatedRequestNamespace,
    DurableAdmissionMode, RequestNamespaceDigest,
};
use crate::{ChioKernel, ToolCallRequest};
use chio_security_types::recovery::RecoveryScopeV1;

/// Exact content and namespace only. This cannot be decoded or used as a
/// dispatch permit. The trusted process port verifies the committed first
/// attempt before asking its installed Kernel to derive this scope.
#[derive(Clone)]
pub struct RecoveryOriginalRequestScope {
    scope: RecoveryScopeV1,
    namespace: RequestNamespaceDigest,
    request: AdmissionIdentifier,
    exact_seed: [u8; 32],
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum RecoveryOriginalRequestError {
    #[error("recovery original is not eligible")]
    Refused,
    #[error("recovery process journal is busy")]
    Busy,
    #[error(transparent)]
    Store(#[from] AdmissionOperationStoreError),
}

impl From<RecoveryOriginalRequestError> for super::RecoveryCommandPortError {
    fn from(error: RecoveryOriginalRequestError) -> Self {
        match error {
            RecoveryOriginalRequestError::Refused => Self::OriginRefused,
            RecoveryOriginalRequestError::Busy => Self::Busy,
            RecoveryOriginalRequestError::Store(error) => Self::Store(error),
        }
    }
}

impl RecoveryOriginalRequestScope {
    pub fn namespace(&self) -> &RequestNamespaceDigest {
        &self.namespace
    }

    pub fn request_id(&self) -> &AdmissionIdentifier {
        &self.request
    }

    pub fn matches(&self, scope: &RecoveryScopeV1, seed: &ToolCallRequest) -> bool {
        self.scope == *scope
            && self.request.as_str() == seed.request_id
            && exact_seed(seed).is_ok_and(|hash| hash == self.exact_seed)
    }
}

fn exact_seed(seed: &ToolCallRequest) -> Result<[u8; 32], RecoveryOriginalRequestError> {
    let bytes = chio_core_types::canonical_json_bytes(seed)
        .map_err(|_| RecoveryOriginalRequestError::Refused)?;
    Ok(*chio_core_types::sha256(&bytes).as_bytes())
}

impl ChioKernel {
    /// ProcessRuntime invokes without a Kernel session. Its namespace is the
    /// installed coordinator's LOCAL_SYSTEM namespace, independently of the
    /// caller's flow tenant or any caller-provided namespace selector.
    pub fn recovery_process_original_request_scope(
        &self,
        scope: &RecoveryScopeV1,
        seed: &ToolCallRequest,
    ) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError> {
        let authority = self
            .durable_admission_store_uuid()
            .ok_or(RecoveryOriginalRequestError::Refused)?;
        if self.durable_admission_mode() != DurableAdmissionMode::All
            || authority != scope.authority_domain.as_str()
        {
            return Err(RecoveryOriginalRequestError::Refused);
        }
        let coordinator = AdmissionIdentifier::try_new("coordinator_authority_id", authority)
            .map_err(AdmissionOperationStoreError::from)?;
        let namespace = AuthenticatedRequestNamespace::for_local_system(coordinator)
            .map_err(AdmissionOperationStoreError::from)?;
        let request = AdmissionIdentifier::try_new("request_id", &seed.request_id)
            .map_err(AdmissionOperationStoreError::from)?;
        Ok(RecoveryOriginalRequestScope {
            scope: scope.clone(),
            namespace: namespace.digest().clone(),
            request,
            exact_seed: exact_seed(seed)?,
        })
    }
}

/// Prepare outside the native writer. A retained command replay may ignore a
/// failed new proof; only a fresh creation consumes this exact cached result.
pub(crate) struct PreparedOriginalProcessOrigin {
    scope: RecoveryScopeV1,
    expected_session: Option<String>,
    result: Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError>,
}

impl PreparedOriginalProcessOrigin {
    pub(crate) fn new(
        process: &dyn RecoveryProcessOriginPort,
        scope: &RecoveryScopeV1,
        request_seed: &str,
        deployment: Result<RecoveryDeploymentV1, AdmissionOperationStoreError>,
    ) -> Self {
        let mut expected_session = None;
        let result = (|| {
            let seed: ToolCallRequest =
                chio_core_types::recovery::decode_contract(request_seed.as_bytes())
                    .map_err(|_| RecoveryOriginalRequestError::Refused)?;
            let deployment = deployment?;
            let session = deployment.security_context.as_v1().session_id().as_str();
            expected_session = Some(session.to_owned());
            process.original_request_scope(scope, &seed, session)
        })();
        Self {
            scope: scope.clone(),
            expected_session,
            result,
        }
    }
}

impl RecoveryProcessOriginPort for PreparedOriginalProcessOrigin {
    fn verify_original_request(
        &self,
        scope: &RecoveryScopeV1,
        request: &ToolCallRequest,
        expected_session: &str,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.original_request_scope(scope, request, expected_session)
            .map(|_| ())
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
        let result = self.result.as_ref().map_err(Clone::clone)?;
        if self.scope != *scope
            || self.expected_session.as_deref() != Some(expected_session)
            || !result.matches(scope, request)
        {
            return Err(RecoveryOriginalRequestError::Refused);
        }
        Ok(result.clone())
    }
}
