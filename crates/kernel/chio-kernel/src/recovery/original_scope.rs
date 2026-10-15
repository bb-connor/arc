//! Original content identity in the trusted process host's native namespace.
use crate::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, AuthenticatedRequestNamespace,
    DurableAdmissionMode, RequestNamespaceDigest,
};
use crate::{ChioKernel, ToolCallRequest};
use chio_security_types::recovery::RecoveryScopeV1;

/// Exact content and namespace only. This cannot be decoded or used as a
/// dispatch permit. The trusted process port verifies the committed first
/// attempt before asking its installed Kernel to derive this scope.
///
/// ```
/// use chio_kernel::admission_operation::RequestNamespaceDigest;
/// use chio_kernel::recovery::RecoveryOriginalRequestScope;
/// fn namespace(scope: &RecoveryOriginalRequestScope) -> &RequestNamespaceDigest {
///     scope.namespace()
/// }
/// let _ = serde_json::Value::Null;
/// ```
///
/// Decoding cannot construct a scope. Expected diagnostic: E0277, the trait
/// bound `RecoveryOriginalRequestScope: Deserialize<'_>` is not satisfied.
/// ```compile_fail,E0277
/// use chio_kernel::recovery::RecoveryOriginalRequestScope;
/// fn decode(wire: &str) -> serde_json::Result<RecoveryOriginalRequestScope> {
///     serde_json::from_str(wire)
/// }
/// ```
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

    /// Compares the scope, request id and canonical seed hash. Consumers also
    /// compare `namespace()` with their own LOCAL_SYSTEM derivation.
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
        original_request_scope(
            self.durable_admission_store_uuid(),
            self.durable_admission_mode(),
            scope,
            seed,
        )
    }
}

/// Only an installed durable admission authority in `All` mode whose store
/// identity is the scope's authority domain derives a scope.
fn original_request_scope(
    store_uuid: Option<&str>,
    mode: DurableAdmissionMode,
    scope: &RecoveryScopeV1,
    seed: &ToolCallRequest,
) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError> {
    let authority = store_uuid.ok_or(RecoveryOriginalRequestError::Refused)?;
    if mode != DurableAdmissionMode::All || authority != scope.authority_domain.as_str() {
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

#[cfg(test)]
#[path = "original_scope_tests.rs"]
mod tests;
