#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
//! Fenced observation of an admission's original composite hold.
use super::*;
use chio_kernel::admission_operation::RetainedToolAdmissionRequestV1;
use chio_kernel::budget_store::{
    BudgetAdmissionBinding, BudgetInvocationQuota, BudgetInvocationState, BudgetMonetaryState,
};

/// Physical custody at one anchored read. This observation grants no authority
/// to authorize, capture, reverse or refund the original hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionBudgetCustodySnapshot {
    pub hold_id: String,
    pub capability_id: String,
    pub grant_index: usize,
    pub admission: BudgetAdmissionBinding,
    pub invocation_quotas: Vec<BudgetInvocationQuota>,
    pub invocation_state: BudgetInvocationState,
    pub monetary_state: BudgetMonetaryState,
}

/// The immutable original request and its physical hold share one authenticated
/// snapshot. Reading this view neither reserves custody nor permits dispatch.
#[derive(Clone, Debug)]
pub struct RetainedToolAdmissionCustodySnapshot {
    pub operation: AdmissionOperationV1,
    pub request: RetainedToolAdmissionRequestV1,
    pub custody: Option<AdmissionBudgetCustodySnapshot>,
}

impl SqliteAdmissionOperationStore {
    /// Locate exact retained supplemental material and authenticate its
    /// original operation, request and hold together. The digest selects
    /// custody; it grants no permission and never chooses a submitted ID.
    pub fn load_retained_tool_admission_custody_by_supplemental_artifact(
        &self,
        artifact_digest: &str,
        expected_native: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
        expected_participant: &chio_kernel::supplemental_admission::SupplementalAdmissionAuthorityBindingV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<RetainedToolAdmissionCustodySnapshot>, AdmissionOperationStoreError> {
        if artifact_digest.len() != 64
            || !artifact_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invariant(
                "supplemental artifact selector digest is invalid",
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
        crate::budget_store::SqliteBudgetStore::verify_supplemental_artifact_selector_index(
            &transaction,
        )
        .map_err(|error| invariant(error.to_string()))?;
        let identifiers = {
            let mut statement = transaction
                .prepare(
                    "SELECT CASE WHEN typeof(operation_id) = 'text'
                         AND length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 512
                         THEN operation_id END
                     FROM budget_authorization_holds
                     INDEXED BY idx_budget_holds_supplemental_artifact
                     WHERE supplemental_artifact_digest = ?1 AND operation_id IS NOT NULL
                     ORDER BY operation_id LIMIT 2",
                )
                .map_err(sqlite_error)?;
            let identifiers = statement
                .query_map([artifact_digest], |row| row.get::<_, Option<String>>(0))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            identifiers
        };
        let operation_id = match identifiers.as_slice() {
            [] => return Ok(None),
            [Some(identifier)] => AdmissionOperationId::from_persisted(identifier.clone())?,
            [None] => {
                return Err(invariant(
                    "supplemental selector operation ID exceeds bounds",
                ))
            }
            _ => {
                return Err(invariant(
                    "supplemental authorization artifact has multiple original operations",
                ))
            }
        };
        let stored = load_by_operation_id_tx(&transaction, &operation_id)?
            .ok_or_else(|| invariant("supplemental original operation disappeared"))?;
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let request = retained_request::load_retained_request_tx(&transaction, &stored.operation)?
            .ok_or_else(|| invariant("supplemental original request disappeared"))?;
        let custody = crate::budget_store::SqliteBudgetStore::load_admission_budget_custody_tx(
            &transaction,
            &stored.operation,
        )
        .map_err(|error| invariant(error.to_string()))?
        .ok_or_else(|| invariant("supplemental original hold disappeared"))?;
        if custody.admission.operation_id != operation_id.as_str()
            || custody
                .admission
                .supplemental_authorization_artifact_digest
                .as_deref()
                != Some(artifact_digest)
            || !custody
                .admission
                .authorization_artifact_digests
                .iter()
                .any(|digest| digest == artifact_digest)
        {
            return Err(invariant(
                "supplemental selector differs from original custody",
            ));
        }
        if request.native_security_authority_binding() != Some(expected_native)
            || request.authority_profile().supplemental_participant() != Some(expected_participant)
        {
            return Ok(None);
        }
        request.validate_native_security_authority(expected_native)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(Some(RetainedToolAdmissionCustodySnapshot {
            operation: stored.operation,
            request,
            custody: Some(custody),
        }))
    }

    pub fn load_retained_tool_admission_custody(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<RetainedToolAdmissionCustodySnapshot>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
        let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let Some(request) =
            retained_request::load_retained_request_tx(&transaction, &stored.operation)?
        else {
            return Ok(None);
        };
        let custody = crate::budget_store::SqliteBudgetStore::load_admission_budget_custody_tx(
            &transaction,
            &stored.operation,
        )
        .map_err(|error| invariant(error.to_string()))?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(Some(RetainedToolAdmissionCustodySnapshot {
            operation: stored.operation,
            request,
            custody,
        }))
    }

    pub fn load_admission_budget_custody(
        &self,
        operation_id: &AdmissionOperationId,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionBudgetCustodySnapshot>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(active_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms, &self.serving_owner)?;
        let Some(stored) = load_by_operation_id_tx(&transaction, operation_id)? else {
            return Ok(None);
        };
        stored.verify_decision_time(trusted_now_unix_ms)?;
        let snapshot = crate::budget_store::SqliteBudgetStore::load_admission_budget_custody_tx(
            &transaction,
            &stored.operation,
        )
        .map_err(|error| invariant(error.to_string()))?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(snapshot)
    }
}
