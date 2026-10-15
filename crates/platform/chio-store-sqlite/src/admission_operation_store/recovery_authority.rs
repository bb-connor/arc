//! Authenticated reads of the installed recovery deployment for the kernel.

use super::*;
use chio_kernel::recovery::{RecoveryDeploymentPort, RecoveryDeploymentV1};
use chio_security_types::recovery::RecoveryScopeV1;

use super::recovery_deployment::{current_key, validate_deployment};
use super::recovery_records::{load_record, protected_scope_key, require_latest_projection_head};
use super::security_participant_state::verify_recovery_binding;

impl RecoveryDeploymentPort for SqliteAdmissionOperationStore {
    /// One read transaction under the live serving owner and anchor, the
    /// caller's exact fence and authority time. The current projection is
    /// authenticated against its latest local event and its latest global
    /// head; the profile is then checked against this authority and its
    /// retained native initialization.
    fn deployment(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now, &self.serving_owner)?;
        let record = load_record(&tx, &current_key(&protected_scope_key(scope)?))?
            .ok_or_else(|| invariant("recovery profile is unsupported"))?;
        require_latest_projection_head(&tx, &record)?;
        let deployment: RecoveryDeploymentV1 = record.decode_payload()?;
        if deployment.scope != *scope {
            return Err(invariant("recovery scope changed"));
        }
        validate_deployment(&deployment, fence)?;
        verify_recovery_binding(&tx, &deployment.native_authority)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(deployment)
    }
}
