//! Information-flow identity selected by the trusted process host.

use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use serde::{Deserialize, Serialize};

use crate::ProcessError;

/// Persistent isolation selection. Workers cannot select or replace it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSecurityProfile {
    pub tenant_id: String,
    pub isolation_epoch_id: String,
    pub generation: u64,
}

impl ProcessSecurityProfile {
    pub fn validate(&self) -> Result<(), ProcessError> {
        TenantId::new(&self.tenant_id).map_err(|_| invalid())?;
        IsolationEpochId::new(&self.isolation_epoch_id).map_err(|_| invalid())?;
        if self.generation == 0 {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn context(
        &self,
        runtime: &str,
        principal: String,
        lineage: &str,
    ) -> Result<SecurityInvocationContext, ProcessError> {
        self.validate()?;
        Ok(SecurityInvocationContext::v1(
            SecurityInvocationContextV1::new(
                TenantId::new(&self.tenant_id).map_err(|_| invalid())?,
                SessionId::new(runtime).map_err(|_| invalid())?,
                PrincipalId::new(principal).map_err(|_| invalid())?,
                IsolationEpochId::new(&self.isolation_epoch_id).map_err(|_| invalid())?,
                LineageId::new(lineage).map_err(|_| invalid())?,
                self.generation,
            ),
        ))
    }
}

fn invalid() -> ProcessError {
    ProcessError::Configuration("invalid host information-flow identity")
}
