//! The broker observes custody owned by the original native kernel lifecycle.
use super::connection::trusted_now_ms;
use super::{canonical, rejected, unavailable, BrokerNativeCaptureReader};
use crate::authority_ipc::{AuthorityControlRequest, BrokerAdmissionAuthority};
use crate::budget::{
    AuthorizeExecutionHoldRequest, BrokerExecutionBudget, CaptureExecutionHoldRequest,
    ExecutionAuthorityCapabilities, ExecutionAuthorityProfile, ExecutionHoldState,
    QueryExecutionHoldRequest, ReverseExecutionHoldRequest,
};
use crate::kernel_admission::BrokerAdmissionParticipant;
use crate::protocol::BrokerExecuteRequest;
use crate::service::TrustedExecutionContext;
use crate::store::AttemptRegistration;
use crate::{BrokerError, Result};
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationId, AdmissionOperationState, AdmissionOperationStore,
};
use chio_kernel::budget_store::BudgetInvocationState;
use chio_store_sqlite::admission_operation_store::AdmissionBudgetCustodySnapshot;
use std::sync::Arc;

/// Read-only broker admission and budget port over the selected native authority.
/// Authorization, reversal and capture requests confirm the original kernel
/// decision; they never create a hold, debit quota, refund or authorize dispatch.
/// Issuance and revocation control are not enabled by installing this port.
pub struct BrokerKernelAdmissionAuthority {
    reader: BrokerNativeCaptureReader,
    participant: Arc<BrokerAdmissionParticipant>,
}

struct OriginalCustody {
    registration: AttemptRegistration,
    execute: BrokerExecuteRequest,
    custody: AdmissionBudgetCustodySnapshot,
}

impl BrokerKernelAdmissionAuthority {
    pub fn new(
        reader: BrokerNativeCaptureReader,
        participant: Arc<BrokerAdmissionParticipant>,
    ) -> Result<Self> {
        if participant.binding() != &reader.participant {
            return Err(rejected());
        }
        Ok(Self {
            reader,
            participant,
        })
    }

    fn original(&self, operation_id: &str, now: u64) -> Result<Option<OriginalCustody>> {
        let operation_id =
            AdmissionOperationId::from_persisted(operation_id).map_err(|_| rejected())?;
        let Some((registration, execute)) =
            self.reader
                .read_registration(self.participant.as_ref(), &operation_id, now)?
        else {
            return Ok(None);
        };
        let custody = self
            .reader
            .store
            .load_admission_budget_custody(&operation_id, &self.reader.fence, now)
            .map_err(unavailable)?
            .ok_or_else(rejected)?;
        Ok(Some(OriginalCustody {
            registration,
            execute,
            custody,
        }))
    }

    fn capture_request(original: &OriginalCustody) -> Result<CaptureExecutionHoldRequest> {
        let registration = &original.registration;
        let revocation_ids = original.custody.admission.revocation_set.ids().to_vec();
        Ok(CaptureExecutionHoldRequest {
            operation_id: registration.ids.operation_id.clone(),
            invocation_id: registration.invocation_id.clone(),
            parent_capability_id: registration.parent_capability_id.clone(),
            broker_capability_id: registration.broker_capability_id.clone(),
            hold_id: registration.ids.hold_id.clone(),
            capture_event_id: registration.ids.capture_event_id.clone(),
            revocation_set_digest: crate::revocation::digest_canonical_revocation_ids(
                &revocation_ids,
            )?,
            revocation_ids,
            authorization_artifact_digest: crate::capability::capability_digest(
                &original.execute.capability,
            )?,
            authority_metadata_digest: registration.authority_metadata_digest.clone(),
        })
    }

    fn state(&self, original: &OriginalCustody, now: u64) -> Result<ExecutionHoldState> {
        match original.custody.invocation_state {
            BudgetInvocationState::Authorized => Ok(ExecutionHoldState::Held),
            BudgetInvocationState::Reversed => Ok(ExecutionHoldState::Reversed),
            BudgetInvocationState::Denied => Ok(ExecutionHoldState::Denied),
            BudgetInvocationState::Absent => Err(rejected()),
            BudgetInvocationState::Captured => self
                .reader
                .read_capture(&Self::capture_request(original)?, now)?
                .map(ExecutionHoldState::Captured)
                .ok_or_else(rejected),
        }
    }

    fn require_ids(
        original: &OriginalCustody,
        invocation: &str,
        parent: &str,
        broker: &str,
        hold: &str,
    ) -> Result<()> {
        let registration = &original.registration;
        if invocation != registration.invocation_id
            || parent != registration.parent_capability_id
            || broker != registration.broker_capability_id
            || hold != registration.ids.hold_id
        {
            return Err(rejected());
        }
        Ok(())
    }
}

impl BrokerAdmissionAuthority for BrokerKernelAdmissionAuthority {
    fn prepare_execution(&self, request: &BrokerExecuteRequest) -> Result<TrustedExecutionContext> {
        request.validate_bounds()?;
        let now = trusted_now_ms()?;
        let (operation, _) = self
            .reader
            .store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &request.invocation_id)
                    .map_err(|_| rejected())?,
                &self.reader.fence,
                now,
            )
            .map_err(unavailable)?
            .ok_or_else(rejected)?;
        let operation_id = operation.binding().operation_id();
        if operation.state() != AdmissionOperationState::DispatchCommitted {
            return Err(rejected());
        }
        let original = self
            .original(operation_id.as_str(), now)?
            .ok_or_else(rejected)?;
        if canonical(&original.execute)? != canonical(request)?
            || !matches!(self.state(&original, now)?, ExecutionHoldState::Captured(_))
        {
            return Err(rejected());
        }
        let retained = self
            .reader
            .read_original(operation_id, now)?
            .ok_or_else(rejected)?;
        let kernel_request = retained.retained.request_for_revalidation();
        if retained.operation.state() != AdmissionOperationState::DispatchCommitted
            || kernel_request.server_id != self.participant.server_id
            || kernel_request.tool_name != self.participant.tool_name
        {
            return Err(rejected());
        }
        let registration = original.registration;
        let context = TrustedExecutionContext {
            prepared_dispatch_id: crate::registration::prepared_dispatch_id(
                &registration,
                request,
            )?,
            admission_operation_id: registration.ids.operation_id,
            quotas: registration.quotas,
            authority_metadata_digest: registration.authority_metadata_digest,
            revocation_authority_domain: registration.revocation_authority_domain,
            // The retained tool request supplies no source receipt identities.
            // Do not manufacture lineage from a capability or an operation ID.
            source_receipt_ids: Vec::new(),
        };
        context.validate_for(request)?;
        Ok(context)
    }

    fn control(&self, _: AuthorityControlRequest) -> Result<Vec<u8>> {
        Err(BrokerError::AuthorizationDenied(
            "kernel custody observation does not grant broker administrative authority".into(),
        ))
    }
}

impl BrokerExecutionBudget for BrokerKernelAdmissionAuthority {
    fn capabilities(&self) -> ExecutionAuthorityCapabilities {
        ExecutionAuthorityCapabilities {
            profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
            atomic_multi_key_holds: true,
            combined_capture_and_revocation: true,
            query_by_id: true,
            shared_revocation_write_domain: true,
        }
    }

    fn query_execution_hold(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let now = trusted_now_ms()?;
        let Some(original) = self.original(&request.operation_id, now)? else {
            return Ok(ExecutionHoldState::Unknown);
        };
        Self::require_ids(
            &original,
            &request.invocation_id,
            &request.parent_capability_id,
            &request.broker_capability_id,
            &request.hold_id,
        )?;
        let ids = &original.registration.ids;
        if request.authorize_event_id != ids.authorize_event_id
            || request.reverse_event_id != ids.reverse_event_id
            || request.capture_event_id != ids.capture_event_id
        {
            return Err(rejected());
        }
        self.state(&original, now)
    }

    fn authorize_execution_hold(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let now = trusted_now_ms()?;
        let Some(original) = self.original(&request.operation_id, now)? else {
            return Ok(ExecutionHoldState::Unknown);
        };
        Self::require_ids(
            &original,
            &request.invocation_id,
            &request.parent_capability_id,
            &request.broker_capability_id,
            &request.hold_id,
        )?;
        let registration = &original.registration;
        if request.authorize_event_id != registration.ids.authorize_event_id
            || request.quotas != registration.quotas
            || request.authority_metadata_digest != registration.authority_metadata_digest
        {
            return Err(rejected());
        }
        self.state(&original, now)
    }

    fn reverse_execution_hold(
        &self,
        request: &ReverseExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let now = trusted_now_ms()?;
        let original = self
            .original(&request.operation_id, now)?
            .ok_or_else(rejected)?;
        Self::require_ids(
            &original,
            &request.invocation_id,
            &request.parent_capability_id,
            &request.broker_capability_id,
            &request.hold_id,
        )?;
        if request.reverse_event_id != original.registration.ids.reverse_event_id
            || original.custody.invocation_state != BudgetInvocationState::Reversed
        {
            return Err(rejected());
        }
        Ok(ExecutionHoldState::Reversed)
    }

    fn capture_execution_hold(
        &self,
        request: &CaptureExecutionHoldRequest,
    ) -> Result<ExecutionHoldState> {
        request.validate()?;
        let now = trusted_now_ms()?;
        let Some(original) = self.original(&request.operation_id, now)? else {
            return Ok(ExecutionHoldState::Unknown);
        };
        if &Self::capture_request(&original)? != request {
            return Err(rejected());
        }
        self.state(&original, now)
    }
}
