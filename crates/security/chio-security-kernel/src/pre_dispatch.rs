use std::sync::Arc;

use chio_flow::DeclassificationDispatchOutcome;
use chio_flow::FlowDenial;
use chio_kernel::{
    KernelError, SecurityDispatchOutcome, SecurityDispatchOutcomeHandle,
    SecurityDispatchOutcomeRecorder, SecurityInvocationContextV1, SecurityPreDispatchContext,
    SecurityPreDispatchHook, SecurityRequestLifecyclePermit,
};
use chio_security_types::ports::RecordId;

/// Authoritative input required to atomically commit the final flow fence.
pub struct FlowPreDispatchInput<'a> {
    pub security_context: &'a SecurityInvocationContextV1,
    pub request: &'a chio_kernel::ToolCallRequest,
    pub canonical_request: &'a [u8],
    pub dispatch_commitment_id: &'a RecordId,
}

/// Port implemented by the authority that owns flow state and egress fences.
pub trait FlowPreDispatchPort: Send + Sync {
    fn acquire_request_lifecycle(
        &self,
        _input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, FlowDenial> {
        Ok(None)
    }

    fn commit(
        &self,
        input: &FlowPreDispatchInput<'_>,
    ) -> Result<Option<Box<dyn FlowDispatchOutcomeRecorder>>, FlowDenial>;
}

/// One-shot flow authority retained across connector execution after a
/// declassification was consumed.
pub trait FlowDispatchOutcomeRecorder: Send {
    fn record(&mut self, outcome: DeclassificationDispatchOutcome) -> Result<(), FlowDenial>;
}

/// Kernel hook adapter for the authoritative final flow-fence commit.
pub struct FlowPreDispatchHook {
    flow: Arc<dyn FlowPreDispatchPort>,
}

impl FlowPreDispatchHook {
    #[must_use]
    pub fn new(flow: Arc<dyn FlowPreDispatchPort>) -> Self {
        Self { flow }
    }
}

impl SecurityPreDispatchHook for FlowPreDispatchHook {
    fn name(&self) -> &str {
        "chio-flow-pre-dispatch"
    }

    fn acquire_request_lifecycle(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        self.flow
            .acquire_request_lifecycle(&FlowPreDispatchInput {
                security_context: context.security_context.as_v1(),
                request: context.request,
                canonical_request: context.canonical_request,
                dispatch_commitment_id: context.dispatch_commitment_id,
            })
            .map_err(|_| {
                KernelError::GuardDenied(
                    "authoritative request lifecycle rejected dispatch".to_string(),
                )
            })
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        let outcome = self
            .flow
            .commit(&FlowPreDispatchInput {
                security_context: context.security_context.as_v1(),
                request: context.request,
                canonical_request: context.canonical_request,
                dispatch_commitment_id: context.dispatch_commitment_id,
            })
            .map_err(|_| {
                KernelError::GuardDenied("authoritative flow dispatch fence rejected".to_string())
            })?;
        Ok(outcome.map(|recorder| {
            SecurityDispatchOutcomeHandle::new(
                context,
                Box::new(KernelFlowDispatchOutcomeRecorder { recorder }),
            )
        }))
    }
}

struct KernelFlowDispatchOutcomeRecorder {
    recorder: Box<dyn FlowDispatchOutcomeRecorder>,
}

impl SecurityDispatchOutcomeRecorder for KernelFlowDispatchOutcomeRecorder {
    fn record(&mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        let outcome = match outcome {
            SecurityDispatchOutcome::Released => DeclassificationDispatchOutcome::Released,
            SecurityDispatchOutcome::DispatchFailed => {
                DeclassificationDispatchOutcome::DispatchFailed
            }
            SecurityDispatchOutcome::OutcomeUnknownAfterDispatch => {
                DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch
            }
        };
        self.recorder.record(outcome).map_err(|_| {
            KernelError::SecurityDispatchOutcomeRecoveryRequired(
                "authoritative declassification dispatch outcome was not durably persisted"
                    .to_string(),
            )
        })
    }
}
