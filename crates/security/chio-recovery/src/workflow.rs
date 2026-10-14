use crate::WorkflowDirective;
use chio_security_types::recovery::{
    EffectObservationV1, RecoveryObservationV1, WorkflowControlV1,
};

/// Pure recommendation from a bounded claim. The driver must authenticate and
/// re-read the native basis before acting, including on a closure recommendation.
/// Cancellation never makes an unresolved operation eligible for replacement.
pub fn advise_workflow(observation: &RecoveryObservationV1) -> WorkflowDirective {
    if observation.control() == WorkflowControlV1::Quarantined {
        return WorkflowDirective::Halt;
    }
    let active = observation.control() == WorkflowControlV1::Active;
    match observation.effect() {
        EffectObservationV1::NeverAdmitted if active => {
            WorkflowDirective::Materialize(observation.step_id().clone())
        }
        EffectObservationV1::NeverAdmitted => WorkflowDirective::Halt,
        EffectObservationV1::AdmissionUnresolved { admission_intent } => {
            WorkflowDirective::ResolveAdmission(admission_intent.clone())
        }
        EffectObservationV1::ClosedBeforeEffect { closure, .. } => {
            WorkflowDirective::PreserveClosure(closure.clone())
        }
        EffectObservationV1::AwaitingApproval { operation } if active => {
            WorkflowDirective::ResumeNativeApproval(operation.clone())
        }
        EffectObservationV1::AwaitingApproval { operation } => {
            WorkflowDirective::Reconcile(operation.clone())
        }
        EffectObservationV1::InFlight { operation }
        | EffectObservationV1::AwaitingCallerReport { operation } => {
            WorkflowDirective::AwaitOutcome(operation.clone())
        }
        EffectObservationV1::Unknown { operation } => {
            WorkflowDirective::Reconcile(operation.clone())
        }
        EffectObservationV1::Complete { operation, .. }
        | EffectObservationV1::Partial { operation, .. }
        | EffectObservationV1::FailedAfterEffect { operation, .. } => {
            WorkflowDirective::ProjectOutcome(operation.clone())
        }
    }
}
