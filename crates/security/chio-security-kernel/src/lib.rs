#![forbid(unsafe_code)]

mod capability_set_suspension;
mod containment;
mod egress_restriction;
mod issuance_freeze;
mod post_invocation;
mod pre_dispatch;
mod pre_invocation;
mod session_throttle;
mod tripwire;

pub use capability_set_suspension::CapabilitySetSuspensionGuard;
pub use containment::{containment_target, ContainmentGuard, ContainmentTargetKind};
pub use egress_restriction::EgressRestrictionGuard;
pub use issuance_freeze::IssuanceFreezeAdmission;
pub use post_invocation::{
    EngineFlowPostInvocationPort, FlowPostInvocationHook, FlowPostInvocationInput,
    FlowPostInvocationPort, FlowPostInvocationResolver, RawOutputTripwireHook,
};
pub use pre_dispatch::{
    FlowDispatchOutcomeRecorder, FlowPreDispatchHook, FlowPreDispatchInput, FlowPreDispatchPort,
};
pub use pre_invocation::{
    EngineFlowPreInvocationPort, FlowPreInvocationGuard, FlowPreInvocationInput,
    FlowPreInvocationPort, FlowPreInvocationResolver,
};
pub use session_throttle::SessionThrottleGuard;
pub use tripwire::{
    DecoyTripwireDetectorPort, SecurityClock, SecurityEventIngress, SystemSecurityClock,
    TripwireEventPublisher, TripwireGuard,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissingContextPolicy {
    Allow,
    Deny,
}

impl MissingContextPolicy {
    #[must_use]
    pub const fn denies(self) -> bool {
        matches!(self, Self::Deny)
    }
}
