//! Research prototype. An offer is advice, and a prepared flow is not a dispatch permit.
#![forbid(unsafe_code)]

pub mod fixture;
mod offer;
mod request;
mod types;

pub use offer::{plan, prepare_approved_offer};
pub use request::resolved_request;
pub use types::{
    DisclosureIntent, DisclosureOffer, HostSnapshot, OperationState, PlanningDecision,
    RecoveryError,
};
