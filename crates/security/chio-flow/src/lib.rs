#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(any(feature = "std", test))]
mod classification;
mod declassification;
mod engine;
mod lattice;

#[cfg(any(feature = "std", test))]
pub use classification::{CategoryLabelMap, ClassificationMappingError, VerifiedClassification};
pub use declassification::{
    canonical_request_hash, information_label_hash, verify_declassification, DeclassificationError,
    DeclassificationVerificationRequest, VerifiedDeclassification,
};
#[cfg(any(feature = "std", test))]
pub use declassification::{ConsumedDeclassification, DeclassificationDispatchOutcome};
#[cfg(any(feature = "std", test))]
pub use engine::evaluate_pre_invocation_with_declassification;
#[cfg(any(feature = "std", test))]
pub use engine::{evaluate_post_invocation, PostInvocationFlow};
pub use engine::{
    evaluate_pre_invocation, prepare_egress_fence, prepare_pre_invocation, EgressFencePlan,
    FlowAdmission, FlowDenial, PreparedFlowAdmission, ResolvedFlowRequest,
};
pub use lattice::{authorize_egress, EgressDenial, InformationFlowLattice, LatticeError};
