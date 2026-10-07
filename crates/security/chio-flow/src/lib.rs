#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(test)]
extern crate std;

#[cfg(any(feature = "std", test))]
mod classification;
mod declassification;
mod engine;
mod lattice;
mod recovery_authority;
pub use recovery_authority::{
    required_recovery_disclosure_obligations, verify_historical_recovery_coverage_digest,
    verify_recovery_coverage, RecoveryAuthorityAssignment, VerifiedRecoveryCoverage,
};

#[cfg(any(feature = "std", test))]
pub use classification::{CategoryLabelMap, ClassificationMappingError, VerifiedClassification};
pub use declassification::{
    canonical_request_hash, information_label_hash, verify_declassification,
    verify_recovery_declassification, DeclassificationError, DeclassificationVerificationRequest,
    VerifiedDeclassification,
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
