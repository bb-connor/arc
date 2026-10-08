mod error;
pub use error::AdmissionOperationError;
#[path = "security_admission_operation/request_binding.rs"]
mod request_binding;
pub use request_binding::{AdmissionRequestBindingInput, AdmissionRequestBindingParts};

mod ids;
mod in_memory;
mod validation;
pub use ids::{derive_cleanup_action_id, derive_operation_id};
pub use in_memory::InMemoryAdmissionOperationStore;
use validation::{
    valid_state_transition, validate_cleanup_claim, validate_cleanup_payload, validate_digest,
    validate_identifier, validate_kind_participants, validate_last_error, validate_optional_digest,
    validate_optional_identifier, validate_state_dispatch_pair,
};

include!("admission_operation.part1.inc");

#[path = "security_admission_operation/recovery_pages.rs"]
mod recovery_pages;

#[cfg(test)]
#[path = "security_admission_operation/review_tests.rs"]
mod review_tests;

#[cfg(test)]
mod tests;
