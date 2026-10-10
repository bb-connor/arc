mod error;
pub use error::AdmissionOperationError;
#[path = "security_admission_operation/request_binding.rs"]
mod request_binding;
pub use request_binding::{AdmissionRequestBindingInput, AdmissionRequestBindingParts};

include!("admission_operation.part1.inc");
include!("admission_operation.part2.inc");
include!("admission_operation.part3.inc");

#[path = "security_admission_operation/recovery_pages.rs"]
mod recovery_pages;

#[cfg(test)]
#[path = "security_admission_operation/review_tests.rs"]
mod review_tests;
