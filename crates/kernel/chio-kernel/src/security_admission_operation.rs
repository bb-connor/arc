mod error;
pub use error::AdmissionOperationError;

include!("admission_operation.part1.inc");
include!("admission_operation.part2.inc");
include!("admission_operation.part3.inc");

#[path = "security_admission_operation/recovery_pages.rs"]
mod recovery_pages;

#[cfg(test)]
#[path = "security_admission_operation/review_tests.rs"]
mod review_tests;
