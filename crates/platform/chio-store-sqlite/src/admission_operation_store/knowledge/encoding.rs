//! Shared typed labels and exact immutable private knowledge framing.

pub(in crate::admission_operation_store) mod chunks;
pub(in crate::admission_operation_store) mod labels;
pub(in crate::admission_operation_store) mod legacy_labels;
pub(in crate::admission_operation_store) mod write;

#[cfg(feature = "admission-test-support")]
mod prefix_fault;
