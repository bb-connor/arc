#[path = "admission_operation_store/part_01.inc"]
mod store;
pub use store::SqliteAdmissionOperationStore;
use store::*;
#[cfg(test)]
mod connection_recovery;
#[cfg(test)]
mod foreign_schema_tests;
#[cfg(test)]
mod review_tests;
include!("admission_operation_store/part_02.inc");

#[path = "security_admission_operation_store/recovery_pages.rs"]
mod recovery_pages;
mod table_shape;
