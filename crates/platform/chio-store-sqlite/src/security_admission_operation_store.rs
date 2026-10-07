include!("admission_operation_store/part_01.inc");
include!("admission_operation_store/part_02.inc");
#[cfg(test)]
mod connection_recovery;
#[cfg(test)]
mod foreign_schema_tests;

#[path = "security_admission_operation_store/recovery_pages.rs"]
mod recovery_pages;
mod table_shape;
