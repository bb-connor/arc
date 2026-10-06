include!("admission_operation_store/part_01.inc");
include!("admission_operation_store/part_02.inc");
#[cfg(test)]
mod connection_recovery;

#[path = "security_admission_operation_store/recovery_pages.rs"]
mod recovery_pages;
