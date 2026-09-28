include!("service_parts/part_01.rs");
include!("service_parts/part_02.rs");
include!("service_parts/part_03.rs");

#[cfg(all(test, unix))]
#[path = "service_parts/error_wire_tests.rs"]
mod error_wire_tests;
