#[path = "receipt_store/bootstrap.rs"]
mod bootstrap;
mod chaos_test_hooks;
#[path = "receipt_store/evidence_retention.rs"]
mod evidence_retention;
#[path = "receipt_store/liability_claims.rs"]
mod liability_claims;
#[path = "receipt_store/liability_market.rs"]
mod liability_market;
#[path = "receipt_store/reports.rs"]
mod reports;
#[path = "receipt_store/support.rs"]
mod support;
#[cfg(test)]
#[path = "receipt_store/tests.rs"]
mod tests;
#[path = "receipt_store/underwriting_credit.rs"]
mod underwriting_credit;

pub(crate) const RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 4;
pub(crate) const RECEIPT_STORE_SCHEMA_KEY: &str = "receipt";

include!("receipt_store_parts/part_01.rs");
include!("receipt_store_parts/part_02.rs");
include!("receipt_store_parts/part_03.rs");
include!("receipt_store_parts/main_locks.rs");
