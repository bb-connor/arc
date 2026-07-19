#[path = "receipt_store/bootstrap.rs"]
mod bootstrap;
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

include!("receipt_store_parts/part_01.rs");
include!("receipt_store_parts/part_02.rs");
include!("receipt_store_parts/part_03.rs");
include!("receipt_store_parts/main_locks.rs");
