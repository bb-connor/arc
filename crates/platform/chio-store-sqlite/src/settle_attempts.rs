//! Durable settlement-retry sink: the bounded `settle_attempts` retry
//! envelope plus the existing dead-letter store, opened alongside the receipt
//! store so `chio settle status` reads tables production code writes.

include!("settle_attempts/authority.inc");
include!("settle_attempts/tests.inc");
