//! HTTP handlers for the budget-metering surface: budget listing and the
//! authorize/release/reconcile exposure-accounting endpoints.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/trust_control/budget_handlers_parts/part_01.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/trust_control/budget_handlers_parts/part_02.inc"
));
