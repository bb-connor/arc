#![allow(clippy::result_large_err, clippy::too_many_arguments)]

mod anchor_egress;
pub mod attestation;
pub mod certify;
mod durable_admission;
pub(crate) use durable_admission::durable_admission_lock_root;
pub use durable_admission::*;
pub mod economic_admission_cancellation;
pub mod economic_effect_coordinator;
pub mod economic_state_anchor;
pub mod economic_state_recovery;
pub mod enterprise_federation;
pub mod evidence_export;
pub mod federation_policy;
pub mod fiscal_runtime_readiness;
pub mod fiscal_runtime_startup;
pub mod fiscal_state_anchor;
pub mod fiscal_state_commit;
pub mod fiscal_state_recovery;
pub mod issuance;
pub mod passport_verifier;
pub mod policy;
pub mod reputation;
pub mod scim_lifecycle;
pub mod security;
pub mod seller_rail;
pub mod transaction_passport_risk;
pub mod trust_control;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_01.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_01_tail.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_02.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/lib_parts/part_03.inc"
));
