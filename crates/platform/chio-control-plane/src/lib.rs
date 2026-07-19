#![allow(clippy::result_large_err, clippy::too_many_arguments)]

pub mod attestation;
pub mod certify;
pub mod enterprise_federation;
pub mod evidence_export;
pub mod federation_policy;
pub mod issuance;
pub mod passport_verifier;
pub mod policy;
pub mod reputation;
pub mod scim_lifecycle;
pub mod security;
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
