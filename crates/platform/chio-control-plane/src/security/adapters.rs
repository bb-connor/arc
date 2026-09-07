pub mod effect_port;
mod native_evidence;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/adapters_parts/part_01.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/adapters_parts/part_02.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/adapters_parts/part_03.inc"
));
