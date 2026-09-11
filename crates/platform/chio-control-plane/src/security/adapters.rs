pub mod effect_port;
mod flow_dispatch;
mod flow_policy;
mod native_evidence;
mod native_flow;

pub use flow_dispatch::PreparedFlowDispatch;
pub use native_flow::{
    NativeFlowCustody, NativeFlowError, NativeFlowPolicyEvidence, NativeFlowResolver,
    PreparedNativeFlowDispatch,
};

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
