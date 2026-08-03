include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/trust_control/service_runtime/budget_parts/part_01.inc"
));

pub use super::partition_escrow_authority::{
    PartitionEscrowRemoteAuthorityDescriptorBody, PartitionEscrowRemoteAuthorityProvisioningInput,
    SealedPartitionEscrowRemoteAuthority, SignedPartitionEscrowRemoteAuthorityDescriptor,
    PARTITION_ESCROW_REMOTE_AUTHORITY_DESCRIPTOR_SCHEMA,
};
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/trust_control/service_runtime/budget_parts/part_02.inc"
));
