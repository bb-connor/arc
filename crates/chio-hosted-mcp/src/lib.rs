#![allow(clippy::result_large_err)]

pub use chio_control_plane::{
    authority_public_key_from_seed_file, build_kernel, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    enterprise_federation, issue_default_capabilities, load_or_create_authority_keypair, policy,
    rotate_authority_keypair, trust_control, CliError, JwtProviderProfile,
};

#[path = "../../chio-cli/src/remote_mcp.rs"]
mod remote_mcp_impl;

pub use remote_mcp_impl::{serve_http, RemoteServeHttpConfig};
