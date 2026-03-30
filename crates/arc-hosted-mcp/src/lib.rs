#![allow(clippy::result_large_err)]

pub use arc_control_plane::{
    authority_public_key_from_seed_file, build_kernel, configure_budget_store,
    configure_capability_authority, configure_receipt_store, configure_revocation_store,
    issue_default_capabilities, load_or_create_authority_keypair, rotate_authority_keypair,
    CliError, JwtProviderProfile,
};

pub mod enterprise_federation {
    pub use arc_control_plane::enterprise_federation::*;
}

pub mod policy {
    pub use arc_control_plane::policy::*;
}

pub mod trust_control {
    pub use arc_control_plane::trust_control::*;
}

#[path = "../../arc-cli/src/remote_mcp.rs"]
mod remote_mcp_impl;

pub use remote_mcp_impl::*;
