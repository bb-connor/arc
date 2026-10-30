//! Load the trust-control access configuration file and the node key its
//! cluster identity names.

use std::path::Path;

use chio_control_plane::trust_control::caller_credentials::{
    AccessConfigDocument, TrustAccess, TrustAccessConfig,
};
use chio_secure_ipc::regular_file::{read_regular_file, OpenPolicy};

use crate::CliError;

/// Largest access configuration document trust-control reads.
const MAX_ACCESS_CONFIG_BYTES: usize = 1024 * 1024;

/// Read, decode and validate the access configuration at `path` and load the
/// node key its cluster identity names.
pub(crate) fn load_trust_access(path: &Path) -> Result<TrustAccess, CliError> {
    let refused = |reason: String| {
        CliError::cli_other_error(format!(
            "trust-control access configuration {}: {reason}",
            path.display()
        ))
    };
    let bytes = read_regular_file(path, MAX_ACCESS_CONFIG_BYTES, OpenPolicy::Trusted)
        .map_err(|error| refused(error.to_string()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| refused("not UTF-8".to_owned()))?;
    let document: AccessConfigDocument =
        toml::from_str(text).map_err(|error| refused(error.message().to_owned()))?;
    let config =
        TrustAccessConfig::from_document(document).map_err(|error| refused(error.to_string()))?;
    let node_keypair = config
        .peers()
        .identity()
        .map(|identity| crate::load_existing_authority_keypair(&identity.node_key_file))
        .transpose()?;
    TrustAccess::from_parts(config, node_keypair).map_err(|error| refused(error.to_string()))
}
