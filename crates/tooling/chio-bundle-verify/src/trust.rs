//! Loading the verifier-owned trust file.

use std::io::Read;
use std::path::Path;

use chio_core_types::root_authority::{VerifierTrust, MAX_VERIFIER_TRUST_BYTES};

use crate::error::BundleVerifyError;

/// Read and load a `chio.verifier-trust.v1` file. An unreadable file is
/// unclassified; a file that fails [`VerifierTrust::load`] is invalid trust.
pub fn read_trust_file(path: &Path) -> Result<VerifierTrust, BundleVerifyError> {
    let file = std::fs::File::open(path).map_err(|error| {
        BundleVerifyError::io(format!(
            "cannot open trust file {}: {error}",
            path.display()
        ))
    })?;
    let bound = u64::try_from(MAX_VERIFIER_TRUST_BYTES)
        .ok()
        .and_then(|bound| bound.checked_add(1))
        .unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    file.take(bound).read_to_end(&mut bytes).map_err(|error| {
        BundleVerifyError::io(format!(
            "cannot read trust file {}: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > MAX_VERIFIER_TRUST_BYTES {
        return Err(BundleVerifyError::trust_invalid(
            "verifier trust file exceeds its byte limit",
        ));
    }
    VerifierTrust::load(&bytes).map_err(|error| BundleVerifyError::trust_invalid(error.to_string()))
}
