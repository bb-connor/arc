//! Adapt a verified bundle to command completion without flattening its error cause.
use crate::CliError;
use std::path::Path;

pub(super) fn verify_manifest(path: &Path) -> Result<(), CliError> {
    chio_proof_room::verify_proof_room_bundle(path)
        .map(|_verified| ())
        .map_err(|error| {
            CliError::with_source(&chio_errors::_generated::error_codes::CLI_OTHER, error)
        })
}
