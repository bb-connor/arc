//! The successful verifier retains the exact manifest identity it authenticated.
use crate::{ProofRoomBundleManifest, ProofRoomError};
use std::path::Path;

/// Authenticated identity of the exact manifest consumed by a successful verifier.
/// This result cannot be decoded or constructed by a caller.
/// ```compile_fail
/// let _ = serde_json::from_str::<chio_proof_room::VerifiedProofRoomBundle>("{}");
/// ```
#[derive(Debug)]
pub struct VerifiedProofRoomBundle {
    manifest: ProofRoomBundleManifest,
    manifest_sha256: String,
}
impl VerifiedProofRoomBundle {
    pub(crate) fn verify(path: &Path) -> Result<Self, ProofRoomError> {
        let (manifest, manifest_sha256) =
            crate::verify_proof_room_bundle_inner_with_options(path, true, true, true)?;
        Ok(Self {
            manifest,
            manifest_sha256,
        })
    }
    pub fn bundle_id(&self) -> &str {
        &self.manifest.bundle_id
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub(crate) fn manifest(&self) -> &ProofRoomBundleManifest {
        &self.manifest
    }
}
