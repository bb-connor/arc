use super::*;
use chio_test_support::ctx::TestUnwrap;

pub(super) fn write_issuers_with_min_version(dir: &std::path::Path, min_version: u64) -> PathBuf {
    let issuer = Keypair::from_seed(&[240u8; 32]);
    let issuers_path = dir.join("issuers.json");
    let issuers = serde_json::json!({
        "issuers": [{
            "issuer": "did:chio:issuer",
            "keyId": "issuer-key-1",
            "publicKey": issuer.public_key(),
        }],
        "minVersion": min_version,
    });
    std::fs::write(&issuers_path, serde_json::to_string(&issuers).test_unwrap("directory fixture")).test_unwrap("directory fixture");
    issuers_path
}

/// Write a signed successor to a FIXED `path` (so successive versions overwrite one
/// bundle the reloader re-reads), binding the LOCAL node at `local_transport_seed`
/// (pass [`LOCAL_TRANSPORT_SEED`] to REBIND this node, any other seed to ROTATE it
/// away), peer `did:chio:bob` live, chaining onto `previous_version_sha256`. Returns
/// the full-document body hash (the successor's chain pin).
pub(super) fn write_local_binding_bundle_at(
    path: &std::path::Path,
    version: u64,
    local_transport_seed: u8,
    previous_version_sha256: Option<String>,
) -> String {
    let (bundle_json, _issuer) = build_signed_bundle_json(
        vec![
            local_relay_entry(local_transport_seed),
            directory_entry("did:chio:bob", 7, 24),
        ],
        version,
        previous_version_sha256,
    );
    std::fs::write(path, &bundle_json).test_unwrap("directory fixture");
    let bundle: TransportDirectoryBundleDocument = crate::input::text(&bundle_json).test_unwrap("directory fixture");
    sha256_hex(&canonical_json_bytes(&bundle).test_unwrap("directory fixture"))
}
