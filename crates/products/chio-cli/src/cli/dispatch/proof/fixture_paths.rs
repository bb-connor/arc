use std::path::PathBuf;

use super::installed_fixture_root;

/// The proof-room fixture sources: the installed root when configured, the
/// checkout the executable runs from, or the packaged install location.
pub(super) fn proof_fixture_source_root() -> PathBuf {
    installed_fixture_root()
        .or_else(|| {
            chio_conformance::peers::checkout_root().map(|root| root.join("fixtures/proof-room"))
        })
        .unwrap_or_else(|| PathBuf::from("/opt/chio/fixtures/proof-room"))
}
