//! Cross-version compatibility-matrix validation.

use std::path::Path;

use chio_replay_gate::cross_version::{CompatLevel, CompatMatrix};

/// Path of the matrix TOML, resolved relative to this crate's
/// `CARGO_MANIFEST_DIR` (i.e. `tests/replay/`).
const MATRIX_FILENAME: &str = "release_compat_matrix.toml";

#[test]
fn matrix_loads_and_has_at_least_two_entries() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(MATRIX_FILENAME);
    let matrix = match CompatMatrix::load(&path) {
        Ok(m) => m,
        Err(err) => panic!(
            "release_compat_matrix.toml failed to load from {}: {err}",
            path.display()
        ),
    };
    assert!(
        matrix.entry.len() >= 2,
        "expected at least 2 matrix entries, got {}",
        matrix.entry.len()
    );
    // Sanity-check the schema tag is the one the loader's strict
    // contract demands. (load() already enforces this; the assert is
    // here as a regression guard in case the constant is ever loosened.)
    assert_eq!(
        matrix.schema, "chio.replay.compat/v1",
        "matrix schema must equal chio.replay.compat/v1"
    );
    // Every entry must declare a known compat level.
    for entry in &matrix.entry {
        assert!(
            matches!(
                entry.compat,
                CompatLevel::Supported | CompatLevel::BestEffort | CompatLevel::Broken
            ),
            "entry {} has unrecognized compat level",
            entry.tag
        );
    }
}
