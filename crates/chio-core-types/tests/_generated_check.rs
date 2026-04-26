//! Integration test that enforces the regenerate-only policy on every file
//! under `crates/chio-core-types/src/_generated/`.
//!
//! For each `*.rs` file under `_generated/` (recursively), we check:
//!
//! 1. The file begins with the canonical `// DO NOT EDIT` header banner. The
//!    banner is byte-for-byte identical with `chio_spec_codegen::GENERATED_HEADER`
//!    so a divergence between the codegen and the on-disk file fails CI.
//! 2. The file is reachable from the codegen pipeline (i.e. its contents do
//!    not contain a `// HAND EDIT` opt-out marker, which we forbid).
//!
//! The test is referenced by the M01.P3.T1 gate
//! (`cargo test -p chio-core-types --test _generated_check`) and by the
//! M01.P3.T5 `header-stamp-untouched` CI lane.
//!
//! Note on file location: the M01.P3.T1 ticket's owner_glob lists
//! `crates/chio-core-types/src/_generated_check.rs`, but cargo's
//! integration-test harness only discovers files under `tests/` (the `--test`
//! flag resolves to a target name, which in turn maps to `tests/<name>.rs`).
//! Putting this file under `src/` would either turn it into a private module
//! that `cargo test --test ...` cannot find, or require a custom `[[test]]`
//! entry in `Cargo.toml` with `path = "src/_generated_check.rs"`, which
//! would be a non-idiomatic Cargo layout. We resolve this by placing the
//! file in the conventional `tests/` location; the owner_glob in the ticket
//! is treated as a typo. The file is logically part of the
//! `_generated/` policy surface and will be referenced from M01.P3.T5 CI.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Header line that must begin every regenerated Rust file under
/// `_generated/`. Must agree with `chio_spec_codegen::GENERATED_HEADER`.
const HEADER_PREFIX: &str =
    "// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.";

/// Marker that some past contributor might use to opt out of the
/// regeneration policy. We forbid it: every file under `_generated/` must be
/// produced by the codegen, period.
const FORBIDDEN_OPT_OUT: &str = "// HAND EDIT";

#[test]
fn every_generated_file_has_canonical_header() {
    let generated_dir = generated_dir();
    let files = collect_rust_files(&generated_dir);
    assert!(
        !files.is_empty(),
        "expected at least the placeholder mod.rs under {}",
        generated_dir.display()
    );
    let mut failures: Vec<String> = Vec::new();
    for path in &files {
        let Ok(body) = fs::read_to_string(path) else {
            failures.push(format!("could not read {}", path.display()));
            continue;
        };
        if !body.starts_with(HEADER_PREFIX) {
            failures.push(format!(
                "{} is missing the canonical `// DO NOT EDIT` header",
                path.display()
            ));
        }
        if body.contains(FORBIDDEN_OPT_OUT) {
            failures.push(format!(
                "{} contains a forbidden `// HAND EDIT` opt-out marker",
                path.display()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "regenerate-only policy violated:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn placeholder_mod_rs_exists() {
    let mod_rs = generated_dir().join("mod.rs");
    assert!(
        mod_rs.exists(),
        "placeholder {} is missing; rerun `cargo xtask codegen rust`",
        mod_rs.display()
    );
}

fn generated_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at `crates/chio-core-types`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("_generated")
}

fn collect_rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_rust_files(&path));
        } else if path.extension().and_then(OsStr::to_str) == Some("rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}
