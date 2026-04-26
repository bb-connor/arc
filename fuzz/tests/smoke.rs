// owned-by: M02 (fuzz lane); shared smoke infra authored under M02.P1.T1.a.
//
//! Smoke tests for libFuzzer targets.
//!
//! Each fuzz target gets a `<target>_smoke` test that loads its seed corpus
//! and exercises the corresponding `fuzz_*` entry point. This catches
//! panics introduced by upstream changes between scheduled fuzz-lane runs:
//! the smoke test runs under the standard `cargo test` lane, which is much
//! faster (and more frequently triggered) than the dedicated `cargo fuzz`
//! campaigns.
//!
//! Targets are added incrementally. M02 P1 lands eleven new targets
//! (T1.a through T8) on top of the existing `attest_verify` target seeded
//! by M09.P3.T5; each ticket appends a `#[test]` block here referencing the
//! target's seed directory under `fuzz/corpus/`.
//!
//! Reference: `.planning/trajectory/02-fuzzing-post-pr13.md` Phase 1.

use std::fs;
use std::path::PathBuf;

/// Resolve a seed-corpus directory by target name. Lives under
/// `<CARGO_MANIFEST_DIR>/corpus/<name>` per the cargo-fuzz layout.
fn corpus_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(name)
}

/// Iterate every readable seed file in `corpus/<target>/` and pass its bytes
/// to `f`. Missing directories, unreadable entries, and read errors are
/// silently skipped so the smoke harness mirrors the libFuzzer
/// best-effort policy: a smoke test is a panic detector, not an integrity
/// check on the corpus directory itself.
fn each_seed<F: FnMut(&[u8])>(target: &str, mut f: F) {
    let dir = corpus_dir(target);
    if !dir.is_dir() {
        return;
    }
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            f(&bytes);
        }
    }
}

#[test]
fn jwt_vc_verify_smoke() {
    use chio_credentials::fuzz::fuzz_jwt_vc_verify;
    each_seed("jwt_vc_verify", fuzz_jwt_vc_verify);
}

#[test]
fn oid4vp_presentation_smoke() {
    use chio_credentials::fuzz::fuzz_oid4vp_presentation;
    each_seed("oid4vp_presentation", fuzz_oid4vp_presentation);
}

#[test]
fn did_resolve_smoke() {
    use chio_did::fuzz::fuzz_did_resolve;
    each_seed("did_resolve", fuzz_did_resolve);
}

#[test]
fn anchor_bundle_verify_smoke() {
    use chio_anchor::fuzz::fuzz_anchor_bundle_verify;
    each_seed("anchor_bundle_verify", fuzz_anchor_bundle_verify);
}

#[test]
fn mcp_envelope_decode_smoke() {
    use chio_mcp_edge::fuzz::fuzz_mcp_envelope_decode;
    each_seed("mcp_envelope_decode", fuzz_mcp_envelope_decode);
}

#[test]
fn a2a_envelope_decode_smoke() {
    use chio_a2a_adapter::fuzz::fuzz_a2a_envelope_decode;
    each_seed("a2a_envelope_decode", fuzz_a2a_envelope_decode);
}

#[test]
fn acp_envelope_decode_smoke() {
    use chio_acp_edge::fuzz::fuzz_acp_envelope_decode;
    each_seed("acp_envelope_decode", fuzz_acp_envelope_decode);
}
