#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration coverage for `chio replay` exit codes.
//!
//! Six tests, one per canonical exit code:
//!
//! | Test name                                      | Exit |
//! |------------------------------------------------|------|
//! | `replay::receipt_only_clean_log_fails_closed_without_rederive_context` | 10 |
//! | `replay::verdict_drift_exits_ten`              | 10   |
//! | `replay::bad_signature_exits_twenty`           | 20   |
//! | `replay::malformed_json_exits_thirty`          | 30   |
//! | `replay::schema_mismatch_exits_forty`          | 40   |
//! | `replay::redaction_mismatch_exits_fifty`       | 50   |
//!
//! Each test loads a fixture from
//! `crates/products/chio-cli/tests/fixtures/replay/<family>/receipts.ndjson`,
//! spawns `chio replay <path> --json`, and asserts the process exit code
//! and the `exit_code` field in the JSON report.
//!
//! All six tests are active - `cmd_replay` is wired (dispatch.rs) and the
//! fixtures exist. Tests spawn the `chio` binary and assert exit codes.
//!
use std::path::{Path, PathBuf};
use std::process::Command;

use chio_core::Keypair;
use serde_json::Value;

// All six exit-code tests are active; cmd_replay is wired and fixtures exist.

// --------------------------------------------------------------------
// Path / fixture helpers
// --------------------------------------------------------------------

/// Absolute path to the fixtures root for this test file. Resolves
/// relative to `CARGO_MANIFEST_DIR` so the same lookup works from
/// `cargo test` invoked at the workspace root or inside the crate.
fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("replay")
}

/// Path to the `receipts.ndjson` for a named fixture family.
fn fixture_path(family: &str) -> PathBuf {
    fixtures_root().join(family).join("receipts.ndjson")
}

/// Stable Ed25519 seed used to sign every fixture receipt. Pinned so
/// regenerating the fixtures via `bless_fixtures` produces byte-equal
/// output across machines. The seed itself is deliberately non-zero
/// to avoid `Keypair::from_seed(&[0; 32])` collisions in unrelated
/// fixtures; the value below is the SHA-256 prefix of the literal
/// string `chio.replay.fixtures/v1` (truncated to 32 bytes) so the
/// derivation is reproducible without committing the key material as
/// a secret.
const FIXTURE_SEED: [u8; 32] = [
    0xd4, 0x7e, 0x7c, 0x46, 0x83, 0x55, 0xa9, 0xab, 0xee, 0x7e, 0xc5, 0x29, 0x6f, 0xc8, 0x88, 0x9c,
    0x12, 0x21, 0xc0, 0x97, 0xb7, 0xfe, 0x32, 0xa4, 0x4d, 0xe6, 0xc4, 0xc4, 0xea, 0xfb, 0x21, 0x33,
];

// --------------------------------------------------------------------
// Process-spawn helpers
// --------------------------------------------------------------------

/// Captured outcome of a `chio replay` invocation.
#[derive(Debug)]
struct ReplayRun {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Spawn `chio replay <log> --json` and capture the result.
fn run_replay_json(log_path: &Path) -> ReplayRun {
    let keypair = Keypair::from_seed(&FIXTURE_SEED);
    let trusted_key = tempfile::NamedTempFile::new().expect("trusted key tempfile");
    std::fs::write(trusted_key.path(), keypair.public_key().as_bytes()).expect("write trusted key");
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("replay")
        .arg(log_path)
        .arg("--trusted-kernel-pubkey")
        .arg(trusted_key.path())
        .arg("--json")
        .output()
        .expect("spawn chio replay");
    ReplayRun {
        exit_code: output.status.code().unwrap_or(i32::MIN),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Parse stdout as a `chio.replay.report/v1` document and return the
/// `exit_code` field. Used by every test as a cross-check that the
/// process exit and the reported exit do not drift.
fn parsed_report(run: &ReplayRun) -> Value {
    serde_json::from_str(&run.stdout).unwrap_or_else(|error| {
        panic!(
            "expected --json stdout to parse as chio.replay.report/v1: {error}\n\
             stdout=<<<{}>>>\nstderr=<<<{}>>>",
            run.stdout, run.stderr,
        )
    })
}

// Tests are wrapped in `mod replay` so the public names are
// `replay::<test_fn>` for filtered runs.

mod replay {
    use super::*;

    /// Exit code 10: a receipt-only log with valid signatures and hashes
    /// still fails closed because it does not carry the policy / guard
    /// context required for verdict re-derivation.
    #[test]
    fn receipt_only_clean_log_fails_closed_without_rederive_context() {
        let fixture = fixture_path("00-clean");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display(),);

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 10,
            "receipt-only replay must fail closed with exit 10; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["schema"], "chio.replay.report/v1");
        assert_eq!(report["exit_code"], 10);
        assert!(
            report["first_divergence"]["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("receipt-only replay cannot safely rederive verdicts"),
            "receipt-only replay must explain the fail-closed verdict; got {}",
            report["first_divergence"],
        );
    }

    /// Exit code 10: at least one receipt's stored decision differs from
    /// what the current build evaluates for the same input.
    ///
    /// The fixture stores a `deny` receipt body that the current evaluator
    /// would render as `allow` (via the per-receipt drift hook in
    /// `crates/products/chio-cli/src/cli/replay/verdict.rs`).
    #[test]
    fn verdict_drift_exits_ten() {
        let fixture = fixture_path("10-verdict-drift");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 10,
            "verdict drift must exit 10; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["exit_code"], 10);
        assert_eq!(report["first_divergence"]["kind"], "verdict_drift");
    }

    /// Exit code 20: an Ed25519 signature does not verify against the embedded `kernel_key`.
    /// The fixture has a single flipped byte in `content_hash`, so the re-canonicalized body
    /// no longer matches the signature.
    #[test]
    fn bad_signature_exits_twenty() {
        let fixture = fixture_path("20-bad-signature");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 20,
            "bad signature must exit 20; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["exit_code"], 20);
        assert_eq!(report["first_divergence"]["kind"], "signature_mismatch");
    }

    /// Exit code 30: a line in the NDJSON log is not valid JSON. The
    /// reader surfaces a structural error before any signature check.
    #[test]
    fn malformed_json_exits_thirty() {
        let fixture = fixture_path("30-malformed-json");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 30,
            "malformed JSON must exit 30; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["exit_code"], 30);
        assert_eq!(report["first_divergence"]["kind"], "parse_error");
    }

    /// Exit code 40: the receipt declares a `schema_version` that the
    /// current build does not support (or otherwise fails the
    /// canonical-JSON schema validator). The fixture carries a sentinel
    /// `"schema_version":"chio.receipt/v999"` field that the dispatcher
    /// rejects before signature verification.
    #[test]
    fn schema_mismatch_exits_forty() {
        let fixture = fixture_path("40-schema-mismatch");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 40,
            "schema mismatch must exit 40; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["exit_code"], 40);
        assert_eq!(report["first_divergence"]["kind"], "schema_mismatch");
    }

    /// Exit code 50: the receipt records a `redaction_pass_id` whose
    /// manifest no longer reproduces the same bytes when re-applied to
    /// the input. The fixture pins a redaction id that the current build
    /// cannot resolve, so the comparator emits a `redaction_mismatch`.
    #[test]
    fn redaction_mismatch_exits_fifty() {
        let fixture = fixture_path("50-redaction-mismatch");
        assert!(fixture.exists(), "fixture missing: {}", fixture.display());

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 50,
            "redaction mismatch must exit 50; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["exit_code"], 50);
        assert_eq!(report["first_divergence"]["kind"], "redaction_mismatch");
    }
} // mod replay
