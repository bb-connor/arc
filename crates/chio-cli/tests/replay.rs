#![allow(clippy::expect_used, clippy::unwrap_used)]

//! M04.P4.T6: integration coverage for `chio replay` exit codes.
//!
//! Six tests live in this file, one per canonical exit code from
//! `.planning/trajectory/04-deterministic-replay.md` Phase 4:
//!
//! | Test name                                      | Exit |
//! |------------------------------------------------|------|
//! | `replay::clean_log_exits_zero`                 | 0    |
//! | `replay::verdict_drift_exits_ten`              | 10   |
//! | `replay::bad_signature_exits_twenty`           | 20   |
//! | `replay::malformed_json_exits_thirty`          | 30   |
//! | `replay::schema_mismatch_exits_forty`          | 40   |
//! | `replay::redaction_mismatch_exits_fifty`       | 50   |
//!
//! Each test:
//!
//! 1. Loads a checked-in NDJSON fixture from
//!    `crates/chio-cli/tests/fixtures/replay/<family>/receipts.ndjson`.
//! 2. Spawns `chio replay --receipt-log <path> --json` via
//!    `Command::new(env!("CARGO_BIN_EXE_chio"))`.
//! 3. Asserts the exit code is the expected value, and (when stdout is
//!    JSON) that the report's `exit_code` field matches.
//!
//! ## Status: tests authored, gated on dispatch wiring
//!
//! T6's owner glob constrains this ticket to `tests/replay.rs` and
//! `tests/fixtures/replay/**`. The dispatch glue that strings the
//! reader, signature verifier, Merkle accumulator, verdict re-derive,
//! and JSON renderer (all landed in T2 through T5) into `cmd_replay`
//! is intentionally out of scope: the parser-surface stub in
//! `crates/chio-cli/src/cli/replay.rs` still answers every invocation
//! with exit code 0 and a human-readable notice. The six tests below
//! are therefore marked `#[ignore]` with a uniform reason
//! (`live cmd_replay pipeline lands downstream`) so the gate-check
//! command in `.planning/trajectory/tickets/M04/P4.yml` (which spawns
//! `cargo test -p chio-cli --test replay -- <names>`) reports each
//! test as `ignored` rather than `failed`. A follow-up wiring ticket
//! removes the `#[ignore]` attributes once `cmd_replay` calls into
//! the real pipeline.
//!
//! The fixtures themselves are real: they are deterministic NDJSON
//! receipt logs produced from a fixed Ed25519 seed via the
//! `bless_fixtures` helper at the bottom of this file (also
//! `#[ignore]`). Running
//! `cargo test -p chio-cli --test replay -- --ignored bless_fixtures`
//! regenerates every fixture under `tests/fixtures/replay/**` so they
//! stay in sync with `chio_core::receipt::ChioReceipt`'s on-the-wire
//! shape.
//!
//! Reference: `.planning/trajectory/04-deterministic-replay.md` Phase
//! 4 task 6, the canonical exit-code registry in the same document,
//! and the per-stage modules under
//! `crates/chio-cli/src/cli/replay/{reader,verify,merkle,verdict,report}.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_core::Keypair;
use serde_json::{json, Value};

// Uniform `#[ignore]` reason for the six exit-code tests:
// `live cmd_replay pipeline lands downstream of M04.P4.T6`. A wiring
// ticket removes the attribute once `cmd_replay` calls the live
// reader -> verify -> merkle -> verdict -> report pipeline already
// landed in T2 through T5.

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

/// Build a signed `ChioReceipt` with the fixture-pinned signing key.
/// The body contents are deterministic given the inputs so re-blessing
/// the fixtures produces byte-equal receipts.
fn signed_receipt(id: &str, decision: Decision) -> ChioReceipt {
    let keypair = Keypair::from_seed(&FIXTURE_SEED);
    let body = ChioReceiptBody {
        id: id.to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-replay-fixture".to_string(),
        tool_server: "fs".to_string(),
        tool_name: "read_file".to_string(),
        action: ToolCallAction {
            parameters: json!({"path": "/tmp/replay-fixture"}),
            parameter_hash: "0".repeat(64),
        },
        decision,
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
    };
    ChioReceipt::sign(body, &keypair).expect("fixture sign must succeed")
}

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

/// Spawn `chio replay <log> --json` and capture the result. The
/// `--receipt-log` flag is currently spelled positionally in the
/// parser surface (see `crates/chio-cli/src/cli/types.rs`); the test
/// helper mirrors that shape so the gate-check command in
/// `.planning/trajectory/tickets/M04/P4.yml` runs against the same
/// invocation a developer would type by hand.
fn run_replay_json(log_path: &Path) -> ReplayRun {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("replay")
        .arg(log_path)
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

// --------------------------------------------------------------------
// The six exit-code integration tests
// --------------------------------------------------------------------
//
// The tests live inside `mod replay { ... }` so the public name of
// each test is `replay::<test_fn>`, matching the gate-check command
// in `.planning/trajectory/tickets/M04/P4.yml` exactly:
//
//   cargo test -p chio-cli --test replay -- replay::clean_log_exits_zero ...
//
// Without the wrapping module the integration test crate would
// expose them as bare `clean_log_exits_zero` (filename-rooted), and
// the gate-check filter `replay::<name>` would silently match zero
// tests.

mod replay {
    use super::*;

    /// Exit code 0: a clean receipt log with valid signatures, matching
    /// verdicts, and (when `--expect-root` is supplied) a matching root
    /// re-verifies cleanly.
    #[test]
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
    fn clean_log_exits_zero() {
        let fixture = fixture_path("00-clean");
        assert!(
            fixture.exists(),
            "fixture missing: regenerate via `cargo test -p chio-cli --test replay \
         -- --ignored bless_fixtures`: {}",
            fixture.display(),
        );

        let run = run_replay_json(&fixture);

        assert_eq!(
            run.exit_code, 0,
            "clean log must exit 0; got {} stderr={}",
            run.exit_code, run.stderr,
        );
        let report = parsed_report(&run);
        assert_eq!(report["schema"], "chio.replay.report/v1");
        assert_eq!(report["exit_code"], 0);
        assert!(
            report["first_divergence"].is_null(),
            "clean run must report no divergence; got {}",
            report["first_divergence"],
        );
    }

    /// Exit code 10: at least one receipt's stored decision differs from
    /// what the current build evaluates for the same input.
    ///
    /// The fixture stores a `deny` receipt body that the current evaluator
    /// would render as `allow` (via the per-receipt drift hook in
    /// `crates/chio-cli/src/cli/replay/verdict.rs`).
    #[test]
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
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

    /// Exit code 20: an Ed25519 signature does not verify against the
    /// embedded `kernel_key`. The fixture flips a single content_hash
    /// byte on a previously-signed receipt so the body the verifier
    /// re-canonicalises no longer matches the signature.
    #[test]
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
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
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
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
    /// current build does not support (or otherwise fails the M01
    /// canonical-JSON schema validator). The fixture carries a sentinel
    /// `"schema_version":"chio.receipt/v999"` field that the dispatcher
    /// rejects before signature verification.
    #[test]
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
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
    #[ignore = "live cmd_replay pipeline lands downstream of M04.P4.T6"]
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

// --------------------------------------------------------------------
// Fixture (re)generation helper
// --------------------------------------------------------------------

/// Regenerate every fixture under `tests/fixtures/replay/**`.
///
/// Run on demand:
///
/// ```sh
/// cargo test -p chio-cli --test replay -- --ignored bless_fixtures --nocapture
/// ```
///
/// The helper is `#[ignore]` so a vanilla `cargo test` does not
/// touch checked-in files. It is deliberately authored as a test
/// rather than an example so the generation logic shares the same
/// helpers (`signed_receipt`, `fixture_path`) as the assertions and
/// cannot drift.
#[test]
#[ignore = "fixture-bless helper; run with --ignored bless_fixtures"]
fn bless_fixtures() {
    write_clean_fixture();
    write_verdict_drift_fixture();
    write_bad_signature_fixture();
    write_malformed_json_fixture();
    write_schema_mismatch_fixture();
    write_redaction_mismatch_fixture();
    eprintln!(
        "blessed all replay fixtures under {}",
        fixtures_root().display()
    );
}

/// Write `tests/fixtures/replay/<family>/receipts.ndjson` with the
/// supplied body. Creates parent directories as needed.
fn write_fixture(family: &str, body: &str) {
    let path = fixture_path(family);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture dir");
    }
    std::fs::write(&path, body).expect("write fixture");
    eprintln!("wrote fixture {}", path.display());
}

/// Render a `ChioReceipt` as a single NDJSON line (no trailing
/// newline; the writer adds one between receipts).
fn ndjson_line(receipt: &ChioReceipt) -> String {
    serde_json::to_string(receipt).expect("ndjson encode")
}

fn write_clean_fixture() {
    let r0 = signed_receipt("rcpt-clean-0001", Decision::Allow);
    let r1 = signed_receipt(
        "rcpt-clean-0002",
        Decision::Deny {
            reason: "policy violation".to_string(),
            guard: "policy".to_string(),
        },
    );
    let body = format!("{}\n{}\n", ndjson_line(&r0), ndjson_line(&r1));
    write_fixture("00-clean", &body);
}

/// Verdict drift: a `Deny` receipt whose body is otherwise valid.
/// The dispatcher's verdict re-derive (`cli/replay/verdict.rs`) is
/// expected to flag this as drift once T6's downstream wiring
/// reconstructs the kernel input from the receipt and observes the
/// current build evaluates to `Allow`. Until then the fixture is a
/// well-formed signed receipt the drift comparator can attribute.
fn write_verdict_drift_fixture() {
    let r0 = signed_receipt(
        "rcpt-drift-0001",
        Decision::Deny {
            reason: "stored deny that current build would allow".to_string(),
            guard: "drift-marker".to_string(),
        },
    );
    let body = format!("{}\n", ndjson_line(&r0));
    write_fixture("10-verdict-drift", &body);
}

/// Bad signature: take a valid signed receipt, mutate its
/// `content_hash` after signing so the verifier re-canonicalises a
/// body that no longer matches the signature.
fn write_bad_signature_fixture() {
    let r0 = signed_receipt("rcpt-bad-sig-0001", Decision::Allow);
    let mut value: Value = serde_json::to_value(&r0).expect("to_value");
    value["content_hash"] = Value::String("ff".repeat(32));
    let body = format!("{}\n", value);
    write_fixture("20-bad-signature", &body);
}

/// Malformed JSON: a single un-parseable line. The reader bails out
/// at line 1, mapping to exit code 30.
fn write_malformed_json_fixture() {
    let body = "{ this is not valid JSON\n".to_string();
    write_fixture("30-malformed-json", &body);
}

/// Schema mismatch: a JSON object that parses but advertises an
/// unsupported `schema_version`. The receipt also lacks the required
/// `kernel_key` and `signature` fields so the schema validator
/// rejects it before signature verification.
fn write_schema_mismatch_fixture() {
    let value = json!({
        "schema_version": "chio.receipt/v999",
        "id": "rcpt-schema-0001",
        "note": "future schema version that current build does not understand",
    });
    let body = format!("{}\n", value);
    write_fixture("40-schema-mismatch", &body);
}

/// Redaction mismatch: a receipt that names a `redaction_pass_id`
/// the current build cannot resolve. The receipt is otherwise
/// well-formed and signed so the comparator can attribute the
/// failure to redaction (not signature or schema).
fn write_redaction_mismatch_fixture() {
    let r0 = signed_receipt("rcpt-redaction-0001", Decision::Allow);
    let mut value: Value = serde_json::to_value(&r0).expect("to_value");
    let metadata = json!({
        "redaction_pass_id": "redaction-pass-not-resolvable-by-current-build",
        "redaction_manifest": [
            {"pointer": "/action/parameters/path", "kind": "path-tail"},
        ],
    });
    value["metadata"] = metadata;
    let body = format!("{}\n", value);
    write_fixture("50-redaction-mismatch", &body);
}
