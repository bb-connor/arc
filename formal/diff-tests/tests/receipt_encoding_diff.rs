#![cfg(not(target_arch = "wasm32"))]

//! Cross-language receipt-encoding differential test.
//!
//! Proves that the Rust receipt encoder produces byte-identical canonical JSON
//! to the Python and TypeScript SDK encoders for the same receipt body. The
//! protocol contract is that all three languages MUST emit the same canonical
//! bytes so that the kernel signature attaches to a single agreed-upon byte
//! string.
//!
//! ## Strategy: vectors as cross-language oracle (default)
//!
//! Rather than spawning live Python and Node subprocesses (which would tie
//! the test to a specific local toolchain), this harness uses the receipt
//! vector corpus at `tests/bindings/vectors/receipt/v1.json` as the
//! cross-language oracle. The corpus was produced by the Rust binding-helpers
//! generator and is exercised in lockstep by:
//!
//!   - Rust:        `crates/sdk/chio-binding-helpers/tests/vector_fixtures.rs`
//!     `receipt_fixture_cases_round_trip_through_public_api`
//!   - Python:      `sdks/python/chio-py/tests/test_vectors.py`
//!     compares `receipt_body_canonical_json(receipt)` against the
//!     `receipt_body_canonical_json` field of every case.
//!   - TypeScript:  `sdks/typescript/chio-ts/test/vectors.test.ts`
//!     compares `receiptBodyCanonicalJson(receipt)` against the same field.
//!
//! Because the vectors are continuously triple-blessed by Rust, Python, and
//! TypeScript, byte-equality between the Rust canonicalizer (via this crate's
//! `chio-core` dependency) and the `receipt_body_canonical_json` corpus field
//! implies byte-equality across all three encoder implementations.
//!
//! ## Strategy: proptest invariants
//!
//! The proptest section generates random receipt bodies, canonicalizes them,
//! and verifies that:
//!
//!   - canonicalize is idempotent (re-encoding the parsed canonical JSON
//!     yields the same bytes),
//!   - `ChioReceipt::sign` followed by `body()` and re-canonicalization
//!     reproduces the same bytes that were signed,
//!   - signature verification against the canonical bytes succeeds.
//!
//! ## Strategy: live subprocess
//!
//! Python and Node load the in-tree SDK sources and encode a dynamically
//! generated receipt. Missing runtimes, import failures, and encoding drift
//! fail the test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chio_core::{
    canonical_json_bytes, canonical_json_string,
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
        metadata::{ActorRef, GuardEvidence},
    },
    sha256_hex, Keypair,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Workspace / fixture resolution
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is .../formal/diff-tests; the workspace root is two up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("formal/diff-tests is nested under the workspace root")
        .to_path_buf()
}

fn receipt_vector_path() -> PathBuf {
    workspace_root().join("tests/bindings/vectors/receipt/v1.json")
}

fn read_receipt_vectors() -> Value {
    let raw = std::fs::read_to_string(receipt_vector_path())
        .expect("read tests/bindings/vectors/receipt/v1.json");
    serde_json::from_str(&raw).expect("parse receipt vector JSON")
}

// ---------------------------------------------------------------------------
// Vectors-as-oracle: cross-language byte-equivalence via the blessed corpus
// ---------------------------------------------------------------------------

/// Load every receipt vector case, parse it via `chio-core`'s `serde` derive,
/// re-canonicalize the body, and assert byte-equality against the corpus's
/// `receipt_body_canonical_json` field. The Python and TypeScript SDK test
/// suites assert the same equality on the same field, so passing here implies
/// the Rust encoder produces the same bytes as those two SDKs.
#[test]
fn rust_canonical_receipt_body_matches_blessed_vector_bytes() {
    let fixture = read_receipt_vectors();
    let cases = fixture["cases"].as_array().expect("cases array");
    // Floor matches the checked-in corpus size (the cross-language oracle at
    // tests/bindings/vectors/receipt/v1.json carries 14 cases). It guards
    // against the corpus being accidentally emptied; the byte-equality loop
    // below is the substantive cross-language assertion.
    assert!(
        cases.len() >= 14,
        "expected at least 14 receipt vectors; found {}",
        cases.len()
    );

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let receipt: ChioReceipt = serde_json::from_value(case["receipt"].clone())
            .unwrap_or_else(|err| panic!("parse receipt for case {id}: {err}"));

        let expected = case["receipt_body_canonical_json"]
            .as_str()
            .unwrap_or_else(|| panic!("case {id} missing receipt_body_canonical_json"));

        let body = receipt.body();
        let actual_string =
            canonical_json_string(&body).expect("canonical_json_string of receipt body");
        let actual_bytes =
            canonical_json_bytes(&body).expect("canonical_json_bytes of receipt body");

        assert_eq!(
            actual_string, expected,
            "Rust canonical receipt body diverges from blessed vector for case {id}"
        );
        assert_eq!(
            actual_bytes,
            expected.as_bytes(),
            "Rust canonical bytes diverge from blessed vector UTF-8 for case {id}"
        );
    }
}

/// Sanity-check the signature attaches to the canonical bytes the corpus
/// records. If this fails on a case where signature_valid was true in the
/// vector, the canonical encoding has drifted.
#[test]
fn signed_vector_receipts_verify_against_canonical_bytes() {
    let fixture = read_receipt_vectors();
    let cases = fixture["cases"].as_array().expect("cases array");

    for case in cases {
        let id = case["id"].as_str().expect("case id");
        let expected_signature_valid = case
            .get("expected")
            .and_then(|v| v.get("signature_valid"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !expected_signature_valid {
            continue;
        }

        let receipt: ChioReceipt = serde_json::from_value(case["receipt"].clone())
            .unwrap_or_else(|err| panic!("parse receipt for case {id}: {err}"));

        let signature_valid = receipt
            .verify_signature()
            .unwrap_or_else(|err| panic!("verify_signature for case {id}: {err}"));
        assert!(
            signature_valid,
            "case {id}: vector marks signature_valid=true but verify_signature returned false"
        );
    }
}

// ---------------------------------------------------------------------------
// Proptest: byte-stable round trips on randomly-generated receipt bodies
// ---------------------------------------------------------------------------

fn case_count(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: case_count(64),
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

/// Strategy generating bounded JSON parameter values: arbitrary parameters
/// would make signature math expensive for no test value, so we restrict to a
/// small string-keyed object whose values are simple integers or strings.
fn arb_parameters() -> impl Strategy<Value = Value> {
    proptest::collection::btree_map(
        "[a-z_][a-z0-9_]{0,8}",
        prop_oneof![
            any::<i32>().prop_map(|n| json!(n)),
            "[ -~]{0,16}".prop_map(|s| json!(s)),
            Just(json!(true)),
            Just(json!(false)),
            Just(Value::Null),
        ],
        0..6,
    )
    .prop_map(|map| {
        let mut obj = serde_json::Map::new();
        for (k, v) in map {
            obj.insert(k, v);
        }
        Value::Object(obj)
    })
}

fn arb_decision() -> impl Strategy<Value = Decision> {
    prop_oneof![
        Just(Decision::Allow),
        ("[ -~]{1,32}", "[A-Za-z][A-Za-z0-9]{0,16}")
            .prop_map(|(reason, guard)| { Decision::Deny { reason, guard } }),
        "[ -~]{1,32}".prop_map(|reason| Decision::Cancelled { reason }),
        "[ -~]{1,32}".prop_map(|reason| Decision::Incomplete { reason }),
    ]
}

fn arb_evidence() -> impl Strategy<Value = Vec<GuardEvidence>> {
    proptest::collection::vec(
        (
            "[A-Z][A-Za-z]{2,16}Guard",
            any::<bool>(),
            proptest::option::of("[ -~]{0,32}"),
        )
            .prop_map(|(guard_name, verdict, details)| GuardEvidence {
                guard_name,
                verdict,
                details,
            }),
        0..4,
    )
}

#[derive(Debug, Clone)]
struct ReceiptScaffold {
    id: String,
    timestamp: u64,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    parameters: Value,
    decision: Decision,
    evidence: Vec<GuardEvidence>,
}

fn arb_receipt_scaffold() -> impl Strategy<Value = ReceiptScaffold> {
    (
        "rcpt-[a-z0-9]{1,16}",
        1_700_000_000u64..1_900_000_000u64,
        "cap-[a-z0-9]{1,12}",
        "srv-[a-z]{1,12}",
        "[a-z][a-z_]{1,12}",
        arb_parameters(),
        arb_decision(),
        arb_evidence(),
    )
        .prop_map(
            |(
                id,
                timestamp,
                capability_id,
                tool_server,
                tool_name,
                parameters,
                decision,
                evidence,
            )| {
                ReceiptScaffold {
                    id,
                    timestamp,
                    capability_id,
                    tool_server,
                    tool_name,
                    parameters,
                    decision,
                    evidence,
                }
            },
        )
}

fn build_receipt(scaffold: &ReceiptScaffold, keypair: &Keypair) -> ChioReceipt {
    let action =
        ToolCallAction::from_parameters(scaffold.parameters.clone()).expect("from_parameters");
    let body = ChioReceiptBody {
        id: scaffold.id.clone(),
        timestamp: scaffold.timestamp,
        capability_id: scaffold.capability_id.clone(),
        tool_server: scaffold.tool_server.clone(),
        tool_name: scaffold.tool_name.clone(),
        action,
        decision: Some(scaffold.decision.clone()),
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::None,
        actor_chain: vec![ActorRef {
            actor_id: "agent:diff-test/encoder".to_string(),
            actor_kind: Some("agent".to_string()),
        }],
        content_hash: sha256_hex(scaffold.id.as_bytes()),
        policy_hash: "policy-diff-v1".to_string(),
        evidence: scaffold.evidence.clone(),
        metadata: Some(json!({"surface": "receipt-encoding-diff"})),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, keypair).expect("sign receipt")
}

proptest! {
    #![proptest_config(config())]

    /// Encoding the body twice yields byte-identical output (idempotence /
    /// determinism, the bedrock invariant for cross-language agreement).
    #[test]
    fn canonical_receipt_body_is_idempotent(scaffold in arb_receipt_scaffold()) {
        let keypair = Keypair::from_seed(&[31u8; 32]);
        let receipt = build_receipt(&scaffold, &keypair);
        let body = receipt.body();

        let first = canonical_json_bytes(&body).expect("first encode");
        let second = canonical_json_bytes(&body).expect("second encode");
        prop_assert_eq!(&first, &second, "canonicalization not deterministic");
    }

    /// Re-parsing the canonical JSON and re-canonicalizing yields identical
    /// bytes. This is the JSON-side analogue of "the canonical form is a
    /// fixed point of the encoding pipeline" and matches what the Python and
    /// TS SDKs assert in their own vector tests.
    #[test]
    fn canonical_receipt_body_round_trip_is_stable(scaffold in arb_receipt_scaffold()) {
        let keypair = Keypair::from_seed(&[32u8; 32]);
        let receipt = build_receipt(&scaffold, &keypair);
        let body = receipt.body();

        let first = canonical_json_string(&body).expect("first canonicalize");
        let parsed: Value = serde_json::from_str(&first).expect("parse canonical json");
        let second = canonical_json_string(&parsed).expect("second canonicalize");
        prop_assert_eq!(first, second, "canonical form is not a fixed point");
    }

    /// The signature emitted by `ChioReceipt::sign` must verify against the
    /// canonical bytes produced from `body()`. If this property fails, the
    /// canonical encoder has drifted from the signing pipeline.
    #[test]
    fn signed_receipt_signature_verifies(scaffold in arb_receipt_scaffold()) {
        let keypair = Keypair::from_seed(&[33u8; 32]);
        let receipt = build_receipt(&scaffold, &keypair);

        let valid = receipt
            .verify_signature()
            .expect("verify_signature");
        prop_assert!(valid, "signed receipt failed self-verification");
    }
}

// ---------------------------------------------------------------------------
// Live subprocess differentials
// ---------------------------------------------------------------------------

fn sample_live_receipt() -> ChioReceipt {
    let scaffold = ReceiptScaffold {
        id: "rcpt-live-diff".to_string(),
        timestamp: 1_710_000_300,
        capability_id: "cap-live-diff".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        parameters: json!({"mode": "read", "path": "/workspace/docs/roadmap.md"}),
        decision: Decision::Allow,
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: true,
            details: Some("path allowed".to_string()),
        }],
    };
    let keypair = Keypair::from_seed(&[41u8; 32]);
    build_receipt(&scaffold, &keypair)
}

#[test]
fn live_python_encoder_matches_rust() {
    let receipt = sample_live_receipt();
    let receipt_json = serde_json::to_string(&receipt).expect("serialize receipt to json");
    let expected = canonical_json_string(&receipt.body()).expect("rust canonical body");
    let python_source = workspace_root().join("sdks/python/chio-py/src");

    let script = r#"
import json
import sys

from chio.invariants import receipt_body_canonical_json

receipt = json.loads(sys.stdin.read())
sys.stdout.write(receipt_body_canonical_json(receipt))
"#;

    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .env("PYTHONPATH", python_source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(receipt_json.as_bytes())
                    .expect("write stdin");
            }
            child.wait_with_output()
        });

    let output = output.unwrap_or_else(|err| {
        panic!("live python differential: failed to spawn python3 subprocess: {err}")
    });
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "python receipt-encoder peer failed: status={:?} stderr={}",
            output.status, stderr
        );
    }

    let actual = String::from_utf8(output.stdout).expect("python output utf-8");
    assert_eq!(
        actual, expected,
        "Python receipt encoder bytes diverge from Rust"
    );
}

#[test]
fn live_ts_encoder_matches_rust() {
    let receipt = sample_live_receipt();
    let receipt_json = serde_json::to_string(&receipt).expect("serialize receipt to json");
    let expected = canonical_json_string(&receipt.body()).expect("rust canonical body");

    let sdk_source = workspace_root().join("sdks/typescript/chio-ts/src/invariants/index.ts");
    let script = r#"
import { pathToFileURL } from "node:url";
const sdk = await import(pathToFileURL(process.argv[1]).href);
if (typeof sdk.receiptBodyCanonicalJson !== "function") {
    process.stderr.write("chio-ts missing expected export receiptBodyCanonicalJson\n");
    process.exit(1);
}
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => { buf += chunk; });
process.stdin.on("end", () => {
    try {
        const receipt = JSON.parse(buf);
        const out = sdk.receiptBodyCanonicalJson(receipt);
        process.stdout.write(out);
    } catch (exc) {
        process.stderr.write("chio-ts encoder threw: " + (exc && exc.stack ? exc.stack : exc) + "\n");
        process.exit(1);
    }
});
"#;

    let output = Command::new("node")
        .arg("--experimental-strip-types")
        .arg("--input-type=module")
        .arg("-e")
        .arg(script)
        .arg(sdk_source)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(receipt_json.as_bytes())
                    .expect("write stdin");
            }
            child.wait_with_output()
        });

    let output = output.unwrap_or_else(|err| {
        panic!("live typescript differential: failed to spawn node subprocess: {err}")
    });
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "typescript receipt-encoder peer failed: status={:?} stderr={}",
            output.status, stderr
        );
    }

    let actual = String::from_utf8(output.stdout).expect("node output utf-8");
    assert_eq!(
        actual, expected,
        "TypeScript receipt encoder bytes diverge from Rust"
    );
}
