//! Dual-track receipt byte-identity regression.
//!
//! Anchored to the replay corpus at
//! `tests/replay/fixtures/allow_simple/01_basic_capability.json` plus its
//! blessed receipt stream under `tests/replay/goldens`.
//!
//! Under `legacy-sync`: the async signing path used by
//! `ToolEvaluator::sign_receipt` must emit the same canonical signed receipt
//! bytes as the legacy synchronous signer for the same receipt body.

#![cfg(feature = "legacy-sync")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{sha256_hex, Ed25519Backend, Keypair};
use chio_core::receipt::{ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, ToolCallRequest, ToolCallResponse, ToolEvaluator,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use serde::Deserialize;
use serde_json::json;

const REPLAY_FIXTURE_PATH: &str = "tests/replay/fixtures/allow_simple/01_basic_capability.json";
const GOLDEN_RECEIPTS_PATH: &str =
    "tests/replay/goldens/allow_simple/01_basic_capability/receipts.ndjson";
const REPLAY_FIXTURE: &str =
    include_str!("../../../tests/replay/fixtures/allow_simple/01_basic_capability.json");
const GOLDEN_RECEIPTS: &str =
    include_str!("../../../tests/replay/goldens/allow_simple/01_basic_capability/receipts.ndjson");
const TEST_KEY_SEED: &[u8; 32] = include_bytes!("../../../tests/replay/test-key.seed");
const FIXED_CLOCK_UNIX_SECS: u64 = 1_767_225_600;

#[derive(Debug, Deserialize)]
struct ReplayFixtureMeta {
    clock: String,
    expected_verdict: String,
    family: String,
    name: String,
    schema_version: String,
}

#[derive(Debug, Deserialize)]
struct GoldenReceiptLine {
    nonce: String,
    scenario: String,
    verdict: String,
}

#[derive(Debug, Default)]
struct AsyncReceiptSigner;

impl ToolEvaluator for AsyncReceiptSigner {
    async fn evaluate(
        &self,
        _kernel: &ChioKernel,
        _request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        Err(KernelError::Internal(
            "dual-track identity test only exercises receipt signing".to_string(),
        ))
    }
}

fn fixture_keypair() -> Keypair {
    Keypair::from_seed(TEST_KEY_SEED)
}

fn make_config(keypair: Keypair) -> KernelConfig {
    KernelConfig {
        keypair,
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"policy:dual-track-receipt"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    }
}

fn load_replay_fixture() -> (ReplayFixtureMeta, GoldenReceiptLine) {
    let fixture: ReplayFixtureMeta =
        serde_json::from_str(REPLAY_FIXTURE).expect("replay fixture parses");
    assert_eq!(fixture.schema_version, "v1");
    assert_eq!(fixture.family, "allow_simple");
    assert_eq!(fixture.name, "allow_simple/01_basic_capability");
    assert_eq!(fixture.expected_verdict, "allow");
    assert_eq!(fixture.clock, "2026-01-01T00:00:00Z");

    let golden_line = GOLDEN_RECEIPTS
        .lines()
        .next()
        .expect("golden receipt stream has a first line");
    let golden: GoldenReceiptLine =
        serde_json::from_str(golden_line).expect("golden receipt line parses");
    assert_eq!(golden.scenario, fixture.name);
    assert_eq!(golden.verdict, fixture.expected_verdict);

    (fixture, golden)
}

fn fixture_receipt_body(kernel_key: &Keypair) -> ChioReceiptBody {
    let (fixture, golden) = load_replay_fixture();
    let fixture_name = fixture.name.clone();
    let fixed_clock = fixture.clock.clone();
    let nonce = golden.nonce.clone();
    let action = ToolCallAction::from_parameters(json!({
        "clock": fixed_clock,
        "fixture": fixture_name,
        "golden_receipts": GOLDEN_RECEIPTS_PATH,
        "nonce": nonce,
        "tool_call": {
            "server_id": "replay-fixture",
            "tool_name": "allow_simple"
        }
    }))
    .expect("fixture tool-call parameters canonicalise");

    ChioReceiptBody {
        id: format!("rcpt-{}", golden.nonce),
        timestamp: FIXED_CLOCK_UNIX_SECS,
        capability_id: format!("cap-{}", fixture.name.replace('/', "-")),
        tool_server: "replay-fixture".to_string(),
        tool_name: "allow_simple".to_string(),
        action: action.clone(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(action.parameter_hash.as_bytes()),
        policy_hash: sha256_hex(format!("policy:{}", fixture.name).as_bytes()),
        evidence: Vec::new(),
        metadata: Some(json!({
            "replay_fixture": REPLAY_FIXTURE_PATH,
            "golden_receipts": GOLDEN_RECEIPTS_PATH,
        })),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
    }
}

#[allow(deprecated)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_and_legacy_sync_paths_emit_identical_signed_receipt_bytes_for_replay_fixture() {
    let keypair = fixture_keypair();
    let kernel = ChioKernel::new(make_config(keypair.clone()));
    let body = fixture_receipt_body(&keypair);

    let sync_backend = Ed25519Backend::new(keypair);
    let sync_receipt =
        chio_kernel_core::sign_receipt(body.clone(), &sync_backend).expect("sync signer succeeds");
    let async_receipt = AsyncReceiptSigner
        .sign_receipt(&kernel, body)
        .await
        .expect("async signer succeeds");

    assert!(sync_receipt
        .verify_signature()
        .expect("sync signature verifies"));
    assert!(async_receipt
        .verify_signature()
        .expect("async signature verifies"));

    let sync_bytes = canonical_json_bytes(&sync_receipt).expect("sync receipt canonicalises");
    let async_bytes = canonical_json_bytes(&async_receipt).expect("async receipt canonicalises");

    assert_eq!(
        async_bytes, sync_bytes,
        "async receipt bytes drifted from legacy sync bytes for {REPLAY_FIXTURE_PATH}"
    );
}
