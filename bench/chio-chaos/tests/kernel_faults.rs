//! Real kernel-path chaos scenarios driven through a live `StackHarness`.
//!
//! Each scenario injects a genuine hot-path fault (a tool server that hangs far
//! past the dispatch deadline; a guard that blocks far past the guard-pipeline
//! deadline; a decision-model score source that fails) and asserts the kernel
//! fails closed with a signed deny rather than hanging or erroring. Each carries the InjectionNoOp discipline: a dispatch
//! that returns a normal Allow proves the deadline never fired, so the scenario
//! fails with [`ChaosError::InjectionNoOp`] instead of passing vacuously.
//!
//! The deadline knobs live in `chio_kernel::HotPathDeadlineConfig`
//! (`dispatch_budget_ms`, `guard_pipeline_budget_ms`); the harness threads them
//! into the booted kernel via `StackHarness::boot_with_deadlines`.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use chio_attest_verify::VerifiedAttestation;
use chio_chaos::{chaos_iterations, ChaosError};
use chio_core_types::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core_types::receipt::metadata::DECISION_MODEL_WITNESS_METADATA_KEY;
use chio_guards::{
    DecisionModelBinding, PredicateDagGuard, ScoreError, ScoreSource, Scores,
    PREDICATE_DAG_GUARD_NAME,
};
use chio_kernel::{
    Guard, GuardContext, GuardDecision, GuardEvidenceDeclaration, HotPathDeadlineConfig,
    KernelError, Verdict,
};
use chio_loadgen::{LoadgenConfig, StackHarness, StoreBacking};
use chio_predicate_dag::ATOM_WORDS;
use chio_test_support::prelude::*;
use chio_weights::{weights_hash_of, ModelCard, StringSet, VerifiedModelCard};
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

/// Default round count for the fast PR tier. The nightly lane raises
/// `CHIO_CHAOS_ITERATIONS`.
const DEFAULT_ITERATIONS: u64 = 3;

/// Dispatch and guard-pipeline budgets driven into the kernel. Small so a
/// breach is unambiguous while leaving wide headroom over scheduling jitter.
const DISPATCH_BUDGET_MS: u64 = 200;
const GUARD_BUDGET_MS: u64 = 200;

/// Tool-server latency for the hung-server scenario, set far above the dispatch
/// budget so the deadline must fire before the tool would return. The stub
/// server sleeps asynchronously, so a fired deadline cancels the sleep with no
/// blocking-thread cost.
const HUNG_TOOL_LATENCY_MS: u64 = 4_000;

/// How long the blocking guard stalls: far past the guard-pipeline budget, and
/// bounded so the detached blocking thread does not stall runtime teardown after
/// the deadline has fired.
const GUARD_SLEEP: Duration = Duration::from_secs(2);

fn iterations() -> u64 {
    chaos_iterations(DEFAULT_ITERATIONS).test_expect("CHIO_CHAOS_ITERATIONS must be a u64")
}

/// A durable Sqlite-backed config; `tool_latency` starts at zero because the
/// hung-server scenario sets the latency at runtime via `set_tool_latency_ms`.
fn sqlite_config(db_path: std::path::PathBuf) -> LoadgenConfig {
    LoadgenConfig {
        arrival_rate_hz: 1,
        duration: Duration::from_secs(1),
        tool_latency: Duration::from_millis(0),
        store: StoreBacking::Sqlite { path: db_path },
        p99_budget: Duration::from_millis(1),
        rss_growth_budget_bytes: 0,
    }
}

/// A guard whose `evaluate` blocks well past any budget, modeling a guard doing
/// synchronous blocking I/O. It ultimately allows, so if the guard-pipeline
/// deadline never fires the whole dispatch allows and the scenario's
/// InjectionNoOp check trips.
struct BlockingGuard {
    stall: Duration,
    entered: mpsc::Sender<()>,
}

impl Guard for BlockingGuard {
    fn name(&self) -> &str {
        "chaos-blocking-guard"
    }

    fn evidence_declaration(&self) -> GuardEvidenceDeclaration {
        GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        let _ = self.entered.send(());
        std::thread::sleep(self.stall);
        Ok(GuardDecision::allow())
    }
}

/// A tool server hung far past the dispatch deadline must be cut short with a
/// typed fail-closed deny, and the kernel's signed Cancelled receipt for each
/// timed-out dispatch must survive a flush.
#[test]
fn chaos_hung_tool_server_hits_deadline_and_denies() {
    let rounds = iterations();
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = sqlite_config(db_path);
    let deadlines = HotPathDeadlineConfig {
        dispatch_budget_ms: DISPATCH_BUDGET_MS,
        ..HotPathDeadlineConfig::default()
    };
    let harness = StackHarness::boot_with_deadlines(&config, deadlines)
        .test_expect("boot stack with a dispatch deadline");
    // Drive the stub tool server far past the dispatch deadline at runtime.
    harness.set_tool_latency_ms(HUNG_TOOL_LATENCY_MS);

    let floor_before = harness.flush_durable().test_expect("flush before rounds");

    for round in 0..rounds {
        let outcome = harness
            .dispatch_once_verdict()
            .test_expect("dispatch under the dispatch deadline");

        // InjectionNoOp: a normal Allow means the hung tool did not breach the
        // deadline; nothing was fault-tested this round.
        if outcome.verdict == Verdict::Allow {
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "hung-tool dispatch returned Allow; the dispatch deadline did not fire"
                )
            );
        }
        assert_eq!(
            outcome.verdict,
            Verdict::Deny,
            "round {round}: a breached dispatch deadline must deny fail-closed"
        );
        let reason = outcome.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("deadline exceeded"),
            "round {round}: deny reason must name the hot-path deadline, got {reason:?}"
        );
        assert!(
            outcome.elapsed < Duration::from_millis(HUNG_TOOL_LATENCY_MS),
            "round {round}: the deadline must cut the {HUNG_TOOL_LATENCY_MS}ms tool short, took {:?}",
            outcome.elapsed
        );
    }

    // Each timed-out dispatch emits a signed Cancelled (deny) receipt; after a
    // flush those receipts are durably committed, so the committed floor must
    // advance by at least one entry per round.
    let floor_after = harness.flush_durable().test_expect("flush after rounds");
    assert!(
        floor_after >= floor_before + rounds,
        "each timed-out dispatch must persist a deny receipt: committed floor {floor_before} -> {floor_after} over {rounds} rounds"
    );
}

/// A guard blocking far past the guard-pipeline deadline must be cut short with
/// a typed fail-closed deny.
#[test]
fn chaos_blocking_guard_times_out_fail_closed() {
    let rounds = iterations();
    let dir = tempfile::tempdir().test_unwrap();
    let db_path = dir.path().join("receipts.sqlite");

    let config = sqlite_config(db_path);
    let deadlines = HotPathDeadlineConfig {
        guard_pipeline_budget_ms: GUARD_BUDGET_MS,
        ..HotPathDeadlineConfig::default()
    };
    let mut harness = StackHarness::boot_with_deadlines(&config, deadlines)
        .test_expect("boot stack with a guard-pipeline deadline");
    let (guard_entered_sender, guard_entered_receiver) = mpsc::channel();
    harness.add_guard(Box::new(BlockingGuard {
        stall: GUARD_SLEEP,
        entered: guard_entered_sender,
    }));

    for round in 0..rounds {
        let (guard_entry, dispatch_result) = std::thread::scope(|scope| {
            let dispatch = scope.spawn(|| harness.dispatch_once_verdict());
            let guard_entry =
                guard_entered_receiver.recv_timeout(Duration::from_millis(GUARD_BUDGET_MS));
            let dispatch_result = dispatch
                .join()
                .test_expect("guard-deadline dispatch thread must not panic");
            (guard_entry, dispatch_result)
        });
        if let Err(error) = guard_entry {
            eprintln!("round {round}: blocking guard entry handshake failed: {error}");
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "blocking guard did not enter before the guard-pipeline deadline"
                )
            );
        }
        let outcome = dispatch_result.test_expect("dispatch under the guard-pipeline deadline");

        // InjectionNoOp: the guard ultimately allows, so an Allow verdict means
        // the guard-pipeline deadline never fired and the guard was never cut
        // short.
        if outcome.verdict == Verdict::Allow {
            panic!(
                "{}",
                ChaosError::InjectionNoOp(
                    "blocking-guard dispatch returned Allow; the guard-pipeline deadline did not fire"
                )
            );
        }
        assert_eq!(
            outcome.verdict,
            Verdict::Deny,
            "round {round}: a breached guard-pipeline deadline must deny fail-closed"
        );
        let reason = outcome.reason.clone().unwrap_or_default();
        assert!(
            reason.contains("deadline exceeded"),
            "round {round}: deny reason must name the hot-path deadline, got {reason:?}"
        );
        assert!(
            outcome.elapsed < GUARD_SLEEP,
            "round {round}: the deadline must cut the guard short, took {:?}",
            outcome.elapsed
        );
    }
}

/// A one-atom `chio.decision-model.v1` artifact whose single rule denies when
/// atom 0 is true. Atom 0 is exact: `tau_neg = tau_pos = 1.0`.
fn deny_on_atom_zero() -> Vec<u8> {
    const ONE: i32 = 1 << 16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CDM1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&ONE.to_le_bytes());
    bytes.extend_from_slice(&ONE.to_le_bytes());
    for (code, mask) in [(1u8, 1u64), (5, 0), (6, 0)] {
        bytes.push(code);
        bytes.push(0);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
    }
    bytes
}

fn verified_card(artifact: &[u8]) -> VerifiedModelCard {
    let card = ModelCard::new(
        weights_hash_of(artifact),
        StringSet::new(["tool:*"]),
        StringSet::new(Vec::<String>::new()),
        "synthetic",
        "https://example.com/issuer",
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .test_unwrap(),
        Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0)
            .single()
            .test_unwrap(),
    )
    .test_unwrap();
    let mut subject_digest_sha256 = [0u8; 32];
    subject_digest_sha256.copy_from_slice(&Sha256::digest(card.to_canonical_json().test_unwrap()));
    VerifiedModelCard {
        card,
        attestation: VerifiedAttestation {
            subject_digest_sha256,
            certificate_identity: "https://example.com/issuer".into(),
            certificate_oidc_issuer: "https://token.example.com".into(),
            rekor_log_index: 7,
            rekor_inclusion_verified: true,
            signed_at: std::time::SystemTime::UNIX_EPOCH,
        },
    }
}

/// A score source that is down: it counts every call and never returns scores.
struct UnavailableScores {
    calls: Arc<AtomicU64>,
}

impl ScoreSource for UnavailableScores {
    fn provided_atoms(&self) -> [u64; ATOM_WORDS] {
        let mut words = [0u64; ATOM_WORDS];
        words[0] = 1;
        words
    }

    fn scores(&self, _ctx: &GuardContext<'_>) -> Result<Scores, ScoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ScoreError::Unavailable)
    }
}

/// A decision-model guard whose score source is down must deny every call with
/// a signed receipt carrying a `scorer_error` fallback witness that charged no
/// work, never an allow and never a kernel error.
#[test]
fn chaos_decision_model_scorer_outage_denies_with_a_fallback_witness() {
    let rounds = iterations();
    let dir = tempfile::tempdir().test_unwrap();
    let config = sqlite_config(dir.path().join("receipts.sqlite"));
    let mut harness = StackHarness::boot(&config).test_expect("boot stack");

    let artifact = deny_on_atom_zero();
    let calls = Arc::new(AtomicU64::new(0));
    let guard = PredicateDagGuard::load(
        &verified_card(&artifact),
        &artifact,
        Box::new(UnavailableScores {
            calls: Arc::clone(&calls),
        }),
        &DecisionModelBinding {
            requested_scopes: StringSet::new(["tool:*"]),
            requested_tools: StringSet::new(Vec::<String>::new()),
        },
        1_000,
    )
    .test_expect("load the decision model");
    harness.add_guard(Box::new(guard));

    for round in 0..rounds {
        let outcome = harness
            .dispatch_once_verdict()
            .test_expect("dispatch with the score source down");
        if calls.load(Ordering::SeqCst) != round + 1 {
            panic!(
                "{}",
                ChaosError::InjectionNoOp("the decision-model score source was never called")
            );
        }
        assert_eq!(
            outcome.verdict,
            Verdict::Deny,
            "round {round}: a scorer outage must deny fail-closed"
        );
        assert!(
            outcome
                .receipt
                .verify_signature_with_floor(
                    &harness.receipt_signing_key().test_unwrap(),
                    ReceiptCryptoFloor::AllowClassical,
                )
                .test_unwrap(),
            "round {round}: the deny receipt must be signed"
        );
        assert!(
            outcome
                .receipt
                .evidence
                .iter()
                .any(|evidence| evidence.guard_name == PREDICATE_DAG_GUARD_NAME
                    && evidence.details.as_deref() == Some("action=deny; reason=decision-model")),
            "round {round}: the deny must carry the fixed decision-model evidence"
        );
        let metadata = outcome.receipt.metadata.clone().test_unwrap();
        let witness = &metadata[DECISION_MODEL_WITNESS_METADATA_KEY];
        assert_eq!(witness["outcome"], "deny", "round {round}");
        assert_eq!(witness["evaluation"], "fallback", "round {round}");
        assert_eq!(witness["fallback_reason"], "scorer_error", "round {round}");
        assert_eq!(witness["work_ops"], 0, "round {round}");
    }
}
