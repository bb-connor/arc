//! The predicate DAG guard: load-time refusals, verdict projection, the
//! receipt witness and the D12 work-metering stages.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_attest_verify::VerifiedAttestation;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::metadata::{
    DecisionModelEvaluation, DecisionModelFallbackReason, DecisionModelOutcome,
    DECISION_MODEL_WITNESS_METADATA_KEY,
};
use chio_fixed::Q16_16;
use chio_guards::{
    AtomPredicate, DecisionModelBinding, DecisionModelLoadError, ExactPredicateSource, JsonKind,
    PredicateDagGuard, ScoreError, ScoreSource, Scores,
};
use chio_kernel::{
    ChioKernel, Guard, GuardContext, GuardDecision, KernelConfig, KernelError, ToolCallRequest,
    ToolServerConnection, Verdict,
};
use chio_predicate_dag::{RulePolarity, ATOM_WORDS};
use chio_security_types::work::{VerificationBudget, WorkBudgetError};
use chio_weights::{ModelCard, StringSet, VerifiedModelCard};
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

const DENY_EVIDENCE: &str = "action=deny; reason=decision-model";
const ONE: i32 = 1 << 16;

/// A `chio.decision-model.v1` artifact of single-atom rules: rule `i` fires
/// on atom `atoms[i].0` with polarity `atoms[i].1`. Every atom is exact:
/// `tau_neg = tau_pos = 1.0`.
fn artifact(atom_count: u16, rules: &[(u16, RulePolarity)]) -> Vec<u8> {
    let mut ops: Vec<(u8, u8, u16, u64)> = Vec::new();
    for (id, (atom, polarity)) in rules.iter().enumerate() {
        ops.push((1, u8::try_from(atom / 64).unwrap(), 0, 1u64 << (atom % 64)));
        ops.push((5, 0, 0, 0));
        let code = match polarity {
            RulePolarity::Deny => 0,
            RulePolarity::Hold => 1,
            RulePolarity::Advisory => 2,
        };
        ops.push((6, code, u16::try_from(id).unwrap(), 0));
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"CDM1");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&atom_count.to_le_bytes());
    out.extend_from_slice(&u16::try_from(rules.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&u32::try_from(ops.len()).unwrap().to_le_bytes());
    for _ in 0..atom_count {
        out.extend_from_slice(&ONE.to_le_bytes());
        out.extend_from_slice(&ONE.to_le_bytes());
    }
    for (code, word, arg, mask) in ops {
        out.push(code);
        out.push(word);
        out.extend_from_slice(&arg.to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
    }
    out
}

fn card_for(artifact: &[u8], banned_tools: &[&str]) -> VerifiedModelCard {
    let card = ModelCard::new(
        sha256_hex(artifact),
        StringSet::new(["tool:*"]),
        StringSet::new(banned_tools.iter().copied()),
        "synthetic",
        "https://example.com/issuer",
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap(),
    )
    .unwrap();
    let bytes = card.to_canonical_json().unwrap();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&Sha256::digest(&bytes));
    VerifiedModelCard {
        card,
        attestation: VerifiedAttestation {
            subject_digest_sha256: digest,
            certificate_identity: "https://example.com/issuer".into(),
            certificate_oidc_issuer: "https://token.example.com".into(),
            rekor_log_index: 7,
            rekor_inclusion_verified: true,
            signed_at: std::time::SystemTime::UNIX_EPOCH,
        },
    }
}

fn binding() -> DecisionModelBinding {
    DecisionModelBinding {
        requested_scopes: StringSet::new(["tool:*"]),
        requested_tools: StringSet::new(["write_file"]),
    }
}

/// Atom 0: the call carries a `path` argument. Atom 1: the tool is
/// `delete_file`.
fn exact_source() -> Box<dyn ScoreSource> {
    Box::new(ExactPredicateSource::new(vec![
        AtomPredicate::ArgumentPresent("path".into()),
        AtomPredicate::ToolName("delete_file".into()),
    ]))
}

struct FixedScores(Result<Scores, ScoreError>, usize);

impl ScoreSource for FixedScores {
    fn provided_atoms(&self) -> [u64; ATOM_WORDS] {
        let mut words = [0u64; ATOM_WORDS];
        for atom in 0..self.1 {
            words[atom / 64] |= 1 << (atom % 64);
        }
        words
    }
    fn scores(&self, _ctx: &GuardContext<'_>) -> Result<Scores, ScoreError> {
        self.0.clone()
    }
}

fn scores(values: &[i32], attested: &[bool]) -> Scores {
    let mut words = [0u64; ATOM_WORDS];
    for (atom, set) in attested.iter().enumerate() {
        if *set {
            words[atom / 64] |= 1 << (atom % 64);
        }
    }
    Scores {
        scores: values.iter().map(|v| Q16_16::from_bits(*v)).collect(),
        attested: words,
    }
}

fn request(tool: &str, args: serde_json::Value) -> (ToolCallRequest, ChioScope, String, String) {
    let kp = Keypair::generate();
    let scope = ChioScope::default();
    let body = chio_core::capability::token::CapabilityTokenBody {
        id: "cap-dag".to_string(),
        issuer: kp.public_key(),
        subject: kp.public_key(),
        scope: scope.clone(),
        issued_at: 0,
        expires_at: u64::MAX,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    let capability = chio_core::capability::token::CapabilityToken::sign(body, &kp).unwrap();
    let request = ToolCallRequest {
        request_id: "req-dag".to_string(),
        capability,
        tool_name: tool.to_string(),
        server_id: "srv".to_string(),
        agent_id: kp.public_key().to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    (request, scope, kp.public_key().to_hex(), "srv".to_string())
}

fn decide(guard: &PredicateDagGuard, tool: &str, args: serde_json::Value) -> GuardDecision {
    let (request, scope, agent, server) = request(tool, args);
    let mut ctx = GuardContext::new(&request, &scope);
    ctx.agent_id = &agent;
    ctx.server_id = &server;
    guard.evaluate(&ctx).unwrap()
}

fn decide_with_budget(guard: &PredicateDagGuard, budget: &mut VerificationBudget) -> GuardDecision {
    let (request, scope, agent, server) = request("write_file", serde_json::json!({}));
    let mut ctx = GuardContext::new(&request, &scope);
    ctx.agent_id = &agent;
    ctx.server_id = &server;
    guard.evaluate_with_budget(&ctx, budget).unwrap()
}

fn load(
    artifact: &[u8],
    source: Box<dyn ScoreSource>,
    work_cap: u32,
) -> Result<PredicateDagGuard, DecisionModelLoadError> {
    PredicateDagGuard::load(
        &card_for(artifact, &[]),
        artifact,
        source,
        &binding(),
        work_cap,
    )
}

fn deny_on_path() -> Vec<u8> {
    artifact(2, &[(0, RulePolarity::Deny)])
}

#[test]
fn allow_carries_a_validated_witness_bound_to_the_card_and_artifact() {
    let bytes = deny_on_path();
    let card = card_for(&bytes, &[]);
    let guard = PredicateDagGuard::load(&card, &bytes, exact_source(), &binding(), 1_000).unwrap();
    let decision = decide(&guard, "write_file", serde_json::json!({"content": "x"}));
    assert_eq!(decision.verdict, Verdict::Allow);
    assert!(decision.evidence.is_empty());
    let witness = decision.witness.expect("allow carries a witness");
    witness.validate_for_artifact(guard.op_count()).unwrap();
    assert_eq!(witness.outcome, DecisionModelOutcome::Allow);
    assert_eq!(witness.evaluation, DecisionModelEvaluation::Evaluated);
    assert_eq!(witness.artifact_digest, sha256_hex(&bytes));
    assert_eq!(
        witness.model_card_digest,
        sha256_hex(&card.card.to_canonical_json().unwrap())
    );
    assert_eq!(witness.work_ops, guard.op_count());
}

#[test]
fn a_fired_deny_rule_denies_with_the_fixed_evidence_and_no_rule_id() {
    let guard = load(&deny_on_path(), exact_source(), 1_000).unwrap();
    let decision = decide(&guard, "write_file", serde_json::json!({"path": "/etc"}));
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(decision.evidence.len(), 1);
    assert_eq!(decision.evidence[0].guard_name, "predicate-dag");
    assert!(!decision.evidence[0].verdict);
    assert_eq!(decision.evidence[0].details.as_deref(), Some(DENY_EVIDENCE));
    let witness = decision.witness.unwrap();
    assert_eq!(witness.outcome, DecisionModelOutcome::Deny);
    assert_eq!(witness.evaluation, DecisionModelEvaluation::Evaluated);
    assert_eq!(witness.fallback_reason, None);
}

#[test]
fn a_fired_hold_rule_is_pending_approval() {
    let guard = load(
        &artifact(2, &[(1, RulePolarity::Hold)]),
        exact_source(),
        1_000,
    )
    .unwrap();
    let decision = decide(&guard, "delete_file", serde_json::json!({}));
    assert_eq!(decision.verdict, Verdict::PendingApproval);
    assert_eq!(
        decision.witness.unwrap().outcome,
        DecisionModelOutcome::Hold
    );
}

#[test]
fn an_unattested_atom_under_a_deny_rule_is_pending_approval() {
    let bytes = deny_on_path();
    let source = Box::new(FixedScores(Ok(scores(&[ONE, 0], &[false, true])), 2));
    let guard = load(&bytes, source, 1_000).unwrap();
    let decision = decide(&guard, "write_file", serde_json::json!({}));
    assert_eq!(decision.verdict, Verdict::PendingApproval);
    let witness = decision.witness.unwrap();
    assert_eq!(witness.outcome, DecisionModelOutcome::Hold);
    assert_eq!(witness.evaluation, DecisionModelEvaluation::Evaluated);
}

#[test]
fn equal_public_tuples_give_identical_witnesses_and_evidence_whatever_the_arguments() {
    let guard = load(&deny_on_path(), exact_source(), 1_000).unwrap();
    let a = decide(&guard, "write_file", serde_json::json!({"path": "/a"}));
    let b = decide(
        &guard,
        "write_file",
        serde_json::json!({"path": "/b", "mode": 7}),
    );
    assert_eq!(
        serde_json::to_vec(&a.witness).unwrap(),
        serde_json::to_vec(&b.witness).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&a.evidence).unwrap(),
        serde_json::to_vec(&b.evidence).unwrap()
    );
}

#[test]
fn load_refuses_a_card_bound_to_other_weights() {
    let bytes = deny_on_path();
    let card = card_for(b"other weights", &[]);
    let refused = PredicateDagGuard::load(&card, &bytes, exact_source(), &binding(), 1_000);
    assert!(matches!(refused, Err(DecisionModelLoadError::Binding(_))));
}

#[test]
fn load_refuses_a_card_banning_a_requested_tool() {
    let bytes = deny_on_path();
    let card = card_for(&bytes, &["write_file"]);
    let refused = PredicateDagGuard::load(&card, &bytes, exact_source(), &binding(), 1_000);
    assert!(matches!(refused, Err(DecisionModelLoadError::Binding(_))));
}

#[test]
fn load_refuses_an_attestation_for_different_card_bytes() {
    let bytes = deny_on_path();
    let mut card = card_for(&bytes, &[]);
    card.attestation.subject_digest_sha256 = [7u8; 32];
    let refused = PredicateDagGuard::load(&card, &bytes, exact_source(), &binding(), 1_000);
    assert!(matches!(
        refused,
        Err(DecisionModelLoadError::CardDigestMismatch)
    ));
}

#[test]
fn load_refuses_an_atom_the_source_does_not_provide() {
    let bytes = artifact(3, &[(2, RulePolarity::Deny)]);
    let refused = load(&bytes, exact_source(), 1_000);
    assert!(matches!(
        refused,
        Err(DecisionModelLoadError::UnprovidedAtom { atom: 2 })
    ));
}

#[test]
fn load_refuses_a_source_that_scores_atoms_the_artifact_lacks() {
    let bytes = artifact(1, &[(0, RulePolarity::Deny)]);
    assert!(matches!(
        load(&bytes, exact_source(), 1_000),
        Err(DecisionModelLoadError::SourceCoverage { atoms: 1 })
    ));
}

#[test]
fn load_refuses_a_malformed_artifact() {
    let mut bytes = deny_on_path();
    bytes[0] = b'X';
    assert!(matches!(
        load(&bytes, exact_source(), 1_000),
        Err(DecisionModelLoadError::Artifact(_))
    ));
}

#[test]
fn load_refuses_a_work_cap_below_the_schedule() {
    let bytes = deny_on_path();
    let ops = load(&bytes, exact_source(), 1_000).unwrap().op_count();
    assert!(matches!(
        load(&bytes, exact_source(), ops - 1),
        Err(DecisionModelLoadError::WorkCapBelowSchedule { cap, ops: o }) if cap == ops - 1 && o == ops
    ));
    assert!(load(&bytes, exact_source(), ops).is_ok());
}

#[test]
fn a_score_source_error_denies_with_a_scorer_error_fallback_and_charges_nothing() {
    let source = Box::new(FixedScores(Err(ScoreError::Unavailable), 2));
    let guard = load(&deny_on_path(), source, 1_000).unwrap();
    let mut budget = VerificationBudget::new(10, 1_000).unwrap();
    let decision = decide_with_budget(&guard, &mut budget);
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(decision.evidence[0].details.as_deref(), Some(DENY_EVIDENCE));
    let witness = decision.witness.unwrap();
    witness.validate().unwrap();
    assert_eq!(witness.outcome, DecisionModelOutcome::Deny);
    assert_eq!(witness.evaluation, DecisionModelEvaluation::Fallback);
    assert_eq!(
        witness.fallback_reason,
        Some(DecisionModelFallbackReason::ScorerError)
    );
    assert_eq!(witness.work_ops, 0);
    assert_eq!(budget.remaining(), 10);
}

#[test]
fn a_budget_one_below_the_schedule_falls_back_and_exhausts_the_meter() {
    let source = Box::new(FixedScores(Ok(scores(&[0, 0], &[true, true])), 2));
    let guard = load(&deny_on_path(), source, 1_000).unwrap();
    let n = guard.op_count();
    let mut budget = VerificationBudget::new(n - 1, 1_000).unwrap();
    let decision = decide_with_budget(&guard, &mut budget);
    assert_eq!(decision.verdict, Verdict::Deny);
    let witness = decision.witness.unwrap();
    assert_eq!(
        witness.fallback_reason,
        Some(DecisionModelFallbackReason::WorkExhausted)
    );
    assert_eq!(witness.work_ops, 0);
    assert_eq!(budget.remaining(), 0);
    assert_eq!(budget.charge(0), Err(WorkBudgetError::Exhausted));
}

#[test]
fn a_budget_equal_to_the_schedule_evaluates_and_leaves_zero() {
    let source = Box::new(FixedScores(Ok(scores(&[0, 0], &[true, true])), 2));
    let guard = load(&deny_on_path(), source, 1_000).unwrap();
    let n = guard.op_count();
    let mut budget = VerificationBudget::new(n, 1_000).unwrap();
    let decision = decide_with_budget(&guard, &mut budget);
    assert_eq!(decision.verdict, Verdict::Allow);
    assert_eq!(decision.witness.unwrap().work_ops, n);
    assert_eq!(budget.remaining(), 0);
}

#[test]
fn a_budget_above_the_schedule_is_charged_exactly_once() {
    let source = Box::new(FixedScores(Ok(scores(&[0, 0], &[true, true])), 2));
    let guard = load(&deny_on_path(), source, 1_000).unwrap();
    let n = guard.op_count();
    let mut budget = VerificationBudget::new(n + 1, 1_000).unwrap();
    let decision = decide_with_budget(&guard, &mut budget);
    assert_eq!(decision.verdict, Verdict::Allow);
    assert_eq!(budget.remaining(), 1);
}

#[test]
fn exact_predicates_read_argument_types_without_copying_values() {
    let bytes = artifact(2, &[(0, RulePolarity::Deny)]);
    let source = Box::new(ExactPredicateSource::new(vec![
        AtomPredicate::ArgumentKind {
            key: "path".into(),
            kind: JsonKind::String,
        },
        AtomPredicate::ServerId("srv".into()),
    ]));
    let guard = load(&bytes, source, 1_000).unwrap();
    assert_eq!(
        decide(&guard, "write_file", serde_json::json!({"path": "/x"})).verdict,
        Verdict::Deny
    );
    assert_eq!(
        decide(&guard, "write_file", serde_json::json!({"path": 3})).verdict,
        Verdict::Allow
    );
}

#[test]
fn a_scorer_failure_is_a_deny_decision_not_a_guard_error() {
    let source = Box::new(FixedScores(Err(ScoreError::Unavailable), 2));
    let guard = load(&deny_on_path(), source, 1_000).unwrap();
    let (request, scope, agent, server) = request("write_file", serde_json::json!({}));
    let mut ctx = GuardContext::new(&request, &scope);
    ctx.agent_id = &agent;
    ctx.server_id = &server;
    let result: Result<GuardDecision, KernelError> = guard.evaluate(&ctx);
    assert!(matches!(result, Ok(ref decision) if decision.verdict == Verdict::Deny));
}

struct EchoServer;

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        "srv"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["*".to_string()]
    }
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({ "tool": tool_name, "echo": arguments }))
    }
}

fn kernel_with(guard: PredicateDagGuard) -> ChioKernel {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.register_tool_server(Box::new(EchoServer));
    kernel.add_guard(Box::new(guard));
    kernel
}

fn kernel_request(kernel: &ChioKernel, args: serde_json::Value) -> ToolCallRequest {
    let agent = Keypair::generate();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let capability = kernel
        .issue_capability(&agent.public_key(), scope, 300)
        .unwrap();
    let (mut request, _, _, _) = request("write_file", args);
    request.capability = capability;
    request.agent_id = agent.public_key().to_hex();
    request
}

async fn dispatch(args: serde_json::Value) -> chio_kernel::ToolCallResponse {
    let kernel = kernel_with(load(&deny_on_path(), exact_source(), 1_000).unwrap());
    let request = kernel_request(&kernel, args);
    kernel.evaluate_tool_call(&request).await.unwrap()
}

#[tokio::test]
async fn an_allow_receipt_signs_the_guard_witness() {
    let args = serde_json::json!({"content": "x"});
    let expected = decide(
        &load(&deny_on_path(), exact_source(), 1_000).unwrap(),
        "write_file",
        args.clone(),
    )
    .witness
    .unwrap();
    let response = dispatch(args).await;
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.verify_signature().unwrap());
    let metadata = response.receipt.metadata.unwrap();
    assert_eq!(
        metadata[DECISION_MODEL_WITNESS_METADATA_KEY],
        serde_json::to_value(&expected).unwrap()
    );
}

#[tokio::test]
async fn a_deny_receipt_signs_the_guard_witness_and_only_the_fixed_evidence() {
    let response = dispatch(serde_json::json!({"path": "/etc"})).await;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature().unwrap());
    let dag_evidence: Vec<_> = response
        .receipt
        .evidence
        .iter()
        .filter(|evidence| evidence.guard_name == "predicate-dag")
        .collect();
    assert_eq!(dag_evidence.len(), 1);
    assert_eq!(dag_evidence[0].details.as_deref(), Some(DENY_EVIDENCE));
    let metadata = response.receipt.metadata.unwrap();
    let witness = &metadata[DECISION_MODEL_WITNESS_METADATA_KEY];
    assert_eq!(witness["outcome"], "deny");
    assert_eq!(witness["evaluation"], "evaluated");
}

/// The schedule storage holds about 1 MiB of ops. Loading must never stage
/// it on the stack, so a load on a thread far smaller than the storage
/// succeeds in an unoptimized build.
#[test]
fn load_never_stages_the_schedule_storage_on_the_stack() {
    let loaded = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| load(&deny_on_path(), exact_source(), 1_000).is_ok())
        .unwrap()
        .join()
        .unwrap();
    assert!(loaded);
}
