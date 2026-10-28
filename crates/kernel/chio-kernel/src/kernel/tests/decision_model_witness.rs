use super::*;
use crate::ToolCallResponse;
use chio_core::crypto::{canonical_json_bytes, sha256_hex};
use chio_core::receipt::metadata::{
    DecisionModelEvaluation, DecisionModelFallbackReason, DecisionModelOutcome,
    DecisionModelWitness, DECISION_MODEL_WITNESS_METADATA_KEY,
};

const OP_COUNT: u32 = 1_413;
const DENY_EVIDENCE: &str = "action=deny; reason=decision-model";

fn witness(outcome: DecisionModelOutcome) -> DecisionModelWitness {
    DecisionModelWitness::evaluated(
        sha256_hex(b"decision-model-card"),
        sha256_hex(b"decision-model-artifact"),
        outcome,
        OP_COUNT,
    )
    .unwrap()
}

struct WitnessGuard {
    name: &'static str,
    decision: GuardDecision,
}

impl Guard for WitnessGuard {
    fn name(&self) -> &str {
        self.name
    }
    fn evidence_declaration(&self) -> crate::GuardEvidenceDeclaration {
        crate::GuardEvidenceDeclaration::SAFE
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        Ok(self.decision.clone())
    }
}

fn allowing(name: &'static str, witness: DecisionModelWitness) -> WitnessGuard {
    WitnessGuard {
        name,
        decision: GuardDecision::allow().with_witness(witness),
    }
}

fn denying(name: &'static str, witness: Option<DecisionModelWitness>) -> WitnessGuard {
    let decision = GuardDecision::deny(vec![GuardEvidence {
        guard_name: name.to_string(),
        verdict: false,
        details: Some(DENY_EVIDENCE.to_string()),
    }]);
    WitnessGuard {
        name,
        decision: match witness {
            Some(witness) => decision.with_witness(witness),
            None => decision,
        },
    }
}

fn call(guards: Vec<WitnessGuard>, request_id: &str) -> ToolCallResponse {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    for guard in guards {
        kernel.add_guard(Box::new(guard));
    }
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request(request_id, &cap, "read_file", "srv-a");
    kernel.evaluate_tool_call_blocking(&request).unwrap()
}

fn receipt_witness(response: &ToolCallResponse) -> Option<serde_json::Value> {
    response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(DECISION_MODEL_WITNESS_METADATA_KEY))
        .cloned()
}

fn decoded(response: &ToolCallResponse) -> DecisionModelWitness {
    let value = receipt_witness(response).expect("receipt carries the witness");
    let witness: DecisionModelWitness = serde_json::from_value(value).unwrap();
    witness.validate_for_artifact(OP_COUNT).unwrap();
    witness
}

#[test]
fn allow_receipt_carries_the_guard_witness() {
    let expected = witness(DecisionModelOutcome::Allow);
    let response = call(
        vec![allowing("predicate-dag", expected.clone())],
        "req-dm-allow",
    );
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(decoded(&response), expected);
}

#[test]
fn deny_receipt_carries_the_witness_and_the_fixed_evidence() {
    let expected = witness(DecisionModelOutcome::Deny);
    let response = call(
        vec![denying("predicate-dag", Some(expected.clone()))],
        "req-dm-deny",
    );
    assert_eq!(response.verdict, Verdict::Deny);
    let witness = decoded(&response);
    assert_eq!(witness, expected);
    assert_eq!(witness.outcome, DecisionModelOutcome::Deny);
    assert_eq!(witness.evaluation, DecisionModelEvaluation::Evaluated);
    assert_eq!(response.receipt.evidence.len(), 1);
    assert_eq!(
        response.receipt.evidence[0].details.as_deref(),
        Some(DENY_EVIDENCE)
    );
}

#[test]
fn fallback_witness_binds_into_the_deny_receipt() {
    let expected = DecisionModelWitness::fallback(
        sha256_hex(b"decision-model-card"),
        sha256_hex(b"decision-model-artifact"),
        DecisionModelFallbackReason::ScorerError,
    )
    .unwrap();
    let response = call(
        vec![denying("predicate-dag", Some(expected.clone()))],
        "req-dm-fallback",
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(decoded(&response), expected);
}

#[test]
fn two_witnesses_deny_the_call_and_bind_neither() {
    let response = call(
        vec![
            allowing("predicate-dag-a", witness(DecisionModelOutcome::Allow)),
            allowing("predicate-dag-b", witness(DecisionModelOutcome::Allow)),
        ],
        "req-dm-duplicate",
    );
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("duplicate decision-model witness"),
        "reason was: {reason}"
    );
    assert_eq!(receipt_witness(&response), None);
}

#[test]
fn malformed_witness_denies_the_call_and_is_not_bound() {
    let mut malformed = witness(DecisionModelOutcome::Allow);
    malformed.fallback_reason = Some(DecisionModelFallbackReason::ScorerError);
    let response = call(
        vec![allowing("predicate-dag", malformed)],
        "req-dm-malformed",
    );
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("decision-model witness"),
        "reason was: {reason}"
    );
    assert_eq!(receipt_witness(&response), None);
}

/// The witness records the decision-model guard's own outcome: when it allows
/// and a later guard denies, the deny receipt carries `outcome: allow`,
/// byte-identical to the witness of an allowed call with the same tuple.
#[test]
fn later_guard_deny_keeps_the_witness_outcome_allow() {
    let allowed = call(
        vec![allowing(
            "predicate-dag",
            witness(DecisionModelOutcome::Allow),
        )],
        "req-dm-control-allow",
    );
    let denied = call(
        vec![
            allowing("predicate-dag", witness(DecisionModelOutcome::Allow)),
            denying("later-guard", None),
        ],
        "req-dm-control-deny",
    );
    assert_eq!(allowed.verdict, Verdict::Allow, "{:?}", allowed.reason);
    assert_eq!(denied.verdict, Verdict::Deny);
    let allowed = decoded(&allowed);
    let denied = decoded(&denied);
    assert_eq!(denied.outcome, DecisionModelOutcome::Allow);
    assert_eq!(
        canonical_json_bytes(&allowed).unwrap(),
        canonical_json_bytes(&denied).unwrap()
    );
}

#[test]
fn guard_without_a_witness_writes_no_block() {
    let response = call(vec![denying("plain-deny", None)], "req-dm-none");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(receipt_witness(&response), None);
}
