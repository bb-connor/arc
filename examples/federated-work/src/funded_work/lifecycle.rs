//! End-to-end private Finding and observed settlement reproduction.
use super::{
    evidence::{self, Submission},
    native::Native,
    settlement::{self, Action},
    smoke::{setup, Scenario},
    verification::{self, Decision, PythonChecker},
};
use crate::common::{self, Result};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};

pub fn run(state: &Path, mode: &str) -> Result<Value> {
    if !["pay", "reject", "absent", "unavailable", "preexpired"].contains(&mode) {
        return Err("unsupported lifecycle mode".into());
    }
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(state)?;
    chain.request(json!({"method":"pin-verifier","key":native.policy.verifier_key.to_hex()}))?;
    let first = native.execute(&agreement, &request)?;
    if mode == "preexpired" {
        chain.request(
            json!({"method":"advance","allocation":funding["allocationId"],"phase":"refund"}),
        )?;
        chain.request(json!({"method":"expire","allocation":funding["allocationId"]}))?;
    }
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    let step = progress(state, &native, &request, mode, &checkpoint, &|phase| {
        chain.request(
            json!({"method":"advance","allocation":funding["allocationId"],"phase":phase}),
        )?;
        Ok(())
    })?;
    drop(native);
    let recovered = Native::open(state, chain.clone())?;
    let replay = recovered.execute(&agreement, &request)?;
    let summary =
        chain.request(json!({"method":"summary","allocation":funding["allocationId"]}))?;
    Ok(json!({"first":first,"verification":step,"replay":replay,"chain":summary}))
}

pub(super) fn progress(
    state: &Path,
    native: &Native,
    request: &chio_kernel::ToolCallRequest,
    mode: &str,
    checkpoint: &super::Checkpoint,
    advance: &dyn Fn(&str) -> Result<()>,
) -> Result<Value> {
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("original lifecycle request missing")?;
    let drive = |action| {
        settlement::drive(
            &entry,
            action,
            &native.policy,
            &native.journal,
            native.source.as_ref(),
            &action_checkpoint(action, checkpoint.clone()),
        )
    };
    let started = common::now()?;
    let snapshot = native.source.observe(&entry.allocation)?;
    let (_, work) = super::observer::verify_snapshot(
        &native.policy.domain,
        &entry.agreement.body.terms()?,
        &snapshot,
        started,
        common::now()?,
        false,
    )?;
    let chain_time = snapshot.independent_head.timestamp;
    if (work.state == 1 && chain_time > entry.agreement.body.work.submit_by)
        || (work.state == 2 && chain_time > entry.agreement.body.work.resolve_by)
        || matches!(work.state, 6 | 7)
    {
        advance("refund")?;
        drive(Action::Refund)?;
        return Ok(
            json!({"decision":if work.decisionDigest != alloy_primitives::B256::ZERO {"verified-rejection"}
            else if mode == "absent" || mode == "preexpired" {"absent"} else if mode == "unavailable" {"unavailable"} else {"unrecorded-expired"},"financial":"refund"}),
        );
    }
    if mode == "absent" {
        advance("refund")?;
        drive(Action::Refund)?;
        return Ok(json!({"decision":"absent","finding":null,"financial":"refund"}));
    }
    let original = native.evidence(request)?;
    let submission: Submission = match native.journal.retained(&entry.allocation, "submission")? {
        Some(submission) => submission,
        None => {
            let output = if mode == "reject" {
                json!([])
            } else {
                original.output.clone()
            };
            let submission =
                evidence::submit(&original, &output, &common::key(state)?, &native.journal)?;
            native
                .journal
                .retain(&entry.allocation, "submission", &submission)?;
            submission
        }
    };
    checkpoint("after-submission")?;
    let claim = drive(Action::Submit)?;
    checkpoint("after-claim")?;
    if mode == "unavailable" {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Unavailable(AtomicBool);
        impl verification::Checker for Unavailable {
            fn check(&self, _input: &str) -> Result<Value> {
                self.0.store(true, Ordering::SeqCst);
                Err("injected independent verifier outage".into())
            }
        }
        advance("decision")?;
        let claim = drive(Action::Submit)?;
        let unavailable = Unavailable(AtomicBool::new(false));
        if verification::decide(
            &original,
            &submission,
            &claim,
            &verification::Verifier {
                policy: &native.policy,
                custody: &native.journal,
                key: &common::key(&state.join("verifier"))?,
                checker: &unavailable,
            },
        )
        .is_ok()
            || !unavailable.0.load(Ordering::SeqCst)
            || native
                .journal
                .retained::<Decision>(&entry.allocation, "decision")?
                .is_some()
        {
            return Err("unavailable verifier produced a decision".into());
        }
        advance("refund")?;
        drive(Action::Refund)?;
        return Ok(
            json!({"decision":"unavailable","findingId":submission.body.finding.finding_id,"financial":"refund"}),
        );
    }
    if claim.chain_time > entry.agreement.body.work.resolve_by && matches!(claim.state, 2 | 7) {
        advance("refund")?;
        drive(Action::Refund)?;
        return Ok(
            json!({"decision":"unrecorded-expired","findingId":submission.body.finding.finding_id,"financial":"refund"}),
        );
    }
    let decision: Decision = match native.journal.retained(&entry.allocation, "decision")? {
        Some(decision) => {
            verification::verify_decision(&decision, &submission, &native.policy)?;
            decision
        }
        None => {
            advance("decision")?;
            let claim = drive(Action::Submit)?;
            let python = PythonChecker(
                std::env::var_os("CHIO_FUNDED_PYTHON")
                    .unwrap_or_else(|| "python3".into())
                    .into(),
            );
            verification::decide(
                &original,
                &submission,
                &claim,
                &verification::Verifier {
                    policy: &native.policy,
                    custody: &native.journal,
                    key: &common::key(&state.join("verifier"))?,
                    checker: &python,
                },
            )?
        }
    };
    checkpoint("after-decision")?;
    drive(Action::Record)?;
    checkpoint("after-recorded-decision")?;
    if mode == "earn" {
        if !decision.body.accepted {
            return Err("earned child requires accepted work".into());
        }
        return Ok(json!({"financial":"payable","findingId":submission.body.finding.finding_id}));
    }
    let paid = decision.body.accepted;
    let observed = drive(if paid { Action::Pay } else { Action::Refund })?;
    checkpoint("before-native-acknowledgement")?;
    Ok(
        json!({"findingId":submission.body.finding.finding_id,"commitment":decision.body.commitment,
        "decision":"verified","accepted":paid,"decisionSha256":common::digest(&decision.body)?,
        "financial":if paid {"payout"} else {"refund"},"transactionHash":observed.transaction_hash,
        "observationSha256":observed.observation_sha256,"findingAssessment":decision.body.finding_assessment,
        "findingAssurance":"asserted-finding-with-explicit-facets-and-independent-w0-checks"}),
    )
}

fn action_checkpoint(action: Action, checkpoint: super::Checkpoint) -> super::Checkpoint {
    Arc::new(move |point| {
        checkpoint(match (action, point) {
            (Action::Submit, "after-prepare") => "claim-after-prepare",
            (Action::Submit, "after-broadcast") => "claim-after-broadcast",
            (Action::Submit, "after-observation") => "claim-after-observation",
            (Action::Record, "after-prepare") => "decision-after-prepare",
            (Action::Record, "after-broadcast") => "decision-after-broadcast",
            (Action::Record, "after-observation") => "decision-after-observation",
            (Action::Pay, "after-prepare") => "pay-after-prepare",
            (Action::Pay, "after-broadcast") => "pay-after-broadcast",
            (Action::Pay, "after-observation") => "pay-after-observation",
            (Action::Refund, "after-prepare") => "refund-after-prepare",
            (Action::Refund, "after-broadcast") => "refund-after-broadcast",
            (Action::Refund, "after-observation") => "refund-after-observation",
            _ => point,
        })
    })
}
