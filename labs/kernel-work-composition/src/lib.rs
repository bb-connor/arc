//! Executable research model, not a Chio native implementation.
pub mod baseline;
pub mod continuation;
mod exploration;
pub mod model;
use model::{Command, Fault, Oracle, State};
use serde_json::{Value, json};
#[derive(Clone, Copy, Debug)]
pub enum Arm {
    Candidate,
    Baseline,
    DenyAll,
    RetryAll,
    Removal(&'static str),
}

pub fn decide(s: &State, c: &Command, arm: Arm) -> (bool, usize) {
    if matches!(arm, Arm::Baseline) {
        return baseline::decide(s, c);
    }
    let checks = continuation::obligations(s, c);
    let removed = match arm {
        Arm::RetryAll => Some("one_send"),
        Arm::Removal("owners") => Some("owners"),
        Arm::Removal("one_send") => Some("one_send"),
        Arm::Removal("backing") => Some("backing"),
        Arm::Removal("lifetime") => Some("lifetime"),
        _ => None,
    };
    let mut allowed = checks.iter().all(|c| Some(c.rule) == removed || c.holds);
    if matches!(arm, Arm::DenyAll)
        && matches!(
            c,
            Command::Capture { .. }
                | Command::Send { .. }
                | Command::Release { .. }
                | Command::Pay { .. }
                | Command::ReadResult { .. }
        )
    {
        allowed = false;
    }
    if matches!(arm, Arm::Removal("settlement")) && matches!(c, Command::Settle { .. }) {
        allowed = allowed && s.caller && s.read;
    }
    (allowed, checks.len())
}
pub(crate) fn step(
    s: &mut State,
    c: &Command,
    arm: Arm,
    fault: &Fault,
    oracle: &mut Oracle,
) -> (bool, usize) {
    let (allowed, mut cost) = decide(s, c, arm);
    let feasible = if allowed && matches!(c,Command::Plan{limit,registered:true} if *limit>0) {
        let (ok, checks) = decide(
            s,
            &Command::Capture {
                op: 0,
                epoch: s.epoch,
                mode: "live".into(),
            },
            arm,
        );
        cost += checks;
        ok
    } else {
        false
    };
    model::apply(s, c, allowed, fault, oracle);
    if feasible {
        s.advice = "feasible".into();
    }
    (allowed, cost)
}
pub fn fixture_data() -> Result<Value, String> {
    serde_json::from_str(include_str!(
        "../../../docs/research/kernel-work/fixtures.json"
    ))
    .map_err(|e| e.to_string())
}
pub fn run(fixture: &Value, arm: Arm) -> Result<Value, String> {
    let profile = fixture["profile"].as_str().ok_or("missing profile")?;
    let commands: Vec<Command> =
        serde_json::from_value(fixture["commands"].clone()).map_err(|e| e.to_string())?;
    let faults: Vec<Fault> =
        serde_json::from_value(fixture["faults"].clone()).map_err(|e| e.to_string())?;
    let mut s = State::new(profile, &fixture["initial_state"])?;
    let mut oracle = Oracle::default();
    let mut steps = Vec::new();
    let mut accepted = Vec::new();
    let mut predicate_checks = 0;
    for (index, c) in commands.iter().enumerate() {
        let fault = faults
            .iter()
            .find(|f| f.at == index)
            .cloned()
            .unwrap_or_default();
        let (allowed, cost) = step(&mut s, c, arm, &fault, &mut oracle);
        predicate_checks += cost;
        accepted.push(allowed);
        let mut view = s.view();
        view["effects"] = json!(oracle.effects);
        steps.push(view);
    }
    let mut view = s.view();
    view["effects"] = json!(oracle.effects);
    view["accepted"] = json!(accepted);
    Ok(json!({"view":view,"steps":steps,"controller_state":s,"predicate_checks":predicate_checks}))
}
pub fn explore() -> Result<Value, String> {
    exploration::explore()
}
