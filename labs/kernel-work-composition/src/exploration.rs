use crate::{
    Arm, decide, fixture_data,
    model::{self, Command, Fault, Oracle, Outcome, State},
    run,
};
use serde_json::{Value, json};

#[derive(Clone)]
struct Event {
    command: Command,
    fault: Fault,
}
fn event(value: Value) -> Result<Event, String> {
    Ok(Event {
        command: serde_json::from_value(value).map_err(|e| e.to_string())?,
        fault: Fault::default(),
    })
}
fn fixture<'a>(data: &'a Value, id: &str) -> Result<&'a Value, String> {
    data["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .flat_map(|f| f["variants"].as_array().into_iter().flatten())
        .find(|f| f["id"] == id)
        .ok_or_else(|| format!("fixture {id}"))
}
fn seed(data: &Value, id: &str, count: usize) -> Result<(State, Oracle), String> {
    let f = fixture(data, id)?;
    let mut s = State::new(f["profile"].as_str().ok_or("profile")?, &f["initial_state"])?;
    let mut oracle = Oracle::default();
    let commands: Vec<Command> =
        serde_json::from_value(f["commands"].clone()).map_err(|e| e.to_string())?;
    let faults: Vec<Fault> =
        serde_json::from_value(f["faults"].clone()).map_err(|e| e.to_string())?;
    for (i, c) in commands.iter().take(count).enumerate() {
        let fault = faults
            .iter()
            .find(|f| f.at == i)
            .cloned()
            .unwrap_or_default();
        let (allowed, _) = decide(&s, c, Arm::Candidate);
        model::apply(&mut s, c, allowed, &fault, &mut oracle);
    }
    Ok((s, oracle))
}
fn invariants(old: &State, s: &State, old_oracle: &Oracle, oracle: &Oracle) -> bool {
    if s.allocated() > s.wallet
        || s.recovery_spent > 3
        || (s.knowledge & old.knowledge) != old.knowledge
    {
        return false;
    }
    if s.view()["exposure"].as_u64().is_none_or(|n| n > 10) {
        return false;
    }
    for (i, o) in s.ops.iter().enumerate() {
        if oracle.effects[i] > 1 || o.nonces != o.captures || o.captures > 1 {
            return false;
        }
        if oracle.effects[i] > old_oracle.effects[i] && old.ops[i].captures != 1 {
            return false;
        }
        if old.ops[i].attempted && !o.attempted {
            return false;
        }
        if !o.history.starts_with(&old.ops[i].history) {
            return false;
        }
    }
    for (id, f) in &old.funds {
        if f.earned
            && !s
                .funds
                .get(id)
                .is_some_and(|n| n.earned && n.amount == f.amount && n.beneficiary == f.beneficiary)
        {
            return false;
        }
    }
    true
}
struct Counts {
    transitions: u64,
    violations: u64,
    divergences: u64,
    excluded: u64,
    max_state: usize,
    max_checks: usize,
    first: Option<Value>,
}
fn visit(
    states: (&State, &State),
    oracles: (&Oracle, &Oracle),
    alphabet: &[Event],
    depth: usize,
    trace: &mut Vec<Value>,
    counts: &mut Counts,
) -> Result<(), String> {
    let (s, b) = states;
    let (oracle, b_oracle) = oracles;
    if depth == 0 {
        return Ok(());
    }
    for event in alphabet {
        // E1 is a qualified truthful source. A contradictory terminal transcript
        // is deliberately admitted as a robustness probe, but a false first
        // authoritative result is outside that trust premise. This filter is
        // experiment-only and its excluded prefixes are counted explicitly.
        if let Command::Evidence {
            op,
            key,
            basis,
            outcome,
            signer,
            ..
        } = &event.command
            && *op < 3
            && *key == *op as u64 + 1
            && *signer == 9
            && s.ops[*op].finalized.is_some_and(|f| f.2 == *basis)
            && !s.ops[*op].outcome.terminal()
        {
            let physical = oracle.effects[*op] > 0;
            if (*outcome == Outcome::None && physical)
                || (*outcome == Outcome::Applied && !physical)
            {
                counts.excluded += 1;
                continue;
            }
        }
        let (allow, cost) = decide(s, &event.command, Arm::Candidate);
        let (b_allow, _) = decide(b, &event.command, Arm::Baseline);
        let mut next = s.clone();
        let mut b_next = b.clone();
        let mut next_o = oracle.clone();
        let mut next_bo = b_oracle.clone();
        model::apply(&mut next, &event.command, allow, &event.fault, &mut next_o);
        model::apply(
            &mut b_next,
            &event.command,
            b_allow,
            &event.fault,
            &mut next_bo,
        );
        counts.transitions += 1;
        counts.max_checks = counts.max_checks.max(cost);
        let n = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
        let bn = serde_json::to_vec(&b_next).map_err(|e| e.to_string())?;
        counts.max_state = counts.max_state.max(n.len());
        let safety = invariants(s, &next, oracle, &next_o);
        let parity = allow == b_allow && n == bn && next_o.effects == next_bo.effects;
        trace.push(json!({"command":event.command,"fault":event.fault}));
        if !safety {
            counts.violations += 1;
        }
        if !parity {
            counts.divergences += 1;
        }
        if (!safety || !parity) && counts.first.is_none() {
            counts.first = Some(
                json!({"trace":trace,"candidate":next,"baseline":b_next,"effects":next_o,"safety":safety,"parity":parity}),
            );
        }
        visit(
            (&next, &b_next),
            (&next_o, &next_bo),
            alphabet,
            depth - 1,
            trace,
            counts,
        )?;
        trace.pop();
    }
    Ok(())
}
pub fn explore() -> Result<Value, String> {
    let data = fixture_data()?;
    let mut scenarios = Vec::new();
    let mut counterexamples = Vec::new();
    for family in data["cases"].as_array().ok_or("cases")? {
        for f in family["variants"].as_array().ok_or("variants")? {
            let candidate = run(f, Arm::Candidate)?;
            let baseline = run(f, Arm::Baseline)?;
            for arm in [&candidate, &baseline] {
                for group in [
                    "effects",
                    "authority",
                    "knowledge",
                    "resources",
                    "obligations",
                    "progress",
                ] {
                    for (k, expected) in f[format!("expected_{group}")]
                        .as_object()
                        .ok_or("expected")?
                    {
                        if arm["view"][k] != *expected {
                            return Err(format!(
                                "{} {k}: {} != {expected}",
                                f["id"], arm["view"][k]
                            ));
                        }
                    }
                }
            }
            if candidate["controller_state"] != baseline["controller_state"]
                || candidate["view"] != baseline["view"]
            {
                return Err(format!("scenario parity {}", f["id"]));
            }
            scenarios.push(json!({"id":f["id"],"candidate":candidate,"baseline":baseline}));
        }
    }
    for (arm, id, label) in [
        (Arm::DenyAll, "F01_exact", "deny_all_loses_progress"),
        (Arm::RetryAll, "F05_true", "retry_all_duplicates"),
        (Arm::Removal("owners"), "F02_partial", "owners"),
        (Arm::Removal("one_send"), "F05_true", "one_send"),
        (Arm::Removal("backing"), "F10_fork", "backing"),
        (Arm::Removal("lifetime"), "F13_held", "lifetime"),
        (Arm::Removal("settlement"), "F07_internal", "settlement"),
    ] {
        let f = fixture(&data, id)?;
        counterexamples.push(json!({"removed_rule_or_control":label,"fixture":f,"intact":run(f,Arm::Candidate)?,"modified":run(f,arm)?}));
    }
    let ev = |outcome: &str, key: u64| json!({"kind":"evidence","op":0,"signer":9,"key":key,"basis":[1,1,1,1,1],"outcome":outcome,"complete":true,"fenced":true,"retained":true});
    let cap = |op: usize, epoch: u64| json!({"kind":"capture","op":op,"epoch":epoch,"mode":"live"});
    let send = |op: usize| json!({"kind":"send","op":op});
    let fund = |id: u8, amount: u64| json!({"kind":"fund","id":id,"amount":amount,"beneficiary":7,"predicate":1,"op":2});
    let groups = vec![
        (
            "admission_crash_duplicate",
            "F01_exact",
            4,
            vec![
                cap(0, 1),
                cap(0, 2),
                send(0),
                json!({"kind":"crash"}),
                json!({"kind":"rollback","epoch":1}),
                json!({"kind":"readback","op":0,"issuance":11,"envelope":21}),
            ],
        ),
        (
            "opaque_recovery",
            "F05_true",
            6,
            vec![
                send(0),
                cap(0, 1),
                cap(0, 2),
                json!({"kind":"crash"}),
                json!({"kind":"refund_parent"}),
                json!({"kind":"gc","op":0}),
            ],
        ),
        (
            "concurrent_backing",
            "F10_fork",
            0,
            vec![
                fund(1, 60),
                fund(2, 60),
                fund(2, 40),
                json!({"kind":"accept","id":1,"beneficiary":7,"predicate":1,"op":2,"signer":8}),
                json!({"kind":"pay","id":1}),
                json!({"kind":"refund_parent"}),
            ],
        ),
        (
            "evidence_and_stale_settlement",
            "F06_applied",
            6,
            vec![
                ev("applied", 1),
                ev("none", 1),
                ev("applied", 2),
                json!({"kind":"crash"}),
                json!({"kind":"settle","op":0,"epoch":1}),
                json!({"kind":"settle","op":0,"epoch":2}),
            ],
        ),
        (
            "custody_basis",
            "F04_original",
            4,
            vec![
                cap(0, 1),
                cap(0, 2),
                send(0),
                json!({"kind":"crash"}),
                json!({"kind":"change","field":"account","value":2}),
                json!({"kind":"readback","op":0,"issuance":11,"envelope":21}),
            ],
        ),
        (
            "typed_dependencies",
            "F01_exact",
            4,
            vec![
                cap(0, 1),
                send(0),
                json!({"kind":"dependency","dependency_kind":"held","revision":1,"until":2}),
                json!({"kind":"advance_dependency","revision":2,"time":3}),
                json!({"kind":"crash"}),
                json!({"kind":"dependency","dependency_kind":"historical","revision":1,"until":2}),
            ],
        ),
    ];
    let mut schedules = Vec::new();
    let mut total = 0;
    let mut violations = 0;
    let mut divergences = 0;
    for (name, id, prefix, values) in groups {
        let (s, o) = seed(&data, id, prefix)?;
        let mut alphabet = values
            .into_iter()
            .map(event)
            .collect::<Result<Vec<_>, _>>()?;
        if name == "admission_crash_duplicate" {
            for applied in [false, true] {
                let mut e = event(send(0))?;
                e.fault.applied = Some(applied);
                e.fault.ack = Some(false);
                alphabet.push(e);
            }
        }
        let mut counts = Counts {
            transitions: 0,
            violations: 0,
            divergences: 0,
            excluded: 0,
            max_state: 0,
            max_checks: 0,
            first: None,
        };
        visit(
            (&s, &s),
            (&o, &o),
            &alphabet,
            5,
            &mut Vec::new(),
            &mut counts,
        )?;
        total += counts.transitions;
        violations += counts.violations;
        divergences += counts.divergences;
        schedules.push(json!({"name":name,"seed_fixture":id,"seed_prefix":prefix,"depth":5,"alphabet":alphabet.iter().map(|e|json!({"command":e.command,"fault":e.fault})).collect::<Vec<_>>(),"transitions":counts.transitions,"violations":counts.violations,"divergences":counts.divergences,"excluded_unqualified_provider_prefixes":counts.excluded,"max_serialized_controller_state_bytes":counts.max_state,"max_candidate_top_level_checks":counts.max_checks,"first_counterexample":counts.first}));
    }
    Ok(
        json!({"schema":"chio.kernel-work.model-results.v1","profile":"KW1","transitions":total,"violations":violations,"divergences":divergences,"scenarios":scenarios,"schedules":schedules,"counterexamples":counterexamples,"arbitrary_trace_theorem":false,"native_correspondence_proved":false,"independent_operation":false}),
    )
}
