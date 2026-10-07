//! Two synthetic task families over unchanged KW1, with shared adapter accounting.
use kernel_work_composition::{Arm, run};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub family: String,
    pub channel: String,
    pub recipient: String,
    pub source_version: u16,
    pub payload: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Approval {
    pub principal: u8,
    pub role: String,
    pub binding: Binding,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Crossing {
    pub binding: Binding,
    pub approvals: Vec<Approval>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workload {
    pub prepared: Crossing,
    pub seed: Option<Crossing>,
    pub qualified_host: bool,
    pub revoke_audience: bool,
}

pub fn specimen(family: &str) -> Workload {
    let crossing = |channel: &str, recipient: &str, payload: Value| {
        let binding = Binding {
            family: family.into(),
            channel: channel.into(),
            recipient: recipient.into(),
            source_version: 1,
            payload,
        };
        let approvals = [
            (0, "confidentiality"),
            (1, "confidentiality"),
            (2, "integrity"),
        ]
        .into_iter()
        .map(|(principal, role)| Approval {
            principal,
            role: role.into(),
            binding: binding.clone(),
        })
        .collect();
        Crossing { binding, approvals }
    };
    if family == "support" {
        Workload {
            prepared: crossing(
                "result",
                "public-issue",
                json!({"title":"Export timeout", "body":"Reproduced with the synthetic account."}),
            ),
            seed: None,
            qualified_host: true,
            revoke_audience: false,
        }
    } else {
        Workload {
            prepared: crossing(
                "return",
                "parent",
                json!({"decision":"accept", "evidence_id":1}),
            ),
            seed: Some(crossing(
                "seed",
                "reader",
                json!({"document":"Synthetic private source A.", "source_id":1}),
            )),
            qualified_host: true,
            revoke_audience: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    title: String,
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Return {
    decision: String,
    evidence_id: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    document: String,
    source_id: u8,
}

fn exact_crossing(
    c: &Crossing,
    family: &str,
    channel: &str,
    recipient: &str,
) -> Result<(), String> {
    if c.binding.family != family
        || c.binding.channel != channel
        || c.binding.recipient != recipient
        || c.binding.source_version == 0
        || c.approvals.len() > 16
        || c.approvals.iter().any(|a| {
            a.binding != c.binding
                || a.principal > 3
                || !matches!(a.role.as_str(), "confidentiality" | "integrity")
        })
    {
        return Err("unbound materialization or unsupported crossing".into());
    }
    Ok(())
}

fn validate(work: &Workload) -> Result<(), String> {
    match work.prepared.binding.family.as_str() {
        "support" => {
            exact_crossing(&work.prepared, "support", "result", "public-issue")?;
            if work.seed.is_some() {
                return Err("support has no seed crossing".into());
            }
            let issue: Issue = serde_json::from_value(work.prepared.binding.payload.clone())
                .map_err(|e| e.to_string())?;
            if issue.title.is_empty() || issue.title.len() > 96 || issue.body.len() > 512 {
                return Err("issue schema bound".into());
            }
        }
        "research" => {
            if !work.qualified_host {
                return Err("qualified confinement premise absent".into());
            }
            exact_crossing(&work.prepared, "research", "return", "parent")?;
            let seed = work.seed.as_ref().ok_or("admitted seed absent")?;
            exact_crossing(seed, "research", "seed", "reader")?;
            let seed: Seed =
                serde_json::from_value(seed.binding.payload.clone()).map_err(|e| e.to_string())?;
            if seed.document.len() > 512 || seed.source_id > 3 {
                return Err("seed schema bound".into());
            }
            let payload = &work.prepared.binding.payload;
            let returned: Return =
                serde_json::from_value(payload.clone()).map_err(|e| e.to_string())?;
            if !matches!(returned.decision.as_str(), "accept" | "reject")
                || returned.evidence_id > 3
                || serde_json::to_vec(payload)
                    .map_err(|e| e.to_string())?
                    .len()
                    > 64
            {
                return Err("bounded return schema".into());
            }
        }
        _ => return Err("unsupported family".into()),
    }
    Ok(())
}

fn release(c: &Crossing) -> Value {
    json!({"kind":"release","channel":c.binding.channel,"recipient":5,"bounded":true,
        "claims":c.approvals.iter().map(|a|json!({"principal":a.principal,"role":a.role,
            "channel":c.binding.channel,"recipient":5,"version":1})).collect::<Vec<_>>()})
}

pub fn execute(work: &Workload, arm: Arm, lost_ack: bool) -> Result<Value, String> {
    validate(work)?;
    let mut commands = Vec::new();
    if let Some(seed) = &work.seed {
        commands.push(release(seed));
        let seed_report = run(
            &json!({"profile":"E2","initial_state":{},
            "commands":commands,"faults":[]}),
            arm,
        )?;
        if seed_report["view"]["accepted"][0] != true {
            return Ok(json!({"seed_refused":true,"delivered":false,"core":seed_report}));
        }
    }
    let op = if work.prepared.binding.family == "support" {
        0
    } else {
        2
    };
    for a in &work.prepared.approvals {
        commands.push(json!({"kind":"approve","op":op,"principal":a.principal,
            "role":a.role,"basis":[1,1,1,1,1]}));
    }
    commands.push(json!({"kind":"finalize","op":op,"issuance":11,"envelope":21}));
    commands.push(json!({"kind":"capture","op":op,"epoch":1,"mode":"live"}));
    let send_index = commands.len();
    commands.push(json!({"kind":"send","op":op}));
    if work.revoke_audience {
        commands.push(json!({"kind":"permission","name":"read","value":false}));
    }
    commands.push(json!({"kind":"read_result","op":op}));
    let faults = if lost_ack {
        json!([{"at":send_index,"applied":true,"ack":false}])
    } else {
        json!([])
    };
    let mut fixture =
        json!({"profile":"E2","initial_state":{},"commands":commands,"faults":faults});
    let probe = run(&fixture, arm)?;
    // The controller sees permission/outcome decisions, never the fault oracle.
    let available = probe["view"]["accepted"]
        .as_array()
        .ok_or("accepted")?
        .last()
        == Some(&Value::Bool(true));
    if available {
        fixture["commands"]
            .as_array_mut()
            .ok_or("commands")?
            .push(release(&work.prepared));
    }
    let core = run(&fixture, arm)?;
    let delivered = available
        && core["view"]["accepted"]
            .as_array()
            .ok_or("accepted")?
            .last()
            == Some(&Value::Bool(true));
    Ok(
        json!({"materialization":work,"seed_refused":false,"delivered":delivered,
        "fixture":fixture,"core":core}),
    )
}
