use kernel_work_composition::Arm;
use kernel_work_families::{execute, specimen};
use serde_json::json;

fn main() -> Result<(), String> {
    let mut reports = Vec::new();
    for family in ["support", "research"] {
        for case in [
            "authorized",
            "lost_ack",
            "missing_owner",
            "wrong_role",
            "changed_bytes",
            "changed_version",
            "changed_recipient",
            "error_channel",
            "log_channel",
            "payment_channel",
            "revoked_audience",
            "unqualified_host",
            "missing_seed_owner",
            "seed_metadata",
            "return_extra_field",
            "return_out_of_range",
            "return_oversized",
        ] {
            if family == "support"
                && matches!(
                    case,
                    "unqualified_host"
                        | "missing_seed_owner"
                        | "seed_metadata"
                        | "return_extra_field"
                        | "return_out_of_range"
                        | "return_oversized"
                )
            {
                continue;
            }
            let mut work = specimen(family);
            let adapter_error = matches!(
                case,
                "changed_bytes"
                    | "changed_version"
                    | "changed_recipient"
                    | "error_channel"
                    | "log_channel"
                    | "payment_channel"
                    | "unqualified_host"
                    | "seed_metadata"
                    | "return_extra_field"
                    | "return_out_of_range"
                    | "return_oversized"
            );
            match case {
                "missing_owner" => work.prepared.approvals.retain(|a| a.principal != 1),
                "wrong_role" => {
                    for a in &mut work.prepared.approvals {
                        if a.principal == 1 {
                            a.role = "integrity".into();
                        }
                    }
                }
                "changed_bytes" => work.prepared.binding.payload["extra"] = json!("private-canary"),
                "changed_version" => work.prepared.binding.source_version = 2,
                "changed_recipient" => work.prepared.binding.recipient = "attacker".into(),
                "error_channel" | "log_channel" | "payment_channel" => {
                    work.prepared.binding.channel = case.split('_').next().ok_or("channel")?.into()
                }
                "revoked_audience" => work.revoke_audience = true,
                "unqualified_host" => work.qualified_host = false,
                "missing_seed_owner" => work
                    .seed
                    .as_mut()
                    .ok_or("seed")?
                    .approvals
                    .retain(|a| a.principal != 1),
                "seed_metadata" => {
                    work.seed.as_mut().ok_or("seed")?.binding.payload["metadata"] =
                        json!("private-canary")
                }
                "return_extra_field" | "return_out_of_range" | "return_oversized" => {
                    match case {
                        "return_extra_field" => {
                            work.prepared.binding.payload["extra"] = json!("private-canary")
                        }
                        "return_out_of_range" => {
                            work.prepared.binding.payload["evidence_id"] = json!(4)
                        }
                        _ => work.prepared.binding.payload["decision"] = json!("x".repeat(1024)),
                    }
                    for a in &mut work.prepared.approvals {
                        a.binding = work.prepared.binding.clone();
                    }
                }
                _ => {}
            }
            let a = execute(&work, Arm::Candidate, case == "lost_ack");
            let b = execute(&work, Arm::Baseline, case == "lost_ack");
            if adapter_error {
                if a.is_ok() || b.is_ok() {
                    return Err(format!("adapter accepted {family}/{case}"));
                }
                reports.push(json!({"family":family,"case":case,"input":work,"adapter_denied":true,"candidate":a.err(),"baseline":b.err()}));
            } else {
                let (a, b) = (a?, b?);
                if a["core"]["view"] != b["core"]["view"] {
                    return Err(format!("arm mismatch {family}/{case}"));
                }
                if a["delivered"] != (case == "authorized") {
                    return Err(format!("wrong delivery {family}/{case}"));
                }
                let op = if family == "support" { 0 } else { 2 };
                let expected_effect = u64::from(matches!(
                    case,
                    "authorized" | "lost_ack" | "revoked_audience"
                ));
                if a["core"]["view"]["effects"][op] != expected_effect {
                    return Err(format!("wrong effect {family}/{case}"));
                }
                reports.push(json!({"family":family,"case":case,"input":work,"adapter_denied":false,"candidate":a,"baseline":b}));
            }
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"schema":"chio.research.family-results.v1",
        "scope":"synthetic symbolic compatibility; no independent operation or cost measurement",
        "cases":reports}))
        .map_err(|e| e.to_string())?
    );
    Ok(())
}
