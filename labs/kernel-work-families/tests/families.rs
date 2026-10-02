use kernel_work_composition::Arm;
use kernel_work_families::{execute, specimen};
use serde_json::{Value, json};

#[test]
fn both_families_reject_rebound_materializations_and_invalid_returns() -> Result<(), String> {
    for family in ["support", "research"] {
        for arm in [Arm::Candidate, Arm::Baseline] {
            for field in [
                "payload",
                "source_version",
                "recipient",
                "channel",
                "family",
            ] {
                let mut work = specimen(family);
                match field {
                    "payload" => work.prepared.binding.payload["extra"] = json!("secret"),
                    "source_version" => work.prepared.binding.source_version = 2,
                    "recipient" => work.prepared.binding.recipient = "attacker".into(),
                    "channel" => work.prepared.binding.channel = "log".into(),
                    _ => work.prepared.binding.family = "different-family".into(),
                }
                assert!(
                    execute(&work, arm, false).is_err(),
                    "{family} {arm:?} {field}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn both_families_preserve_positive_work_uncertainty_and_current_audience() -> Result<(), String> {
    for family in ["support", "research"] {
        let op = if family == "support" { 0 } else { 2 };
        for arm in [Arm::Candidate, Arm::Baseline] {
            let mut work = specimen(family);
            let good = execute(&work, arm, false)?;
            assert_eq!(good["delivered"], true);
            assert_eq!(good["core"]["view"]["effects"][op], 1);
            let lost = execute(&work, arm, true)?;
            assert_eq!(lost["delivered"], false);
            assert_eq!(lost["core"]["view"]["effects"][op], 1);
            work.revoke_audience = true;
            assert_eq!(execute(&work, arm, false)?["delivered"], false);
            work.revoke_audience = false;
            work.prepared.approvals.retain(|a| a.principal != 1);
            let denied = execute(&work, arm, false)?;
            assert_eq!(denied["delivered"], false);
            assert_eq!(denied["core"]["view"]["effects"][op], 0);
        }
        let work = specimen(family);
        let a = execute(&work, Arm::Candidate, false)?;
        let b = execute(&work, Arm::Baseline, false)?;
        assert_eq!(a["core"]["view"], b["core"]["view"]);
    }
    Ok(())
}

#[test]
fn confinement_and_return_schema_are_actual_adapter_obligations() -> Result<(), String> {
    for arm in [Arm::Candidate, Arm::Baseline] {
        let mut work = specimen("research");
        work.qualified_host = false;
        assert!(execute(&work, arm, false).is_err());
        work.qualified_host = true;
        work.seed = None;
        assert!(execute(&work, arm, false).is_err());
        for payload in [
            json!({"decision":"accept","evidence_id":1,"leak":"private"}),
            json!({"decision":"private","evidence_id":1}),
            json!({"decision":"accept","evidence_id":99}),
            Value::Null,
        ] {
            let mut work = specimen("research");
            work.prepared.binding.payload = payload;
            for approval in &mut work.prepared.approvals {
                approval.binding = work.prepared.binding.clone();
            }
            assert!(execute(&work, arm, false).is_err());
        }
    }
    Ok(())
}
