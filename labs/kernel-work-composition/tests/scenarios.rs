use kernel_work_composition::{Arm, run};
use serde_json::Value;

fn fixtures() -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../../docs/research/kernel-work/fixtures.json"
    ))?)
}
fn variant(id: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let data = fixtures()?;
    for family in data["cases"].as_array().ok_or("cases")? {
        for fixture in family["variants"].as_array().ok_or("variants")? {
            if fixture["id"] == id {
                return Ok(fixture.clone());
            }
        }
    }
    Err(format!("missing fixture {id}").into())
}

#[test]
fn lost_ack_partial_fixtures_refine_through_authenticated_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    for id in ["F06_partial", "F14_refinement"] {
        for arm in [Arm::Candidate, Arm::Baseline] {
            let report = run(&variant(id)?, arm)?;
            assert_eq!(report["steps"][5]["outcomes"][0], "unknown", "{id} {arm:?}");
            assert_eq!(report["steps"][6]["outcomes"][0], "partial", "{id} {arm:?}");
            assert_eq!(report["view"]["outcomes"][0], "partial", "{id} {arm:?}");
        }
    }
    Ok(())
}
fn check_family(id: &str, arm: Arm) -> Result<(), Box<dyn std::error::Error>> {
    let data = fixtures()?;
    let family = data["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|f| f["id"] == id)
        .ok_or("family")?;
    for fixture in family["variants"].as_array().ok_or("variants")? {
        let report = run(fixture, arm)?;
        for group in [
            "effects",
            "authority",
            "knowledge",
            "resources",
            "obligations",
            "progress",
        ] {
            for (key, expected) in fixture[format!("expected_{group}")]
                .as_object()
                .ok_or("expectations")?
            {
                assert_eq!(
                    &report["view"][key], expected,
                    "{} {arm:?} {key}",
                    fixture["id"]
                );
            }
        }
        // Independent oracle assertions, checked after every step, not just final counts.
        for step in report["steps"].as_array().ok_or("steps")? {
            for effects in step["effects"].as_array().ok_or("effects")? {
                assert!(effects.as_u64().ok_or("count")? <= 1);
            }
            assert!(step["exposure"].as_u64().ok_or("exposure")? <= 10);
            assert!(
                step["wallet_reserved"].as_u64().ok_or("reserved")?
                    <= step["wallet"].as_u64().ok_or("wallet")?
            );
            assert_eq!(step["captures"], step["nonces"]);
            for identity in ["issuances", "envelopes"] {
                let values = step[identity].as_array().ok_or("identity vector")?;
                let mut seen = std::collections::BTreeSet::new();
                for value in values {
                    let id = value.as_u64().ok_or("identity")?;
                    assert!(
                        id == 0 || seen.insert(id),
                        "duplicate {identity} in {}",
                        fixture["id"]
                    );
                }
            }
            let knowledge = step["knowledge"].as_u64().ok_or("knowledge")?;
            assert_eq!(knowledge & 3, 3);
        }
    }
    Ok(())
}
#[test]
fn candidate_f01() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F01", Arm::Candidate)
}
#[test]
fn baseline_f01() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F01", Arm::Baseline)
}
#[test]
fn candidate_f02() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F02", Arm::Candidate)
}
#[test]
fn baseline_f02() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F02", Arm::Baseline)
}
#[test]
fn candidate_f03() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F03", Arm::Candidate)
}
#[test]
fn baseline_f03() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F03", Arm::Baseline)
}
#[test]
fn candidate_f04() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F04", Arm::Candidate)
}
#[test]
fn baseline_f04() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F04", Arm::Baseline)
}
#[test]
fn candidate_f05() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F05", Arm::Candidate)
}
#[test]
fn baseline_f05() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F05", Arm::Baseline)
}
#[test]
fn candidate_f06() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F06", Arm::Candidate)
}
#[test]
fn baseline_f06() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F06", Arm::Baseline)
}
#[test]
fn candidate_f07() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F07", Arm::Candidate)
}
#[test]
fn baseline_f07() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F07", Arm::Baseline)
}
#[test]
fn candidate_f08() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F08", Arm::Candidate)
}
#[test]
fn baseline_f08() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F08", Arm::Baseline)
}
#[test]
fn candidate_f09() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F09", Arm::Candidate)
}
#[test]
fn baseline_f09() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F09", Arm::Baseline)
}
#[test]
fn candidate_f10() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F10", Arm::Candidate)
}
#[test]
fn baseline_f10() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F10", Arm::Baseline)
}
#[test]
fn candidate_f11() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F11", Arm::Candidate)
}
#[test]
fn baseline_f11() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F11", Arm::Baseline)
}
#[test]
fn candidate_f12() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F12", Arm::Candidate)
}
#[test]
fn baseline_f12() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F12", Arm::Baseline)
}
#[test]
fn candidate_f13() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F13", Arm::Candidate)
}
#[test]
fn baseline_f13() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F13", Arm::Baseline)
}
#[test]
fn candidate_f14() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F14", Arm::Candidate)
}
#[test]
fn baseline_f14() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F14", Arm::Baseline)
}
#[test]
fn candidate_f15() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F15", Arm::Candidate)
}
#[test]
fn baseline_f15() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F15", Arm::Baseline)
}
#[test]
fn candidate_f16() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F16", Arm::Candidate)
}
#[test]
fn baseline_f16() -> Result<(), Box<dyn std::error::Error>> {
    check_family("F16", Arm::Baseline)
}
#[test]
fn opaque_histories_have_identical_controller_views() -> Result<(), Box<dyn std::error::Error>> {
    for arm in [Arm::Candidate, Arm::Baseline] {
        let mut zero = run(&variant("F05_false")?, arm)?["view"].clone();
        let mut one = run(&variant("F05_true")?, arm)?["view"].clone();
        assert_ne!(zero["effects"], one["effects"]);
        zero.as_object_mut().ok_or("view")?.remove("effects");
        one.as_object_mut().ok_or("view")?.remove("effects");
        assert_eq!(zero, one);
    }
    Ok(())
}
#[test]
fn controls_fail_for_progress_and_safety_respectively() -> Result<(), Box<dyn std::error::Error>> {
    let denied = run(&variant("F01_exact")?, Arm::DenyAll)?;
    assert_eq!(denied["view"]["effects"][0], 0);
    let retry = run(&variant("F05_true")?, Arm::RetryAll)?;
    assert_eq!(retry["view"]["effects"][0], 2);
    Ok(())
}
#[test]
fn removals_have_named_counterexamples() -> Result<(), Box<dyn std::error::Error>> {
    for (rule, id, key) in [
        ("owners", "F02_partial", "captures"),
        ("one_send", "F05_true", "effects"),
        ("backing", "F10_fork", "wallet_reserved"),
        ("lifetime", "F13_held", "captures"),
        ("settlement", "F07_internal", "settled"),
    ] {
        let fixture = variant(id)?;
        let intact = run(&fixture, Arm::Candidate)?;
        let removed = run(&fixture, Arm::Removal(rule))?;
        assert_ne!(
            intact["view"][key], removed["view"][key],
            "ineffective removal {rule}"
        );
        let positive = variant(
            fixture["positive_counterpart"]
                .as_str()
                .ok_or("counterpart")?,
        )?;
        let pass = run(&positive, Arm::Candidate)?;
        assert_eq!(
            pass["view"]["accepted"],
            positive["expected_progress"]["accepted"]
        );
    }
    Ok(())
}
#[test]
fn bounded_schedules_preserve_safety_and_match_b1() -> Result<(), Box<dyn std::error::Error>> {
    let report = kernel_work_composition::explore()?;
    assert_eq!(report["violations"], 0);
    assert_eq!(report["divergences"], 0);
    assert!(report["transitions"].as_u64().ok_or("transitions")? > 10000);
    Ok(())
}
