use super::*;
use std::io::Write;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn required_swarm_policy_is_loaded_into_the_kernel() -> TestResult {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(b"kernel:\n  require_swarm_admission: true\n")?;
    let loaded = load_policy(file.path())?;
    assert!(loaded.kernel.require_swarm_admission);
    let kernel = crate::build_kernel(loaded, &chio_core::Keypair::generate());
    assert!(kernel.swarm_admission_required());
    Ok(())
}

#[test]
fn required_swarm_policy_changes_runtime_identity_without_default_hash_churn() -> TestResult {
    let ordinary = parse_policy("{}")?;
    let explicit_optional = parse_policy("kernel:\n  require_swarm_admission: false\n")?;
    let required = parse_policy("kernel:\n  require_swarm_admission: true\n")?;
    assert!(!ordinary.kernel.require_swarm_admission);
    let ordinary_wire = serde_json::to_value(&ordinary)?;
    assert!(ordinary_wire["kernel"]
        .get("require_swarm_admission")
        .is_none());
    assert_eq!(ordinary_wire, serde_json::to_value(&explicit_optional)?);
    let hash = |policy: &ChioPolicy| -> Result<String, PolicyError> {
        let caps = build_runtime_default_capabilities(policy)?;
        util::runtime_hash_for_chio_yaml(policy, &caps)
    };
    assert_eq!(hash(&ordinary)?, hash(&explicit_optional)?);
    assert_ne!(hash(&ordinary)?, hash(&required)?);
    Ok(())
}

#[test]
fn required_swarm_policy_rejects_non_boolean_values() {
    for value in ["null", "0", "1", "[]", "{}", "\"true\"", "enabled"] {
        assert!(
            parse_policy(&format!("kernel:\n  require_swarm_admission: {value}\n")).is_err(),
            "accepted {value}"
        );
    }
}
