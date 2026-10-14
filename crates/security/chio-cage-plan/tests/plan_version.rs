use chio_cage_plan::{validate_cage_target_fd_binding, CageError, CageInitPlan, FileIdentity};

const NATIVE_PLAN: &str = include_str!(
    "../../../../tests/bindings/vectors/security/cage/positive/cage-init-plan-native-v1.json"
);
const TARGET_BINDING: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn target_identity() -> Result<FileIdentity, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "device": 2049,
        "gid": 1000,
        "inode": 101,
        "kind": "regular_file",
        "mode": 33261,
        "mount_id": 44,
        "uid": 1000
    }))
}

fn refusal(plan: &CageInitPlan) -> Result<Option<&'static str>, serde_json::Error> {
    Ok(
        match validate_cage_target_fd_binding(plan, TARGET_BINDING, target_identity()?) {
            Err(CageError::InvalidTargetFdBinding(reason)) => Some(reason),
            Err(_) | Ok(()) => None,
        },
    )
}

#[test]
fn current_plan_passes_the_version_gate() -> Result<(), serde_json::Error> {
    let plan: CageInitPlan = serde_json::from_str(NATIVE_PLAN)?;
    assert_ne!(refusal(&plan)?, Some("plan_version"));
    Ok(())
}

#[test]
fn retired_plan_schema_id_is_refused() -> Result<(), serde_json::Error> {
    let mut plan: CageInitPlan = serde_json::from_str(NATIVE_PLAN)?;
    plan.schema = "chio.cage.init-plan.v2".to_string();
    assert_eq!(refusal(&plan)?, Some("plan_version"));
    Ok(())
}

#[test]
fn retired_compiler_version_is_refused() -> Result<(), serde_json::Error> {
    let mut plan: CageInitPlan = serde_json::from_str(NATIVE_PLAN)?;
    plan.compiler_version = "chio-cage-compiler.v2".to_string();
    assert_eq!(refusal(&plan)?, Some("plan_version"));
    Ok(())
}
