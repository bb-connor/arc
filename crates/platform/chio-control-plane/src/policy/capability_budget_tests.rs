use super::*;

#[test]
fn explicit_invocation_ceilings_survive_capability_compilation() {
    for (setting, expected) in [
        ("", None),
        ("max_invocations: 0", Some(0)),
        ("max_invocations: 6", Some(6)),
        ("max_invocations: 4294967295", Some(u32::MAX)),
    ] {
        let policy = parse_policy(&format!(
            "capabilities:\n  default:\n    tools:\n      - server: reference-reader\n        tool: stat\n        {setting}\n"
        )).unwrap_or_else(|error| panic!("parse bounded policy: {error}"));
        let capabilities = build_runtime_default_capabilities(&policy)
            .unwrap_or_else(|error| panic!("compile bounded policy: {error}"));
        assert_eq!(capabilities.len(), 1);
        assert_eq!(capabilities[0].scope.grants[0].max_invocations, expected);
    }
}

#[test]
fn malformed_invocation_ceilings_reject_at_policy_load() {
    for setting in ["-1", "4294967296", "1.5", "unlimited"] {
        assert!(parse_policy(&format!(
            "capabilities:\n  default:\n    tools:\n      - server: reference-reader\n        tool: stat\n        max_invocations: {setting}\n"
        )).is_err(), "accepted {setting}");
    }
}
