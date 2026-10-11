use chio_core::capability::scope::{Constraint, Operation};
use chio_policy::{compile_policy, evaluate, load_builtin, Decision, EvaluationAction, HushSpec};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn kg5_absent_or_disabled_tool_rules_compile_no_authority() -> TestResult {
    let mut implicit_authority = Vec::new();
    for (name, rules) in [
        ("missing-rules", ""),
        ("empty-rules", "rules: {}"),
        ("guard-only", "rules:\n  shell_commands:\n    enabled: true"),
        (
            "disabled-tools",
            "rules:\n  tool_access:\n    enabled: false\n    default: allow",
        ),
    ] {
        let spec = HushSpec::parse(&format!("hushspec: \"0.1.0\"\n{rules}\n"))?;
        let compiled = compile_policy(&spec)?;
        if !compiled.default_scope.grants.is_empty() {
            implicit_authority.push(name);
        }
        // No policy restriction remains Allow in the pure evaluator; that
        // result must not itself become capability issuance authority.
        assert_eq!(
            evaluate(
                &spec,
                &EvaluationAction {
                    action_type: "tool_call".to_owned(),
                    target: Some("inspect".to_owned()),
                    ..EvaluationAction::default()
                },
            )
            .decision,
            Decision::Allow,
            "{name} changed the reference evaluator contract"
        );
    }
    assert!(
        implicit_authority.is_empty(),
        "implicit capability authority: {implicit_authority:?}"
    );
    Ok(())
}

#[test]
fn kg5_explicit_tool_rules_preserve_grants_and_constraints() -> TestResult {
    let permissive = compile_policy(&HushSpec::parse(
        "hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    enabled: true\n    default: allow\n",
    )?)?;
    assert_eq!(permissive.default_scope.grants.len(), 1);
    assert_eq!(permissive.default_scope.grants[0].tool_name, "*");

    let bounded = compile_policy(&HushSpec::parse(
        "hushspec: \"0.1.0\"\nrules:\n  tool_access:\n    enabled: true\n    default: block\n    allow: [inspect]\n    max_args_size: 32\n    require_confirmation: [inspect]\n    dpop_required: true\n",
    )?)?;
    assert_eq!(bounded.default_scope.grants.len(), 1);
    let grant = &bounded.default_scope.grants[0];
    assert_eq!(grant.tool_name, "inspect");
    assert_eq!(grant.operations, vec![Operation::Invoke]);
    assert_eq!(grant.dpop_required, Some(true));
    assert!(grant.constraints.contains(&Constraint::MaxArgsSize(32)));
    assert!(grant
        .constraints
        .contains(&Constraint::RequireApprovalAbove { threshold_units: 0 }));
    Ok(())
}

#[test]
fn kg5_remote_desktop_guards_do_not_grant_every_tool() -> TestResult {
    let compiled = load_builtin("remote-desktop")?;
    assert!(compiled.guard_names.contains(&"computer-use".to_owned()));
    assert!(compiled.default_scope.grants.is_empty());
    Ok(())
}

#[test]
fn kg5_explicit_permissive_builtin_retains_tool_authority() -> TestResult {
    let compiled = load_builtin("permissive")?;
    assert_eq!(compiled.default_scope.grants.len(), 1);
    assert_eq!(compiled.default_scope.grants[0].server_id, "*");
    assert_eq!(compiled.default_scope.grants[0].tool_name, "*");
    Ok(())
}
