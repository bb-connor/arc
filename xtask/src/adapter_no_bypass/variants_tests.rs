use super::*;

fn facts(source: &str) -> SourceFacts {
    match parse_source(source, "fixture.rs") {
        Ok(facts) => facts,
        Err(error) => panic!("fixture must parse: {error}"),
    }
}

#[test]
fn platform_variants_remain_separate_and_all_are_scanned() {
    let safe = r#"
        #[cfg(unix)] fn permissions() { validate_mode(); }
        #[cfg(not(unix))] fn permissions() { validate_acl(); }
    "#;
    let source = facts(safe);
    assert_eq!(source.functions["permissions"].len(), 2);
    let path = "crates/protocol/chio-example-edge/src/lib.rs".to_owned();
    assert!(validate_dangerous_calls(&BTreeMap::from([(path.clone(), source)]), false).is_ok());
    // The non-host implementation must not be ignored by a Linux scanner.
    let unsafe_variant = safe.replace("validate_acl()", "Command::new(\"tool\")");
    let result = validate_dangerous_calls(&BTreeMap::from([(path, facts(&unsafe_variant))]), false);
    assert!(result.is_err_and(|error| error.contains("unregistered production side effect")));
}

#[test]
fn duplicate_unconditional_or_identically_guarded_functions_fail() {
    for source in [
        "fn run() {} fn run() {}",
        "#[cfg(unix)] fn run() {} #[cfg(unix)] fn run() {}",
        "fn run() {} #[cfg(unix)] fn run() {}",
        "#[cfg(unix)] fn run() {} fn run() {}",
    ] {
        assert!(parse_source(source, "fixture.rs")
            .is_err_and(|error| error.contains("duplicate function identity")));
    }
}

#[test]
fn impl_and_module_configuration_is_inherited_without_leaking() {
    let source = facts(
        r#"
        #[cfg(unix)] mod platform {
            impl Adapter { fn evaluate(&self) { kernel.evaluate(); } }
        }
        #[cfg(not(unix))] impl Adapter {
            fn evaluate(&self) { kernel.evaluate(); }
        }
        fn unconditional() {}
    "#,
    );
    assert_eq!(source.functions["Adapter::evaluate"].len(), 2);
    assert!(source.functions["unconditional"][0]
        .configuration
        .is_empty());
}

fn variant_pair(second_body: &str) -> SourceFacts {
    facts(&format!(
        r#"
        #[cfg(unix)] fn dispatch() {{
            kernel.evaluate("bound");
            let registry = NoopBudgetRegistry;
            let equal = continuation.id == reference.id;
        }}
        #[cfg(not(unix))] fn dispatch() {{ {second_body} }}
    "#
    ))
}

#[test]
fn every_variant_must_independently_satisfy_all_contract_kinds() {
    let complete = r#"
        kernel.evaluate("bound");
        let registry = NoopBudgetRegistry;
        let equal = continuation.id == reference.id;
    "#;
    let call = CallContract {
        path: "fixture.rs",
        function: "dispatch",
        target: "kernel.evaluate",
        minimum: 1,
    };
    let complete_source = variant_pair(complete);
    assert!(require_call(&complete_source, &call).is_ok());
    assert!(require_path(&complete_source, "dispatch", "NoopBudgetRegistry").is_ok());
    assert!(require_call_tokens(
        &complete_source,
        "dispatch",
        "kernel.evaluate",
        &["\"bound\""]
    )
    .is_ok());
    assert!(require_binary_tokens(
        &complete_source,
        "dispatch",
        &["continuation.id", "reference.id"]
    )
    .is_ok());

    let no_call = variant_pair(&complete.replace("kernel.evaluate", "other.evaluate"));
    assert!(require_call(&no_call, &call).is_err());
    let no_path = variant_pair(&complete.replace("NoopBudgetRegistry", "OtherRegistry"));
    assert!(require_path(&no_path, "dispatch", "NoopBudgetRegistry").is_err());
    let wrong_argument = variant_pair(&complete.replace("bound", "unrelated"));
    assert!(require_call_tokens(
        &wrong_argument,
        "dispatch",
        "kernel.evaluate",
        &["\"bound\""]
    )
    .is_err());
    let wrong_comparison = variant_pair(&complete.replace("reference.id", "other.id"));
    assert!(require_binary_tokens(
        &wrong_comparison,
        "dispatch",
        &["continuation.id", "reference.id"]
    )
    .is_err());
}

#[test]
fn separate_variants_cannot_pool_calls_to_meet_a_contract() {
    let source = variant_pair("kernel.evaluate(\"bound\");");
    let contract = CallContract {
        path: "fixture.rs",
        function: "dispatch",
        target: "kernel.evaluate",
        minimum: 2,
    };
    assert!(require_call(&source, &contract).is_err());
}
