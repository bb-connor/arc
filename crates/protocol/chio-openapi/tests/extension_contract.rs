use chio_http_core::HttpMethod;
use chio_openapi::{
    ChioExtensions, DefaultPolicy, GeneratorConfig, ManifestGenerator, OpenApiError, OpenApiSpec,
    PolicyDecision,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn spec(extension_lines: &str) -> String {
    format!(
        "openapi: 3.1.0\ninfo:\n  title: Extension contract\n  version: 1.0.0\npaths:\n  /data:\n    get:\n      operationId: readData\n{extension_lines}      responses:\n        '200':\n          description: ok\n"
    )
}

fn rejected(text: &str) -> Result<OpenApiError, Box<dyn Error>> {
    OpenApiSpec::parse(text)
        .err()
        .ok_or_else(|| std::io::Error::other("invalid extension reached loaded operation").into())
}

#[test]
fn f069_load_rejects_malformed_extension_types() -> TestResult {
    for line in [
        "      x-chio-approval-required: 'true'\n",
        "      x-chio-approval-required: yes\n",
        "      x-chio-approval-required: null\n",
        "      x-chio-side-effects: 0\n",
        "      x-chio-side-effects: null\n",
        "      x-chio-publish: 'false'\n",
        "      x-chio-publish: null\n",
        "      x-chio-sensitivity: Restricted\n",
        "      x-chio-sensitivity: unknown\n",
        "      x-chio-sensitivity: 1\n",
        "      x-chio-sensitivity: null\n",
        "      x-chio-flow: 7\n",
        "      x-chio-flow: null\n",
    ] {
        let error = rejected(&spec(line))?;
        assert_eq!(
            error.to_string(),
            "urn:chio:error:transport:invalid-request-shape"
        );
    }
    Ok(())
}

#[test]
fn f069_load_rejects_nonobject_operation() -> TestResult {
    for operation in ["null", "7", "'private-operation-marker'", "[]"] {
        let text = format!(
            "openapi: 3.1.0\ninfo:\n  title: Nonobject\n  version: 1.0.0\npaths:\n  /data:\n    get: {operation}\n"
        );
        let error = rejected(&text)?;
        assert!(
            error.source().is_none(),
            "manual object validation fabricated a cause"
        );
        assert!(
            !format!("{error} {error:?} {}", error.operator_diagnostic())
                .contains("private-operation-marker")
        );
    }
    Ok(())
}

#[test]
fn f069_load_rejects_unsupported_reserved_operations() -> TestResult {
    for key in [
        "x-chio-private-unknown-marker",
        "x-chio-scope",
        "x-chio-guard",
        "x-chio-rate-limit",
        "x-chio-require-auth",
        "x-chio-tool-name",
        "x-chio-cost-units",
    ] {
        let error = rejected(&spec(&format!("      {key}: private-value-marker\n")))?;
        let rendering = format!(
            "{error} {error:?} {error:#?} {}",
            error.operator_diagnostic()
        );
        assert!(!rendering.contains(key));
        assert!(!rendering.contains("private-value-marker"));
        assert!(
            error.source().is_none(),
            "unsupported semantics fabricated a parser cause"
        );
    }
    Ok(())
}

#[test]
fn f069_load_rejects_unbound_budget_limit() -> TestResult {
    for value in [
        "0",
        "5000",
        "18446744073709551615",
        "-1",
        "'private-budget-marker'",
        "null",
    ] {
        let error = rejected(&spec(&format!("      x-chio-budget-limit: {value}\n")))?;
        let diagnostic = error.operator_diagnostic().to_string();
        assert!(diagnostic.contains("unsupported"));
        assert!(!diagnostic.contains("private-budget-marker"));
        assert!(
            error.source().is_none(),
            "unsupported budget fabricated a currency/parser cause"
        );
    }
    Ok(())
}

#[test]
fn f069_sensitivity_drives_actual_manifest_approval() -> TestResult {
    for sensitivity in ["sensitive", "restricted"] {
        let loaded = OpenApiSpec::parse(spec(&format!(
            "      x-chio-sensitivity: {sensitivity}\n      x-chio-side-effects: false\n      x-chio-approval-required: false\n"
        )))?;
        let tools = ManifestGenerator::new(GeneratorConfig::default()).generate_tools(&loaded)?;
        assert_eq!(tools.len(), 1);
        let tool = tools.first().ok_or("missing generated tool")?;
        assert_eq!(tool.name, "readData");
        assert!(tool.annotations.read_only);
        assert!(
            tool.annotations.requires_approval,
            "classification was ignored by manifest"
        );
        let operation = loaded
            .paths
            .first()
            .and_then(|(_, path)| path.operations.first())
            .ok_or("missing parsed operation")?;
        let extensions = OpenApiSpec::extensions_for(&operation.1)?;
        assert_eq!(
            extensions.approval_required,
            Some(false),
            "input declaration was rewritten"
        );
        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Get, &extensions),
            PolicyDecision::DenyByDefault
        );
    }
    Ok(())
}

#[test]
fn f069_native_validation_source_has_closed_private_projection() -> TestResult {
    let error = ChioExtensions::from_operation(&serde_json::json!({
        "x-chio-sensitivity": "private-sensitivity-marker"
    }))
    .err()
    .ok_or("invalid sensitivity accepted")?;
    let native = error
        .source()
        .and_then(|source| source.downcast_ref::<serde_json::Error>())
        .ok_or("native validation source was discarded")?;
    assert_eq!(native.classify(), serde_json::error::Category::Data);
    let projection = format!(
        "{error} {error:?} {error:#?} {}",
        error.operator_diagnostic()
    );
    assert!(!projection.contains("private-sensitivity-marker"));
    assert!(projection.contains("category=data"));
    assert!(projection.len() < 2048);
    Ok(())
}

#[test]
fn f069_public_internal_and_method_defaults_are_preserved() -> TestResult {
    for sensitivity in [None, Some("public"), Some("internal")] {
        let lines = sensitivity
            .map(|s| format!("      x-chio-sensitivity: {s}\n"))
            .unwrap_or_default();
        let loaded = OpenApiSpec::parse(spec(&lines))?;
        let tools = ManifestGenerator::new(GeneratorConfig::default()).generate_tools(&loaded)?;
        assert!(
            !tools
                .first()
                .ok_or("missing tool")?
                .annotations
                .requires_approval
        );
        let operation = &loaded
            .paths
            .first()
            .ok_or("missing path")?
            .1
            .operations
            .first()
            .ok_or("missing operation")?
            .1;
        let ext = OpenApiSpec::extensions_for(operation)?;
        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Get, &ext),
            PolicyDecision::SessionAllow
        );
        assert_eq!(
            DefaultPolicy::for_method_with_extensions(HttpMethod::Post, &ext),
            PolicyDecision::DenyByDefault
        );
    }
    let loaded = OpenApiSpec::parse(spec("      x-chio-sensitivity: public\n      x-chio-approval-required: true\n      x-chio-side-effects: false\n"))?;
    let tools = ManifestGenerator::new(GeneratorConfig::default()).generate_tools(&loaded)?;
    assert!(
        tools
            .first()
            .ok_or("missing tool")?
            .annotations
            .requires_approval
    );
    Ok(())
}

#[test]
fn f069_flow_publish_vendor_and_nested_bridge_hints_are_preserved() -> TestResult {
    let flow = serde_json::json!({
        "output_label": {"kind":"known","owners":{},"compartments":["pii"]},
        "input_clearance": {"kind":"known","owners":{},"compartments":["pii"]},
        "egress":true,"declassification_purposes":["billing"]
    });
    let raw = serde_json::json!({"openapi":"3.1.0", "info":{"title":"Supported","version":"1"},"paths":{
        "/visible":{"get":{"operationId":"visible","x-vendor-private-marker":true,"x-chio-flow":flow,
            "requestBody":{"content":{"application/json":{"schema":{"type":"object","x-chio-target-protocol":"mcp","x-chio-streaming":true}}}},
            "responses":{"200":{"description":"ok"}}}},
        "/hidden":{"get":{"operationId":"hidden","x-chio-publish":false,"responses":{"200":{"description":"ok"}}}}
    }});
    let loaded = OpenApiSpec::parse(serde_json::to_vec(&raw)?)?;
    assert_eq!(
        loaded.raw()["paths"]["/visible"]["get"]["x-vendor-private-marker"],
        true
    );
    assert_eq!(
        loaded.raw()["paths"]["/visible"]["get"]["requestBody"]["content"]["application/json"]
            ["schema"]["x-chio-target-protocol"],
        "mcp"
    );
    let tools = ManifestGenerator::new(GeneratorConfig::default()).generate_tools(&loaded)?;
    assert_eq!(tools.len(), 1);
    let tool = tools.first().ok_or("missing visible tool")?;
    assert_eq!(tool.name, "visible");
    assert_eq!(
        serde_json::to_value(tool.flow.as_ref().ok_or("flow dropped")?)?,
        flow
    );
    Ok(())
}

#[test]
fn f069_examples_capture_actual_generated_tool_definitions() -> TestResult {
    let fixtures = [
        ("coordinator", "0xbb39319d6e56893d14beedb29817a58635a3d48d89dc589ae0e9ca53b91f2f19", include_str!("../../../../examples/internet-of-agents-incident-network/services/coordinator-openapi.yaml"), vec!["health", "process_task"]),
        ("executor", "0xd4cbcdc362fb0d74f1988f09f07240a9cb735c3029adf0fb2773f18cb8d470d8", include_str!("../../../../examples/internet-of-agents-incident-network/services/executor-openapi.yaml"), vec!["execute", "health"]),
        ("market_broker", "0x90cc4c68dadb68a52cf483cc4b5ed274b32692f28de569c81acceb485f41cfa4", include_str!("../../../../examples/internet-of-agents-web3-network/services/market-broker-openapi.yaml"), vec!["acceptFulfillment", "requestPaymentRequirements", "requestQuote", "requestRfq", "submitPaymentProof"]),
        ("settlement_desk", "0x8ae498673d0a393912540b48c179a8d1a53d292c317e90657c011dc48c63fb49", include_str!("../../../../examples/internet-of-agents-web3-network/services/settlement-desk-openapi.yaml"), vec!["assembleDisputePacket", "assembleSettlementPacket"]),
    ];
    for (label, expected_digest, text, expected_names) in fixtures {
        let tools = chio_openapi::tools_from_spec(text)?;
        let mut names: Vec<_> = tools.iter().map(|tool| tool.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, expected_names);
        let canonical = chio_core_types::canonical::canonical_json_bytes(&tools)?;
        let digest = chio_core_types::sha256(&canonical);
        // Golden digests were captured from original production before hint removal.
        assert_eq!(
            digest.to_string(),
            expected_digest,
            "{label} tool definitions changed"
        );
    }
    Ok(())
}
