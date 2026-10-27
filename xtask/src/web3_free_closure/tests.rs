use super::*;

const POLICY: &str = r#"
schema = "chio.ci-gate.web3-free-closure.v1"
roots = ["chio-core", "chio-kernel"]

[deny]
packages = ["chio-web3", "alloy-*", "chio-finding-*"]
features = ["web3", "finding-market"]
"#;

const CLEAN_TREE: &str = concat!(
    "0chio-core v0.1.0 (/w/crates/core/chio-core) default\n",
    "1chio-core-types feature \"default\"\n",
    "2chio-core-types v0.1.0 (/w/crates/core/chio-core-types) default,std\n",
    "3serde feature \"default\"\n",
    "4serde v1.0.228 default,std\n",
    "1serde feature \"default\" (*)\n",
    "1chio-market feature \"default\"\n",
    "2chio-market v0.1.0 (/w/crates/economy/chio-market) \n",
    "3chio-core-types feature \"default\" (*)\n",
);

const DENIED_TREE: &str = concat!(
    "0chio-core v0.1.0 (/w/crates/core/chio-core) default\n",
    "1chio-autonomy feature \"default\"\n",
    "2chio-autonomy v0.1.0 (/w/crates/economy/chio-autonomy) \n",
    "3chio-web3 feature \"default\"\n",
    "4chio-web3 v0.1.0 (/w/crates/economy/chio-web3) \n",
    "5alloy-primitives feature \"default\"\n",
    "6alloy-primitives v1.5.7 default,std\n",
    "1chio-web3 feature \"default\" (*)\n",
    "1chio-settle feature \"default\"\n",
    "2chio-settle v0.1.0 (/w/crates/economy/chio-settle) default,web3\n",
    "2chio-settle feature \"web3\"\n",
    "3chio-settle v0.1.0 (/w/crates/economy/chio-settle) default,web3 (*)\n",
    "3chio-finding-verifier feature \"default\"\n",
    "4chio-finding-verifier v0.1.0 (/w/crates/economy/chio-finding-verifier) \n",
);

fn policy() -> Result<Policy, String> {
    Policy::parse(POLICY)
}

#[test]
fn clean_closure_passes() -> Result<(), String> {
    let graph = ClosureGraph::parse(CLEAN_TREE)?;
    assert_eq!(graph.root_name(), "chio-core");
    assert_eq!(evaluate(&policy()?, &graph), Vec::new());
    Ok(())
}

#[test]
fn denied_packages_and_features_are_reported_with_paths() -> Result<(), String> {
    let graph = ClosureGraph::parse(DENIED_TREE)?;
    let violations = evaluate(&policy()?, &graph);
    let expected = vec![
        Violation {
            root: "chio-core".into(),
            denied: Denied::Package {
                package: "alloy-primitives".into(),
            },
            inverted_path: vec![
                "alloy-primitives".into(),
                "chio-web3".into(),
                "chio-core".into(),
            ],
            via: vec!["chio-autonomy".into(), "chio-web3".into()],
        },
        Violation {
            root: "chio-core".into(),
            denied: Denied::Package {
                package: "chio-finding-verifier".into(),
            },
            inverted_path: vec![
                "chio-finding-verifier".into(),
                "chio-settle/web3".into(),
                "chio-core".into(),
            ],
            via: vec!["chio-settle".into()],
        },
        Violation {
            root: "chio-core".into(),
            denied: Denied::Package {
                package: "chio-web3".into(),
            },
            inverted_path: vec!["chio-web3".into(), "chio-core".into()],
            via: vec!["chio-autonomy".into(), "chio-web3".into()],
        },
        Violation {
            root: "chio-core".into(),
            denied: Denied::Feature {
                package: "chio-settle".into(),
                feature: "web3".into(),
            },
            inverted_path: vec!["chio-settle/web3".into(), "chio-core".into()],
            via: vec!["chio-settle".into()],
        },
    ];
    assert_eq!(violations, expected);
    Ok(())
}

#[test]
fn denied_feature_on_root_package_line_is_reported() -> Result<(), String> {
    let tree = "0chio-kernel v0.1.0 (/w/crates/kernel/chio-kernel) default,finding-market\n";
    let violations = evaluate(&policy()?, &ClosureGraph::parse(tree)?);
    assert_eq!(
        violations,
        vec![Violation {
            root: "chio-kernel".into(),
            denied: Denied::Feature {
                package: "chio-kernel".into(),
                feature: "finding-market".into(),
            },
            inverted_path: vec!["chio-kernel".into()],
            via: Vec::new(),
        }]
    );
    Ok(())
}

#[test]
fn prefix_pattern_does_not_match_the_bare_stem() -> Result<(), String> {
    let tree = concat!(
        "0chio-core v0.1.0 (/w/crates/core/chio-core) default\n",
        "1chio-finding v0.1.0 (/w/crates/economy/chio-finding) \n",
        "1alloy v1.0.0\n",
    );
    assert_eq!(
        evaluate(&policy()?, &ClosureGraph::parse(tree)?),
        Vec::new()
    );
    Ok(())
}

#[test]
fn render_names_root_item_path_and_inspect_command() -> Result<(), String> {
    let graph = ClosureGraph::parse(DENIED_TREE)?;
    let violations = evaluate(&policy()?, &graph);
    let rendered = violations
        .iter()
        .find(|v| {
            v.denied
                == Denied::Package {
                    package: "chio-web3".into(),
                }
        })
        .map(Violation::render)
        .ok_or("chio-web3 violation missing")?;
    assert_eq!(
        rendered,
        "web3-free-closure: chio-core: denied package `chio-web3`\n  path (inverted): chio-web3 <- chio-core\n  via direct dependencies: chio-autonomy, chio-web3\n  inspect: cargo tree -p chio-core -e normal,features -i chio-web3"
    );
    Ok(())
}

#[test]
fn malformed_tree_output_is_rejected() {
    assert_eq!(
        ClosureGraph::parse("").map(|_| ()),
        Err("cargo tree printed no nodes".to_string())
    );
    assert_eq!(
        ClosureGraph::parse("chio-core v0.1.0 default\n").map(|_| ()),
        Err("line 1 has no depth prefix: `chio-core v0.1.0 default`".to_string())
    );
    assert_eq!(
        ClosureGraph::parse("0chio-core v0.1.0 default\n2serde v1.0.0 std\n").map(|_| ()),
        Err("line 2 skips a depth level: `2serde v1.0.0 std`".to_string())
    );
    assert_eq!(
        ClosureGraph::parse("0chio-core v0.1.0 default\n0chio-kernel v0.1.0 default\n").map(|_| ()),
        Err("line 2 starts a second root: `0chio-kernel v0.1.0 default`".to_string())
    );
    assert_eq!(
        ClosureGraph::parse("0warning: something\n").map(|_| ()),
        Err("line 1 is not a tree node: `0warning: something`".to_string())
    );
}

#[test]
fn policy_rejects_bad_files() {
    let cases = [
        (
            POLICY.replace("web3-free-closure.v1", "web3-free-closure.v0"),
            "schema is `chio.ci-gate.web3-free-closure.v0`, expected `chio.ci-gate.web3-free-closure.v1`",
        ),
        (
            POLICY.replace(r#"roots = ["chio-core", "chio-kernel"]"#, "roots = []"),
            "`roots` is empty",
        ),
        (
            POLICY.replace(r#""chio-web3", "alloy-*""#, r#""chio-web3", "chio-web3""#),
            "`deny.packages` lists `chio-web3` twice",
        ),
        (
            POLICY.replace(r#""alloy-*""#, r#""al*loy""#),
            "malformed package pattern `al*loy`",
        ),
        (
            POLICY.replace(r#""alloy-*""#, r#""*""#),
            "malformed package pattern `*`",
        ),
        (
            POLICY.replace(r#"features = ["web3", "finding-market"]"#, "features = []"),
            "`deny.features` is empty",
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            Policy::parse(&text).map(|_| ()),
            Err(expected.to_string()),
            "{text}"
        );
    }
    let unknown = format!("{POLICY}\nextra = true\n");
    assert!(
        matches!(Policy::parse(&unknown), Err(detail) if detail.contains("unknown field `extra`"))
    );
}

#[test]
fn checked_in_policy_lists_the_adr_roots() -> Result<(), String> {
    let root = workspace_root().map_err(|err| err.to_string())?;
    let policy = load_policy(&root).map_err(|err| err.to_string())?;
    assert_eq!(
        policy.roots(),
        [
            "chio-kernel",
            "chio-core",
            "chio-core-types",
            "chio-control-plane",
            "chio-cli"
        ]
    );
    Ok(())
}

#[test]
fn unknown_requested_root_is_a_usage_error() -> Result<(), String> {
    let policy = policy()?;
    let err = select_roots(&policy, &["chio-web3".to_string()])
        .map(|_| ())
        .map_err(|err| err.to_string());
    assert_eq!(
        err,
        Err("usage: root `chio-web3` is not listed in ci-gates/web3-free-closure.toml".to_string())
    );
    assert_eq!(
        select_roots(&policy, &[]).map_err(|err| err.to_string())?,
        vec!["chio-core".to_string(), "chio-kernel".to_string()]
    );
    Ok(())
}
