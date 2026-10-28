use super::*;

const POLICY: &str = r#"
schema = "chio.ci-gate.web3-free-closure.v1"

[[mode]]
name = "default"
features = []
deny_packages = ["chio-web3", "alloy-*", "chio-finding-*"]
deny_features = ["web3", "finding-market"]

[[mode.root]]
name = "chio-core"
require = []

[[mode.root]]
name = "chio-kernel"
require = []

[[mode]]
name = "web3"
features = ["web3"]
deny_packages = ["chio-finding", "chio-finding-*", "chio-open-market"]
deny_features = ["finding-market"]

[[mode.root]]
name = "chio-cli"
require = ["chio-settle", "chio-web3", "chio-proof-room"]

[[mode]]
name = "web3-finding-market"
features = ["web3", "finding-market"]
deny_packages = []
deny_features = []

[[mode.root]]
name = "chio-cli"
require = ["chio-settle", "chio-web3", "chio-finding", "chio-proof-room"]
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

const WEB3_CLEAN_TREE: &str = concat!(
    "0chio-cli v0.1.0 (/w/crates/products/chio-cli) web3\n",
    "1chio-settle feature \"web3\"\n",
    "2chio-settle v0.1.0 (/w/crates/economy/chio-settle) web3\n",
    "3chio-web3 feature \"default\"\n",
    "4chio-web3 v0.1.0 (/w/crates/economy/chio-web3) \n",
    "1chio-proof-room feature \"default\"\n",
    "2chio-proof-room v0.1.0 (/w/crates/products/chio-proof-room) \n",
    "3chio-web3 feature \"default\" (*)\n",
);

const WEB3_SETTLE_PULLS_FINDING_TREE: &str = concat!(
    "0chio-cli v0.1.0 (/w/crates/products/chio-cli) web3\n",
    "1chio-settle feature \"web3\"\n",
    "2chio-settle v0.1.0 (/w/crates/economy/chio-settle) web3\n",
    "3chio-web3 feature \"default\"\n",
    "4chio-web3 v0.1.0 (/w/crates/economy/chio-web3) \n",
    "3chio-finding feature \"default\"\n",
    "4chio-finding v0.1.0 (/w/crates/economy/chio-finding) \n",
    "3chio-open-market feature \"default\"\n",
    "4chio-open-market v0.1.0 (/w/crates/economy/chio-open-market) \n",
    "5chio-finding feature \"default\" (*)\n",
    "1chio-proof-room feature \"default\"\n",
    "2chio-proof-room v0.1.0 (/w/crates/products/chio-proof-room) \n",
);

const WEB3_MISSING_FORWARD_TREE: &str = concat!(
    "0chio-cli v0.1.0 (/w/crates/products/chio-cli) web3\n",
    "1chio-settle feature \"web3\"\n",
    "2chio-settle v0.1.0 (/w/crates/economy/chio-settle) web3\n",
    "3chio-web3 feature \"default\"\n",
    "4chio-web3 v0.1.0 (/w/crates/economy/chio-web3) \n",
);

const COMBINED_TREE: &str = concat!(
    "0chio-cli v0.1.0 (/w/crates/products/chio-cli) finding-market,web3\n",
    "1chio-settle feature \"web3\"\n",
    "2chio-settle v0.1.0 (/w/crates/economy/chio-settle) web3\n",
    "3chio-web3 feature \"default\"\n",
    "4chio-web3 v0.1.0 (/w/crates/economy/chio-web3) \n",
    "1chio-kernel feature \"finding-market\"\n",
    "2chio-kernel v0.1.0 (/w/crates/kernel/chio-kernel) finding-market\n",
    "3chio-finding feature \"default\"\n",
    "4chio-finding v0.1.0 (/w/crates/economy/chio-finding) \n",
    "1chio-proof-room feature \"default\"\n",
    "2chio-proof-room v0.1.0 (/w/crates/products/chio-proof-room) \n",
);

type ModeShape = (String, Vec<String>, Vec<(String, Vec<String>)>);

fn policy() -> Result<Policy, String> {
    Policy::parse(POLICY)
}

fn mode<'p>(policy: &'p Policy, name: &str) -> Result<&'p Mode, String> {
    policy
        .modes()
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| format!("mode `{name}` missing"))
}

fn rule<'m>(mode: &'m Mode, root: &str) -> Result<&'m RootRule, String> {
    mode.roots
        .iter()
        .find(|r| r.name == root)
        .ok_or_else(|| format!("root `{root}` missing"))
}

fn run_check(mode_name: &str, root: &str, tree: &str) -> Result<Vec<Violation>, String> {
    let policy = policy()?;
    let mode = mode(&policy, mode_name)?;
    let rule = rule(mode, root)?;
    check_root(mode, rule, Ok(tree.to_string())).map(|(_, violations)| violations)
}

fn denied(mode: &str, root: &str, package: &str, path: &[&str], via: &[&str]) -> Violation {
    Violation {
        mode: mode.into(),
        root: root.into(),
        breach: Breach::DeniedPackage {
            package: package.into(),
        },
        inverted_path: path.iter().map(|s| s.to_string()).collect(),
        via: via.iter().map(|s| s.to_string()).collect(),
    }
}

fn missing(mode: &str, root: &str, package: &str) -> Violation {
    Violation {
        mode: mode.into(),
        root: root.into(),
        breach: Breach::MissingPackage {
            package: package.into(),
        },
        inverted_path: Vec::new(),
        via: Vec::new(),
    }
}

#[test]
fn default_mode_clean_closure_passes() -> Result<(), String> {
    assert_eq!(run_check("default", "chio-core", CLEAN_TREE)?, Vec::new());
    Ok(())
}

#[test]
fn default_mode_reports_denied_packages_and_features_with_paths() -> Result<(), String> {
    let violations = run_check("default", "chio-core", DENIED_TREE)?;
    let expected = vec![
        denied(
            "default",
            "chio-core",
            "alloy-primitives",
            &["alloy-primitives", "chio-web3", "chio-core"],
            &["chio-autonomy", "chio-web3"],
        ),
        denied(
            "default",
            "chio-core",
            "chio-finding-verifier",
            &["chio-finding-verifier", "chio-settle/web3", "chio-core"],
            &["chio-settle"],
        ),
        denied(
            "default",
            "chio-core",
            "chio-web3",
            &["chio-web3", "chio-core"],
            &["chio-autonomy", "chio-web3"],
        ),
        Violation {
            mode: "default".into(),
            root: "chio-core".into(),
            breach: Breach::DeniedFeature {
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
    assert_eq!(
        run_check("default", "chio-kernel", tree)?,
        vec![Violation {
            mode: "default".into(),
            root: "chio-kernel".into(),
            breach: Breach::DeniedFeature {
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
    assert_eq!(run_check("default", "chio-core", tree)?, Vec::new());
    Ok(())
}

#[test]
fn web3_mode_clean_closure_passes() -> Result<(), String> {
    assert_eq!(run_check("web3", "chio-cli", WEB3_CLEAN_TREE)?, Vec::new());
    Ok(())
}

#[test]
fn web3_mode_rejects_settlement_web3_pulling_finding_market() -> Result<(), String> {
    let violations = run_check("web3", "chio-cli", WEB3_SETTLE_PULLS_FINDING_TREE)?;
    assert_eq!(
        violations,
        vec![
            denied(
                "web3",
                "chio-cli",
                "chio-finding",
                &[
                    "chio-finding",
                    "chio-settle",
                    "chio-settle/web3",
                    "chio-cli"
                ],
                &["chio-settle"],
            ),
            denied(
                "web3",
                "chio-cli",
                "chio-open-market",
                &[
                    "chio-open-market",
                    "chio-settle",
                    "chio-settle/web3",
                    "chio-cli"
                ],
                &["chio-settle"],
            ),
        ]
    );
    Ok(())
}

#[test]
fn web3_mode_reports_a_missing_required_forward() -> Result<(), String> {
    assert_eq!(
        run_check("web3", "chio-cli", WEB3_MISSING_FORWARD_TREE)?,
        vec![missing("web3", "chio-cli", "chio-proof-room")]
    );
    Ok(())
}

#[test]
fn combined_mode_positive_control_passes() -> Result<(), String> {
    assert_eq!(
        run_check("web3-finding-market", "chio-cli", COMBINED_TREE)?,
        Vec::new()
    );
    Ok(())
}

#[test]
fn combined_mode_requires_the_finding_crate() -> Result<(), String> {
    assert_eq!(
        run_check("web3-finding-market", "chio-cli", WEB3_CLEAN_TREE)?,
        vec![missing("web3-finding-market", "chio-cli", "chio-finding")]
    );
    Ok(())
}

#[test]
fn cargo_failure_and_wrong_root_fail_the_check() -> Result<(), String> {
    let policy = policy()?;
    let web3 = mode(&policy, "web3")?;
    let cli = rule(web3, "chio-cli")?;
    let failure = "cargo tree failed with exit status: 101: error: the package 'chio-cli' does not contain this feature: web3";
    assert_eq!(
        check_root(web3, cli, Err(failure.to_string())).map(|_| ()),
        Err(failure.to_string())
    );
    assert_eq!(
        check_root(web3, cli, Ok(CLEAN_TREE.to_string())).map(|_| ()),
        Err("cargo tree resolved root `chio-core`".to_string())
    );
    Ok(())
}

#[test]
fn render_names_mode_root_item_path_and_inspect_command() -> Result<(), String> {
    let policy = policy()?;
    let default = mode(&policy, "default")?;
    let web3 = mode(&policy, "web3")?;
    let violations = run_check("default", "chio-core", DENIED_TREE)?;
    let rendered = violations
        .iter()
        .find(|v| {
            v.breach
                == Breach::DeniedPackage {
                    package: "chio-web3".into(),
                }
        })
        .map(|v| v.render(default))
        .ok_or("chio-web3 violation missing")?;
    assert_eq!(
        rendered,
        "web3-free-closure: chio-core [default]: denied package `chio-web3`\n  path (inverted): chio-web3 <- chio-core\n  via direct dependencies: chio-autonomy, chio-web3\n  inspect: cargo tree -p chio-core -e normal,features -i chio-web3"
    );
    assert_eq!(
        missing("web3", "chio-cli", "chio-proof-room").render(web3),
        "web3-free-closure: chio-cli [web3]: required package `chio-proof-room` is not reached\n  inspect: cargo tree -p chio-cli -e normal,features --features web3"
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
            POLICY.replace(r#"name = "web3-finding-market""#, r#"name = "web3""#),
            "mode `web3` is listed twice",
        ),
        (
            POLICY.replace(r#""chio-web3", "alloy-*""#, r#""chio-web3", "chio-web3""#),
            "mode `default` deny_packages lists `chio-web3` twice",
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
            POLICY.replace(r#"features = ["web3"]"#, r#"features = ["web 3"]"#),
            "mode `web3` features entry `web 3` is malformed",
        ),
        (
            POLICY.replace(
                r#"require = ["chio-settle", "chio-web3", "chio-finding", "chio-proof-room"]"#,
                "require = []",
            ),
            "mode `web3-finding-market` root `chio-cli` has no denied or required entry",
        ),
        (
            POLICY.replace(
                "[[mode.root]]\nname = \"chio-kernel\"\nrequire = []\n",
                "[[mode.root]]\nname = \"chio-core\"\nrequire = []\n",
            ),
            "mode `default` lists root `chio-core` twice",
        ),
        (
            "schema = \"chio.ci-gate.web3-free-closure.v1\"\nmode = []\n".to_string(),
            "no `[[mode]]` entries",
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(
            Policy::parse(&text).map(|_| ()),
            Err(expected.to_string()),
            "{text}"
        );
    }
    let unknown = format!("{POLICY}extra = true\n");
    assert!(
        matches!(Policy::parse(&unknown), Err(detail) if detail.contains("unknown field `extra`"))
    );
}

#[test]
fn checked_in_policy_matches_adr_modes_and_roots() -> Result<(), String> {
    let root = workspace_root().map_err(|err| err.to_string())?;
    let policy = load_policy(&root).map_err(|err| err.to_string())?;
    let shape: Vec<ModeShape> = policy
        .modes()
        .iter()
        .map(|m| {
            (
                m.name.clone(),
                m.features.clone(),
                m.roots
                    .iter()
                    .map(|r| (r.name.clone(), r.require.clone()))
                    .collect(),
            )
        })
        .collect();
    let owned = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let expected = vec![
        (
            "default".to_string(),
            Vec::new(),
            [
                "chio-kernel",
                "chio-core",
                "chio-core-types",
                "chio-control-plane",
                "chio-cli",
            ]
            .iter()
            .map(|r| (r.to_string(), Vec::new()))
            .collect(),
        ),
        (
            "web3".to_string(),
            owned(&["web3"]),
            vec![
                (
                    "chio-control-plane".to_string(),
                    owned(&["chio-settle", "chio-web3"]),
                ),
                (
                    "chio-cli".to_string(),
                    owned(&["chio-settle", "chio-web3", "chio-proof-room"]),
                ),
            ],
        ),
        (
            "web3-finding-market".to_string(),
            owned(&["web3", "finding-market"]),
            vec![
                (
                    "chio-control-plane".to_string(),
                    owned(&["chio-settle", "chio-web3", "chio-finding"]),
                ),
                (
                    "chio-cli".to_string(),
                    owned(&[
                        "chio-settle",
                        "chio-web3",
                        "chio-finding",
                        "chio-proof-room",
                    ]),
                ),
            ],
        ),
    ];
    assert_eq!(shape, expected);
    Ok(())
}

#[test]
fn selection_filters_and_rejects_unknown_modes_and_roots() -> Result<(), String> {
    let policy = policy()?;
    let pairs = |modes: &[&str], roots: &[&str]| {
        select(
            &policy,
            &modes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &roots.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .map(|selected| {
            selected
                .iter()
                .map(|(m, r)| format!("{}:{}", m.name, r.name))
                .collect::<Vec<_>>()
        })
        .map_err(|err| err.to_string())
    };
    assert_eq!(
        pairs(&[], &[])?,
        vec![
            "default:chio-core",
            "default:chio-kernel",
            "web3:chio-cli",
            "web3-finding-market:chio-cli"
        ]
    );
    assert_eq!(
        pairs(&[], &["chio-cli"])?,
        vec!["web3:chio-cli", "web3-finding-market:chio-cli"]
    );
    assert_eq!(pairs(&["web3"], &[])?, vec!["web3:chio-cli"]);
    assert_eq!(
        pairs(&["nope"], &[]),
        Err("usage: mode `nope` is not listed in ci-gates/web3-free-closure.toml".to_string())
    );
    assert_eq!(
        pairs(&["web3"], &["chio-core"]),
        Err("usage: root `chio-core` is not listed in ci-gates/web3-free-closure.toml for the selected modes".to_string())
    );
    Ok(())
}
