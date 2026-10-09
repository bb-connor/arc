use super::*;

#[test]
fn open_attestation_residual_is_retained_but_never_reported_as_executed() {
    let root = match workspace_root() {
        Ok(root) => root,
        Err(error) => panic!("workspace root failed: {error}"),
    };
    let build = match build_coverage(&root) {
        Ok(build) => build,
        Err(error) => panic!("coverage build failed: {error}"),
    };
    let id = ".kani/harnesses.toml::chio-attest-verify/public_expect_report_data_determinism_and_binding";
    let artifact = match build.artifacts.iter().find(|artifact| artifact.id == id) {
        Some(artifact) => artifact,
        None => panic!("the unfinished attestation obligation must remain visible"),
    };
    assert_eq!(
        artifact.qualifiers.get("status").map(String::as_str),
        Some("unproved")
    );
    assert_eq!(
        artifact
            .qualifiers
            .get("execution_lane")
            .map(String::as_str),
        Some("not-executed")
    );
    assert_eq!(
        artifact.qualifiers.get("followup").map(String::as_str),
        Some("KANI-ATTEST-DECOMP")
    );
    assert_eq!(
        build
            .artifacts
            .iter()
            .filter(|artifact| artifact
                .qualifiers
                .get("status")
                .is_some_and(|status| status == "unproved")
                && artifact.lane == "kani")
            .count(),
        1
    );
}

#[test]
fn unknown_open_residual_cannot_be_classified_as_accepted() {
    let source = r#"crate = "chio-attest-verify"
harness = "public_expect_report_data_determinism_and_binding"
lane = "pr"
open_residual = "some-other-proof"
"#;
    assert!(parse_toml::<KaniHarness>("fixture", source).is_err());
}
