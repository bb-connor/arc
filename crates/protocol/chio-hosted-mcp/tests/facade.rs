fn normal_dependency_names(manifest: &str) -> Vec<String> {
    let mut in_dependencies = false;
    let mut names = Vec::new();

    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed == "[dependencies]" {
            in_dependencies = true;
            continue;
        }
        if in_dependencies && trimmed.starts_with('[') {
            break;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, _)) = trimmed.split_once('=') else {
            continue;
        };
        names.push(name.trim().trim_matches('"').to_string());
    }

    names
}

#[test]
fn hosted_mcp_normal_dependencies_are_reexport_boundary_only() {
    assert_eq!(
        normal_dependency_names(include_str!("../Cargo.toml")),
        vec!["chio-control-plane", "chio-mcp-remote"]
    );
}
