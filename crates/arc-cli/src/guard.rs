use std::fs;
use std::path::Path;

use crate::CliError;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

const CARGO_TOML_TEMPLATE: &str = r#"[package]
name = "{{PACKAGE_NAME}}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
arc-guard-sdk = "0.1"
arc-guard-sdk-macros = "0.1"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
"#;

const LIB_RS_TEMPLATE: &str = r#"use arc_guard_sdk::prelude::*;
use arc_guard_sdk_macros::arc_guard;

#[arc_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // TODO: implement your guard logic here.
    //
    // Access request fields:
    //   req.tool_name      -- the tool being invoked
    //   req.action_type    -- pre-extracted action category
    //   req.extracted_path -- normalized file path (if applicable)
    //
    // Return GuardVerdict::allow() or GuardVerdict::deny("reason").
    let _ = &req;
    GuardVerdict::allow()
}
"#;

const MANIFEST_YAML_TEMPLATE: &str = r#"name: {{PACKAGE_NAME}}
version: "0.1.0"
abi_version: "1"
wasm_path: "target/wasm32-unknown-unknown/release/{{UNDERSCORED_NAME}}.wasm"
wasm_sha256: "TODO: run `arc guard build` and update this hash"
"#;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub(crate) fn cmd_guard_new(name: &str) -> Result<(), CliError> {
    let project_dir = Path::new(name);
    ensure_target_dir(project_dir)?;

    let dir_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| {
            CliError::Other(format!(
                "could not derive a project name from `{}`",
                project_dir.display()
            ))
        })?;
    let package_name = sanitize_package_name(dir_name);
    let underscored_name = package_name.replace('-', "_");

    // Write Cargo.toml
    let cargo_toml = CARGO_TOML_TEMPLATE.replace("{{PACKAGE_NAME}}", &package_name);
    write_file(&project_dir.join("Cargo.toml"), &cargo_toml)?;

    // Write src/lib.rs
    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| {
        CliError::Other(format!("failed to create {}: {e}", src_dir.display()))
    })?;
    write_file(&src_dir.join("lib.rs"), LIB_RS_TEMPLATE)?;

    // Write guard-manifest.yaml
    let manifest_yaml = MANIFEST_YAML_TEMPLATE
        .replace("{{PACKAGE_NAME}}", &package_name)
        .replace("{{UNDERSCORED_NAME}}", &underscored_name);
    write_file(&project_dir.join("guard-manifest.yaml"), &manifest_yaml)?;

    println!("created guard project at ./{name}");
    println!();
    println!("Next steps:");
    println!("  cd {name}");
    println!("  arc guard build");
    println!(
        "  arc guard inspect target/wasm32-unknown-unknown/release/{underscored_name}.wasm"
    );

    Ok(())
}

pub(crate) fn cmd_guard_build() -> Result<(), CliError> {
    Err(CliError::Other("not yet implemented".to_string()))
}

pub(crate) fn cmd_guard_inspect(_path: &Path) -> Result<(), CliError> {
    Err(CliError::Other("not yet implemented".to_string()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_target_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "refusing to scaffold into non-directory `{}`",
                path.display()
            )));
        }
        if path.read_dir()?.next().is_some() {
            return Err(CliError::Other(format!(
                "refusing to scaffold into non-empty directory `{}`",
                path.display()
            )));
        }
        return Ok(());
    }

    fs::create_dir_all(path)?;
    Ok(())
}

fn sanitize_package_name(input: &str) -> String {
    let mut package = input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();

    while package.contains("--") {
        package = package.replace("--", "-");
    }
    package = package.trim_matches('-').to_string();

    if package.is_empty() {
        "arc-guard".to_string()
    } else {
        package
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), CliError> {
    fs::write(path, content).map_err(|e| {
        CliError::Other(format!("failed to write {}: {e}", path.display()))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_package_name_normalizes_input() {
        assert_eq!(sanitize_package_name("my-guard"), "my-guard");
        assert_eq!(sanitize_package_name("My Guard"), "my-guard");
        assert_eq!(sanitize_package_name("UPPER_CASE"), "upper-case");
        assert_eq!(sanitize_package_name("___"), "arc-guard");
        assert_eq!(sanitize_package_name("a--b"), "a-b");
    }

    #[test]
    fn cmd_guard_new_creates_project_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("test-guard");
        let project_name = project_path.to_str().unwrap();

        cmd_guard_new(project_name).unwrap();

        // Check files exist
        assert!(project_path.join("Cargo.toml").exists());
        assert!(project_path.join("src/lib.rs").exists());
        assert!(project_path.join("guard-manifest.yaml").exists());

        // Check Cargo.toml content
        let cargo = fs::read_to_string(project_path.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"test-guard\""));
        assert!(cargo.contains("crate-type = [\"cdylib\"]"));
        assert!(cargo.contains("arc-guard-sdk = \"0.1\""));
        assert!(cargo.contains("arc-guard-sdk-macros = \"0.1\""));
        assert!(cargo.contains("unwrap_used = \"deny\""));

        // Check src/lib.rs content
        let lib_rs = fs::read_to_string(project_path.join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("#[arc_guard]"));
        assert!(lib_rs.contains("fn evaluate(req: GuardRequest) -> GuardVerdict"));
        assert!(lib_rs.contains("GuardVerdict::allow()"));

        // Check guard-manifest.yaml content
        let manifest = fs::read_to_string(project_path.join("guard-manifest.yaml")).unwrap();
        assert!(manifest.contains("name: test-guard"));
        assert!(manifest.contains("abi_version: \"1\""));
        assert!(manifest.contains("wasm_sha256: \"TODO:"));
        assert!(manifest.contains("test_guard.wasm"));
    }

    #[test]
    fn cmd_guard_new_refuses_non_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("existing-guard");
        fs::create_dir_all(&project_path).unwrap();
        fs::write(project_path.join("some-file.txt"), "content").unwrap();

        let result = cmd_guard_new(project_path.to_str().unwrap());
        assert!(result.is_err());
    }
}
