use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::CliError;

use arc_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use arc_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use serde::Deserialize;

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
    // Verify Cargo.toml exists and contains cdylib crate-type
    let cargo_toml_contents = fs::read_to_string("Cargo.toml").map_err(|e| {
        CliError::Other(format!(
            "could not read Cargo.toml in current directory: {e}"
        ))
    })?;
    if !cargo_toml_contents.contains("cdylib") {
        return Err(CliError::Other(
            "current directory does not appear to be a guard project (no cdylib crate-type in Cargo.toml)"
                .to_string(),
        ));
    }

    // Extract the package name from Cargo.toml
    let package_name = cargo_toml_contents
        .lines()
        .find(|line| line.starts_with("name = "))
        .and_then(|line| {
            let trimmed = line.trim_start_matches("name = ").trim();
            let unquoted = trimmed.trim_matches('"');
            if unquoted.is_empty() {
                None
            } else {
                Some(unquoted.to_string())
            }
        })
        .ok_or_else(|| {
            CliError::Other("could not extract package name from Cargo.toml".to_string())
        })?;
    let underscored_name = package_name.replace('-', "_");

    // Run cargo build
    let status = Command::new("cargo")
        .args(["build", "--target", "wasm32-unknown-unknown", "--release"])
        .status()
        .map_err(|e| CliError::Other(format!("failed to run cargo: {e}")))?;

    if !status.success() {
        return Err(CliError::Other("cargo build failed".to_string()));
    }

    // Verify the output .wasm file exists
    let wasm_path = format!(
        "target/wasm32-unknown-unknown/release/{underscored_name}.wasm"
    );
    let metadata = fs::metadata(&wasm_path).map_err(|e| {
        CliError::Other(format!("expected output not found at {wasm_path}: {e}"))
    })?;

    let size = metadata.len();
    let formatted_size = format_size(size);

    println!("build complete: {wasm_path}");
    println!("binary size: {formatted_size}");

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub(crate) fn cmd_guard_inspect(path: &Path) -> Result<(), CliError> {
    let wasm_bytes = fs::read(path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", path.display()))
    })?;

    let file_size = wasm_bytes.len() as u64;

    // Parse the WASM binary
    let parser = wasmparser::Parser::new(0);
    let mut export_list: Vec<(String, &str)> = Vec::new();
    let mut memory_info: Vec<String> = Vec::new();

    for payload in parser.parse_all(&wasm_bytes) {
        let payload = payload.map_err(|e| {
            CliError::Other(format!("wasm parse error: {e}"))
        })?;
        match payload {
            wasmparser::Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| {
                        CliError::Other(format!("wasm export parse error: {e}"))
                    })?;
                    let kind_str = match export.kind {
                        wasmparser::ExternalKind::Func => "function",
                        wasmparser::ExternalKind::Memory => "memory",
                        wasmparser::ExternalKind::Table => "table",
                        wasmparser::ExternalKind::Global => "global",
                        wasmparser::ExternalKind::Tag => "tag",
                    };
                    export_list.push((export.name.to_string(), kind_str));
                }
            }
            wasmparser::Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.map_err(|e| {
                        CliError::Other(format!("wasm memory parse error: {e}"))
                    })?;
                    let initial_pages = memory.initial;
                    let max_str = memory
                        .maximum
                        .map(|m| format!("{m}"))
                        .unwrap_or_else(|| "unbounded".to_string());
                    let initial_kib = initial_pages * 64;
                    memory_info.push(format!(
                        "initial={initial_pages} pages ({initial_kib} KiB), max={max_str} pages"
                    ));
                }
            }
            _ => {}
        }
    }

    // Print header
    println!("=== WASM Guard Inspection ===");
    println!();
    println!("File: {}", path.display());
    println!("Size: {}", format_size(file_size));
    println!();

    // Print exported functions
    println!("Exported functions:");
    if export_list.is_empty() {
        println!("  (none)");
    } else {
        // Find the longest export name for alignment
        let max_name_len = export_list
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);
        for (name, kind) in &export_list {
            println!("  {name:<width$} ({kind})", width = max_name_len);
        }
    }
    println!();

    // ABI compatibility check
    let required_abi = ["evaluate", "arc_alloc", "arc_deny_reason"];
    let exported_func_names: Vec<&str> = export_list
        .iter()
        .filter(|(_, kind)| *kind == "function")
        .map(|(name, _)| name.as_str())
        .collect();

    let all_present = required_abi
        .iter()
        .all(|name| exported_func_names.contains(name));

    if all_present {
        println!("ABI compatibility: COMPATIBLE");
    } else {
        println!("ABI compatibility: INCOMPATIBLE");
    }
    for name in &required_abi {
        if exported_func_names.contains(name) {
            println!("  [+] {name}");
        } else {
            println!("  [-] {name} (MISSING)");
        }
    }
    println!();

    // Memory info
    println!("Memory:");
    if memory_info.is_empty() {
        println!("  (no memory section found)");
    } else {
        for info in &memory_info {
            println!("  {info}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// A single test fixture entry loaded from a YAML file.
#[derive(Debug, Deserialize)]
struct TestFixture {
    /// Human-readable fixture name.
    name: String,
    /// Request fields matching GuardRequest shape.
    request: GuardRequest,
    /// Expected verdict: "allow" or "deny".
    expected_verdict: String,
    /// If verdict is deny, the deny reason must contain this substring.
    #[serde(default)]
    deny_reason_contains: Option<String>,
}

pub(crate) fn cmd_guard_test(
    wasm_path: &Path,
    fixture_paths: &[PathBuf],
    fuel_limit: u64,
) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", wasm_path.display()))
    })?;

    let mut total = 0u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    for fixture_path in fixture_paths {
        let yaml_content = fs::read_to_string(fixture_path).map_err(|e| {
            CliError::Other(format!(
                "failed to read fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;
        let fixtures: Vec<TestFixture> = serde_yml::from_str(&yaml_content).map_err(|e| {
            CliError::Other(format!(
                "failed to parse fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;

        for fixture in &fixtures {
            total += 1;

            // Create a fresh backend per fixture to reset fuel and memory state.
            let mut backend = WasmtimeBackend::new().map_err(|e| {
                CliError::Other(format!("failed to create wasmtime backend: {e}"))
            })?;
            backend.load_module(&wasm_bytes, fuel_limit).map_err(|e| {
                CliError::Other(format!("failed to load wasm module: {e}"))
            })?;

            match backend.evaluate(&fixture.request) {
                Ok(verdict) => {
                    let result = check_verdict(&fixture.name, &verdict, fixture);
                    match result {
                        FixtureResult::Pass => {
                            passed += 1;
                            println!("[PASS] {}", fixture.name);
                        }
                        FixtureResult::Fail(reason) => {
                            failed += 1;
                            println!("[FAIL] {}: {reason}", fixture.name);
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    println!("[FAIL] {}: evaluation error: {e}", fixture.name);
                }
            }
        }
    }

    println!();
    println!("{passed} passed, {failed} failed out of {total} total");

    if failed > 0 {
        Err(CliError::Other(format!("{failed} test(s) failed")))
    } else {
        Ok(())
    }
}

enum FixtureResult {
    Pass,
    Fail(String),
}

fn check_verdict(
    _name: &str,
    verdict: &GuardVerdict,
    fixture: &TestFixture,
) -> FixtureResult {
    match fixture.expected_verdict.as_str() {
        "allow" => {
            if verdict.is_allow() {
                FixtureResult::Pass
            } else {
                let reason = match verdict {
                    GuardVerdict::Deny { reason } => reason
                        .as_deref()
                        .unwrap_or("(no reason)")
                        .to_string(),
                    _ => String::new(),
                };
                FixtureResult::Fail(format!("expected allow, got deny: {reason}"))
            }
        }
        "deny" => match verdict {
            GuardVerdict::Allow => {
                FixtureResult::Fail("expected deny, got allow".to_string())
            }
            GuardVerdict::Deny { reason } => {
                if let Some(expected_substr) = &fixture.deny_reason_contains {
                    let actual = reason.as_deref().unwrap_or("");
                    if actual.contains(expected_substr.as_str()) {
                        FixtureResult::Pass
                    } else {
                        FixtureResult::Fail(format!(
                            "deny reason '{}' does not contain '{expected_substr}'",
                            actual
                        ))
                    }
                } else {
                    FixtureResult::Pass
                }
            }
        },
        other => FixtureResult::Fail(format!(
            "unknown expected_verdict '{other}' (use 'allow' or 'deny')"
        )),
    }
}

pub(crate) fn cmd_guard_bench(
    _wasm_path: &Path,
    _iterations: u32,
    _fuel_limit: u64,
) -> Result<(), CliError> {
    // Implemented in Task 3.
    Err(CliError::Other("guard bench not yet implemented".to_string()))
}

pub(crate) fn cmd_guard_pack() -> Result<(), CliError> {
    // Implemented in Plan 02.
    Err(CliError::Other("guard pack not yet implemented".to_string()))
}

pub(crate) fn cmd_guard_install(_path: &Path, _target_dir: &Path) -> Result<(), CliError> {
    // Implemented in Plan 02.
    Err(CliError::Other("guard install not yet implemented".to_string()))
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

    #[test]
    fn test_fixture_yaml_deserializes() {
        let yaml = r#"
- name: "allows read in /home"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/home/user/doc.txt"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/home/user/doc.txt"
  expected_verdict: allow

- name: "denies read in /etc"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/etc/shadow"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/etc/shadow"
  expected_verdict: deny
  deny_reason_contains: "restricted"
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 2);

        // First fixture: allow
        assert_eq!(fixtures[0].name, "allows read in /home");
        assert_eq!(fixtures[0].request.tool_name, "read_file");
        assert_eq!(fixtures[0].request.server_id, "fs-server");
        assert_eq!(fixtures[0].request.agent_id, "agent-1");
        assert_eq!(fixtures[0].request.scopes, vec!["fs-server:read_file"]);
        assert_eq!(
            fixtures[0].request.action_type.as_deref(),
            Some("file_access")
        );
        assert_eq!(
            fixtures[0].request.extracted_path.as_deref(),
            Some("/home/user/doc.txt")
        );
        assert_eq!(fixtures[0].expected_verdict, "allow");
        assert!(fixtures[0].deny_reason_contains.is_none());

        // Second fixture: deny with reason substring
        assert_eq!(fixtures[1].name, "denies read in /etc");
        assert_eq!(fixtures[1].expected_verdict, "deny");
        assert_eq!(
            fixtures[1].deny_reason_contains.as_deref(),
            Some("restricted")
        );
    }

    #[test]
    fn test_fixture_expected_verdict_values() {
        let allow_yaml = r#"
- name: "allow case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: allow
"#;
        let deny_yaml = r#"
- name: "deny case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: deny
"#;

        let allow_fixtures: Vec<TestFixture> = serde_yml::from_str(allow_yaml).unwrap();
        assert_eq!(allow_fixtures[0].expected_verdict, "allow");

        let deny_fixtures: Vec<TestFixture> = serde_yml::from_str(deny_yaml).unwrap();
        assert_eq!(deny_fixtures[0].expected_verdict, "deny");
    }

    #[test]
    fn test_fixture_all_guard_request_fields() {
        let yaml = r#"
- name: "full fields"
  request:
    tool_name: write_file
    server_id: fs-server
    agent_id: agent-2
    arguments:
      content: "hello"
    scopes:
      - "fs-server:write_file"
    action_type: file_write
    extracted_path: "/tmp/out.txt"
    extracted_target: "example.com"
    filesystem_roots:
      - "/tmp"
      - "/home"
    matched_grant_index: 3
  expected_verdict: allow
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 1);
        let req = &fixtures[0].request;
        assert_eq!(req.tool_name, "write_file");
        assert_eq!(req.server_id, "fs-server");
        assert_eq!(req.agent_id, "agent-2");
        assert_eq!(req.action_type.as_deref(), Some("file_write"));
        assert_eq!(req.extracted_path.as_deref(), Some("/tmp/out.txt"));
        assert_eq!(req.extracted_target.as_deref(), Some("example.com"));
        assert_eq!(req.filesystem_roots, vec!["/tmp", "/home"]);
        assert_eq!(req.matched_grant_index, Some(3));
    }

    #[test]
    fn test_check_verdict_allow_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Allow;
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_allow_but_denied_fails() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("nope".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_match() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("path is restricted zone".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_mismatch() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked by policy".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    fn make_test_request() -> GuardRequest {
        GuardRequest {
            tool_name: "test_tool".to_string(),
            server_id: "test-server".to_string(),
            agent_id: "test-agent".to_string(),
            arguments: serde_json::json!({}),
            scopes: Vec::new(),
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        }
    }
}
