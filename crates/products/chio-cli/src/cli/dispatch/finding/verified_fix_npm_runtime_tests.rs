use super::*;

fn package_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("bin")).unwrap();
    fs::create_dir_all(root.path().join("node_modules/@fixture/dependency")).unwrap();
    fs::write(root.path().join("bin/npm-cli.js"), "#!/usr/bin/env node\n").unwrap();
    fs::write(root.path().join("bin/npx-cli.js"), "#!/usr/bin/env node\n").unwrap();
    fs::write(
        root.path().join("package.json"),
        serde_json::to_vec(&serde_json::json!({
            "name": "npm",
            "version": "9.2.0",
            "bin": {"npm": "bin/npm-cli.js", "npx": "bin/npx-cli.js"},
            "dependencies": {"@fixture/dependency": "1.0.0"},
            "bundleDependencies": ["@fixture/dependency"]
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        root.path()
            .join("node_modules/@fixture/dependency/package.json"),
        br#"{"name":"@fixture/dependency","version":"1.0.0"}"#,
    )
    .unwrap();
    root
}

fn assert_rejected(root: &Path, error: &str) {
    let mut builder = RuntimeMountSpecBuilder::default();
    builder.files.insert((
        PathBuf::from("/selected/source"),
        PathBuf::from("/selected/target"),
    ));
    assert_eq!(
        builder
            .add_npm_runtime(&root.join("bin/npm-cli.js"))
            .unwrap_err(),
        error
    );
    let spec = builder.finish();
    assert_eq!(
        spec.files,
        vec![(
            PathBuf::from("/selected/source"),
            PathBuf::from("/selected/target")
        )]
    );
    assert_eq!(spec.trees, Vec::<(PathBuf, PathBuf)>::new());
    assert_eq!(spec.symlinks, Vec::<(PathBuf, PathBuf)>::new());
}

#[test]
fn npm_package_is_selected_from_its_executable() {
    let root = package_fixture();
    let mut builder = RuntimeMountSpecBuilder::default();
    builder
        .add_npm_runtime(&root.path().join("bin/npm-cli.js"))
        .unwrap();
    let spec = builder.finish();
    assert_eq!(
        spec.trees,
        vec![(
            root.path().canonicalize().unwrap(),
            PathBuf::from("/runtime/npm")
        )]
    );
    assert_eq!(
        spec.symlinks,
        vec![
            (
                PathBuf::from("/runtime/npm/bin/npm-cli.js"),
                PathBuf::from("/runtime/bin/npm")
            ),
            (
                PathBuf::from("/runtime/npm/bin/npx-cli.js"),
                PathBuf::from("/runtime/bin/npx")
            ),
        ]
    );
}

#[test]
fn npm_split_package_is_rejected_without_publishing_mounts() {
    let root = package_fixture();
    fs::remove_dir_all(root.path().join("node_modules/@fixture/dependency")).unwrap();
    assert_rejected(root.path(), SELF_CONTAINED_NPM_REQUIRED);
}

#[test]
fn npm_invalid_metadata_is_rejected() {
    for metadata in [b"{invalid".as_slice(), br#"{"name":"other"}"#.as_slice()] {
        let root = package_fixture();
        fs::write(root.path().join("package.json"), metadata).unwrap();
        assert_rejected(root.path(), "npm runtime package metadata is invalid");
    }
}

#[test]
fn npm_package_identity_and_version_are_required() {
    for (field, value) in [("name", "different-package"), ("version", " ")] {
        let root = package_fixture();
        let path = root.path().join("package.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        metadata[field] = serde_json::json!(value);
        fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_rejected(root.path(), "npm runtime package metadata is invalid");
    }
}

#[test]
fn npm_metadata_with_duplicate_keys_is_rejected() {
    let root = package_fixture();
    let path = root.path().join("package.json");
    let metadata = fs::read_to_string(&path).unwrap();
    fs::write(
        path,
        format!("{{\"annotation\":0,\"annotation\":1,{}", &metadata[1..]),
    )
    .unwrap();
    assert_rejected(root.path(), "npm runtime package metadata is invalid");
}

#[test]
fn npm_executable_outside_the_package_bin_is_rejected() {
    let root = package_fixture();
    let executable = root.path().join("npm-cli.js");
    fs::write(&executable, "#!/usr/bin/env node\n").unwrap();
    assert_eq!(
        RuntimeMountSpecBuilder::default()
            .add_npm_runtime(&executable)
            .unwrap_err(),
        "npm runtime executable must resolve to bin/npm-cli.js"
    );
}

#[test]
fn npm_bundled_package_identity_is_required() {
    let root = package_fixture();
    fs::write(
        root.path()
            .join("node_modules/@fixture/dependency/package.json"),
        br#"{"name":"different-package"}"#,
    )
    .unwrap();
    assert_rejected(root.path(), SELF_CONTAINED_NPM_REQUIRED);
}

#[test]
fn npm_metadata_read_is_bounded() {
    let root = package_fixture();
    fs::write(
        root.path().join("package.json"),
        vec![b' '; MAX_NPM_METADATA_BYTES + 1],
    )
    .unwrap();
    assert_rejected(
        root.path(),
        "npm runtime package metadata exceeds its size bound",
    );
}

#[test]
fn npm_invalid_bin_metadata_is_rejected() {
    let root = package_fixture();
    let path = root.path().join("package.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["bin"]["npm"] = serde_json::json!("../outside.js");
    fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert_rejected(root.path(), "npm runtime bin metadata is invalid");
}

#[test]
fn npm_missing_bin_target_is_rejected() {
    let root = package_fixture();
    fs::remove_file(root.path().join("bin/npx-cli.js")).unwrap();
    assert_rejected(root.path(), "npm runtime bin target is invalid");
}

#[test]
fn npm_bundle_metadata_is_validated() {
    for (dependencies, bundles) in [
        (
            serde_json::json!({"@fixture/dependency": "1.0.0"}),
            serde_json::json!([]),
        ),
        (
            serde_json::json!({"@fixture/dependency": "1.0.0"}),
            serde_json::json!(["@fixture/dependency", "@fixture/dependency"]),
        ),
        (
            serde_json::json!({"../outside": "1.0.0"}),
            serde_json::json!(["../outside"]),
        ),
    ] {
        let root = package_fixture();
        let path = root.path().join("package.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        metadata["dependencies"] = dependencies;
        metadata["bundleDependencies"] = bundles;
        fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_rejected(root.path(), SELF_CONTAINED_NPM_REQUIRED);
    }
}

#[cfg(unix)]
#[test]
fn npm_internal_relative_aliases_are_supported() {
    let root = package_fixture();
    fs::create_dir(root.path().join("node_modules/.bin")).unwrap();
    std::os::unix::fs::symlink(
        "../../bin/npm-cli.js",
        root.path().join("node_modules/.bin/npm"),
    )
    .unwrap();
    let mut builder = RuntimeMountSpecBuilder::default();
    builder
        .add_npm_runtime(&root.path().join("bin/npm-cli.js"))
        .unwrap();
    assert_eq!(builder.finish().trees.len(), 1);
}

#[cfg(unix)]
#[test]
fn npm_escaping_absolute_and_cyclic_aliases_are_rejected() {
    for target in ["../../outside", "/etc/passwd", "alias"] {
        let root = package_fixture();
        std::os::unix::fs::symlink(target, root.path().join("alias")).unwrap();
        assert_rejected(
            root.path(),
            "npm runtime package tree contains an invalid symlink",
        );
    }
}

#[cfg(unix)]
#[test]
fn npm_relative_alias_cannot_leave_and_reenter_the_package() {
    let root = package_fixture();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(root.path().join("bin"), outside.path().join("back")).unwrap();
    let target = Path::new("..")
        .join(outside.path().file_name().unwrap())
        .join("back");
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(target, &alias).unwrap();
    assert_eq!(
        alias.canonicalize().unwrap(),
        root.path().join("bin").canonicalize().unwrap()
    );
    assert_rejected(
        root.path(),
        "npm runtime package tree contains an invalid symlink",
    );
}

#[cfg(unix)]
#[test]
fn npm_relative_alias_cannot_escape_through_an_intermediate_alias() {
    let root = package_fixture();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(root.path().join("bin"), outside.path().join("back")).unwrap();
    std::os::unix::fs::symlink(".", root.path().join("jump")).unwrap();
    let target = Path::new("jump/..")
        .join(outside.path().file_name().unwrap())
        .join("back");
    let alias = root.path().join("alias");
    std::os::unix::fs::symlink(target, &alias).unwrap();
    assert_eq!(
        alias.canonicalize().unwrap(),
        root.path().join("bin").canonicalize().unwrap()
    );
    assert_rejected(
        root.path(),
        "npm runtime package tree contains an invalid symlink",
    );
}

#[test]
fn npm_tree_inventory_is_bounded() {
    let root = package_fixture();
    assert_eq!(
        validate_package_tree(root.path(), 1).unwrap_err(),
        "npm runtime package tree exceeded its entry bound"
    );
}

#[cfg(unix)]
#[test]
fn npm_socket_entry_is_rejected() {
    let root = package_fixture();
    let _socket = std::os::unix::net::UnixListener::bind(root.path().join("socket")).unwrap();
    assert_rejected(
        root.path(),
        "npm runtime package tree contains an unsupported entry",
    );
}

#[test]
#[ignore = "requires bubblewrap, prlimit, cgroup isolation and a self-contained node and npm on PATH"]
fn npm_runs_an_offline_script_in_the_sandbox() {
    use super::super::{find_executable, require_sandbox, run_test_command_with_timeout};

    let search_path = std::env::var_os("PATH").unwrap_or_default();

    for executable in ["node", "npm"] {
        assert!(
            find_executable(executable, &search_path).is_some(),
            "npm sandbox test requires {executable} on PATH"
        );
    }
    if let Err(error) = require_sandbox() {
        panic!("npm sandbox test requires the verified-fix sandbox: {error}");
    }
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("package.json"),
        serde_json::to_vec(&serde_json::json!({
            "name": "sandbox-script-probe",
            "version": "1.0.0",
            "scripts": {
                "probe": "node -e \"require('node:fs').writeFileSync('npm-probe', 'ready')\""
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let result = run_test_command_with_timeout(
        root.path(),
        "npm --offline --ignore-scripts=false run probe && test \"$(cat npm-probe)\" = ready",
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(result.exit_code, 0);
    assert_eq!(
        fs::metadata(root.path().join("npm-probe"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound
    );
}
