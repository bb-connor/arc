#![allow(clippy::unwrap_used)]

use super::*;

fn fake_sysroot() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("bin")).unwrap();
    fs::create_dir_all(root.path().join("lib/rustlib/target/lib")).unwrap();
    for path in [
        "bin/cargo",
        "bin/rustc",
        "lib/rustlib/target/lib/libstd.rlib",
    ] {
        fs::write(root.path().join(path), b"fixture").unwrap();
    }
    root
}

#[test]
fn rust_runtime_excludes_ambient_bin_lib_and_documentation() {
    let root = fake_sysroot();
    for path in ["bin/operator-tool", "lib/operator-secret", "share/doc/rust"] {
        let path = root.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"not a runtime input").unwrap();
    }
    let mut selected = RuntimeMountSpecBuilder::default();
    selected.add_rust_sysroot(root.path()).unwrap();
    assert!(selected.trees.is_empty());
    let destinations = selected
        .files
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<Vec<_>>();
    assert_eq!(destinations.len(), 3);
    for relative in [
        "bin/cargo",
        "bin/rustc",
        "lib/rustlib/target/lib/libstd.rlib",
    ] {
        assert!(destinations.contains(&Path::new(RUST_RUNTIME).join(relative)));
    }
}

#[test]
fn rust_runtime_keeps_the_selected_tree_entry_bound() {
    let root = fake_sysroot();
    let library = root.path().join("lib/rustlib/target/lib");
    for index in 0..MAX_RUNTIME_TREE_ENTRIES {
        fs::write(library.join(format!("entry-{index}")), b"").unwrap();
    }
    let mut selected = RuntimeMountSpecBuilder::default();
    let error = selected.add_rust_sysroot(root.path()).unwrap_err();
    assert!(error.contains("entry bound"), "{error}");
    assert!(selected.files.is_empty());
    assert!(selected.symlinks.is_empty());
}

#[test]
fn rust_runtime_rejects_missing_required_components_without_partial_mounts() {
    for missing in ["bin/rustc", "lib/rustlib"] {
        let root = fake_sysroot();
        fs::rename(
            root.path().join(missing),
            root.path().join("removed-component"),
        )
        .unwrap();
        let mut selected = RuntimeMountSpecBuilder::default();
        assert!(selected.add_rust_sysroot(root.path()).is_err());
        assert!(selected.files.is_empty());
        assert!(selected.symlinks.is_empty());
    }
}

#[test]
fn rust_runtime_relocates_only_its_own_dependency_paths() {
    let root = Path::new("/usr");
    let mut selected = RuntimeMountSpecBuilder::default();
    selected.files.insert((
        PathBuf::from("/usr/lib/librustc.so"),
        PathBuf::from("/usr/bin/../lib/librustc.so"),
    ));
    selected
        .files
        .insert((PathBuf::from("/lib/libc.so"), PathBuf::from("/lib/libc.so")));
    selected.relocate_rust_dependencies(root).unwrap();
    assert_eq!(selected.files.len(), 3);
    assert!(selected.files.contains(&(
        PathBuf::from("/usr/lib/librustc.so"),
        PathBuf::from("/runtime/rust/lib/librustc.so"),
    )));
    assert!(!selected
        .files
        .iter()
        .any(|(_, path)| path == Path::new("/runtime/rust/lib/libc.so")));
}

#[cfg(unix)]
#[test]
fn rust_runtime_rejects_component_symlink_escapes_and_cycles() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::NamedTempFile::new().unwrap();
    for (alias, target) in [
        ("bin/cargo", outside.path().to_str().unwrap()),
        ("lib/rustlib/escape", "../operator-secret"),
        ("lib/rustlib/cycle", "cycle"),
        ("lib/rustlib/escape-dir", "../outside"),
    ] {
        let root = fake_sysroot();
        fs::write(root.path().join("lib/operator-secret"), b"private").unwrap();
        fs::create_dir(root.path().join("lib/outside")).unwrap();
        if root.path().join(alias).exists() {
            fs::rename(root.path().join(alias), root.path().join("saved-tool")).unwrap();
        }
        symlink(target, root.path().join(alias)).unwrap();
        let mut selected = RuntimeMountSpecBuilder::default();
        assert!(
            selected.add_rust_sysroot(root.path()).is_err(),
            "accepted {alias}"
        );
        assert!(selected.files.is_empty());
        assert!(selected.symlinks.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn rust_runtime_resolves_internal_file_and_directory_aliases() {
    use std::os::unix::fs::symlink;

    let root = fake_sysroot();
    let rustlib = root.path().join("lib/rustlib");
    symlink("target/lib/libstd.rlib", rustlib.join("std-alias.rlib")).unwrap();
    symlink(rustlib.join("target"), rustlib.join("target-alias")).unwrap();
    let mut selected = RuntimeMountSpecBuilder::default();
    selected.add_rust_sysroot(root.path()).unwrap();
    assert!(selected.files.contains(&(
        rustlib.join("target/lib/libstd.rlib"),
        PathBuf::from("/runtime/rust/lib/rustlib/std-alias.rlib"),
    )));
    assert!(selected.symlinks.contains(&(
        PathBuf::from("/runtime/rust/lib/rustlib/target"),
        PathBuf::from("/runtime/rust/lib/rustlib/target-alias"),
    )));
}

#[cfg(unix)]
#[test]
fn rust_runtime_dependency_resolves_host_symlinks_before_parent_components() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("actual/nested")).unwrap();
    fs::write(
        root.path().join("actual/library.so"),
        b"selected dependency",
    )
    .unwrap();
    fs::write(root.path().join("library.so"), b"wrong lexical source").unwrap();
    symlink("actual/nested", root.path().join("alias")).unwrap();
    let mut selected = RuntimeMountSpecBuilder::default();
    assert!(selected
        .add_dependency_path(&root.path().join("alias/../library.so"))
        .unwrap());
    assert_eq!(
        selected.files,
        [(
            root.path().join("actual/library.so"),
            root.path().join("library.so"),
        )]
        .into_iter()
        .collect()
    );
}

#[cfg(unix)]
#[test]
fn rust_runtime_rejects_redirected_rustlib_without_changing_existing_mounts() {
    use std::os::unix::fs::symlink;

    let root = fake_sysroot();
    fs::rename(
        root.path().join("lib/rustlib"),
        root.path().join("redirected"),
    )
    .unwrap();
    symlink("../redirected", root.path().join("lib/rustlib")).unwrap();
    let existing = (
        PathBuf::from("/selected/tool"),
        PathBuf::from("/runtime/bin/tool"),
    );
    let mut selected = RuntimeMountSpecBuilder::default();
    selected.files.insert(existing.clone());
    let error = selected.add_rust_sysroot(root.path()).unwrap_err();
    assert!(error.contains("unredirected"), "{error}");
    assert_eq!(selected.files, [existing].into_iter().collect());
    assert!(selected.symlinks.is_empty());
}

#[test]
fn rust_runtime_rejects_filesystem_root() {
    let mut selected = RuntimeMountSpecBuilder::default();
    assert!(selected
        .add_rust_sysroot(Path::new("/"))
        .unwrap_err()
        .contains("non-root"));
}
