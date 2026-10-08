use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use super::*;
use crate::{effective_uid, refusal, Owner, OwnerPolicy, PrivateDirectory, Refusal};

#[test]
fn prepare_creates_missing_directories_owner_only() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("state").join("locks");

    let prepared = PrivateDirectory::prepare(&target, &DIRECTORY)?;

    assert_eq!(prepared.path(), fs::canonicalize(&target)?);
    assert_eq!(mode_of(&root.path().join("state"))?, 0o700);
    assert_eq!(mode_of(&target)?, 0o700);
    assert!(prepared.is_empty()?);
    Ok(())
}

#[test]
fn prepare_keeps_an_existing_mode_the_policy_allows() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("project");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;

    PrivateDirectory::prepare(&target, &DIRECTORY)?;

    assert_eq!(mode_of(&target)?, 0o755);
    Ok(())
}

#[test]
fn prepare_refuses_group_writable_target_without_changing_it() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("project");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o775))?;

    let result = PrivateDirectory::prepare(&target, &DIRECTORY);

    assert_eq!(refusal_of(result)?, Refusal::Mode);
    assert_eq!(mode_of(&target)?, 0o775);
    Ok(())
}

#[test]
fn owner_only_policy_refuses_group_readable_target() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("state");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;

    PrivateDirectory::prepare(&target, &DIRECTORY)?;
    let result = PrivateDirectory::prepare(&target, &OWNER_ONLY_DIRECTORY);

    assert_eq!(refusal_of(result)?, Refusal::Mode);
    Ok(())
}

#[test]
fn hardened_preparation_resets_an_existing_mode() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("locks");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o775))?;

    PrivateDirectory::prepare_hardened(&target, &DIRECTORY)?;

    assert_eq!(mode_of(&target)?, 0o700);
    Ok(())
}

#[test]
fn prepare_refuses_a_final_symlink_without_changing_its_target() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("attacker-selected");
    let alias = root.path().join("project");
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
    symlink(&target, &alias)?;

    let failure = walk_failure(PrivateDirectory::prepare(&alias, &DIRECTORY))?;

    assert!(names_symlink_refusal(&failure), "{failure}");
    assert_eq!(mode_of(&target)?, 0o755);
    Ok(())
}

#[test]
fn prepare_refuses_an_intermediate_symlink() -> TestResult {
    let root = private_root()?;
    let target_parent = root.path().join("attacker-selected");
    let alias_parent = root.path().join("alias");
    fs::create_dir(&target_parent)?;
    fs::create_dir(target_parent.join("project"))?;
    symlink(&target_parent, &alias_parent)?;

    let failure = walk_failure(PrivateDirectory::prepare(
        &alias_parent.join("project"),
        &DIRECTORY,
    ))?;

    assert!(names_symlink_refusal(&failure), "{failure}");
    Ok(())
}

#[test]
fn prepare_refuses_an_ancestor_writable_by_others() -> TestResult {
    let root = private_root()?;
    let shared = root.path().join("shared");
    fs::create_dir(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))?;

    let result = PrivateDirectory::prepare(&shared.join("locks"), &DIRECTORY);

    assert_eq!(refusal_of(result)?, Refusal::AncestorWritable);
    assert!(!shared.join("locks").exists());
    Ok(())
}

#[test]
fn prepare_refuses_a_target_owned_by_another_user() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("state");
    let policy = OwnerPolicy {
        owner: Owner::Uid(foreign_uid()),
        ..DIRECTORY
    };

    let result = PrivateDirectory::prepare(&target, &policy);

    assert_eq!(refusal_of(result)?, Refusal::Owner);
    Ok(())
}

#[test]
fn owner_rules_admit_only_their_users() -> TestResult {
    assert!(Owner::EffectiveUser.permits(effective_uid()));
    assert!(!Owner::EffectiveUser.permits(foreign_uid()));
    assert!(Owner::EffectiveUserOrRoot.permits(crate::policy::ROOT_UID));
    assert!(!Owner::Uid(foreign_uid()).permits(effective_uid()));
    assert!(Owner::Unchecked.permits(foreign_uid()));

    let filesystem_root = fs::metadata("/")?;
    if filesystem_root.uid() == effective_uid() {
        return Ok(());
    }
    let error = DIRECTORY
        .check_owner(&filesystem_root, crate::policy::Subject::Directory)
        .err()
        .ok_or("a directory owned by another user was accepted")?;

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(refusal(&error), Some(Refusal::Owner));
    assert!(error
        .to_string()
        .contains("must be owned by the effective user"));
    Ok(())
}

#[test]
fn revalidation_detects_a_replaced_path_while_operations_stay_pinned() -> TestResult {
    let root = private_root()?;
    let target = root.path().join("project");
    let pinned = root.path().join("pinned");
    let prepared = PrivateDirectory::prepare(&target, &DIRECTORY)?;
    prepared.revalidate()?;
    fs::rename(&target, &pinned)?;
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;

    let result = prepared.revalidate();
    prepared.write_new(Path::new("worker.json"), b"pinned", 0o600)?;

    assert_eq!(refusal_of(result)?, Refusal::PathReplaced);
    assert_eq!(fs::read(pinned.join("worker.json"))?, b"pinned");
    assert!(fs::read_dir(&target)?.next().is_none());
    Ok(())
}

#[test]
fn created_child_directories_follow_the_requested_mode() -> TestResult {
    let root = private_root()?;
    let prepared = PrivateDirectory::prepare(&root.path().join("project"), &DIRECTORY)?;

    prepared.create_dir_all(Path::new("src/bin"), 0o700)?;
    prepared.write_new(Path::new("src/bin/main.rs"), b"fn main() {}\n", 0o600)?;

    let project = prepared.path();
    assert_eq!(mode_of(&project.join("src"))?, 0o700);
    assert_eq!(
        fs::read(project.join("src/bin/main.rs"))?,
        b"fn main() {}\n"
    );
    assert!(!prepared.is_empty()?);
    Ok(())
}

#[test]
fn child_directories_must_satisfy_the_directory_policy() -> TestResult {
    let root = private_root()?;
    let prepared = PrivateDirectory::prepare(&root.path().join("project"), &DIRECTORY)?;
    let shared = prepared.path().join("shared");
    fs::create_dir(&shared)?;
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777))?;

    let nested = prepared.create_dir_all(Path::new("shared/inner"), 0o700);
    let written = prepared.write_new(Path::new("shared/file"), b"x", 0o600);

    assert_eq!(refusal_of(nested)?, Refusal::Mode);
    assert_eq!(refusal_of(written)?, Refusal::Mode);
    assert!(!shared.join("inner").exists());
    Ok(())
}

#[test]
fn relative_paths_must_contain_only_normal_components() -> TestResult {
    let root = private_root()?;
    let prepared = PrivateDirectory::prepare(&root.path().join("project"), &DIRECTORY)?;

    for relative in ["../escape", "/absolute", "a/../b", ""] {
        let result = prepared.write_new(Path::new(relative), b"x", 0o600);
        assert_eq!(refusal_of(result)?, Refusal::InvalidPath, "{relative}");
    }
    Ok(())
}

#[test]
fn new_files_never_replace_entries_or_follow_symlinks() -> TestResult {
    let root = private_root()?;
    let prepared = PrivateDirectory::prepare(&root.path().join("project"), &DIRECTORY)?;
    let outside = root.path().join("outside.txt");
    fs::write(&outside, b"outside")?;
    symlink(&outside, prepared.path().join("README.md"))?;
    prepared.write_new(Path::new("Cargo.toml"), b"first", 0o600)?;

    let overwrite = prepared.write_new(Path::new("Cargo.toml"), b"second", 0o600);
    let redirected = prepared.create_new(Path::new("README.md"), 0o600);

    assert_eq!(os_error_kind(overwrite)?, io::ErrorKind::AlreadyExists);
    assert_eq!(os_error_kind(redirected)?, io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(prepared.path().join("Cargo.toml"))?, b"first");
    assert_eq!(fs::read(&outside)?, b"outside");
    assert_eq!(mode_of(&prepared.path().join("Cargo.toml"))? & 0o077, 0);
    Ok(())
}

#[test]
fn creation_modes_must_be_permission_bits() -> TestResult {
    let root = private_root()?;
    let prepared = PrivateDirectory::prepare(&root.path().join("project"), &DIRECTORY)?;

    let result = prepared.write_new(Path::new("setuid"), b"x", 0o4755);

    assert_eq!(refusal_of(result)?, Refusal::InvalidMode);
    assert!(!prepared.path().join("setuid").exists());
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn ancestors_are_walked_with_a_path_only_descriptor() -> TestResult {
    assert!(crate::walk::traversal_flags()?.contains(rustix::fs::OFlags::PATH));
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
))]
#[test]
fn prepare_traverses_a_search_only_ancestor() -> TestResult {
    let root = private_root()?;
    let search_only = root.path().join("search-only");
    let target = search_only.join("project");
    fs::create_dir(&search_only)?;
    fs::create_dir(&target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&search_only, fs::Permissions::from_mode(0o100))?;

    let prepared = PrivateDirectory::prepare(&target, &DIRECTORY);
    fs::set_permissions(&search_only, fs::Permissions::from_mode(0o700))?;

    assert!(prepared?.is_empty()?);
    Ok(())
}
