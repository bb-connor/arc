use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::Path;

use super::*;
use crate::{
    open_directory_nofollow, publish_at, refusal, Expect, OwnerPolicy, PrivateDirectory, Refusal,
};

fn entries(directory: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut names = fs::read_dir(directory)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, io::Error>>()?;
    names.sort();
    Ok(names)
}

fn state(root: &Path) -> Result<PrivateDirectory, Box<dyn Error>> {
    Ok(PrivateDirectory::prepare(&root.join("state"), &DIRECTORY)?)
}

#[test]
fn publish_creates_an_absent_destination() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;

    let identity =
        directory.atomic_publish(name("seed"), b"first", 0o600, Expect::Absent, &SECRET)?;

    let path = directory.path().join("seed");
    let metadata = fs::metadata(&path)?;
    assert_eq!(fs::read(&path)?, b"first");
    assert_eq!(identity.inode(), metadata.ino());
    assert_eq!(identity.length(), 5);
    assert_eq!(metadata.mode() & 0o077, 0);
    assert_eq!(entries(directory.path())?, ["seed"]);
    Ok(())
}

#[test]
fn publish_refuses_an_existing_destination_when_absence_is_expected() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.atomic_publish(name("seed"), b"first", 0o600, Expect::Absent, &SECRET)?;

    let result =
        directory.atomic_publish(name("seed"), b"second", 0o600, Expect::Absent, &SECRET);

    assert_eq!(refusal_of(result)?, Refusal::DestinationExists);
    assert_eq!(fs::read(directory.path().join("seed"))?, b"first");
    assert_eq!(entries(directory.path())?, ["seed"]);
    Ok(())
}

#[test]
fn publish_replaces_only_the_expected_identity() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    let first =
        directory.atomic_publish(name("seed"), b"first", 0o600, Expect::Absent, &SECRET)?;
    let second = directory.atomic_publish(
        name("seed"),
        b"second",
        0o600,
        Expect::Identity(first),
        &SECRET,
    )?;

    let stale = directory.atomic_publish(
        name("seed"),
        b"third",
        0o600,
        Expect::Identity(first),
        &SECRET,
    );

    assert_ne!(first, second);
    assert_eq!(refusal_of(stale)?, Refusal::DestinationChanged);
    assert_eq!(fs::read(directory.path().join("seed"))?, b"second");
    assert_eq!(entries(directory.path())?, ["seed"]);
    Ok(())
}

#[test]
fn publish_refuses_a_missing_expected_destination() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    let first =
        directory.atomic_publish(name("seed"), b"first", 0o600, Expect::Absent, &SECRET)?;
    fs::remove_file(directory.path().join("seed"))?;

    let result = directory.atomic_publish(
        name("seed"),
        b"second",
        0o600,
        Expect::Identity(first),
        &SECRET,
    );

    let error = result.err().ok_or("a missing destination was replaced")?;
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(refusal(&error), Some(Refusal::DestinationChanged));
    assert!(entries(directory.path())?.is_empty());
    Ok(())
}

#[test]
fn replacing_publish_replaces_a_symlink_without_following_it() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    let outside = root.path().join("outside");
    fs::write(&outside, b"outside")?;
    symlink(&outside, directory.path().join("seed"))?;

    directory.atomic_publish(name("seed"), b"private", 0o600, Expect::Replace, &SECRET)?;

    let metadata = fs::symlink_metadata(directory.path().join("seed"))?;
    assert!(metadata.file_type().is_file());
    assert_eq!(fs::read(&outside)?, b"outside");
    Ok(())
}

#[test]
fn publish_refuses_a_staged_file_the_policy_rejects() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;

    let seed_policy = OwnerPolicy {
        forbidden_mode: 0o177,
        ..SECRET
    };

    let result =
        directory.atomic_publish(name("seed"), b"first", 0o700, Expect::Absent, &seed_policy);

    assert_eq!(refusal_of(result)?, Refusal::Mode);
    assert!(entries(directory.path())?.is_empty());
    Ok(())
}

#[test]
fn publish_names_must_be_one_normal_component() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;

    for invalid in ["a/b", "..", ".", "", "/seed", "seed/"] {
        let result =
            directory.atomic_publish(name(invalid), b"x", 0o600, Expect::Replace, &SECRET);
        assert_eq!(refusal_of(result)?, Refusal::InvalidPath, "{invalid:?}");
    }
    assert!(entries(directory.path())?.is_empty());
    Ok(())
}

#[test]
fn path_publishing_refuses_a_symlinked_directory() -> TestResult {
    let root = private_root()?;
    let real = root.path().join("real");
    let alias = root.path().join("alias");
    fs::create_dir(&real)?;
    symlink(&real, &alias)?;

    let refused = os_error_kind(open_directory_nofollow(&alias))?;
    let directory = open_directory_nofollow(&real)?;
    publish_at(
        &directory,
        name("seed"),
        b"seed",
        0o600,
        Expect::Absent,
        &SECRET,
    )?;

    assert!(
        matches!(
            refused,
            io::ErrorKind::NotADirectory | io::ErrorKind::FilesystemLoop
        ),
        "{refused:?}"
    );
    assert_eq!(fs::read(real.join("seed"))?, b"seed");
    Ok(())
}

#[test]
fn locks_are_created_private_and_reopened_unchanged() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;

    let created = directory.open_lock(name("host.lock"), 0o600, &SECRET)?;
    drop(created);
    fs::write(directory.path().join("host.lock"), b"held")?;
    let reopened = directory.open_lock(name("host.lock"), 0o600, &SECRET)?;

    assert_eq!(reopened.metadata()?.mode() & 0o077, 0);
    assert_eq!(fs::read(directory.path().join("host.lock"))?, b"held");
    Ok(())
}

#[test]
fn locks_refuse_links_and_symlinks() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    let outside = root.path().join("outside.lock");
    write_private(&outside, b"")?;
    symlink(&outside, directory.path().join("host.lock"))?;
    directory.open_lock(name("other.lock"), 0o600, &SECRET)?;
    fs::hard_link(
        directory.path().join("other.lock"),
        directory.path().join("other-alias.lock"),
    )?;

    let symlinked = os_error_kind(directory.open_lock(name("host.lock"), 0o600, &SECRET))?;
    let linked = directory.open_lock(name("other.lock"), 0o600, &SECRET);

    assert_eq!(symlinked, io::ErrorKind::FilesystemLoop);
    assert_eq!(refusal_of(linked)?, Refusal::LinkCount);
    Ok(())
}
