use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use super::*;
use crate::{
    private_file_identity, read_private_file, Owner, OwnerPolicy, PrivateDirectory, Refusal,
};

fn state(root: &Path) -> Result<PrivateDirectory, Box<dyn Error>> {
    Ok(PrivateDirectory::prepare(&root.join("state"), &DIRECTORY)?)
}

#[test]
fn private_files_read_their_exact_bytes() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;

    let bytes = directory.read_private(Path::new("host.json"), &SECRET, 2)?;

    assert_eq!(bytes.as_slice(), b"{}");
    Ok(())
}

#[test]
fn private_reads_refuse_a_symlink() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    let outside = root.path().join("outside.json");
    write_private(&outside, b"{}")?;
    symlink(&outside, directory.path().join("host.json"))?;

    let kind = os_error_kind(directory.read_private(Path::new("host.json"), &SECRET, 64))?;

    assert_eq!(kind, io::ErrorKind::FilesystemLoop);
    Ok(())
}

#[test]
fn private_reads_refuse_a_directory() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.create_dir_all(Path::new("host.json"), 0o700)?;

    let result = directory.read_private(Path::new("host.json"), &SECRET, 64);

    assert_eq!(refusal_of(result)?, Refusal::NotRegularFile);
    Ok(())
}

#[test]
fn private_reads_refuse_group_or_other_mode_bits() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;

    for mode in [0o640, 0o604, 0o620] {
        fs::set_permissions(
            directory.path().join("host.json"),
            fs::Permissions::from_mode(mode),
        )?;
        let result = directory.read_private(Path::new("host.json"), &SECRET, 64);
        assert_eq!(refusal_of(result)?, Refusal::Mode, "{mode:o}");
    }
    Ok(())
}

#[test]
fn private_reads_refuse_a_hard_linked_file() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;
    fs::hard_link(
        directory.path().join("host.json"),
        directory.path().join("alias.json"),
    )?;

    let result = directory.read_private(Path::new("host.json"), &SECRET, 64);

    assert_eq!(refusal_of(result)?, Refusal::LinkCount);
    Ok(())
}

#[test]
fn private_reads_refuse_a_file_owned_by_another_user() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;
    let policy = OwnerPolicy {
        owner: Owner::Uid(foreign_uid()),
        ..SECRET
    };

    let result = directory.read_private(Path::new("host.json"), &policy, 64);

    assert_eq!(refusal_of(result)?, Refusal::Owner);
    Ok(())
}

#[test]
fn private_reads_refuse_more_than_the_limit() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"12345", 0o600)?;

    let oversized = directory.read_private(Path::new("host.json"), &SECRET, 4);
    let exact = directory.read_private(Path::new("host.json"), &SECRET, 5)?;

    assert_eq!(refusal_of(oversized)?, Refusal::TooLarge);
    assert_eq!(exact.as_slice(), b"12345");
    Ok(())
}

#[test]
fn growth_between_open_and_read_is_refused() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;
    let mut file = directory.open_private(Path::new("host.json"), &SECRET)?;

    append(&directory.path().join("host.json"), b" ")?;
    let result = file.read_bounded(64);

    assert_eq!(refusal_of(result)?, Refusal::ChangedWhileReading);
    Ok(())
}

#[test]
fn replacement_between_open_and_read_is_refused() -> TestResult {
    let root = private_root()?;
    let directory = state(root.path())?;
    directory.write_new(Path::new("host.json"), b"{}", 0o600)?;
    directory.write_new(Path::new("next.json"), b"{}", 0o600)?;
    let mut file = directory.open_private(Path::new("host.json"), &SECRET)?;

    fs::rename(
        directory.path().join("next.json"),
        directory.path().join("host.json"),
    )?;
    let bytes = file.read_bounded(64)?;
    let confirmed = directory.confirm(Path::new("host.json"), &file);

    assert_eq!(bytes.as_slice(), b"{}");
    assert_eq!(refusal_of(confirmed)?, Refusal::ChangedWhileReading);
    Ok(())
}

#[test]
fn path_reads_return_bytes_and_identity() -> TestResult {
    let root = private_root()?;
    let seed = root.path().join("authority.seed");
    write_private(&seed, b"seed")?;

    let (bytes, identity) = read_private_file(&seed, &SECRET, 64)?;
    let metadata = fs::metadata(&seed)?;

    assert_eq!(bytes.as_slice(), b"seed");
    assert_eq!(identity.inode(), metadata.ino());
    assert_eq!(identity.device(), metadata.dev());
    assert_eq!(identity.length(), 4);
    assert_eq!(private_file_identity(&seed, &SECRET)?, identity);
    Ok(())
}

#[test]
fn path_reads_refuse_every_custody_violation() -> TestResult {
    let root = private_root()?;
    let seed = root.path().join("authority.seed");
    let alias = root.path().join("alias.seed");
    write_private(&seed, b"seed")?;

    symlink(&seed, &alias)?;
    let symlinked = read_private_file(&alias, &SECRET, 64);
    fs::remove_file(&alias)?;

    fs::hard_link(&seed, &alias)?;
    let linked = read_private_file(&seed, &SECRET, 64);
    fs::remove_file(&alias)?;

    fs::set_permissions(&seed, fs::Permissions::from_mode(0o644))?;
    let broad = read_private_file(&seed, &SECRET, 64);
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600))?;

    let foreign = read_private_file(
        &seed,
        &OwnerPolicy {
            owner: Owner::Uid(foreign_uid()),
            ..SECRET
        },
        64,
    );
    let oversized = read_private_file(&seed, &SECRET, 3);

    assert_eq!(refusal_of(symlinked)?, Refusal::NotRegularFile);
    assert_eq!(refusal_of(linked)?, Refusal::LinkCount);
    assert_eq!(refusal_of(broad)?, Refusal::Mode);
    assert_eq!(refusal_of(foreign)?, Refusal::Owner);
    assert_eq!(refusal_of(oversized)?, Refusal::TooLarge);
    Ok(())
}

#[test]
fn path_identity_cannot_honor_an_acl_rule() -> TestResult {
    let root = private_root()?;
    let seed = root.path().join("authority.seed");
    write_private(&seed, b"seed")?;
    let policy = OwnerPolicy {
        reject_acl: true,
        ..SECRET
    };

    let result = private_file_identity(&seed, &policy);

    assert_eq!(refusal_of(result)?, Refusal::Acl);
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn acl_rule_admits_a_file_without_an_extended_acl() -> TestResult {
    let root = private_root()?;
    let seed = root.path().join("authority.seed");
    write_private(&seed, b"seed")?;
    let policy = OwnerPolicy {
        reject_acl: true,
        ..SECRET
    };

    let (bytes, _) = read_private_file(&seed, &policy, 64)?;

    assert_eq!(bytes.as_slice(), b"seed");
    Ok(())
}
