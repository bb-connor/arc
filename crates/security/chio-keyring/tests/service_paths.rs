#![cfg(unix)]

use std::fs::Permissions;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use chio_core_types::Hash;
use chio_keyring::{open_or_provision_once, KeyringError};
use chio_test_support::prelude::*;

mod support;

const OPEN_LIMIT: Duration = Duration::from_secs(3);

fn identity() -> Hash {
    chio_core_types::sha256(b"chio.key-log.provisioning-record.test")
}

fn record_bytes() -> Vec<u8> {
    format!("{}\n", identity().to_hex()).into_bytes()
}

fn record_path(database: &Path) -> PathBuf {
    let mut name = database.file_name().test_unwrap().to_os_string();
    name.push(".provisioned");
    database.with_file_name(name)
}

fn private_directory(directory: &tempfile::TempDir, relative: &str, mode: u32) -> PathBuf {
    let path = support::trusted_temp_path(directory, relative);
    std::fs::create_dir_all(&path).test_unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(mode)).test_unwrap();
    path
}

/// Lays out an existing store and the record a first start wrote for it.
fn provisioned_store(directory: &Path) -> PathBuf {
    let database = directory.join("witness.sqlite");
    support::write_private_file(&database, b"").test_unwrap();
    support::write_private_file(record_path(&database), record_bytes()).test_unwrap();
    database
}

fn reopen(database: &Path) -> chio_keyring::Result<()> {
    open_or_provision_once(database, true, |_| Ok(()), |_: &()| identity())
}

fn assert_refused_by_policy(result: chio_keyring::Result<()>) {
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}

#[test]
fn a_first_start_record_is_exact_and_reopens() {
    let directory = support::private_tempdir().test_unwrap();
    let database = support::trusted_temp_path(&directory, "witness.sqlite");
    open_or_provision_once(
        &database,
        true,
        |provision| {
            assert!(provision);
            support::write_private_file(&database, b"")?;
            Ok(())
        },
        |_: &()| identity(),
    )
    .test_unwrap();
    assert_eq!(
        std::fs::read(record_path(&database)).test_unwrap(),
        record_bytes()
    );
    reopen(&database).test_unwrap();
}

#[test]
fn a_fifo_provisioning_record_is_refused_without_blocking() {
    let directory = support::private_tempdir().test_unwrap();
    let database = support::trusted_temp_path(&directory, "witness.sqlite");
    support::write_private_file(&database, b"").test_unwrap();
    let record = record_path(&database);
    let status = std::process::Command::new("mkfifo")
        .arg(&record)
        .status()
        .test_unwrap();
    assert!(status.success());

    let (sender, receiver) = mpsc::channel();
    let opener = {
        let database = database.clone();
        std::thread::spawn(move || {
            let _ = sender.send(reopen(&database));
        })
    };
    let Ok(result) = receiver.recv_timeout(OPEN_LIMIT) else {
        // A writer releases a reader blocked in open(2) so the thread ends.
        let _ = rustix::fs::open(
            &record,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        );
        let _ = opener.join();
        panic!("opening a FIFO provisioning record blocked for {OPEN_LIMIT:?}");
    };
    let _ = opener.join();
    assert_refused_by_policy(result);
}

#[test]
fn a_provisioning_record_with_excess_bytes_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    for excess in [1_usize, 200] {
        let mut bytes = record_bytes();
        bytes.extend(std::iter::repeat_n(b' ', excess));
        support::write_private_file(record_path(&database), bytes).test_unwrap();
        let result = reopen(&database);
        assert!(
            matches!(result, Err(KeyringError::StateInvariant(_))),
            "{excess} excess bytes: {result:?}"
        );
    }
}

#[test]
fn a_symlinked_provisioning_record_is_refused_with_its_native_cause() {
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    let record = record_path(&database);
    let target = support::trusted_temp_path(&directory, "elsewhere.provisioned");
    std::fs::rename(&record, &target).test_unwrap();
    std::os::unix::fs::symlink(&target, &record).test_unwrap();
    let result = reopen(&database);
    assert!(
        matches!(
            &result,
            Err(KeyringError::Io(error))
                if error.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error())
        ),
        "{result:?}"
    );
}

#[test]
fn a_hard_linked_provisioning_record_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    std::fs::hard_link(
        record_path(&database),
        support::trusted_temp_path(&directory, "second-name"),
    )
    .test_unwrap();
    assert_refused_by_policy(reopen(&database));
}

#[test]
fn a_provisioning_record_with_group_or_other_mode_bits_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    for mode in [0o640, 0o620, 0o604, 0o602] {
        std::fs::set_permissions(record_path(&database), Permissions::from_mode(mode))
            .test_unwrap();
        let result = reopen(&database);
        assert!(
            matches!(result, Err(KeyringError::StateInvariant(_))),
            "mode {mode:o}: {result:?}"
        );
    }
}

#[test]
fn a_foreign_owned_provisioning_record_is_refused() {
    if !rustix::process::geteuid().is_root() {
        eprintln!("skipped: changing a file owner requires root");
        return;
    }
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    std::os::unix::fs::chown(record_path(&database), Some(65_534), None).test_unwrap();
    assert_refused_by_policy(reopen(&database));
}

#[test]
fn a_provisioning_record_with_an_acl_grant_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let database = provisioned_store(&support::trusted_temp_path(&directory, ""));
    let record = record_path(&database);
    if !support::grant_foreign_acl(&record).test_unwrap() {
        eprintln!("skipped: this host has no ACL tool");
        return;
    }
    let mode = std::fs::symlink_metadata(&record)
        .test_unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
    assert_refused_by_policy(reopen(&database));
}

#[test]
fn a_provisioning_record_in_a_group_writable_directory_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let shared = private_directory(&directory, "shared", 0o770);
    assert_refused_by_policy(reopen(&provisioned_store(&shared)));
}

#[test]
fn a_provisioning_record_in_a_directory_with_an_acl_grant_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let store = private_directory(&directory, "store", 0o700);
    let database = provisioned_store(&store);
    if !support::grant_foreign_acl(&store).test_unwrap() {
        eprintln!("skipped: this host has no ACL tool");
        return;
    }
    assert_refused_by_policy(reopen(&database));
}

#[test]
fn a_provisioning_record_reached_through_a_symlinked_directory_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let real = private_directory(&directory, "real", 0o700);
    provisioned_store(&real);
    let link = support::trusted_temp_path(&directory, "link");
    std::os::unix::fs::symlink(&real, &link).test_unwrap();
    let result = reopen(&link.join("witness.sqlite"));
    assert!(matches!(result, Err(KeyringError::Io(_))), "{result:?}");
}

fn bind(socket: &Path) -> chio_keyring::Result<()> {
    chio_keyring::bind_private_unix_listener(socket).map(drop)
}

#[test]
fn a_service_socket_in_a_private_trusted_directory_binds_privately_and_exclusively() {
    let directory = support::private_tempdir().test_unwrap();
    let run = private_directory(&directory, "run", 0o700);
    let socket = run.join("witness.sock");
    let listener = chio_keyring::bind_private_unix_listener(&socket).test_unwrap();
    let metadata = std::fs::symlink_metadata(&socket).test_unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    std::os::unix::net::UnixStream::connect(&socket).test_unwrap();
    assert_refused_by_policy(bind(&socket));
    drop(listener);
    bind(&socket).test_unwrap();
}

#[test]
fn a_service_socket_directory_other_users_can_search_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let run = private_directory(&directory, "run", 0o711);
    assert_refused_by_policy(bind(&run.join("witness.sock")));
}

#[test]
fn a_service_socket_below_a_symlinked_ancestor_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let real_run = private_directory(&directory, "real/run", 0o700);
    let link = support::trusted_temp_path(&directory, "link");
    std::os::unix::fs::symlink(support::trusted_temp_path(&directory, "real"), &link).test_unwrap();
    let result = bind(&link.join("run").join("witness.sock"));
    assert!(matches!(result, Err(KeyringError::Io(_))), "{result:?}");
    assert!(!real_run.join("witness.sock").exists());
}

#[test]
fn a_service_socket_below_a_group_or_world_writable_ancestor_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let shared = private_directory(&directory, "shared", 0o700);
    let run = private_directory(&directory, "shared/run", 0o700);
    for mode in [0o770, 0o707] {
        std::fs::set_permissions(&shared, Permissions::from_mode(mode)).test_unwrap();
        let result = bind(&run.join("witness.sock"));
        assert!(
            matches!(result, Err(KeyringError::StateInvariant(_))),
            "ancestor mode {mode:o}: {result:?}"
        );
    }
}

#[test]
fn a_service_socket_directory_with_an_acl_grant_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let run = private_directory(&directory, "run", 0o700);
    if !support::grant_foreign_acl(&run).test_unwrap() {
        eprintln!("skipped: this host has no ACL tool");
        return;
    }
    let mode = std::fs::symlink_metadata(&run)
        .test_unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
    assert_refused_by_policy(bind(&run.join("witness.sock")));
}

#[test]
fn a_service_socket_below_an_ancestor_with_an_acl_grant_is_refused() {
    let directory = support::private_tempdir().test_unwrap();
    let outer = private_directory(&directory, "outer", 0o755);
    let run = private_directory(&directory, "outer/run", 0o700);
    if !support::grant_foreign_acl(&outer).test_unwrap() {
        eprintln!("skipped: this host has no ACL tool");
        return;
    }
    assert_refused_by_policy(bind(&run.join("witness.sock")));
}
