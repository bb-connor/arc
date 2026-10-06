use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use chio_test_support::prelude::*;

use super::listener::{
    bind_private_unix_listener_with, open_private_socket_directory, publish_generation,
    socket_generation, ListenerHooks,
};
use crate::KeyringError;

const CRASH_HELPER_SOCKET: &str = "CHIO_KEYRING_TEST_PUBLICATION_CRASH_SOCKET";

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .test_unwrap();
    let root = std::fs::canonicalize(directory.path()).test_unwrap();
    (directory, root)
}

/// Bind with no hooks. A child process another test spawns holds a copy of
/// every descriptor until it execs, so a lock this test just released can
/// still be held for a moment; only that refusal is retried.
fn bind_listener(socket: &Path) -> crate::Result<super::PrivateUnixListener> {
    let started = std::time::Instant::now();
    loop {
        match bind_private_unix_listener_with(socket, ListenerHooks::default()) {
            Err(KeyringError::StateInvariant("another service instance holds this socket"))
                if started.elapsed() < std::time::Duration::from_secs(5) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

fn bind(socket: &Path) -> crate::Result<()> {
    bind_listener(socket).map(drop)
}

fn inode(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).test_unwrap().ino()
}

fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.file_name().test_unwrap().to_os_string();
    name.push(".lock");
    socket.with_file_name(name)
}

/// A socket file with no listener, as a crashed holder leaves it. The socket
/// is bound but never listens, so a child process another test spawns cannot
/// keep it listening by holding a copy of its descriptor.
fn stale_socket(socket: &Path) -> u64 {
    let unbound = rustix::net::socket(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        None,
    )
    .test_unwrap();
    rustix::net::bind(
        &unbound,
        &rustix::net::SocketAddrUnix::new(socket).test_unwrap(),
    )
    .test_unwrap();
    drop(unbound);
    std::fs::set_permissions(socket, Permissions::from_mode(0o600)).test_unwrap();
    inode(socket)
}

/// Record `socket`'s current generation in its lock, as a managed holder that
/// crashed after publishing leaves it.
fn record_current_generation(socket: &Path) {
    let parent = open_private_socket_directory(socket.parent().test_unwrap()).test_unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path(socket))
        .test_unwrap();
    let name = socket.file_name().test_unwrap();
    let stat =
        rustix::fs::statat(&parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).test_unwrap();
    let generation = socket_generation(&parent, &lock, name, &stat).test_unwrap();
    publish_generation(&lock, &parent, generation).test_unwrap();
}

fn write_lock(socket: &Path, bytes: &[u8]) {
    std::fs::write(lock_path(socket), bytes).test_unwrap();
    std::fs::set_permissions(lock_path(socket), Permissions::from_mode(0o600)).test_unwrap();
}

fn assert_refused_as_unproven(result: crate::Result<()>) {
    assert!(
        matches!(
            &result,
            Err(KeyringError::Io(error))
                if error.raw_os_error() == Some(rustix::io::Errno::CONNREFUSED.raw_os_error())
        ),
        "{result:?}"
    );
}

fn assert_state_invariant(result: crate::Result<()>) {
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}

#[test]
fn a_service_socket_directory_replaced_before_bind_is_detected() {
    let (_directory, root) = private_root();
    let run = root.join("run");
    std::fs::create_dir(&run).test_unwrap();
    std::fs::set_permissions(&run, Permissions::from_mode(0o700)).test_unwrap();
    let displaced = root.join("run.displaced");

    let result = bind_private_unix_listener_with(
        &run.join("witness.sock"),
        ListenerHooks {
            before_bind: Some(Box::new(|| -> std::io::Result<()> {
                std::fs::rename(&run, &displaced)?;
                std::fs::create_dir(&run)?;
                std::fs::set_permissions(&run, Permissions::from_mode(0o700))
            })),
            ..ListenerHooks::default()
        },
    )
    .map(drop);
    assert_state_invariant(result);
}

#[test]
fn a_recorded_stale_generation_is_removed_and_rebound() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    stale_socket(&socket);
    record_current_generation(&socket);
    let recorded = std::fs::read(lock_path(&socket)).test_unwrap();

    let listener = bind_listener(&socket).test_unwrap();
    // The new socket can reuse the stale one's inode number, so its new
    // generation and live listener show the replacement.
    let published = std::fs::read(lock_path(&socket)).test_unwrap();
    assert_eq!(published.len(), 65);
    assert_ne!(published, recorded);
    std::os::unix::net::UnixStream::connect(&socket).test_unwrap();
    drop(listener);
    assert!(!socket.exists());
}

#[test]
fn a_socket_replaced_during_the_stale_check_is_kept() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    stale_socket(&socket);
    record_current_generation(&socket);
    let replacement = std::cell::Cell::new(None);

    let result = bind_private_unix_listener_with(
        &socket,
        ListenerHooks {
            before_stale_unlink: Some(Box::new(|| -> std::io::Result<()> {
                // Bound beside the original and renamed over it, so the
                // replacement cannot reuse the original's inode number.
                let beside = root.join("replacement.sock");
                drop(std::os::unix::net::UnixListener::bind(&beside)?);
                std::fs::rename(&beside, &socket)?;
                replacement.set(Some(std::fs::symlink_metadata(&socket)?.ino()));
                Ok(())
            })),
            ..ListenerHooks::default()
        },
    )
    .map(drop);
    assert_state_invariant(result);
    assert_eq!(Some(inode(&socket)), replacement.get());
}

#[test]
fn a_stale_socket_without_a_recorded_generation_is_kept() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    let stale = stale_socket(&socket);
    assert_refused_as_unproven(bind(&socket));
    assert_eq!(inode(&socket), stale);
    assert_eq!(std::fs::read(lock_path(&socket)).test_unwrap(), b"");
}

#[test]
fn a_wrong_or_malformed_generation_record_does_not_authorize_removal() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    let stale = stale_socket(&socket);
    record_current_generation(&socket);
    let exact = std::fs::read(lock_path(&socket)).test_unwrap();
    let exact_text = std::str::from_utf8(&exact).test_unwrap();

    write_lock(
        &socket,
        format!(
            "{}\n",
            chio_core_types::sha256(b"another generation").to_hex()
        )
        .as_bytes(),
    );
    assert_refused_as_unproven(bind(&socket));
    assert_eq!(inode(&socket), stale);

    let malformed = [
        exact_text.to_uppercase().into_bytes(),
        [exact.as_slice(), b"\n"].concat(),
        exact[..64].to_vec(),
        exact[..10].to_vec(),
        format!("{} ", exact_text.trim_end()).into_bytes(),
        b"not a generation record\n".to_vec(),
    ];
    for record in malformed {
        write_lock(&socket, &record);
        assert_state_invariant(bind(&socket));
        assert_eq!(inode(&socket), stale, "record {record:?}");
    }
}

#[test]
fn a_lock_without_private_custody_refuses_before_the_socket_is_probed() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    let stale = stale_socket(&socket);
    record_current_generation(&socket);
    let lock = lock_path(&socket);

    std::fs::set_permissions(&lock, Permissions::from_mode(0o640)).test_unwrap();
    assert_state_invariant(bind(&socket));
    std::fs::set_permissions(&lock, Permissions::from_mode(0o600)).test_unwrap();

    let second_link = root.join("second-link");
    std::fs::hard_link(&lock, &second_link).test_unwrap();
    assert_state_invariant(bind(&socket));
    std::fs::remove_file(&second_link).test_unwrap();

    let kept = root.join("kept.lock");
    std::fs::rename(&lock, &kept).test_unwrap();
    std::os::unix::fs::symlink(&kept, &lock).test_unwrap();
    let result = bind(&socket);
    assert!(matches!(result, Err(KeyringError::Io(_))), "{result:?}");
    std::fs::remove_file(&lock).test_unwrap();

    let made = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&lock)
        .status()
        .test_unwrap();
    assert!(made.success());
    assert_state_invariant(bind(&socket));
    assert_eq!(inode(&socket), stale);
}

/// Runs only in the child process that
/// `a_crash_before_publication_leaves_a_socket_that_refuses_restart` starts:
/// binds the socket the parent names and exits before recording its
/// generation, without running any destructor.
#[test]
fn publication_crash_helper() {
    let Some(socket) = std::env::var_os(CRASH_HELPER_SOCKET) else {
        return;
    };
    let result = bind_private_unix_listener_with(
        Path::new(&socket),
        ListenerHooks {
            before_publication: Some(Box::new(|| -> std::io::Result<()> {
                std::process::exit(0)
            })),
            ..ListenerHooks::default()
        },
    );
    std::process::exit(if result.is_err() { 2 } else { 3 });
}

#[test]
fn a_crash_before_publication_leaves_a_socket_that_refuses_restart() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    let status = std::process::Command::new(std::env::current_exe().test_unwrap())
        .args([
            "--exact",
            "ipc::listener_tests::publication_crash_helper",
            "--nocapture",
        ])
        .env(CRASH_HELPER_SOCKET, &socket)
        .stdout(std::process::Stdio::null())
        .status()
        .test_unwrap();
    assert_eq!(status.code(), Some(0));
    let unpublished = inode(&socket);
    assert_eq!(std::fs::read(lock_path(&socket)).test_unwrap(), b"");

    assert_refused_as_unproven(bind(&socket));
    assert_eq!(inode(&socket), unpublished);

    // Operator recovery after stopping every holder: remove the stale name
    // and its record, then start normally.
    std::fs::remove_file(&socket).test_unwrap();
    std::fs::remove_file(lock_path(&socket)).test_unwrap();
    bind(&socket).test_unwrap();
}

#[test]
fn a_failed_publication_removes_only_the_socket_it_bound() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");
    let result = bind_private_unix_listener_with(
        &socket,
        ListenerHooks {
            before_publication: Some(Box::new(|| -> std::io::Result<()> {
                Err(std::io::Error::other("publication refused"))
            })),
            ..ListenerHooks::default()
        },
    )
    .map(drop);
    assert!(matches!(result, Err(KeyringError::Io(_))), "{result:?}");
    assert!(!socket.exists());
    assert_eq!(std::fs::read(lock_path(&socket)).test_unwrap(), b"");
}

#[test]
fn dropping_a_listener_leaves_a_name_it_no_longer_holds() {
    let (_directory, root) = private_root();
    let socket = root.join("witness.sock");

    let listener = bind_listener(&socket).test_unwrap();
    let beside = root.join("replacement.sock");
    drop(std::os::unix::net::UnixListener::bind(&beside).test_unwrap());
    std::fs::rename(&beside, &socket).test_unwrap();
    let replacement = inode(&socket);
    drop(listener);
    assert_eq!(inode(&socket), replacement);
    std::fs::remove_file(&socket).test_unwrap();

    let listener = bind_listener(&socket).test_unwrap();
    std::fs::remove_file(&socket).test_unwrap();
    std::os::unix::fs::symlink(&beside, &socket).test_unwrap();
    drop(listener);
    assert!(std::fs::symlink_metadata(&socket)
        .test_unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn the_listener_directory_and_lock_close_on_exec() {
    let (_directory, root) = private_root();
    let listener = bind_listener(&root.join("witness.sock")).test_unwrap();
    assert_eq!(
        listener.descriptors_close_on_exec().test_unwrap(),
        [true; 3]
    );
}

#[test]
fn a_peer_running_as_the_service_user_is_accepted() {
    let (client, server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    super::require_service_peer(&server).test_unwrap();
    super::require_service_peer(&client).test_unwrap();
}

#[test]
fn a_peer_running_as_another_user_is_refused() {
    let (_client, server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    let other_user = rustix::process::geteuid().as_raw().wrapping_add(1);
    let result = super::require_peer_uid(&server, other_user);
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}

#[test]
fn a_deadline_stream_reads_a_buffered_response_after_both_directions_close() {
    use std::io::{Read as _, Write as _};

    let (client, mut server) = std::os::unix::net::UnixStream::pair().test_unwrap();
    client.shutdown(std::net::Shutdown::Write).test_unwrap();
    server.write_all(b"response").test_unwrap();
    drop(server);
    let mut stream =
        super::DeadlineUnixStream::new(client, std::time::Duration::from_secs(5)).test_unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).test_unwrap();
    assert_eq!(response, b"response");
}
