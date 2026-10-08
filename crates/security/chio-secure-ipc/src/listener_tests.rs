use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use chio_test_support::prelude::*;

use super::*;

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn gid() -> u32 {
    rustix::process::getegid().as_raw()
}

fn directory(mode: u32) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().test_unwrap();
    let root = std::fs::canonicalize(directory.path()).test_unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).test_unwrap();
    (directory, root)
}

fn owner_custody(socket_path: PathBuf, peer: PeerPolicy) -> SocketCustody {
    SocketCustody {
        socket_path,
        trusted_service_uid: uid(),
        access: SocketAccess::Owner,
        peer,
    }
}

fn this_user() -> PeerPolicy {
    PeerPolicy::User { uid: uid() }
}

#[test]
fn an_owner_socket_is_private_locked_and_removed_on_drop() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let listener =
        CustodialUnixListener::bind(owner_custody(socket.clone(), this_user())).test_unwrap();
    let metadata = std::fs::symlink_metadata(&socket).test_unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), uid());

    let second = CustodialUnixListener::bind(owner_custody(socket.clone(), this_user()));
    assert!(matches!(second, Err(ListenerError::LockHeld(_))));
    assert!(socket.exists());

    drop(listener);
    assert!(!socket.exists());
    drop(CustodialUnixListener::bind(owner_custody(socket, this_user())).test_unwrap());
}

#[test]
fn an_existing_socket_path_is_never_replaced() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let stale = UnixListener::bind(&socket).test_unwrap();
    drop(stale);
    let inode = std::fs::symlink_metadata(&socket).test_unwrap().ino();
    let result = CustodialUnixListener::bind(owner_custody(socket.clone(), this_user()));
    assert!(matches!(result, Err(ListenerError::PathOccupied)));
    assert_eq!(
        std::fs::symlink_metadata(&socket).test_unwrap().ino(),
        inode
    );
}

#[test]
fn a_directory_open_to_others_or_reached_through_a_symlink_is_refused() {
    let (_open, open_root) = directory(0o755);
    let result =
        CustodialUnixListener::bind(owner_custody(open_root.join("service.sock"), this_user()));
    assert!(matches!(result, Err(ListenerError::DirectoryCustody)));

    let (_directory, root) = directory(0o700);
    let target = root.join("target");
    std::fs::create_dir(&target).test_unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).test_unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&target, &alias).test_unwrap();
    let result =
        CustodialUnixListener::bind(owner_custody(alias.join("service.sock"), this_user()));
    assert!(matches!(result, Err(ListenerError::DirectoryCustody)));
    assert!(!target.join("service.sock").exists());
}

#[test]
fn an_invalid_path_or_peer_policy_is_refused_before_binding() {
    let (_directory, root) = directory(0o700);
    let relative =
        CustodialUnixListener::bind(owner_custody(PathBuf::from("relative.sock"), this_user()));
    assert!(matches!(relative, Err(ListenerError::InvalidPath)));
    let this_process = CustodialUnixListener::bind(owner_custody(
        root.join("service.sock"),
        PeerPolicy::Process(PeerIdentity {
            process_id: std::process::id(),
            user_id: uid(),
            group_id: gid(),
        }),
    ));
    assert!(matches!(
        this_process,
        Err(ListenerError::InvalidPeerPolicy(
            "service and client must be separate processes"
        ))
    ));
    assert!(!root.join("service.sock").exists());
}

#[test]
fn a_peer_of_the_authorized_user_is_accepted() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let listener =
        CustodialUnixListener::bind(owner_custody(socket.clone(), this_user())).test_unwrap();
    let _client = UnixStream::connect(&socket).test_unwrap();
    listener.accept_authenticated().test_unwrap();
}

#[test]
fn a_peer_outside_the_policy_is_refused_with_its_observed_identity() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let other_user = uid().wrapping_add(1);
    for policy in [
        PeerPolicy::User { uid: other_user },
        PeerPolicy::UserAndGroup {
            uid: uid(),
            gid: gid().wrapping_add(1),
        },
        PeerPolicy::Process(PeerIdentity {
            process_id: std::process::id().wrapping_add(1),
            user_id: uid(),
            group_id: gid(),
        }),
    ] {
        let listener =
            CustodialUnixListener::bind(owner_custody(socket.clone(), policy)).test_unwrap();
        let _client = UnixStream::connect(&socket).test_unwrap();
        let result = listener.accept_authenticated();
        assert!(
            matches!(
                &result,
                Err(ListenerError::UnauthorizedPeer { observed })
                    if observed.user_id == uid()
                        && observed.group_id == gid()
                        && observed.process_id == std::process::id()
            ),
            "{policy:?}: {result:?}"
        );
    }
}

#[test]
fn a_replaced_socket_path_refuses_accepts_and_survives_drop() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let listener =
        CustodialUnixListener::bind(owner_custody(socket.clone(), this_user())).test_unwrap();
    let _client = UnixStream::connect(&socket).test_unwrap();
    std::fs::rename(&socket, root.join("moved.sock")).test_unwrap();
    let replacement = UnixListener::bind(&socket).test_unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).test_unwrap();
    let replacement_inode = std::fs::symlink_metadata(&socket).test_unwrap().ino();

    let result = listener.accept_authenticated();
    assert!(
        matches!(result, Err(ListenerError::SocketReplaced)),
        "{result:?}"
    );
    drop(listener);
    assert_eq!(
        std::fs::symlink_metadata(&socket).test_unwrap().ino(),
        replacement_inode
    );
    drop(replacement);
}

#[test]
fn a_group_socket_admits_only_its_group_and_directory_mode() {
    let (_open, open_root) = directory(0o750);
    let custody = |socket_path: PathBuf, peer| SocketCustody {
        socket_path,
        trusted_service_uid: uid(),
        access: SocketAccess::Group { gid: gid() },
        peer,
    };
    let result = CustodialUnixListener::bind(custody(
        open_root.join("audit.sock"),
        PeerPolicy::UserAndGroup {
            uid: uid(),
            gid: gid(),
        },
    ));
    assert!(matches!(result, Err(ListenerError::DirectoryCustody)));

    let (_directory, root) = directory(0o710);
    let socket = root.join("audit.sock");
    let listener = CustodialUnixListener::bind(custody(
        socket.clone(),
        PeerPolicy::UserAndGroup {
            uid: uid(),
            gid: gid(),
        },
    ))
    .test_unwrap();
    let metadata = std::fs::symlink_metadata(&socket).test_unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o660);
    assert_eq!(metadata.gid(), gid());
    let _client = UnixStream::connect(&socket).test_unwrap();
    listener.accept_authenticated().test_unwrap();
}

#[test]
fn a_bounded_accept_returns_at_its_deadline_or_with_the_next_peer() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let listener =
        CustodialUnixListener::bind(owner_custody(socket.clone(), this_user())).test_unwrap();
    let started = Instant::now();
    let idle = listener
        .accept_authenticated_within(Duration::from_millis(100))
        .test_unwrap();
    let elapsed = started.elapsed();
    assert!(idle.is_none());
    assert!(elapsed >= Duration::from_millis(90), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");

    let connector = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        UnixStream::connect(&socket)
    });
    let started = Instant::now();
    let accepted = listener
        .accept_authenticated_within(Duration::from_secs(5))
        .test_unwrap();
    assert!(accepted.is_some());
    assert!(started.elapsed() < Duration::from_secs(2));
    connector.join().test_unwrap().test_unwrap();
    // Read deadlines are socket timeouts, so an accepted stream must block.
    let flags = rustix::fs::fcntl_getfl(accepted.test_unwrap()).test_unwrap();
    assert!(!flags.contains(rustix::fs::OFlags::NONBLOCK));
}

#[test]
fn provisional_cleanup_removes_the_exact_socket_after_a_validation_failure() {
    let (_directory, root) = directory(0o700);
    let socket = root.join("service.sock");
    let listener = UnixListener::bind(&socket).test_unwrap();
    let cleanup = ProvisionalSocketCleanup::new(&socket).test_unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).test_unwrap();
    let result = validate_socket_identity(&owner_custody(socket.clone(), this_user()));
    assert!(matches!(result, Err(ListenerError::SocketCustody)));

    drop(cleanup);
    assert!(!socket.exists());
    drop(listener);
}

#[test]
fn a_readiness_wait_reports_data_hangup_or_its_deadline() {
    use std::io::Write as _;

    let (mut writer, reader) = UnixStream::pair().test_unwrap();
    let started = Instant::now();
    assert!(!wait_readable(&reader, Duration::from_millis(50)).test_unwrap());
    assert!(started.elapsed() >= Duration::from_millis(40));
    writer.write_all(b"x").test_unwrap();
    assert!(wait_readable(&reader, Duration::from_secs(5)).test_unwrap());

    let (writer, reader) = UnixStream::pair().test_unwrap();
    drop(writer);
    let started = Instant::now();
    assert!(wait_readable(&reader, Duration::from_secs(5)).test_unwrap());
    assert!(started.elapsed() < Duration::from_secs(2));
}
