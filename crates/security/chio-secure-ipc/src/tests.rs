use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::fs::PermissionsExt;

use chio_test_support::prelude::*;
use rustix::io::{fcntl_getfd, FdFlags};

use super::*;

#[test]
fn bounded_frame_round_trip_and_limits_fail_closed() {
    let mut encoded = Vec::new();
    write_bounded_frame(&mut encoded, b"trusted", 16).test_expect("encode bounded frame");
    assert_eq!(
        read_bounded_frame(&mut Cursor::new(encoded), 16).test_expect("decode bounded frame"),
        b"trusted"
    );
    assert!(write_bounded_frame(&mut Vec::new(), b"", 16).is_err());
    assert!(read_bounded_frame(&mut Cursor::new(17_u32.to_be_bytes()), 16).is_err());
}

#[test]
fn peer_identity_rejects_zero_process_id() {
    assert!(PeerIdentity {
        process_id: 0,
        user_id: 1,
        group_id: 1,
    }
    .validate()
    .is_err());
}

#[test]
fn inherited_descriptor_is_duplicated_cloexec_and_original_is_retired() {
    let mut source = tempfile::tempfile().test_expect("create inherited file");
    source.write_all(b"authority-key").test_expect("write key");
    source.seek(SeekFrom::Start(0)).test_expect("rewind key");
    let mut alias = source.try_clone().test_expect("clone key descriptor");
    let raw_fd = source.into_raw_fd();

    // SAFETY: into_raw_fd transfers exclusive ownership to this test.
    #[allow(unsafe_code)]
    let adopted = unsafe {
        InheritedSecretFile::adopt(
            u32::try_from(raw_fd).test_expect("nonnegative descriptor"),
            "authority key",
        )
    }
    .test_expect("adopt descriptor");
    let mut file = adopted.into_file();
    assert_ne!(file.as_raw_fd(), raw_fd);
    assert!(fcntl_getfd(&file)
        .test_expect("descriptor flags")
        .contains(FdFlags::CLOEXEC));
    // SAFETY: F_GETFD reports EBADF for a closed descriptor number.
    #[allow(unsafe_code)]
    let closed = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } < 0
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    assert!(closed);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).test_expect("read adopted key");
    assert_eq!(bytes, b"authority-key");
    alias.seek(SeekFrom::Start(0)).test_expect("rewind alias");
    bytes.clear();
    alias.read_to_end(&mut bytes).test_expect("read alias");
    assert_eq!(bytes, b"authority-key");
}

#[cfg(target_os = "linux")]
#[test]
fn listener_refuses_same_process_and_non_private_parent() {
    let directory = tempfile::tempdir().test_expect("create socket directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
        .test_expect("set unsafe permissions");
    let config = SecureUnixListenerConfig {
        socket_path: directory.path().join("authority.sock"),
        trusted_service_uid: rustix::process::getuid().as_raw(),
        expected_peer: PeerIdentity {
            process_id: std::process::id().saturating_add(1),
            user_id: rustix::process::getuid().as_raw(),
            group_id: rustix::process::getgid().as_raw(),
        },
    };
    assert!(SecureUnixListener::bind(config).is_err());
}
