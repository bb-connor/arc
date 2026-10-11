#![cfg(unix)]

//! Connections the audit service accepts from its nonblocking listener get
//! the full exchange deadline, whatever flags they inherit from it.

use std::io::{ErrorKind, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use chio_keyring::{
    bind_private_unix_listener, read_single_canonical_frame, require_service_peer,
    write_canonical_frame, AuditServiceOperation, AuditServiceRequest, DeadlineUnixStream,
    KeyringError, PrivateUnixListener, KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA,
    KEY_LOG_IPC_REQUEST_DEADLINE,
};
use chio_test_support::prelude::*;

mod support;

const ACCEPT_LIMIT: Duration = Duration::from_secs(10);

fn request(nonce: &str) -> AuditServiceRequest {
    AuditServiceRequest {
        schema: KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA.to_string(),
        operation: AuditServiceOperation::Readiness {
            nonce: nonce.to_string(),
        },
    }
}

fn frame(request: &AuditServiceRequest) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_canonical_frame(&mut bytes, request).test_unwrap();
    bytes
}

/// A managed audit socket in a private directory, nonblocking as the audit
/// service sets it.
fn audit_listener(directory: &tempfile::TempDir) -> (PrivateUnixListener, PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;

    let run = support::trusted_temp_path(directory, "run");
    std::fs::create_dir(&run).test_unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).test_unwrap();
    let socket = run.join("audit.sock");
    let listener = bind_private_unix_listener(&socket).test_unwrap();
    listener.set_nonblocking(true).test_unwrap();
    (listener, socket)
}

/// Accept one connection as the audit service does, then read its single
/// request frame under the exchange deadline. Returns the result and the time
/// the read took after the deadline started.
fn serve_one(
    listener: &PrivateUnixListener,
) -> (chio_keyring::Result<AuditServiceRequest>, Duration) {
    let started = Instant::now();
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                assert!(started.elapsed() < ACCEPT_LIMIT, "no client connected");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return (Err(KeyringError::Io(error)), started.elapsed()),
        }
    };
    if let Err(error) = require_service_peer(&stream) {
        return (Err(error), started.elapsed());
    }
    let accepted = Instant::now();
    let result = DeadlineUnixStream::new(stream, KEY_LOG_IPC_REQUEST_DEADLINE)
        .map_err(KeyringError::Io)
        .and_then(|mut stream| read_single_canonical_frame(&mut stream));
    (result, accepted.elapsed())
}

/// Connect, wait `first_byte_delay`, write each piece with `gap` between them,
/// then end the request and wait for the service to close.
fn send_slowly(
    socket: &Path,
    first_byte_delay: Duration,
    pieces: Vec<Vec<u8>>,
    gap: Duration,
) -> thread::JoinHandle<std::io::Result<()>> {
    let socket = socket.to_path_buf();
    thread::spawn(move || {
        let mut stream = UnixStream::connect(&socket)?;
        thread::sleep(first_byte_delay);
        for piece in pieces {
            stream.write_all(&piece)?;
            thread::sleep(gap);
        }
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        Ok(())
    })
}

fn assert_expired(result: &chio_keyring::Result<AuditServiceRequest>) {
    assert!(
        matches!(
            result,
            Err(KeyringError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
        ),
        "{result:?}"
    );
}

#[test]
fn an_accepted_stream_reads_a_request_that_arrived_before_accept() {
    let directory = support::private_tempdir().test_unwrap();
    let (listener, socket) = audit_listener(&directory);
    let sent = request("already-queued");
    let mut client = UnixStream::connect(&socket).test_unwrap();
    client.write_all(&frame(&sent)).test_unwrap();
    client.shutdown(std::net::Shutdown::Write).test_unwrap();

    let (result, _) = serve_one(&listener);
    let received = result.test_unwrap();
    assert_eq!(frame(&received), frame(&sent));
}

#[test]
fn an_accepted_stream_waits_for_a_delayed_fragmented_request() {
    let directory = support::private_tempdir().test_unwrap();
    let (listener, socket) = audit_listener(&directory);
    let sent = request("delayed-and-fragmented");
    let bytes = frame(&sent);
    let pieces = vec![
        bytes[..2].to_vec(),
        bytes[2..9].to_vec(),
        bytes[9..].to_vec(),
    ];
    let client = send_slowly(
        &socket,
        Duration::from_millis(300),
        pieces,
        Duration::from_millis(200),
    );

    let (result, elapsed) = serve_one(&listener);
    let received = result.test_unwrap();
    client.join().test_unwrap().test_unwrap();
    assert_eq!(frame(&received), bytes);
    assert!(elapsed < KEY_LOG_IPC_REQUEST_DEADLINE, "{elapsed:?}");
}

#[test]
fn a_trickling_client_is_cut_off_at_the_absolute_deadline_and_the_next_is_served() {
    let directory = support::private_tempdir().test_unwrap();
    let (listener, socket) = audit_listener(&directory);
    let mut announced = 1_000_u32.to_be_bytes().to_vec();
    announced.push(b'{');
    let trickle = std::iter::once(announced)
        .chain(std::iter::repeat_n(b" ".to_vec(), 40))
        .collect();
    let client = send_slowly(&socket, Duration::ZERO, trickle, Duration::from_millis(200));

    let (result, elapsed) = serve_one(&listener);
    assert_expired(&result);
    assert!(
        elapsed >= KEY_LOG_IPC_REQUEST_DEADLINE - Duration::from_millis(250),
        "the exchange ended early after {elapsed:?}: {result:?}"
    );
    assert!(
        elapsed < KEY_LOG_IPC_REQUEST_DEADLINE + Duration::from_secs(2),
        "a trickling client held the service for {elapsed:?}"
    );
    let _ = client.join();

    let sent = request("after-expiry");
    let client = send_slowly(
        &socket,
        Duration::from_millis(100),
        vec![frame(&sent)],
        Duration::ZERO,
    );
    let (result, _) = serve_one(&listener);
    let received = result.test_unwrap();
    client.join().test_unwrap().test_unwrap();
    assert_eq!(frame(&received), frame(&sent));
}
