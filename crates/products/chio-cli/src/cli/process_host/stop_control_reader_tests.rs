use super::*;
use std::fs::OpenOptions;
use std::io::{BufRead, Read};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn socket_exchange(state: &Path) -> Result<Option<serde_json::Value>, CliError> {
    let listener = std::os::unix::net::UnixListener::bind(state.join(SOCKET_FILE))?;
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let (stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        let mut stream = std::io::BufReader::new(stream);
        let mut request = String::new();
        if stream.read_line(&mut request)? != 0 {
            stream.get_mut().write_all(b"{\"ok\":true}\n")?;
        }
        Ok(())
    });
    let result = via_socket(state, ControlOp::Status);
    server
        .join()
        .map_err(|_| error("socket fixture panicked"))??;
    result
}

#[test]
fn host_reader_stop_token_fifo_is_refused_without_blocking() -> TestResult {
    super::super::artifact_reader_tests::fifo_refusal(|path, _| {
        let directory = path
            .parent()
            .ok_or_else(|| error("missing fixture parent"))?;
        std::fs::hard_link(path, directory.join(TOKEN_FILE))?;
        socket_exchange(directory).map(|_| ())
    })
}

#[test]
fn host_reader_stop_token_regular_control() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join(TOKEN_FILE), "ab".repeat(32))?;
    assert_eq!(
        socket_exchange(directory.path())?,
        Some(serde_json::json!({"ok": true}))
    );
    Ok(())
}

#[test]
fn host_reader_stop_token_oversized_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join(TOKEN_FILE), "a".repeat(65))?;
    let Err(CliError::Io(failure)) = socket_exchange(directory.path()) else {
        return Err("expected bounded token refusal".into());
    };
    assert_eq!(failure.kind(), std::io::ErrorKind::Other);
    let detail = failure
        .get_ref()
        .and_then(|e| e.downcast_ref::<chio_core::canonical::UntrustedJsonError>());
    assert!(matches!(
        detail,
        Some(chio_core::canonical::UntrustedJsonError::TooLarge {
            bytes: 65,
            bound: 64
        })
    ));
    Ok(())
}

#[tokio::test]
async fn host_reader_stop_token_writer_refuses_fifo_before_writing() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let lease = Lease::acquire(directory.path(), true)?;
    let path = directory.path().join(TOKEN_FILE);
    assert!(std::process::Command::new("mkfifo")
        .arg(&path)
        .status()?
        .success());
    let mut held = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)?;
    let result = ControlServer::bind(&lease);
    let Err(CliError::Io(failure)) = result else {
        return Err("expected nonregular token refusal".into());
    };
    assert_eq!(failure.kind(), std::io::ErrorKind::Other);
    assert_eq!(failure.to_string(), "input must be a regular file");
    let mut byte = [0_u8; 1];
    assert_eq!(
        held.read(&mut byte).err().map(|e| e.kind()),
        Some(std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[tokio::test]
async fn host_reader_stop_token_writer_truncates_regular_stale_suffix() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let lease = Lease::acquire(directory.path(), true)?;
    let path = directory.path().join(TOKEN_FILE);
    std::fs::write(&path, "x".repeat(128))?;
    let server = ControlServer::bind(&lease)?;
    let bytes = std::fs::read(&path)?;
    assert_eq!(bytes.len(), 64);
    assert_eq!(bytes, server.token.as_bytes());
    assert!(bytes.iter().all(u8::is_ascii_hexdigit));
    Ok(())
}

#[tokio::test]
async fn host_reader_stop_token_writer_refuses_symlink_without_truncation() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let lease = Lease::acquire(directory.path(), true)?;
    let outside = tempfile::NamedTempFile::new()?;
    std::fs::write(outside.path(), b"preserve these bytes")?;
    std::os::unix::fs::symlink(outside.path(), directory.path().join(TOKEN_FILE))?;
    let Err(CliError::Io(failure)) = ControlServer::bind(&lease) else {
        return Err("symlink token output accepted".into());
    };
    assert_eq!(failure.raw_os_error(), Some(libc::ELOOP));
    assert_eq!(std::fs::read(outside.path())?, b"preserve these bytes");
    Ok(())
}
