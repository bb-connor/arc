use super::read_bounded;
#[cfg(unix)]
use super::{decode, CliError, MAX_SIGNED_FILE_BYTES};
use std::io::ErrorKind;

#[cfg(unix)]
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[cfg(unix)]
#[test]
fn regular_file_preserves_original_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.json");
    let bytes = b"{ \"amount\":18446744073709551615 }\n";
    std::fs::write(&path, bytes)?;
    assert_eq!(read_bounded(&path)?, bytes);
    Ok(())
}

#[cfg(unix)]
#[test]
fn directory_is_refused_before_reading() -> TestResult {
    let directory = tempfile::tempdir()?;
    let Err(error) = read_bounded(directory.path()) else {
        panic!("directory was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "signed input must be a regular file");
    Ok(())
}

#[cfg(unix)]
#[test]
fn symbolic_link_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.json");
    let link = directory.path().join("link.json");
    std::fs::write(&path, b"{}")?;
    std::os::unix::fs::symlink(&path, &link)?;
    let Err(error) = read_bounded(&link) else {
        panic!("symbolic link was followed");
    };
    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::LOOP.raw_os_error())
    );
    assert_eq!(std::fs::read(path)?, b"{}");
    Ok(())
}

#[cfg(unix)]
#[test]
fn oversized_file_stops_at_the_decoder_sentinel() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.json");
    let file = std::fs::File::create(&path)?;
    file.set_len(u64::try_from(MAX_SIGNED_FILE_BYTES + 4096)?)?;
    let bytes = read_bounded(&path)?;
    assert_eq!(bytes.len(), MAX_SIGNED_FILE_BYTES + 1);
    assert!(matches!(
        decode::<serde_json::Value>(&bytes),
        Err(CliError::SignedJson(
            chio_core::canonical::UntrustedJsonError::TooLarge { bytes, bound }
        )) if bytes == MAX_SIGNED_FILE_BYTES + 1 && bound == MAX_SIGNED_FILE_BYTES
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifo_without_a_writer_is_refused_without_blocking() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("input.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = sender.send(read_bounded(&path));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(reader.join().is_ok(), "file reader panicked");
    let Err(error) = result else {
        panic!("FIFO was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "signed input must be a regular file");
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_file_retains_not_found() -> TestResult {
    let directory = tempfile::tempdir()?;
    let Err(error) = read_bounded(&directory.path().join("absent.json")) else {
        panic!("missing file was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::NotFound);
    Ok(())
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_refuses_file_reads() {
    let Err(error) = read_bounded(std::path::Path::new("input.json")) else {
        panic!("unsupported file open was accepted");
    };
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(
        error.to_string(),
        "signed input requires nonblocking no-follow file reads"
    );
}
