use std::io::ErrorKind;

use super::read_regular_file;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LIMIT: usize = 64;

#[test]
fn regular_file_preserves_original_bytes() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("input.json");
    let bytes = b"{ \"amount\":18446744073709551615 }\n";
    std::fs::write(&path, bytes)?;
    assert_eq!(read_regular_file(&path, LIMIT)?, bytes);
    Ok(())
}

#[test]
fn directory_is_refused_before_reading() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let Err(error) = read_regular_file(directory.path(), LIMIT) else {
        return Err("directory was accepted".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "input must be a regular file");
    Ok(())
}

#[test]
fn symbolic_link_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("input.json");
    let link = directory.path().join("link.json");
    std::fs::write(&path, b"{}")?;
    std::os::unix::fs::symlink(&path, &link)?;
    let Err(error) = read_regular_file(&link, LIMIT) else {
        return Err("symbolic link was followed".into());
    };
    assert_eq!(
        error.raw_os_error(),
        Some(rustix::io::Errno::LOOP.raw_os_error())
    );
    assert_eq!(std::fs::read(path)?, b"{}");
    Ok(())
}

#[test]
fn oversized_file_stops_one_byte_past_the_limit() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("input.json");
    std::fs::File::create(&path)?.set_len(u64::try_from(LIMIT + 4096)?)?;
    assert_eq!(read_regular_file(&path, LIMIT)?.len(), LIMIT + 1);
    std::fs::File::create(&path)?.set_len(u64::try_from(LIMIT)?)?;
    assert_eq!(read_regular_file(&path, LIMIT)?.len(), LIMIT);
    assert_eq!(read_regular_file(&path, 0)?.len(), 1);
    Ok(())
}

#[test]
fn fifo_without_a_writer_is_refused_without_blocking() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("input.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = sender.send(read_regular_file(&path, LIMIT));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
    assert!(reader.join().is_ok(), "file reader panicked");
    let Err(error) = result else {
        return Err("FIFO was accepted".into());
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "input must be a regular file");
    Ok(())
}

#[test]
fn missing_file_retains_not_found() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let Err(error) = read_regular_file(&directory.path().join("absent.json"), LIMIT) else {
        return Err("missing file was accepted".into());
    };
    assert_eq!(error.kind(), ErrorKind::NotFound);
    Ok(())
}
