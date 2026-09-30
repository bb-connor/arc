//! Canonical artifact verification and durable provisioning output.
use super::*;

pub(super) fn require_canonical_json<T: Serialize>(
    value: &T,
    bytes: &[u8],
    label: &str,
) -> Result<(), CliError> {
    let canonical = chio_core::canonical_json_bytes(value).map_err(|error| {
        CliError::cli_other_error(format!("failed to canonicalize {label}: {error}"))
    })?;
    if canonical != bytes {
        Err(tampered(&format!("{label} is not canonical JSON")))
    } else {
        Ok(())
    }
}

pub(super) fn sync_directory(path: &Path) -> Result<(), CliError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to sync directory {}: {error}",
                path.display()
            ))
        })
}

pub(super) fn write_report_to_stdout(report: &ProvisionReport) -> Result<(), CliError> {
    let bytes = chio_core::canonical_json_bytes(report).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode demo provision report: {error}"))
    })?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(&bytes).map_err(|error| {
        CliError::cli_io_error(format!("failed to write demo provision report: {error}"))
    })?;
    lock.write_all(b"\n").map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to terminate demo provision report: {error}"
        ))
    })
}
