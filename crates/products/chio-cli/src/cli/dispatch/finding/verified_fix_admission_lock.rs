use super::CliError;

use std::fs::File;
use std::path::Path;
use std::time::{Duration, Instant};

const ADMISSION_JOB_LOCK_FILE: &str = ".finding-admission-jobs.lock";
const ADMISSION_JOB_LOCK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(super) struct FindingAdmissionJobLock {
    file: File,
}

impl FindingAdmissionJobLock {
    pub(super) fn acquire(operator_root: &Path) -> Result<Self, CliError> {
        Self::acquire_with_timeout(operator_root, ADMISSION_JOB_LOCK_TIMEOUT)
    }

    fn acquire_with_timeout(operator_root: &Path, timeout: Duration) -> Result<Self, CliError> {
        let path = operator_root.join(ADMISSION_JOB_LOCK_FILE);
        let file = open_job_lock(operator_root).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to open admission-job lock {}: {error}",
                path.display()
            ))
        })?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { file }),
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(CliError::cli_io_error(format!(
                        "admission-job lock {} exceeded its deadline",
                        path.display()
                    )));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(CliError::cli_io_error(format!(
                        "failed to acquire admission-job lock {}: {error}",
                        path.display()
                    )));
                }
            }
        }
    }
}

/// The admission-job lock is a regular file. Its mode, owner and link count
/// are not checked after creation.
#[cfg(unix)]
const ADMISSION_JOB_LOCK_POLICY: chio_secure_fs::OwnerPolicy = chio_secure_fs::OwnerPolicy {
    owner: chio_secure_fs::Owner::Unchecked,
    forbidden_mode: 0,
    require_single_link: false,
    reject_acl: false,
};

/// Opens the lock read-write, creating it at 0600, never truncating it and
/// never following a symlink.
#[cfg(unix)]
fn open_job_lock(operator_root: &Path) -> std::io::Result<File> {
    let directory = File::open(operator_root)?;
    chio_secure_fs::open_lock_at(
        &directory,
        std::ffi::OsStr::new(ADMISSION_JOB_LOCK_FILE),
        0o600,
        &ADMISSION_JOB_LOCK_POLICY,
    )
}

#[cfg(not(unix))]
fn open_job_lock(operator_root: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(operator_root.join(ADMISSION_JOB_LOCK_FILE))
}

impl Drop for FindingAdmissionJobLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn admission_job_lock_serializes_independent_open_files() {
        let root = tempfile::tempdir().unwrap();
        let first = FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap();
        let blocked = FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(blocked.to_string().contains("exceeded its deadline"));
        drop(first);
        FindingAdmissionJobLock::acquire_with_timeout(
            root.path(),
            Duration::from_millis(50),
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn admission_job_lock_never_follows_a_symlink() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere.lock");
        std::os::unix::fs::symlink(&elsewhere, root.path().join(ADMISSION_JOB_LOCK_FILE)).unwrap();

        let error =
            FindingAdmissionJobLock::acquire_with_timeout(root.path(), Duration::from_millis(50))
                .unwrap_err()
                .to_string();

        assert!(error.contains("failed to open admission-job lock"), "{error}");
        assert!(error.contains("symbolic links"), "{error}");
        assert!(!elsewhere.exists());
    }
}
