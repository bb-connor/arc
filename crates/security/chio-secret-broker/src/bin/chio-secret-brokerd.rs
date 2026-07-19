use std::fs::File;
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::ExitCode;

use chio_secret_broker::daemon_runtime::{
    secure_inherited_key_file, BrokerDaemonConfig, BrokerDaemonRuntime,
};
use chio_secret_broker::{BrokerError, Result};

struct Args {
    config_path: PathBuf,
    master_key_fd: u32,
    signing_key_fd: u32,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        let mut config_path = None;
        let mut master_key_fd = None;
        let mut signing_key_fd = None;
        while let Some(flag) = arguments.next() {
            let value = arguments.next().ok_or_else(|| {
                BrokerError::InvalidRequest("daemon argument is missing its value".to_string())
            })?;
            match flag.to_str() {
                Some("--config") if config_path.is_none() => {
                    config_path = Some(PathBuf::from(value));
                }
                Some("--master-key-fd") if master_key_fd.is_none() => {
                    master_key_fd = Some(parse_fd(value, "master key")?);
                }
                Some("--signing-key-fd") if signing_key_fd.is_none() => {
                    signing_key_fd = Some(parse_fd(value, "signing key")?);
                }
                _ => {
                    return Err(BrokerError::InvalidRequest(
                        "daemon argument is unknown or repeated".to_string(),
                    ))
                }
            }
        }
        let master_key_fd = master_key_fd.ok_or_else(|| {
            BrokerError::InvalidRequest("master-key descriptor is required".to_string())
        })?;
        let signing_key_fd = signing_key_fd.ok_or_else(|| {
            BrokerError::InvalidRequest("signing-key descriptor is required".to_string())
        })?;
        if master_key_fd == signing_key_fd {
            return Err(BrokerError::Custody(
                "master and signing keys must use distinct inherited descriptors".to_string(),
            ));
        }
        Ok(Self {
            config_path: config_path.ok_or_else(|| {
                BrokerError::InvalidRequest("daemon config path is required".to_string())
            })?,
            master_key_fd,
            signing_key_fd,
        })
    }
}

fn parse_fd(value: std::ffi::OsString, label: &str) -> Result<u32> {
    let value = value.into_string().map_err(|_| {
        BrokerError::InvalidRequest(format!("{label} descriptor is not valid UTF-8"))
    })?;
    value.parse::<u32>().map_err(|_| {
        BrokerError::InvalidRequest(format!("{label} descriptor is not an unsigned integer"))
    })
}

fn run() -> Result<()> {
    let args = Args::parse()?;
    let config = BrokerDaemonConfig::load(args.config_path)?;
    let master_key = secure_inherited_key_file(
        take_inherited_key_file(args.master_key_fd, "master key")?,
        "master key",
    )?;
    let signing_key = secure_inherited_key_file(
        take_inherited_key_file(args.signing_key_fd, "signing key")?,
        "signing key",
    )?;
    BrokerDaemonRuntime::build(config, master_key, signing_key)?.serve()
}

fn take_inherited_key_file(fd: u32, label: &str) -> Result<File> {
    if !(3..=65_535).contains(&fd) {
        return Err(BrokerError::Custody(format!(
            "{label} inherited descriptor number is invalid"
        )));
    }
    #[cfg(unix)]
    {
        let raw_fd = i32::try_from(fd).map_err(|_| {
            BrokerError::Custody(format!("{label} inherited descriptor number is invalid"))
        })?;
        // SAFETY: raw fcntl accepts an integer descriptor and reports EBADF for
        // a closed number without first requiring a Rust descriptor borrow.
        let duplicated = unsafe { libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor duplication failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returns a new live descriptor
        // uniquely owned by this function with CLOEXEC set atomically.
        let descriptor = unsafe { OwnedFd::from_raw_fd(duplicated) };
        // SAFETY: daemon launch transfers exclusive ownership of each inherited
        // descriptor. The successful duplication above established that the
        // original was live, and the transfer contract requires retiring it.
        if unsafe { libc::close(raw_fd) } != 0 {
            return Err(BrokerError::Custody(format!(
                "{label} inherited descriptor retirement failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(File::from(descriptor))
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        Err(BrokerError::Custody(
            "inherited key descriptors require Unix descriptor custody".to_string(),
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, IntoRawFd};

    use super::*;

    fn descriptor_is_closed(raw_fd: i32) -> bool {
        // SAFETY: F_GETFD accepts an integer descriptor and reports EBADF when
        // the number does not designate an open descriptor.
        let result = unsafe { libc::fcntl(raw_fd, libc::F_GETFD) };
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
    }

    #[test]
    fn closed_inherited_descriptor_is_rejected_before_adoption() {
        let raw_fd = tempfile::tempfile()
            .unwrap_or_else(|error| panic!("create closed-descriptor fixture: {error}"))
            .into_raw_fd();
        // SAFETY: into_raw_fd transferred ownership to this test, which closes
        // the descriptor exactly once before exercising the rejection path.
        assert_eq!(unsafe { libc::close(raw_fd) }, 0);

        let error = take_inherited_key_file(
            u32::try_from(raw_fd)
                .unwrap_or_else(|error| panic!("fixture descriptor is nonnegative: {error}")),
            "test key",
        )
        .err()
        .unwrap_or_else(|| panic!("closed inherited descriptor must be rejected"));

        assert!(matches!(
            error,
            BrokerError::Custody(message)
                if message.contains("inherited descriptor duplication failed")
        ));
        assert!(descriptor_is_closed(raw_fd));
    }

    #[test]
    fn inherited_transfer_retires_only_the_original_descriptor() {
        let mut source = tempfile::tempfile()
            .unwrap_or_else(|error| panic!("create ownership-transfer fixture: {error}"));
        source
            .write_all(b"broker-key")
            .unwrap_or_else(|error| panic!("write ownership-transfer fixture: {error}"));
        source
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|error| panic!("rewind ownership-transfer fixture: {error}"));
        let mut independent_alias = source
            .try_clone()
            .unwrap_or_else(|error| panic!("duplicate ownership-transfer fixture: {error}"));
        let raw_fd = source.into_raw_fd();

        let mut adopted = take_inherited_key_file(
            u32::try_from(raw_fd)
                .unwrap_or_else(|error| panic!("fixture descriptor is nonnegative: {error}")),
            "test key",
        )
        .unwrap_or_else(|error| panic!("adopt inherited descriptor: {error}"));

        assert_ne!(adopted.as_raw_fd(), raw_fd);
        assert!(descriptor_is_closed(raw_fd));
        // SAFETY: adopted owns a live descriptor for the duration of this call.
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        let mut bytes = Vec::new();
        adopted
            .read_to_end(&mut bytes)
            .unwrap_or_else(|error| panic!("read adopted descriptor: {error}"));
        assert_eq!(bytes, b"broker-key");
        drop(adopted);

        independent_alias
            .seek(SeekFrom::Start(0))
            .unwrap_or_else(|error| panic!("rewind independent alias: {error}"));
        bytes.clear();
        independent_alias
            .read_to_end(&mut bytes)
            .unwrap_or_else(|error| panic!("read independent alias: {error}"));
        assert_eq!(bytes, b"broker-key");
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("chio-secret-brokerd failed closed: {}", error_code(&error));
            ExitCode::FAILURE
        }
    }
}

fn error_code(error: &BrokerError) -> &'static str {
    match error {
        BrokerError::InvalidRequest(_) => "invalid_configuration",
        BrokerError::AuthorizationDenied(_) => "authorization_denied",
        BrokerError::AuthorityUnavailable(_) => "authority_unavailable",
        BrokerError::Conflict(_) => "state_conflict",
        BrokerError::Invariant(_) => "runtime_invariant",
        BrokerError::Storage(_) => "storage_unavailable",
        BrokerError::Upstream(_) => "upstream_unavailable",
        BrokerError::ResponseRejected(_) => "response_rejected",
        BrokerError::Custody(_) => "custody_unavailable",
    }
}
