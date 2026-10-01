//! Transfer binary credentials to a child through owned inherited descriptors.

use std::str::FromStr;

use super::credentials::{is_credential_name, CredentialError};

/// The service's long option (without `--`) and its credential file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorCredentialBinding {
    argument: String,
    name: String,
}

impl FromStr for DescriptorCredentialBinding {
    type Err = CredentialError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            CredentialError::Binding(
                spec.to_owned(),
                "expected ARGUMENT=CREDENTIAL with a lowercase long option and a credential file name",
            )
        };
        let (argument, name) = spec.split_once('=').ok_or_else(invalid)?;
        if !argument.starts_with(|c: char| c.is_ascii_lowercase())
            || !argument
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || !is_credential_name(name)
        {
            return Err(invalid());
        }
        Ok(Self {
            argument: argument.to_owned(),
            name: name.to_owned(),
        })
    }
}

#[cfg(unix)]
mod unix {
    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    use super::{CredentialError, DescriptorCredentialBinding};
    use crate::supervise::credentials::MAX_CREDENTIAL_BYTES;

    /// Open descriptors remain close-on-exec in the supervisor. Only the
    /// selected child clears that flag immediately before its exec transition.
    #[derive(Default)]
    pub struct DescriptorCredentials(Vec<(String, File)>);

    impl DescriptorCredentials {
        pub fn load(
            directory: Option<&Path>,
            bindings: &[DescriptorCredentialBinding],
        ) -> Result<Self, CredentialError> {
            let mut arguments = BTreeSet::new();
            let mut files = Vec::with_capacity(bindings.len());
            for binding in bindings {
                let argument = format!("--{}", binding.argument);
                if !arguments.insert(argument.clone()) {
                    return Err(CredentialError::Duplicate(argument));
                }
                let directory = directory.ok_or(CredentialError::NoDirectory)?;
                let unreadable = |reason: String| CredentialError::Unreadable {
                    name: binding.name.clone(),
                    reason,
                };
                // Nonblocking open also prevents a substituted FIFO from
                // hanging startup before its file type can be inspected.
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                    .open(directory.join(&binding.name))
                    .map_err(|error| unreadable(error.to_string()))?;
                let metadata = file
                    .metadata()
                    .map_err(|error| unreadable(error.to_string()))?;
                if !metadata.is_file() {
                    return Err(CredentialError::NotARegularFile(binding.name.clone()));
                }
                // SAFETY: geteuid reads process identity and has no arguments.
                let uid = unsafe { libc::geteuid() };
                if metadata.nlink() != 1
                    || (metadata.uid() != uid || metadata.mode() & 0o077 != 0)
                        && !chio_secure_ipc::credentials::is_systemd_credential(&file, uid)
                            .map_err(|error| unreadable(error.to_string()))?
                {
                    return Err(unreadable("descriptor credential must be private, singly linked and owned by the service user".to_owned()));
                }
                if metadata.len() == 0 {
                    return Err(CredentialError::Empty(binding.name.clone()));
                }
                if metadata.len() > MAX_CREDENTIAL_BYTES {
                    return Err(CredentialError::TooLarge(binding.name.clone()));
                }
                #[cfg(target_os = "linux")]
                let file = super::sealed_credential(file)
                    .map_err(|error| unreadable(error.to_string()))?;
                if !(3..=65_535).contains(&file.as_raw_fd()) {
                    return Err(unreadable(
                        "descriptor is outside the inherited custody range".to_owned(),
                    ));
                }
                files.push((argument, file));
            }
            Ok(Self(files))
        }

        pub fn configure(self, command: &mut Command) -> io::Result<()> {
            for (argument, file) in &self.0 {
                let inline = format!("{argument}=");
                if command.get_args().any(|value| {
                    value == argument.as_str()
                        || value
                            .to_str()
                            .is_some_and(|value| value.starts_with(&inline))
                }) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("credential descriptor option {argument} is already supplied"),
                    ));
                }
                // Allocate descriptor numbers by opening the files, then pass
                // those exact numbers. Fixed dup2 targets could overwrite the
                // process library's child-error pipe or another live descriptor.
                command.arg(argument).arg(file.as_raw_fd().to_string());
            }
            // SAFETY: files are owned by this command and remain open through
            // fork. The child callback uses only async-signal-safe fcntl calls;
            // no descriptor number is replaced and the parent's flags stay set.
            unsafe {
                command.pre_exec(move || {
                    for (_, file) in &self.0 {
                        if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub use unix::DescriptorCredentials;

#[cfg(target_os = "linux")]
fn sealed_credential(mut source: std::fs::File) -> std::io::Result<std::fs::File> {
    use rustix::fs::{fchmod, fcntl_add_seals, memfd_create, MemfdFlags, Mode, SealFlags};
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    (&mut source)
        .take(super::credentials::MAX_CREDENTIAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > super::credentials::MAX_CREDENTIAL_BYTES {
        return Err(std::io::Error::other(
            "binary credential changed length while being read",
        ));
    }
    let mut sealed = std::fs::File::from(memfd_create(
        c"chio-service-credential",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    fchmod(&sealed, Mode::RUSR | Mode::WUSR)?;
    sealed.write_all(&bytes)?;
    fcntl_add_seals(
        &sealed,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )?;
    // Reopening our owned descriptor gives the child a read-only handle at
    // offset zero. The write-capable handle is dropped before launch.
    std::fs::File::open(format!("/proc/self/fd/{}", sealed.as_raw_fd()))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{Read, Seek, Write};

    #[test]
    fn binary_delivery_is_sealed_read_only_and_preserves_every_byte() -> std::io::Result<()> {
        let original = [0_u8, 255, 7, b'\n'];
        let mut source = tempfile::tempfile()?;
        source.write_all(&original)?;
        source.rewind()?;
        let mut delivered = super::sealed_credential(source)?;
        assert!(chio_secure_ipc::credentials::is_sealed_credential(
            &delivered
        )?);
        let mut bytes = Vec::new();
        delivered.read_to_end(&mut bytes)?;
        assert_eq!(bytes, original);
        assert!(delivered.write_all(b"replace").is_err());
        Ok(())
    }
}
