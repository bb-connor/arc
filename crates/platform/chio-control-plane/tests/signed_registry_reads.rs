#![cfg(unix)]

use std::io::Write;

use chio_control_plane::federation_policy::FederationAdmissionPolicyRegistry;
use chio_control_plane::scim_lifecycle::ScimLifecycleRegistry;
use chio_control_plane::CliError;
use chio_core::canonical::UntrustedJsonError;
use chio_secure_ipc::regular_file::RegularFileError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REGISTRY_LIMIT: usize = 64 * 1024 * 1024;

macro_rules! registry_reader_tests {
    ($module:ident, $registry:ty) => {
        mod $module {
            use super::*;

            type Registry = $registry;

            #[test]
            fn missing_file_is_an_empty_registry() -> TestResult {
                let dir = tempfile::tempdir()?;
                let loaded = Registry::load(&dir.path().join("absent.json"))?;
                assert_eq!(
                    serde_json::to_value(loaded)?,
                    serde_json::to_value(Registry::default())?
                );
                Ok(())
            }

            #[test]
            fn regular_file_at_the_existing_limit_loads() -> TestResult {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("registry.json");
                let bytes = serde_json::to_vec(&Registry::default())?;
                let mut file = std::fs::File::create(&path)?;
                file.write_all(&bytes)?;
                let spaces = [b' '; 8192];
                let mut remaining = REGISTRY_LIMIT - bytes.len();
                while remaining > 0 {
                    let count = remaining.min(spaces.len());
                    file.write_all(&spaces[..count])?;
                    remaining -= count;
                }
                drop(file);
                assert_eq!(std::fs::metadata(&path)?.len(), REGISTRY_LIMIT as u64);
                let loaded = Registry::load(&path)?;
                assert_eq!(
                    serde_json::to_value(loaded)?,
                    serde_json::to_value(Registry::default())?
                );
                Ok(())
            }

            #[test]
            fn oversized_read_stops_at_the_decoder_sentinel() -> TestResult {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("registry.json");
                std::fs::File::create(&path)?.set_len((REGISTRY_LIMIT + 4096) as u64)?;
                let error = Registry::load(&path)
                    .err()
                    .ok_or("oversized file accepted")?;
                assert!(
                    matches!(
                        error,
                        CliError::File(RegularFileError::TooLarge {
                            max_bytes: REGISTRY_LIMIT
                        })
                    ),
                    "{error:?}"
                );
                Ok(())
            }

            #[test]
            fn repeated_version_key_is_refused() -> TestResult {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("registry.json");
                let value = serde_json::to_string(&Registry::default())?;
                std::fs::write(&path, &value)?;
                Registry::load(&path)?;
                let tail = value
                    .strip_prefix('{')
                    .ok_or("registry must be an object")?;
                let repeated = format!("{{\"version\":\"discarded\",{tail}");
                std::fs::write(&path, repeated.as_bytes())?;
                let error = Registry::load(&path).err().ok_or("repeated key accepted")?;
                assert!(
                    matches!(
                        error,
                        CliError::SignedJson(UntrustedJsonError::SignedInput(_))
                    ),
                    "{error:?}"
                );
                Ok(())
            }

            #[test]
            fn symlink_to_a_valid_registry_is_refused() -> TestResult {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("registry.json");
                let link = dir.path().join("link.json");
                let bytes = serde_json::to_vec(&Registry::default())?;
                std::fs::write(&path, &bytes)?;
                Registry::load(&path)?;
                std::os::unix::fs::symlink(&path, &link)?;
                let error = Registry::load(&link).err().ok_or("symlink followed")?;
                assert!(
                    matches!(error, CliError::File(RegularFileError::SymbolicLink)),
                    "{error:?}"
                );
                assert_eq!(std::fs::read(path)?, bytes);
                Ok(())
            }

            #[test]
            fn directory_is_refused_before_reading() -> TestResult {
                let dir = tempfile::tempdir()?;
                let error = Registry::load(dir.path())
                    .err()
                    .ok_or("directory accepted")?;
                assert!(
                    matches!(error, CliError::File(RegularFileError::NotRegular)),
                    "{error:?}"
                );
                Ok(())
            }

            #[test]
            fn fifo_without_a_writer_is_refused_without_blocking() -> TestResult {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("registry.fifo");
                rustix::fs::mkfifoat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )?;
                let (sender, receiver) = std::sync::mpsc::channel();
                let reader = std::thread::spawn(move || {
                    let _ = sender.send(Registry::load(&path));
                });
                let result = receiver.recv_timeout(std::time::Duration::from_secs(5))?;
                reader.join().map_err(|_| "registry reader panicked")?;
                let error = result.err().ok_or("FIFO accepted")?;
                assert!(
                    matches!(error, CliError::File(RegularFileError::NotRegular)),
                    "{error:?}"
                );
                Ok(())
            }
        }
    };
}

registry_reader_tests!(federation, FederationAdmissionPolicyRegistry);
registry_reader_tests!(scim, ScimLifecycleRegistry);
