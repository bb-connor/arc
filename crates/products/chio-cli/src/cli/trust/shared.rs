use super::*;

/// The local issuer owns this initialization phase. Reports and remote clients
/// never call it; later business refusal may leave the owner's custody intact.
pub(crate) fn provision_local_issuance_authority(
    authority_seed_path: Option<&Path>,
    authority_db_path: Option<&Path>,
) -> Result<(), CliError> {
    match (authority_seed_path, authority_db_path) {
        (Some(_), Some(_)) => Err(CliError::cli_other_error(
            "local trust issuance requires either --authority-seed-file or --authority-db, not both",
        )),
        (Some(path), None) => match std::fs::symlink_metadata(path) {
            Ok(_) => crate::load_existing_authority_keypair(path).map(|_| ()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                StagedLocalIssuanceSeed::new(path)?.publish()
            }
            Err(error) => Err(error.into()),
        },
        (None, Some(path)) => {
            chio_store_sqlite::SqliteCapabilityAuthority::open(path).map(|_| ()).map_err(Into::into)
        }
        (None, None) => Err(CliError::cli_other_error(
            "local trust issuance requires --authority-seed-file or --authority-db",
        )),
    }
}

/// A fully written candidate whose publication cannot replace another owner.
struct StagedLocalIssuanceSeed {
    directory: chio_control_plane::PreparedPrivateDirectory,
    destination: std::path::PathBuf,
    temporary: tempfile::NamedTempFile,
}

impl StagedLocalIssuanceSeed {
    fn new(path: &Path) -> Result<Self, CliError> {
        use std::io::Write as _;

        let file_name = path
            .file_name()
            .filter(|name| path.as_os_str().as_encoded_bytes().ends_with(name.as_encoded_bytes()))
            .ok_or_else(|| CliError::cli_other_error("authority seed path must name a file"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = chio_control_plane::prepare_private_directory(parent)?;
        let destination = directory.path().join(file_name);
        let mut temporary = tempfile::Builder::new()
            .prefix(".chio-owner-seed-")
            .tempfile_in(directory.path())?;
        let contents = zeroize::Zeroizing::new(chio_core::Keypair::generate().seed_hex());
        temporary.write_all(contents.as_bytes())?;
        temporary.as_file().sync_all()?;
        directory.validate_path_identity()?;
        Ok(Self {
            directory,
            destination,
            temporary,
        })
    }

    fn publish(self) -> Result<(), CliError> {
        self.directory.validate_path_identity()?;
        match self.temporary.persist_noclobber(&self.destination) {
            Ok(file) => file.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Discard only our candidate; the existing winner remains authoritative.
                error.file.close()?;
            }
            Err(error) => return Err(error.error.into()),
        }
        self.directory.validate_path_identity()?;
        #[cfg(unix)]
        std::fs::File::open(self.directory.path())?.sync_all()?;
        crate::load_existing_authority_keypair(&self.destination).map(|_| ())
    }
}

pub(crate) struct QueryBackend<'a> {
    pub(crate) json_output: bool,
    pub(crate) receipt_db_path: Option<&'a Path>,
    pub(crate) control_url: Option<&'a str>,
    pub(crate) control_token: Option<&'a str>,
}

/// Derive a trusted-kernel-key list from an authority seed file. Returns the
/// loaded public key (so locally signed receipts can pass reputation integrity
/// validation) or an empty vec when no seed file is configured. See
/// `chio-reputation::receipt_integrity_valid`.
pub(crate) fn trusted_kernel_keys_from_authority(
    authority_seed_path: Option<&Path>,
) -> Result<Vec<String>, CliError> {
    let Some(path) = authority_seed_path else {
        return Ok(Vec::new());
    };
    let keypair = crate::load_existing_authority_keypair(path)?;
    Ok(vec![keypair.public_key().to_hex()])
}

pub(crate) struct BudgetQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
    /// Optional authority seed file used to derive the trusted kernel key
    /// for local reputation scoring. Plumbing this through means receipts
    /// signed by the local kernel are not silently filtered out as unsigned.
    /// See `chio-reputation::receipt_integrity_valid`.
    pub(crate) authority_seed_path: Option<&'a Path>,
}

pub(crate) struct SignedQueryBackend<'a> {
    pub(crate) query: QueryBackend<'a>,
    pub(crate) budget_db_path: Option<&'a Path>,
    pub(crate) authority_seed_path: Option<&'a Path>,
    pub(crate) authority_db_path: Option<&'a Path>,
    pub(crate) certification_registry_file: Option<&'a Path>,
}

pub(crate) fn load_json_or_yaml<T: DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    crate::input::config::load(path)
}

#[cfg(test)]
mod local_issuance_seed_tests {
    use super::*;

    #[test]
    fn directory_shaped_seed_paths_are_rejected_without_creating_custody(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        for suffix in ["authority.seed/", "authority.seed/."] {
            let path = directory.path().join(suffix);
            let Err(error) = provision_local_issuance_authority(Some(&path), None) else {
                return Err("directory-shaped seed path initialized custody".into());
            };
            assert!(error.to_string().contains("authority seed path must name a file"));
            assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn staged_owners_preserve_the_first_published_seed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("authority.seed");
        let first = StagedLocalIssuanceSeed::new(&path)?;
        let second = StagedLocalIssuanceSeed::new(&path)?;
        first.publish()?;
        let original = zeroize::Zeroizing::new(std::fs::read(&path)?);
        let owner = crate::load_existing_authority_keypair(&path)?.public_key();
        second.publish()?;
        assert_eq!(std::fs::read(&path)?, original.as_slice());
        assert_eq!(crate::load_existing_authority_keypair(&path)?.public_key(), owner);
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn invalid_existing_seed_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;

        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("authority.seed");
        let staged = StagedLocalIssuanceSeed::new(&path)?;
        let mut existing = tempfile::NamedTempFile::new_in(directory.path())?;
        existing.write_all(b"invalid authority material")?;
        existing.persist_noclobber(&path)?;
        let Err(error) = staged.publish() else {
            return Err("invalid existing seed was accepted".into());
        };
        assert!(matches!(error, CliError::Core(chio_core::error::Error::InvalidHex(_))));
        assert_eq!(std::fs::read(&path)?, b"invalid authority material");
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn occupied_symlink_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("authority.seed");
        let existing = directory.path().join("existing.seed");
        StagedLocalIssuanceSeed::new(&existing)?.publish()?;
        let original = zeroize::Zeroizing::new(std::fs::read(&existing)?);
        let staged = StagedLocalIssuanceSeed::new(&path)?;
        std::os::unix::fs::symlink(&existing, &path)?;
        let Err(error) = staged.publish() else {
            return Err("symlink custody was accepted".into());
        };
        assert!(error.to_string().contains("authority seed must be a regular file"));
        assert_eq!(std::fs::read_link(&path)?, existing);
        assert_eq!(std::fs::read(&existing)?, original.as_slice());
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 2);
        Ok(())
    }
}
