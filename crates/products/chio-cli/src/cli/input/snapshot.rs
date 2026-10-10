//! Private captured bytes keep verification and export on the same document set.
use crate::{input, CliError};
use std::path::Path;

pub(crate) struct Snapshot {
    directory: tempfile::TempDir,
}
impl Snapshot {
    fn new() -> Result<Self, CliError> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { directory })
    }

    pub(crate) fn capture(root: &Path) -> Result<Self, CliError> {
        let snapshot = Self::new()?;
        input::collection::walk_files(root, |path, budget| {
            let relative = path.strip_prefix(root).map_err(|source| {
                CliError::with_source(&chio_errors::_generated::error_codes::CLI_IO, source)
            })?;
            snapshot.write(relative, &budget.read(path)?)
        })?;
        Ok(snapshot)
    }

    pub(crate) fn from_entries<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Self, CliError> {
        // Validate the entire namespace before creating any attacker-chosen path.
        let mut budget = input::collection::Budget::default();
        budget.enter(0)?;
        let mut files = std::collections::BTreeSet::new();
        let mut directories = std::collections::BTreeSet::new();
        let mut validated = Vec::new();
        for (path, bytes) in entries {
            let path = crate::archive::safe_archive_member_path(path, "proof snapshot")?;
            let path = std::path::PathBuf::from(path);
            if path.as_os_str().len() > 4096 || bytes.len() > input::MAX_DOCUMENT_BYTES {
                return Err(CliError::cli_other_error(
                    "proof snapshot member exceeds its limit",
                ));
            }
            budget.enter(path.components().count())?;
            budget.charge(bytes.len())?;
            if !files.insert(path.clone()) || directories.contains(&path) {
                return Err(CliError::cli_other_error("proof snapshot path collision"));
            }
            for parent in path
                .ancestors()
                .skip(1)
                .filter(|path| !path.as_os_str().is_empty())
            {
                if files.contains(parent) {
                    return Err(CliError::cli_other_error("proof snapshot path collision"));
                }
                if directories.insert(parent.to_owned()) {
                    budget.enter(parent.components().count())?;
                }
            }
            validated.push((path, bytes));
        }
        let snapshot = Self::new()?;
        for (path, bytes) in validated {
            snapshot.write(&path, bytes)?;
        }
        Ok(snapshot)
    }

    fn write(&self, relative: &Path, bytes: &[u8]) -> Result<(), CliError> {
        let destination = self.directory.path().join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(destination, bytes)?;
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }
}
