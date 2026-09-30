//! Entry and actual-byte custody for CLI proof collection.
use crate::CliError;
use std::path::{Path, PathBuf};

pub(crate) const MAX_ENTRIES: usize = 4096;
pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_BYTES: usize = 128 * 1024 * 1024;

pub(crate) struct Budget {
    entries: usize,
    bytes: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            entries: MAX_ENTRIES,
            bytes: MAX_BYTES,
        }
    }
}
impl Budget {
    pub(crate) fn enter(&mut self, depth: usize) -> Result<(), CliError> {
        if depth > MAX_DEPTH {
            return Err(CliError::cli_other_error(
                "artifact collection depth exceeded",
            ));
        }
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or_else(|| CliError::cli_other_error("artifact collection entry limit exceeded"))?;
        Ok(())
    }
    pub(crate) fn charge(&mut self, bytes: usize) -> Result<(), CliError> {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| CliError::cli_other_error("artifact collection byte limit exceeded"))?;
        Ok(())
    }
    pub(crate) fn read(&mut self, path: &Path) -> Result<Vec<u8>, CliError> {
        let bytes = super::read_regular(path, self.bytes.min(super::MAX_DOCUMENT_BYTES))?;
        self.charge(bytes.len())?;
        Ok(bytes)
    }
}

pub(crate) fn walk_files(
    root: &Path,
    mut visit: impl FnMut(&Path, &mut Budget) -> Result<(), CliError>,
) -> Result<(), CliError> {
    fn walk(
        path: &Path,
        depth: usize,
        budget: &mut Budget,
        visit: &mut impl FnMut(&Path, &mut Budget) -> Result<(), CliError>,
    ) -> Result<(), CliError> {
        budget.enter(depth)?;
        let kind = std::fs::symlink_metadata(path)?.file_type();
        if kind.is_dir() {
            for entry in std::fs::read_dir(path)? {
                walk(&entry?.path(), depth + 1, budget, visit)?;
            }
        } else if kind.is_file() {
            visit(path, budget)?;
        } else {
            return Err(CliError::cli_other_error(
                "artifact collection requires regular files and directories",
            ));
        }
        Ok(())
    }
    walk(root, 0, &mut Budget::default(), &mut visit)
}

pub(crate) fn paths(root: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut paths = Vec::new();
    walk_files(root, |path, _| {
        paths.push(path.to_owned());
        Ok(())
    })?;
    paths.sort();
    Ok(paths)
}

pub(crate) fn sync_tree(root: &Path) -> Result<(), CliError> {
    fn sync(path: &Path, depth: usize, budget: &mut Budget) -> Result<(), CliError> {
        budget.enter(depth)?;
        let kind = std::fs::symlink_metadata(path)?.file_type();
        if kind.is_dir() {
            for entry in std::fs::read_dir(path)? {
                sync(&entry?.path(), depth + 1, budget)?;
            }
            #[cfg(unix)]
            std::fs::File::open(path)?.sync_all()?;
        } else if kind.is_file() {
            std::fs::File::open(path)?.sync_all()?;
        } else {
            return Err(CliError::cli_other_error(
                "proof synchronization requires regular files and directories",
            ));
        }
        Ok(())
    }
    sync(root, 0, &mut Budget::default())
}
