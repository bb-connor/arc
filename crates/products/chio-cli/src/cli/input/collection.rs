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
        if self.bytes == 0 {
            return Err(CliError::cli_other_error(
                "artifact collection byte budget exhausted",
            ));
        }
        let bytes = match super::read_regular(path, self.bytes.min(super::MAX_DOCUMENT_BYTES)) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.bytes = 0;
                return Err(error.into());
            }
        };
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

/// Enumerate one directory with a shared budget, rejecting links and special files.
/// Directories are retained for callers that explicitly select bundle roots.
pub(crate) fn directory(root: &Path, budget: &mut Budget) -> Result<Vec<PathBuf>, CliError> {
    budget.enter(0)?;
    if !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(CliError::cli_other_error(
            "collection root is not a directory",
        ));
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root)? {
        budget.enter(1)?;
        let entry = entry?;
        let kind = entry.file_type()?;
        if !kind.is_file() && !kind.is_dir() {
            return Err(CliError::cli_other_error(
                "collection contains a link or special file",
            ));
        }
        paths.push(entry.path());
    }
    paths.sort();
    Ok(paths)
}

/// Resolve a portable relative member without traversing existing symlinks.
/// Concurrent replacement of ancestor directories requires OS isolation.
pub(crate) fn member(root: &Path, relative: &str) -> Result<PathBuf, CliError> {
    let relative = crate::archive::safe_archive_member_path(relative, "artifact collection")?;
    if relative.split('/').count() > MAX_DEPTH || !std::fs::symlink_metadata(root)?.is_dir() {
        return Err(CliError::cli_other_error(
            "artifact collection root or depth is invalid",
        ));
    }
    let mut path = root.to_path_buf();
    let segments: Vec<_> = relative.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        path.push(segment);
        let kind = std::fs::symlink_metadata(&path)?.file_type();
        if (index + 1 == segments.len() && !kind.is_file())
            || (index + 1 < segments.len() && !kind.is_dir())
        {
            return Err(CliError::cli_other_error(
                "artifact member traverses a link or special file",
            ));
        }
    }
    Ok(path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod remaining_reader_tests {
    use super::*;
    #[test]
    fn repeated_members_consume_the_same_actual_byte_budget() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.json");
        std::fs::write(&path, "{}").unwrap();
        let mut budget = Budget {
            entries: 2,
            bytes: 3,
        };
        assert_eq!(budget.read(&path).unwrap(), b"{}");
        assert!(matches!(budget.read(&path), Err(CliError::Io(_))));
    }
    #[cfg(unix)]
    #[test]
    fn directories_and_members_reject_stable_symlink_escapes() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("a.json"), "{}").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        assert!(matches!(
            directory(root.path(), &mut Budget::default()),
            Err(CliError::Chio(_))
        ));
        assert!(member(root.path(), "escape/a.json").is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod failed_budget_tests {
    use super::*;
    #[test]
    fn oversized_candidate_exhausts_shared_budget_before_next_open() {
        let root = tempfile::tempdir().unwrap();
        let big = root.path().join("big");
        std::fs::write(&big, [0; 5]).unwrap();
        let mut budget = Budget {
            entries: 4,
            bytes: 4,
        };
        assert!(matches!(budget.read(&big), Err(CliError::Io(_))));
        // Even a missing file must now reject at the budget, before opening it.
        let error = budget.read(&root.path().join("not-present")).unwrap_err();
        assert!(error.to_string().contains("budget exhausted"));
        assert_eq!(budget.bytes, 0);
    }
}
