//! Prevalidate a complete namespace before any extraction effects.
use super::{safe_archive_member_path, CliError, SafeArchiveEntry};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Namespace {
    // Folded path -> exact spelling and whether it is a directory.
    paths: BTreeMap<String, (String, bool)>,
    explicit: BTreeSet<String>,
}
impl Namespace {
    pub(super) fn add(&mut self, path: &str, directory: bool) -> Result<(), CliError> {
        safe_archive_member_path(path, "archive namespace")?;
        if !self.explicit.insert(path.to_ascii_lowercase()) {
            return Err(CliError::cli_other_error(
                "duplicate archive namespace member",
            ));
        }
        let mut prefix = String::new();
        let parts: Vec<_> = path.split('/').collect();
        for (index, part) in parts.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let is_dir = index + 1 < parts.len() || directory;
            let folded = prefix.to_ascii_lowercase();
            if let Some((spelling, was_dir)) = self.paths.get(&folded) {
                if spelling != &prefix || *was_dir != is_dir {
                    return Err(CliError::cli_other_error(
                        "archive namespace has a file/directory or case collision",
                    ));
                }
            } else {
                if self.paths.len() >= crate::input::collection::MAX_ENTRIES {
                    return Err(CliError::cli_other_error(
                        "archive namespace entry limit exceeded",
                    ));
                }
                self.paths.insert(folded, (prefix.clone(), is_dir));
            }
        }
        Ok(())
    }
}
pub(super) fn validate(entries: &[SafeArchiveEntry]) -> Result<(), CliError> {
    let mut namespace = Namespace::default();
    for entry in entries {
        namespace.add(&entry.path, false)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn collisions_fail_before_creating_output() {
        for paths in [["a", "a/b"], ["A/x", "a/y"], ["a/b", "a"], ["a", "a"]] {
            let root = tempfile::tempdir().unwrap();
            let out = root.path().join("out");
            let entries = paths.map(|path| SafeArchiveEntry {
                path: path.into(),
                bytes: vec![1],
                mode: 0o600,
            });
            let error =
                super::super::write_entries_to_fresh_dir(&out, "test", &entries).unwrap_err();
            assert!(error.to_string().contains("namespace"), "{error}");
            assert!(!out.exists());
        }
    }
    #[test]
    fn explicit_parent_after_child_is_valid_but_a_duplicate_is_not() {
        let mut ns = Namespace::default();
        ns.add("a/b", false).unwrap();
        ns.add("a", true).unwrap();
        assert!(ns.add("a", true).is_err());
    }
}
