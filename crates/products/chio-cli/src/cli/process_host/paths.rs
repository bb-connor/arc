//! Resolve native launch paths without changing argv or Python venv identity.

use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::state::error;
use crate::CliError;

pub(super) fn directory(base: &Path, value: &Path) -> Result<PathBuf, CliError> {
    let path = if value.is_absolute() {
        value.to_owned()
    } else {
        base.join(value)
    };
    let path = path
        .canonicalize()
        .map_err(|cause| error(format!("working directory {}: {cause}", path.display())))?;
    if !path.is_dir() {
        return Err(error(format!(
            "working directory is not a directory: {}",
            path.display()
        )));
    }
    Ok(path)
}

pub(super) fn executable(cwd: &Path, name: &str) -> Result<PathBuf, CliError> {
    executable_with_path(cwd, name, std::env::var_os("PATH").as_deref())
}

fn executable_with_path(
    cwd: &Path,
    name: &str,
    search: Option<&OsStr>,
) -> Result<PathBuf, CliError> {
    if name.is_empty() || name.contains('\0') {
        return Err(error("native command requires an executable"));
    }
    let candidates = if name.contains('/') {
        vec![if Path::new(name).is_absolute() {
            PathBuf::from(name)
        } else {
            cwd.join(name)
        }]
    } else {
        // Relative PATH entries refer to the initiating shell, not worker cwd.
        let caller = std::env::current_dir()?;
        search
            .map(std::env::split_paths)
            .into_iter()
            .flatten()
            .map(|entry| {
                if entry.is_absolute() {
                    entry.join(name)
                } else {
                    caller.join(entry).join(name)
                }
            })
            .collect()
    };
    for candidate in candidates {
        if let Ok(metadata) = candidate.metadata() {
            if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
                // Canonicalize the parent only. Resolving the final symlink would
                // turn .venv/bin/python into its base interpreter.
                let parent = candidate
                    .parent()
                    .ok_or_else(|| error("executable has no parent"))?
                    .canonicalize()?;
                return Ok(parent.join(
                    candidate
                        .file_name()
                        .ok_or_else(|| error("executable has no filename"))?,
                ));
            }
        }
    }
    Err(error(format!("executable {name:?} was not found or is not executable; install it or correct the command/PATH")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_venv_invocation_path_and_resolves_bare_names() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let bin = root.path().join("project with spaces/.venv/bin");
        std::fs::create_dir_all(&bin)?;
        let target = root.path().join("base-python");
        std::fs::write(&target, b"#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
        std::os::unix::fs::symlink(&target, bin.join("python"))?;
        let cwd = bin.parent().and_then(Path::parent).ok_or("project path")?;
        let expected = bin.canonicalize()?.join("python");
        assert_eq!(
            executable_with_path(cwd, ".venv/bin/python", None)?,
            expected
        );
        assert_eq!(
            executable_with_path(cwd, "python", Some(bin.as_os_str()))?,
            expected
        );
        assert!(executable_with_path(cwd, "missing", Some(bin.as_os_str())).is_err());
        Ok(())
    }
}
