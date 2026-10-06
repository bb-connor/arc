//! Shared objects a dynamic launch target names, resolved against the
//! runtime files declared for it.

use std::collections::BTreeSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::{linkage, open_regular_file, CliError, MAX_EXECUTABLE_BYTES};

/// The DT_NEEDED entries no declared runtime file provides. A name with a
/// slash is a path and must resolve to a declared file. A bare name is
/// provided by a declared file with that name or with that DT_SONAME, the
/// usual case for a versioned library reached through a soname symlink.
pub(super) fn undeclared(
    needed: &[String],
    runtime_files: &BTreeSet<PathBuf>,
) -> Result<Vec<String>, CliError> {
    let mut missing = needed
        .iter()
        .filter(|name| {
            let path = Path::new(name.as_str());
            if name.contains('/') {
                !path.is_absolute()
                    || !std::fs::canonicalize(path)
                        .is_ok_and(|resolved| runtime_files.contains(&resolved))
            } else {
                !runtime_files
                    .iter()
                    .any(|file| file.file_name() == Some(path.as_os_str()))
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    if missing.iter().any(|name| !name.contains('/')) {
        let mut sonames = BTreeSet::new();
        for file in runtime_files {
            sonames.extend(runtime_file_soname(file)?);
        }
        missing.retain(|name| !sonames.contains(name));
    }
    Ok(missing)
}

fn runtime_file_soname(path: &Path) -> Result<Option<String>, CliError> {
    let mut file = open_regular_file(path, false, "runtime file")?;
    let read_error = |error: std::io::Error| {
        CliError::cli_io_error(format!(
            "failed to read runtime file {}: {error}",
            path.display()
        ))
    };
    let mut image = Vec::new();
    (&mut file)
        .take(4)
        .read_to_end(&mut image)
        .map_err(read_error)?;
    if image != b"\x7fELF" {
        return Ok(None);
    }
    file.take(MAX_EXECUTABLE_BYTES)
        .read_to_end(&mut image)
        .map_err(read_error)?;
    Ok(linkage::shared_object_name(&image).ok().flatten())
}
