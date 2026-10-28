use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags};

use super::{
    digest_file, error, SidecarPolicy, CHECKPOINTED, EXCLUDED, EXCLUDED_DIRECTORIES,
    SQLITE_SIDECARS,
};
use crate::CliError;

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(parent: &File, name: &OsStr, label: &str) -> Result<File, CliError> {
    match openat(parent, name, directory_flags(), Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => Err(error(format!(
            "relocation directory is not a nonsymlink directory: {label}"
        ))),
        Err(source) => Err(std::io::Error::from(source).into()),
    }
}

fn open_root(path: &Path) -> Result<File, CliError> {
    let start = if path.is_absolute() { "/" } else { "." };
    let mut directory =
        File::from(open(start, directory_flags(), Mode::empty()).map_err(std::io::Error::from)?);
    let mut traversed = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                traversed.push(name);
                let label = relative_name(&traversed)?;
                directory = open_directory(&directory, name, &label)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(error(
                    "relocation root contains a parent or platform prefix component",
                ));
            }
        }
    }
    Ok(directory)
}

fn relative_name(path: &Path) -> Result<String, CliError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| error("relocated file name is not valid UTF-8"))
}

fn open_regular(parent: &File, name: &OsStr, label: &str) -> Result<File, CliError> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| {
        if source == rustix::io::Errno::LOOP {
            error(format!("host state must not contain symlinks: {label}"))
        } else {
            CliError::from(std::io::Error::from(source))
        }
    })?;
    let file = File::from(fd);
    if !file.metadata()?.is_file() {
        return Err(error(format!(
            "host state contains a nonregular file: {label}"
        )));
    }
    Ok(file)
}

pub(super) fn digests(
    directory: &Path,
    policy: SidecarPolicy,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut files = BTreeMap::new();
    walk(
        directory,
        open_root(directory)?,
        Path::new(""),
        policy,
        0,
        &mut files,
    )?;
    Ok(files)
}

fn walk(
    _directory: &Path,
    current: File,
    relative_directory: &Path,
    policy: SidecarPolicy,
    depth: usize,
    files: &mut BTreeMap<String, String>,
) -> Result<(), CliError> {
    let entries = Dir::read_from(&current).map_err(std::io::Error::from)?;
    for entry in entries {
        let entry = entry.map_err(std::io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes)
            .map_err(|_| error("relocated file name is not valid UTF-8"))?;
        let relative = relative_directory.join(name);
        let label = relative_name(&relative)?;
        let metadata = statat(&current, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(std::io::Error::from)?;
        let kind = FileType::from_raw_mode(metadata.st_mode);
        let at_root = relative_directory.as_os_str().is_empty();
        if kind == FileType::Directory {
            if at_root && EXCLUDED_DIRECTORIES.contains(&name) {
                continue;
            }
            if depth == 64 {
                return Err(error("relocation directory depth exceeds 64"));
            }
            #[cfg(test)]
            super::reader_tests::before_descend(&_directory.join(&relative))?;
            let child = open_directory(&current, OsStr::new(name), &label)?;
            walk(_directory, child, &relative, policy, depth + 1, files)?;
            continue;
        }
        if kind == FileType::Symlink {
            return Err(error(format!(
                "host state must not contain symlinks: {label}"
            )));
        }
        if kind != FileType::RegularFile {
            return Err(error(format!(
                "host state contains a nonregular file: {label}"
            )));
        }
        if at_root && EXCLUDED.contains(&name) {
            continue;
        }
        #[cfg(test)]
        super::reader_tests::before_file_open(&_directory.join(&relative))?;
        let file = open_regular(&current, OsStr::new(name), &label)?;
        if let Some(database) = SQLITE_SIDECARS
            .iter()
            .find_map(|suffix| name.strip_suffix(suffix))
        {
            let known = at_root && (database == "authority.db" || CHECKPOINTED.contains(&database));
            let regular_database =
                known && open_regular(&current, OsStr::new(database), database).is_ok();
            let accepts_wal = matches!(policy, SidecarPolicy::Checkpointable)
                || (matches!(policy, SidecarPolicy::CommittedImport) && database == "authority.db");
            if !regular_database
                || (!accepts_wal && name.ends_with("-wal") && file.metadata()?.len() != 0)
            {
                return Err(error(format!("unverified SQLite sidecar: {label}")));
            }
            continue;
        }
        let expected = file.metadata()?.len();
        files.insert(label, digest_file(file, expected)?);
    }
    Ok(())
}
