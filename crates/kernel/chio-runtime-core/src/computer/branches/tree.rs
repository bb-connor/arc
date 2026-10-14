use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::git::Git;
use super::{BranchError, Limits, UnsupportedKind};

const LFS_POINTER_PREFIX: &[u8] = b"version https://git-lfs.github.com/spec/";
const LFS_POINTER_MAX_BYTES: u64 = 1024;
const REGULAR: &str = "100644";
const EXECUTABLE: &str = "100755";

/// One materializable file of a managed revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub path: String,
    pub executable: bool,
    pub blob: String,
    pub size: u64,
}

/// Checks a repository-relative path against RES-03: no traversal, no empty,
/// absolute or `.git` components, no control or default-ignorable characters
/// and no separators other than `/`.
pub(super) fn check_path(path: &str, limits: &Limits) -> Result<(), BranchError> {
    let refuse = |reason| {
        Err(BranchError::PathRefused {
            path: path.to_owned(),
            reason,
        })
    };
    if path.is_empty() {
        return refuse("empty");
    }
    if path.len() > limits.max_path_bytes {
        return refuse("too_long");
    }
    if path
        .chars()
        .any(|c| c.is_control() || c == '\\' || is_ignorable(c))
    {
        return refuse("character");
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > limits.max_depth {
        return refuse("too_deep");
    }
    for component in components {
        if component.is_empty() {
            return refuse("empty_component");
        }
        if component == "." || component == ".." {
            return refuse("traversal");
        }
        let folded = component.trim_end_matches(['.', ' ']).to_ascii_lowercase();
        if folded == ".git" || folded.starts_with("git~") {
            return refuse("git_metadata");
        }
    }
    Ok(())
}

/// Code points that case-folding filesystems ignore when comparing names.
fn is_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
    )
}

/// Lists a tree and refuses every entry the profile cannot materialize.
pub(super) fn manifest(
    git: &Git,
    tree: &str,
    limits: &Limits,
) -> Result<Vec<TreeEntry>, BranchError> {
    let raw = git.run(
        "ls-tree",
        &["ls-tree", "-r", "-z", "--long", "--full-tree", tree],
        None,
        None,
    )?;
    let mut entries = Vec::new();
    let mut total: u64 = 0;
    for record in raw.split(|byte| *byte == 0).filter(|r| !r.is_empty()) {
        let record = std::str::from_utf8(record).map_err(|_| BranchError::PathRefused {
            path: String::from_utf8_lossy(record).into_owned(),
            reason: "encoding",
        })?;
        let (meta, path) = record.split_once('\t').ok_or(BranchError::Git("ls-tree"))?;
        let fields: Vec<&str> = meta.split_whitespace().collect();
        let [mode, kind, oid, size] = fields.as_slice() else {
            return Err(BranchError::Git("ls-tree"));
        };
        check_path(path, limits)?;
        super::git::check_oid(oid)?;
        let unsupported = |kind| {
            Err(BranchError::UnsupportedEntry {
                path: path.to_owned(),
                kind,
            })
        };
        let executable = match (*mode, *kind) {
            (REGULAR, "blob") => false,
            (EXECUTABLE, "blob") => true,
            ("120000", _) => return unsupported(UnsupportedKind::Symlink),
            ("160000", _) => return unsupported(UnsupportedKind::Submodule),
            _ => return unsupported(UnsupportedKind::Special),
        };
        let size: u64 = size.parse().map_err(|_| BranchError::Git("ls-tree"))?;
        if size > limits.max_file_bytes {
            return Err(BranchError::BoundExceeded("file_bytes"));
        }
        total = total.saturating_add(size);
        if total > limits.max_total_bytes {
            return Err(BranchError::BoundExceeded("total_bytes"));
        }
        if entries.len() >= limits.max_entries {
            return Err(BranchError::BoundExceeded("entries"));
        }
        if size <= LFS_POINTER_MAX_BYTES && git.read_blob(oid)?.starts_with(LFS_POINTER_PREFIX) {
            return unsupported(UnsupportedKind::LfsPointer);
        }
        entries.push(TreeEntry {
            path: path.to_owned(),
            executable,
            blob: (*oid).to_owned(),
            size,
        });
    }
    Ok(entries)
}

/// Reads a host directory into a tree. Symlinks and special files are refused
/// before any content is stored.
pub(super) fn import_directory(
    git: &Git,
    root: &Path,
    limits: &Limits,
) -> Result<String, BranchError> {
    let root = root.canonicalize()?;
    let mut files = Vec::new();
    collect(&root, &root, limits, &mut files)?;
    files.sort();
    let mut edits = Vec::with_capacity(files.len());
    let mut total: u64 = 0;
    for (path, host) in files {
        let (bytes, executable) = read_regular(&host, &path, limits.max_file_bytes)?;
        let size =
            u64::try_from(bytes.len()).map_err(|_| BranchError::BoundExceeded("file_bytes"))?;
        total = total.saturating_add(size);
        if total > limits.max_total_bytes {
            return Err(BranchError::BoundExceeded("total_bytes"));
        }
        if size <= LFS_POINTER_MAX_BYTES && bytes.starts_with(LFS_POINTER_PREFIX) {
            return Err(BranchError::UnsupportedEntry {
                path,
                kind: UnsupportedKind::LfsPointer,
            });
        }
        let blob = git.write_blob(&bytes)?;
        edits.push(Edit::Write {
            path,
            blob,
            executable,
        });
    }
    edit_tree(git, None, &edits)
}

/// Reads one regular file through a handle whose identity matches the
/// unfollowed path, so a file swapped for a link while it is read is refused.
fn read_regular(host: &Path, path: &str, limit: u64) -> Result<(Vec<u8>, bool), BranchError> {
    let file = std::fs::File::open(host)?;
    let opened = file.metadata()?;
    let unfollowed = std::fs::symlink_metadata(host)?;
    if !opened.is_file() || !unfollowed.file_type().is_file() || !same_file(&opened, &unfollowed) {
        return Err(BranchError::SourceChanged(path.to_owned()));
    }
    if opened.len() > limit {
        return Err(BranchError::BoundExceeded("file_bytes"));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    let read = u64::try_from(bytes.len()).map_err(|_| BranchError::BoundExceeded("file_bytes"))?;
    if read > limit {
        return Err(BranchError::BoundExceeded("file_bytes"));
    }
    Ok((bytes, is_executable(&opened)))
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    false
}

fn collect(
    root: &Path,
    dir: &Path,
    limits: &Limits,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), BranchError> {
    if !dir.canonicalize()?.starts_with(root) {
        return Err(BranchError::SourceChanged(
            dir.strip_prefix(root)
                .unwrap_or(dir)
                .to_string_lossy()
                .into_owned(),
        ));
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let host = entry.path();
        let relative = host
            .strip_prefix(root)
            .map_err(|_| BranchError::Io("path outside import root".to_owned()))?;
        let path = relative
            .to_str()
            .ok_or_else(|| BranchError::PathRefused {
                path: relative.to_string_lossy().into_owned(),
                reason: "encoding",
            })?
            .to_owned();
        check_path(&path, limits)?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(BranchError::UnsupportedEntry {
                path,
                kind: UnsupportedKind::Symlink,
            });
        }
        if kind.is_dir() {
            collect(root, &host, limits, out)?;
        } else if kind.is_file() {
            if out.len() >= limits.max_entries {
                return Err(BranchError::BoundExceeded("entries"));
            }
            out.push((path, host.clone()));
        } else {
            return Err(BranchError::UnsupportedEntry {
                path,
                kind: UnsupportedKind::Special,
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub(super) enum Edit {
    Write {
        path: String,
        blob: String,
        executable: bool,
    },
    Remove {
        path: String,
    },
}

static INDEX_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Builds a new tree from `base` (or an empty tree) with `edits` applied,
/// through a private index file that never touches a working directory.
pub(super) fn edit_tree(
    git: &Git,
    base: Option<&str>,
    edits: &[Edit],
) -> Result<String, BranchError> {
    let scratch = git.git_dir().join(format!(
        "chio-index-{}-{}",
        std::process::id(),
        INDEX_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&scratch)?;
    let result = edit_with_index(git, &scratch.join("index"), base, edits);
    std::fs::remove_dir_all(&scratch)?;
    result
}

fn edit_with_index(
    git: &Git,
    index: &Path,
    base: Option<&str>,
    edits: &[Edit],
) -> Result<String, BranchError> {
    match base {
        Some(tree) => git.run("read-tree", &["read-tree", tree], None, Some(index))?,
        None => git.run("read-tree", &["read-tree", "--empty"], None, Some(index))?,
    };
    let mut info = Vec::new();
    for edit in edits {
        match edit {
            Edit::Write {
                path,
                blob,
                executable,
            } => {
                let mode = if *executable { EXECUTABLE } else { REGULAR };
                info.extend_from_slice(format!("{mode} {blob}\t{path}").as_bytes());
            }
            Edit::Remove { path } => {
                info.extend_from_slice(format!("0 {}\t{path}", super::git::ZERO_OID).as_bytes());
            }
        }
        info.push(0);
    }
    git.run(
        "update-index",
        &["update-index", "-z", "--index-info"],
        Some(&info),
        Some(index),
    )?;
    let tree = git.run_line("write-tree", &["write-tree"], None, Some(index))?;
    super::git::check_oid(&tree)?;
    Ok(tree)
}
