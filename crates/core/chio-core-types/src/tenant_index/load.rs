//! Loads a tenant index key set from its provisioning directory.
//!
//! Layout: `<dir>/active` holds the active set key; `<dir>/retired/<hex key_id>` holds each
//! retired set key under its own `key_id`. Each key file is a regular file of exactly 32
//! bytes, owned by the process user and not readable or writable by group or other. Any
//! other entry, a symlink, a missing active key, a misnamed retired key or a duplicate
//! `key_id` refuses the whole set.

use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::{TenantBindingError, TenantIndexKey, TenantIndexKeySet, TENANT_INDEX_KEY_LEN};

const ACTIVE_FILE: &str = "active";
const RETIRED_DIR: &str = "retired";
/// One byte past the key length, so an oversized file reads as the wrong length.
const KEY_READ_LIMIT: u64 = 33;

/// Why a tenant index key set directory is refused.
#[derive(Debug)]
pub enum TenantIndexKeyLoadError {
    Io { path: PathBuf, source: io::Error },
    MissingActive { path: PathBuf },
    NotRegularFile { path: PathBuf },
    NotDirectory { path: PathBuf },
    WrongLength { path: PathBuf },
    LoosePermissions { path: PathBuf },
    NotOwned { path: PathBuf },
    UnexpectedEntry { path: PathBuf },
    RetiredNameMismatch { path: PathBuf },
    UnsupportedPlatform,
    KeySet(TenantBindingError),
}

impl std::fmt::Display for TenantIndexKeyLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "cannot read tenant index key {}: {source}",
                    path.display()
                )
            }
            Self::MissingActive { path } => {
                write!(
                    formatter,
                    "tenant index key set {} has no active key",
                    path.display()
                )
            }
            Self::NotRegularFile { path } => {
                write!(
                    formatter,
                    "tenant index key {} is not a regular file",
                    path.display()
                )
            }
            Self::NotDirectory { path } => {
                write!(
                    formatter,
                    "tenant index key path {} is not a directory",
                    path.display()
                )
            }
            Self::WrongLength { path } => write!(
                formatter,
                "tenant index key {} is not exactly {TENANT_INDEX_KEY_LEN} bytes",
                path.display()
            ),
            Self::LoosePermissions { path } => write!(
                formatter,
                "tenant index key {} is accessible to group or other",
                path.display()
            ),
            Self::NotOwned { path } => write!(
                formatter,
                "tenant index key {} is not owned by the process user",
                path.display()
            ),
            Self::UnexpectedEntry { path } => write!(
                formatter,
                "tenant index key set has an unexpected entry {}",
                path.display()
            ),
            Self::RetiredNameMismatch { path } => write!(
                formatter,
                "retired tenant index key {} is not named by its key_id",
                path.display()
            ),
            Self::UnsupportedPlatform => formatter
                .write_str("tenant index key permissions cannot be checked on this platform"),
            Self::KeySet(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for TenantIndexKeyLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::KeySet(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TenantBindingError> for TenantIndexKeyLoadError {
    fn from(error: TenantBindingError) -> Self {
        Self::KeySet(error)
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> TenantIndexKeyLoadError + '_ {
    move |source| TenantIndexKeyLoadError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl TenantIndexKeySet {
    /// Loads the set provisioned at `dir` (the `--tenant-index-keys <dir>` layout).
    pub fn load_dir(dir: &Path) -> Result<Self, TenantIndexKeyLoadError> {
        require_directory(dir)?;
        let mut has_active = false;
        let mut has_retired = false;
        for entry in fs::read_dir(dir).map_err(io_error(dir))? {
            let entry = entry.map_err(io_error(dir))?;
            let name = entry.file_name();
            if name == ACTIVE_FILE {
                has_active = true;
            } else if name == RETIRED_DIR {
                has_retired = true;
            } else {
                return Err(TenantIndexKeyLoadError::UnexpectedEntry { path: entry.path() });
            }
        }
        let active_path = dir.join(ACTIVE_FILE);
        if !has_active {
            return Err(TenantIndexKeyLoadError::MissingActive {
                path: dir.to_path_buf(),
            });
        }
        let active = read_key(&active_path)?;
        let mut retired = Vec::new();
        if has_retired {
            let retired_dir = dir.join(RETIRED_DIR);
            require_directory(&retired_dir)?;
            for entry in fs::read_dir(&retired_dir).map_err(io_error(&retired_dir))? {
                let path = entry.map_err(io_error(&retired_dir))?.path();
                let key = read_key(&path)?;
                let named_by_key_id = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name == key.key_id().to_bare_hex());
                if !named_by_key_id {
                    return Err(TenantIndexKeyLoadError::RetiredNameMismatch { path });
                }
                retired.push(key);
            }
        }
        Ok(Self::new(active, retired)?)
    }
}

fn require_directory(path: &Path) -> Result<(), TenantIndexKeyLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(TenantIndexKeyLoadError::NotDirectory {
            path: path.to_path_buf(),
        })
    }
}

fn read_key(path: &Path) -> Result<TenantIndexKey, TenantIndexKeyLoadError> {
    let before = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !before.is_file() {
        return Err(TenantIndexKeyLoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let file = File::open(path).map_err(io_error(path))?;
    let opened = file.metadata().map_err(io_error(path))?;
    require_private(path, &opened)?;
    if !opened.is_file() || !same_file(&before, &opened) {
        return Err(TenantIndexKeyLoadError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(TENANT_INDEX_KEY_LEN + 1));
    file.take(KEY_READ_LIMIT)
        .read_to_end(&mut bytes)
        .map_err(io_error(path))?;
    let set_key: Zeroizing<[u8; TENANT_INDEX_KEY_LEN]> =
        Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
            TenantIndexKeyLoadError::WrongLength {
                path: path.to_path_buf(),
            }
        })?);
    Ok(TenantIndexKey::from_set_key(&set_key)?)
}

#[cfg(unix)]
fn same_file(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &Metadata, _after: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn require_private(path: &Path, metadata: &Metadata) -> Result<(), TenantIndexKeyLoadError> {
    use std::os::unix::fs::MetadataExt as _;
    if metadata.mode() & 0o077 != 0 {
        return Err(TenantIndexKeyLoadError::LoosePermissions {
            path: path.to_path_buf(),
        });
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(TenantIndexKeyLoadError::NotOwned {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private(_path: &Path, _metadata: &Metadata) -> Result<(), TenantIndexKeyLoadError> {
    Err(TenantIndexKeyLoadError::UnsupportedPlatform)
}
