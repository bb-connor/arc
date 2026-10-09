use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use chio_kernel::AuthorityStoreError;
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{Connection, OpenFlags};
use rustix::fs::{mkdirat, openat, Mode, OFlags};

use super::{path, refused};

pub(in crate::authority) struct AuthorityCustody {
    path: PathBuf,
    directories: Vec<DirectoryCustody>,
    identity: SqliteFileIdentity,
}

struct DirectoryCustody {
    path: PathBuf,
    handle: File,
    device: u64,
    inode: u64,
}

impl AuthorityCustody {
    pub(in crate::authority) fn prepare(path: &Path) -> Result<Self, AuthorityStoreError> {
        let parsed = path::parse(path)?;
        let parent = parsed
            .filesystem
            .parent()
            .ok_or_else(|| refused("database parent is missing"))?;
        let directories = prepare_directories(parent, parsed.create)?;
        validate_sidecars(&parsed.filesystem)?;
        let metadata = match fs::symlink_metadata(&parsed.filesystem) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && parsed.create => {
                let parent = directories
                    .last()
                    .ok_or_else(|| refused("database parent is missing"))?;
                parent.validate(true)?;
                let filename = parsed
                    .filesystem
                    .file_name()
                    .ok_or_else(|| refused("database filename is missing"))?;
                let descriptor = openat(
                    &parent.handle,
                    filename,
                    OFlags::RDWR
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(std::io::Error::from)?;
                let file = File::from(descriptor);
                let metadata = file.metadata()?;
                validate_file(&metadata)?;
                file.sync_all()?;
                parent.handle.sync_all()?;
                // This descriptor exists only for an exclusively created empty
                // file and closes before SQLite can take any process-wide lock.
                metadata
            }
            Err(error) => return Err(error.into()),
        };
        validate_file(&metadata)?;
        let custody = Self {
            path: parsed.filesystem,
            directories,
            identity: identity(&metadata),
        };
        custody.validate_filesystem()?;
        Ok(custody)
    }

    /// Custody of an existing, nonempty authority database, or `None` when the
    /// database or any ancestor directory is absent or the file was never
    /// initialized. Nothing is created and no permission is repaired.
    pub(in crate::authority) fn inspect_existing(
        path: &Path,
    ) -> Result<Option<Self>, AuthorityStoreError> {
        let parsed = path::parse(path)?;
        let parent = parsed
            .filesystem
            .parent()
            .ok_or_else(|| refused("database parent is missing"))?;
        let directories = match prepare_directories(parent, false) {
            Ok(directories) => directories,
            Err(AuthorityStoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        validate_sidecars(&parsed.filesystem)?;
        let metadata = match fs::symlink_metadata(&parsed.filesystem) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        validate_file(&metadata)?;
        if metadata.len() == 0 {
            return Ok(None);
        }
        let custody = Self {
            path: parsed.filesystem,
            directories,
            identity: identity(&metadata),
        };
        custody.validate_filesystem()?;
        Ok(Some(custody))
    }

    /// A connection that cannot write the database file. SQLite still keeps
    /// its ordinary WAL shared-memory bookkeeping in the private sidecars.
    pub(in crate::authority) fn open_read_only_connection(
        &self,
    ) -> Result<Connection, AuthorityStoreError> {
        self.validate_filesystem()?;
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
        )?;
        self.validate(&connection)?;
        Ok(connection)
    }

    pub(in crate::authority) fn open_connection(&self) -> Result<Connection, AuthorityStoreError> {
        self.validate_filesystem()?;
        // The filename is already decoded and absolute. Do not let SQLite
        // interpret URI parameters, create a missing file, or follow symlinks.
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
        )?;
        self.validate(&connection)?;
        Ok(connection)
    }

    pub(in crate::authority) fn validate(
        &self,
        connection: &Connection,
    ) -> Result<(), AuthorityStoreError> {
        self.validate_filesystem()?;
        let opened =
            main_database_file_identity(connection).map_err(|message| refused(&message))?;
        if opened != self.identity {
            return Err(refused("SQLite opened a different or unlinked database"));
        }
        Ok(())
    }

    fn validate_filesystem(&self) -> Result<(), AuthorityStoreError> {
        for (position, directory) in self.directories.iter().enumerate() {
            directory.validate(position + 1 == self.directories.len())?;
        }
        let metadata = fs::symlink_metadata(&self.path)?;
        validate_file(&metadata)?;
        if identity(&metadata) != self.identity {
            return Err(refused("database identity changed"));
        }
        validate_sidecars(&self.path)
    }
}

impl DirectoryCustody {
    fn new(path: PathBuf, handle: File, immediate: bool) -> Result<Self, AuthorityStoreError> {
        let metadata = handle.metadata()?;
        validate_directory(&metadata, immediate)?;
        let directory = Self {
            path,
            handle,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        directory.validate(immediate)?;
        Ok(directory)
    }

    fn validate(&self, immediate: bool) -> Result<(), AuthorityStoreError> {
        for metadata in [self.handle.metadata()?, fs::symlink_metadata(&self.path)?] {
            validate_directory(&metadata, immediate)?;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(refused("directory identity changed"));
            }
        }
        Ok(())
    }
}

fn prepare_directories(
    parent: &Path,
    create: bool,
) -> Result<Vec<DirectoryCustody>, AuthorityStoreError> {
    let root = PathBuf::from("/");
    let mut directories = vec![DirectoryCustody::new(
        root.clone(),
        File::open(&root)?,
        parent == root,
    )?];
    let mut current = root;
    for component in parent.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err(refused("database path is not absolute and normalized")),
        };
        let ancestor = directories
            .last()
            .ok_or_else(|| refused("database ancestor is missing"))?;
        ancestor.validate(false)?;
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let descriptor = match openat(&ancestor.handle, name, flags, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT && create => {
                match mkdirat(&ancestor.handle, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) => ancestor.handle.sync_all()?,
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(std::io::Error::from(error).into()),
                }
                openat(&ancestor.handle, name, flags, Mode::empty())
                    .map_err(std::io::Error::from)?
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        current.push(name);
        directories.push(DirectoryCustody::new(
            current.clone(),
            File::from(descriptor),
            current == parent,
        )?);
    }
    Ok(directories)
}

fn validate_directory(metadata: &fs::Metadata, immediate: bool) -> Result<(), AuthorityStoreError> {
    let effective_uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_dir() {
        return Err(refused(
            "directory must be a real directory, without symlinks",
        ));
    }
    if immediate {
        if metadata.uid() != effective_uid || metadata.mode() & 0o7777 != 0o700 {
            return Err(refused(
                "database parent must belong to the effective user with mode 0700",
            ));
        }
    } else if (metadata.uid() != effective_uid && metadata.uid() != 0)
        || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0)
    {
        return Err(refused(
            "database ancestor has unsafe ownership or write permissions",
        ));
    }
    Ok(())
}

fn validate_file(metadata: &fs::Metadata) -> Result<(), AuthorityStoreError> {
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(refused(
            "database and sidecars require an owned single-link regular file with mode 0600",
        ));
    }
    Ok(())
}

fn validate_sidecars(path: &Path) -> Result<(), AuthorityStoreError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(PathBuf::from(sidecar)) {
            Ok(metadata) => validate_file(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn identity(metadata: &fs::Metadata) -> SqliteFileIdentity {
    SqliteFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        link_count: metadata.nlink(),
    }
}
