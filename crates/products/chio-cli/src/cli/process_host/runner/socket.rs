//! Short worker endpoints with write-ahead ownership and restart cleanup.
//!
//! Durable host paths are unrestricted by Unix socket address length. The fixed
//! Linux /tmp parent is independent of TMPDIR and never exposes host state.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use super::super::state::error;
use crate::CliError;

const SOCKET: &str = "process.sock";
const MAX_ABANDONED: i64 = 8;

pub(super) struct Endpoint {
    parent: File,
    directory: File,
    name: String,
    path: PathBuf,
}

struct Record {
    name: String,
    directory: Option<(u64, u64)>,
    socket: Option<(u64, u64)>,
}

fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn owned_private(metadata: &Metadata) -> bool {
    // SAFETY: geteuid is a read-only process query.
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0
}

fn open_at(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name)?;
    // SAFETY: name is NUL-terminated and parent remains open for this call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn entry(parent: &File, name: &str) -> io::Result<Option<Metadata>> {
    match open_at(parent, name, libc::O_PATH) {
        Ok(file) => file.metadata().map(Some),
        Err(failure) if failure.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(failure) => Err(failure),
    }
}

fn remove_at(parent: &File, name: &str, directory: bool) -> io::Result<()> {
    let name = CString::new(name)?;
    // SAFETY: name is NUL-terminated and parent remains open for this call.
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            if directory { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()
}

fn parent() -> Result<File, CliError> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/tmp")?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
        return Err(error(
            "worker socket parent /tmp must be a root-owned sticky directory",
        ));
    }
    Ok(parent)
}

fn record(db: &Connection) -> Result<Option<Record>, CliError> {
    db.query_row("SELECT name,directory_device,directory_inode,socket_device,socket_inode FROM run_socket_leases WHERE singleton=1", [], |row| {
        Ok(Record { name: row.get(0)?, directory: read_identity(row, 1)?, socket: read_identity(row, 3)? })
    }).optional().map_err(error)
}

fn read_identity(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<(u64, u64)>> {
    let device: Option<String> = row.get(index)?;
    let inode: Option<String> = row.get(index + 1)?;
    let parse = |value: String| {
        value.parse().map_err(|failure| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                Box::new(failure),
            )
        })
    };
    match (device, inode) {
        (Some(device), Some(inode)) => Ok(Some((parse(device)?, parse(inode)?))),
        (None, None) => Ok(None),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn validate_name(name: &str) -> Result<(), CliError> {
    if !name.strip_prefix("chio-worker-").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(error("invalid recorded worker socket directory name"));
    }
    Ok(())
}

fn abandon(db: &Connection) -> Result<(), CliError> {
    let last: i64 = db
        .query_row(
            "SELECT COALESCE(MAX(singleton),1) FROM run_socket_leases",
            [],
            |row| row.get(0),
        )
        .map_err(error)?;
    if last > MAX_ABANDONED {
        return Err(error("worker socket abandoned-intent limit reached; preserve and inspect the runner journal before further runs"));
    }
    db.execute(
        "UPDATE run_socket_leases SET singleton=?1 WHERE singleton=1",
        [last + 1],
    )
    .map_err(error)?;
    Ok(())
}

fn reconcile(db: &Connection, parent: &File) -> Result<(), CliError> {
    let Some(record) = record(db)? else {
        return Ok(());
    };
    validate_name(&record.name)?;
    if let Some(metadata) = entry(parent, &record.name)? {
        if record.directory.is_none() {
            // The pre-bind intent never issued worker credentials. Preserve the
            // unknown object and history, then use a new random endpoint.
            return abandon(db);
        }
        if !metadata.is_dir()
            || !owned_private(&metadata)
            || Some(identity(&metadata)) != record.directory
        {
            return Err(error(format!("worker socket directory ownership is unresolved: /tmp/{}; preserve the directory and runner journal", record.name)));
        }
        let directory = open_at(parent, &record.name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if Some(identity(&directory.metadata()?)) != record.directory {
            return Err(error("worker socket directory changed during cleanup"));
        }
        if let Some(metadata) = entry(&directory, SOCKET)? {
            if record.socket.is_none() {
                // A listener may have existed, but no worker credential was
                // delivered before the socket identity commit.
                return abandon(db);
            }
            if !metadata.file_type().is_socket()
                || !owned_private(&metadata)
                || metadata.nlink() != 1
                || Some(identity(&metadata)) != record.socket
            {
                return Err(error(format!("worker socket ownership is unresolved: /tmp/{}/{SOCKET}; preserve the endpoint and runner journal", record.name)));
            }
            remove_at(&directory, SOCKET, false)?;
        }
        // Only the known socket is unlinked. Unknown siblings keep the directory
        // and its durable lease intact, even when they belong to the operator.
        if entry(parent, &record.name)?.as_ref().map(identity) != record.directory {
            return Err(error("worker socket directory changed before removal"));
        }
        remove_at(parent, &record.name, true)?;
    }
    db.execute("DELETE FROM run_socket_leases WHERE singleton=1", [])
        .map_err(error)?;
    Ok(())
}

pub(super) fn cleanup_for_export(db: &Connection) -> Result<(), CliError> {
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='run_socket_leases')", [], |row| row.get(0)).map_err(error)?;
    if exists {
        reconcile(db, &parent()?)?;
        if db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM run_socket_leases)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(error)?
        {
            return Err(error("worker socket ownership is unresolved; preserve abandoned endpoint records on the original host before export"));
        }
    }
    Ok(())
}

impl Endpoint {
    pub fn prepare(db: &Connection) -> Result<Self, CliError> {
        db.execute_batch("CREATE TABLE IF NOT EXISTS run_socket_leases(singleton INTEGER PRIMARY KEY CHECK(singleton BETWEEN 1 AND 9), name TEXT NOT NULL UNIQUE, directory_device TEXT, directory_inode TEXT, socket_device TEXT, socket_inode TEXT, CHECK((directory_device IS NULL)=(directory_inode IS NULL)), CHECK((socket_device IS NULL)=(socket_inode IS NULL)))").map_err(error)?;
        let parent = parent()?;
        reconcile(db, &parent)?;
        let name = format!("chio-worker-{}", uuid::Uuid::new_v4().simple());
        // A crash at either filesystem creation boundary leaves a tracked lease.
        // Missing identity is never inferred from a name, owner or permissions.
        db.execute(
            "INSERT INTO run_socket_leases(singleton,name) VALUES(1,?1)",
            [&name],
        )
        .map_err(error)?;
        let c_name = CString::new(name.as_bytes()).map_err(error)?;
        // SAFETY: the name is NUL-terminated and parent remains open.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        parent.sync_all()?;
        let directory = open_at(&parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let metadata = directory.metadata()?;
        if !owned_private(&metadata) {
            return Err(error("new worker socket directory must be private"));
        }
        db.execute("UPDATE run_socket_leases SET directory_device=?1,directory_inode=?2 WHERE singleton=1 AND name=?3", params![metadata.dev().to_string(), metadata.ino().to_string(), name]).map_err(error)?;
        let path = Path::new("/tmp").join(&name).join(SOCKET);
        Ok(Self {
            parent,
            directory,
            name,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bound(&self, db: &Connection) -> Result<(), CliError> {
        let directory = self.directory.metadata()?;
        if entry(&self.parent, &self.name)?.as_ref().map(identity) != Some(identity(&directory)) {
            return Err(error("worker socket directory changed during bind"));
        }
        let metadata = entry(&self.directory, SOCKET)?
            .ok_or_else(|| error("worker socket is missing after bind"))?;
        if !metadata.file_type().is_socket() || !owned_private(&metadata) || metadata.nlink() != 1 {
            return Err(error(
                "new worker socket must be private and operator-owned",
            ));
        }
        self.directory.sync_all()?;
        db.execute("UPDATE run_socket_leases SET socket_device=?1,socket_inode=?2 WHERE singleton=1 AND name=?3", params![metadata.dev().to_string(), metadata.ino().to_string(), self.name]).map_err(error)?;
        Ok(())
    }

    pub fn cleanup(&self, db: &Connection) -> Result<(), CliError> {
        reconcile(db, &self.parent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn bind(
        endpoint: &Endpoint,
        db: &Connection,
    ) -> Result<UnixListener, Box<dyn std::error::Error>> {
        let listener = UnixListener::bind(endpoint.path())?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))?;
        endpoint.bound(db)?;
        Ok(listener)
    }

    #[test]
    fn short_endpoint_recovers_socket_and_cleans_completed_runs() -> TestResult {
        let db = Connection::open_in_memory()?;
        let first = Endpoint::prepare(&db)?;
        assert!(first.path().as_os_str().len() < 104);
        let listener = bind(&first, &db)?;
        std::os::unix::net::UnixStream::connect(first.path())?;
        drop(listener); // Host death leaves the filesystem socket behind.
        let second = Endpoint::prepare(&db)?;
        assert!(!first.path.parent().ok_or("parent")?.exists());
        assert_ne!(first.path(), second.path());
        let listener = bind(&second, &db)?;
        drop(listener);
        second.cleanup(&db)?;
        assert!(!second.path.parent().ok_or("parent")?.exists());
        assert!(record(&db)?.is_none());
        Ok(())
    }

    #[test]
    fn socket_creation_gaps_preserve_objects_and_resume_with_a_new_endpoint() -> TestResult {
        for directory_gap in [true, false] {
            let db = Connection::open_in_memory()?;
            let first = Endpoint::prepare(&db)?;
            let listener = if directory_gap {
                None
            } else {
                Some(bind(&first, &db)?)
            };
            db.execute(
                if directory_gap {
                    "UPDATE run_socket_leases SET directory_device=NULL,directory_inode=NULL"
                } else {
                    "UPDATE run_socket_leases SET socket_device=NULL,socket_inode=NULL"
                },
                [],
            )?;
            let before = first.directory.metadata()?;
            let second = Endpoint::prepare(&db)?;
            assert_eq!(
                identity(&before),
                identity(&std::fs::metadata(first.path.parent().ok_or("parent")?)?)
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM run_socket_leases WHERE singleton>1",
                    [],
                    |row| row.get::<_, i64>(0)
                )?,
                1
            );
            assert!(cleanup_for_export(&db).is_err());
            assert!(first.path.parent().ok_or("parent")?.exists());
            second.cleanup(&db)?;
            drop(listener);
            if first.path.exists() {
                std::fs::remove_file(first.path())?;
            }
            std::fs::remove_dir(first.path.parent().ok_or("parent")?)?;
        }
        Ok(())
    }

    #[test]
    fn recorded_socket_replacement_is_never_unlinked() -> TestResult {
        for symlink_replacement in [true, false] {
            let db = Connection::open_in_memory()?;
            let endpoint = Endpoint::prepare(&db)?;
            let listener = bind(&endpoint, &db)?;
            let original = endpoint.path.with_extension("original");
            std::fs::rename(endpoint.path(), &original)?;
            if symlink_replacement {
                symlink(&original, endpoint.path())?;
            } else {
                std::fs::write(endpoint.path(), b"must survive")?;
            }
            assert!(Endpoint::prepare(&db).is_err());
            assert!(endpoint.path.symlink_metadata().is_ok());
            assert!(record(&db)?.is_some());
            std::fs::remove_file(endpoint.path())?;
            std::fs::rename(&original, endpoint.path())?;
            drop(listener);
            endpoint.cleanup(&db)?;
        }
        Ok(())
    }

    #[test]
    fn replaced_directory_and_unexpected_siblings_survive_cleanup() -> TestResult {
        let db = Connection::open_in_memory()?;
        let endpoint = Endpoint::prepare(&db)?;
        let directory = endpoint.path.parent().ok_or("parent")?;
        let moved = directory.with_extension("original");
        std::fs::rename(directory, &moved)?;
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        assert!(endpoint.cleanup(&db).is_err());
        assert!(directory.exists());
        std::fs::remove_dir(directory)?;
        std::fs::rename(&moved, directory)?;
        let sibling = directory.join("unrelated");
        std::fs::write(&sibling, b"must survive")?;
        assert!(endpoint.cleanup(&db).is_err());
        assert_eq!(std::fs::read(&sibling)?, b"must survive");
        assert!(record(&db)?.is_some());
        std::fs::remove_file(sibling)?;
        endpoint.cleanup(&db)?;
        Ok(())
    }

    #[test]
    fn replacement_socket_identity_blocks_export_until_original_is_restored() -> TestResult {
        let db = Connection::open_in_memory()?;
        let endpoint = Endpoint::prepare(&db)?;
        let listener = bind(&endpoint, &db)?;
        let original = endpoint.path.with_extension("original");
        std::fs::rename(endpoint.path(), &original)?;
        let replacement = UnixListener::bind(endpoint.path())?;
        std::fs::set_permissions(endpoint.path(), std::fs::Permissions::from_mode(0o600))?;
        let replacement_identity = identity(&std::fs::symlink_metadata(endpoint.path())?);
        assert!(cleanup_for_export(&db).is_err());
        assert_eq!(
            identity(&std::fs::symlink_metadata(endpoint.path())?),
            replacement_identity
        );
        drop(replacement);
        std::fs::remove_file(endpoint.path())?;
        std::fs::rename(&original, endpoint.path())?;
        drop(listener);
        cleanup_for_export(&db)?;
        assert!(!endpoint.path.parent().ok_or("parent")?.exists());
        assert!(record(&db)?.is_none());
        Ok(())
    }

    #[test]
    fn broad_permissions_and_hardlinked_socket_preserve_the_lease() -> TestResult {
        let db = Connection::open_in_memory()?;
        let endpoint = Endpoint::prepare(&db)?;
        let listener = bind(&endpoint, &db)?;
        let directory = endpoint.path.parent().ok_or("parent")?;
        for (path, invalid, restored) in
            [(directory, 0o755, 0o700), (endpoint.path(), 0o644, 0o600)]
        {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(invalid))?;
            assert!(endpoint.cleanup(&db).is_err());
            assert!(endpoint.path.exists());
            assert!(record(&db)?.is_some());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(restored))?;
        }
        let alias = directory.join("alias");
        std::fs::hard_link(endpoint.path(), &alias)?;
        assert!(endpoint.cleanup(&db).is_err());
        assert!(endpoint.path.exists());
        std::fs::remove_file(alias)?;
        drop(listener);
        endpoint.cleanup(&db)?;
        Ok(())
    }

    #[test]
    fn absent_intents_clear_and_abandoned_history_is_bounded() -> TestResult {
        let db = Connection::open_in_memory()?;
        let endpoint = Endpoint::prepare(&db)?;
        std::fs::remove_dir(endpoint.path.parent().ok_or("parent")?)?;
        endpoint.cleanup(&db)?;
        assert!(record(&db)?.is_none());
        for index in 2..=9 {
            db.execute(
                "INSERT INTO run_socket_leases(singleton,name) VALUES(?1,?2)",
                params![index, format!("chio-worker-{index:032x}")],
            )?;
        }
        let endpoint = Endpoint::prepare(&db)?;
        db.execute("UPDATE run_socket_leases SET directory_device=NULL,directory_inode=NULL WHERE singleton=1", [])?;
        assert!(Endpoint::prepare(&db).is_err());
        assert!(endpoint.path.parent().ok_or("parent")?.exists());
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM run_socket_leases", [], |row| row
                .get::<_, i64>(0))?,
            9
        );
        std::fs::remove_dir(endpoint.path.parent().ok_or("parent")?)?;
        Ok(())
    }
}
