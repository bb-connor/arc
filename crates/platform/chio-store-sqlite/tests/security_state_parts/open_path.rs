use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chio_security_types::ports::PortErrorKind;
use chio_store_sqlite::SqliteSecurityStateStore;

fn entries(directory: &Path) -> BTreeSet<String> {
    std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read directory: {error}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("directory entry: {error}"))
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

#[test]
fn a_symlinked_path_is_refused_before_the_target_is_created_or_written() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let victim = directory.path().join("victim.db");
    let alias = directory.path().join("alias.db");
    std::os::unix::fs::symlink(&victim, &alias).unwrap_or_else(|error| panic!("symlink: {error}"));
    assert!(SqliteSecurityStateStore::open(&alias).is_err());
    assert_eq!(
        entries(directory.path()),
        BTreeSet::from(["alias.db".to_owned()])
    );

    std::fs::write(&victim, b"").unwrap_or_else(|error| panic!("victim: {error}"));
    assert!(SqliteSecurityStateStore::open(&alias).is_err());
    assert_eq!(
        entries(directory.path()),
        BTreeSet::from(["alias.db".to_owned(), "victim.db".to_owned()])
    );
    assert_eq!(std::fs::read(&victim).unwrap_or_default().len(), 0);
}

#[test]
fn a_hard_linked_path_is_refused_before_it_is_written() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let victim = directory.path().join("victim.db");
    let linked = directory.path().join("linked.db");
    std::fs::write(&victim, b"").unwrap_or_else(|error| panic!("victim: {error}"));
    std::fs::hard_link(&victim, &linked).unwrap_or_else(|error| panic!("hard link: {error}"));
    assert!(SqliteSecurityStateStore::open(&linked).is_err());
    assert_eq!(
        entries(directory.path()),
        BTreeSet::from(["linked.db".to_owned(), "victim.db".to_owned()])
    );
    assert_eq!(std::fs::read(&victim).unwrap_or_default().len(), 0);
}

#[test]
fn a_new_store_is_private_to_its_owner() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = directory.path().join("state");
    let path = parent.join("security.db");
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state: {error}")),
    );
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&parent), 0o700);
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn a_shared_writable_parent_is_refused_before_the_store_is_created() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let shared = directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap_or_else(|error| panic!("shared: {error}"));
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
        .unwrap_or_else(|error| panic!("chmod: {error}"));
    assert!(SqliteSecurityStateStore::open(shared.join("security.db")).is_err());
    assert!(entries(&shared).is_empty());
}

#[test]
fn a_group_writable_parent_is_refused_before_the_store_is_created() {
    // A group member could unlink or replace the database through this parent.
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = directory.path().join("group-writable");
    std::fs::create_dir(&parent).unwrap_or_else(|error| panic!("parent: {error}"));
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o770))
        .unwrap_or_else(|error| panic!("chmod: {error}"));
    assert!(SqliteSecurityStateStore::open(parent.join("security.db")).is_err());
    assert!(entries(&parent).is_empty());
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileMode(u32);

impl std::fmt::Debug for FileMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:04o}", self.0)
    }
}

fn file_mode(path: &Path) -> FileMode {
    FileMode(
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("metadata {}: {error}", path.display()))
            .permissions()
            .mode()
            & 0o7777,
    )
}

fn set_file_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("chmod {}: {error}", path.display()));
}

fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

const PRIVATE_DATABASE: [(&str, FileMode); 3] = [
    ("", FileMode(0o600)),
    ("-wal", FileMode(0o600)),
    ("-shm", FileMode(0o600)),
];

/// The modes of the database and of the sidecars SQLite keeps while open.
fn open_database_modes(path: &Path) -> [(&'static str, FileMode); 3] {
    ["", "-wal", "-shm"].map(|suffix| (suffix, file_mode(&sidecar(path, suffix))))
}

/// An owned parent with no group or other write bit, as a 022 umask leaves it.
fn world_readable_parent(directory: &Path) -> PathBuf {
    let parent = directory.join("state");
    std::fs::create_dir(&parent).unwrap_or_else(|error| panic!("parent: {error}"));
    set_file_mode(&parent, 0o755);
    parent
}

fn closed_store(parent: &Path) -> PathBuf {
    let path = parent.join("security.db");
    drop(
        SqliteSecurityStateStore::open(&path)
            .unwrap_or_else(|error| panic!("open security state: {error}")),
    );
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(
            std::fs::symlink_metadata(sidecar(&path, suffix)).is_err(),
            "{suffix} survived the close"
        );
    }
    path
}

#[test]
fn a_legacy_world_readable_database_is_private_before_sqlite_opens_it() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = world_readable_parent(directory.path());
    let path = closed_store(&parent);
    set_file_mode(&path, 0o644);
    let inode = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("metadata: {error}"))
        .ino();

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen legacy security state: {error}"));
    let observed = open_database_modes(&path);
    drop(store);

    assert_eq!(observed, PRIVATE_DATABASE);
    assert_eq!(
        std::fs::metadata(&path)
            .unwrap_or_else(|error| panic!("metadata: {error}"))
            .ino(),
        inode
    );
    assert_eq!(file_mode(&parent), FileMode(0o755));
}

#[test]
fn legacy_world_readable_sidecars_are_private_before_sqlite_opens_them() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = world_readable_parent(directory.path());
    let path = closed_store(&parent);
    // Non-empty, so SQLite's own empty-file mode fix-up does not apply.
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar(&path, suffix);
        std::fs::write(&sidecar, [0_u8; 4096]).unwrap_or_else(|error| panic!("{suffix}: {error}"));
        set_file_mode(&sidecar, 0o644);
    }

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open with legacy sidecars: {error}"));
    let observed = open_database_modes(&path);
    drop(store);

    assert_eq!(observed, PRIVATE_DATABASE);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SidecarAlias {
    Symlink,
    HardLink,
    Directory,
}

#[derive(Debug, Eq, PartialEq)]
struct SidecarOutcome {
    sidecar: &'static str,
    alias: SidecarAlias,
    open: Result<(), PortErrorKind>,
    victim_unchanged: bool,
    victim_mode: FileMode,
    alias_kept: bool,
}

#[test]
fn an_aliased_or_irregular_sidecar_is_refused_before_sqlite_opens_it() {
    let mut outcomes = Vec::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        for alias in [
            SidecarAlias::Symlink,
            SidecarAlias::HardLink,
            SidecarAlias::Directory,
        ] {
            let directory = chio_test_support::private_tempdir()
                .unwrap_or_else(|error| panic!("tempdir: {error}"));
            let path = closed_store(directory.path());
            let victim = directory.path().join("victim");
            std::fs::write(&victim, b"victim contents")
                .unwrap_or_else(|error| panic!("victim: {error}"));
            set_file_mode(&victim, 0o644);
            let sidecar = sidecar(&path, suffix);
            match alias {
                SidecarAlias::Symlink => std::os::unix::fs::symlink(&victim, &sidecar)
                    .unwrap_or_else(|error| panic!("symlink: {error}")),
                SidecarAlias::HardLink => std::fs::hard_link(&victim, &sidecar)
                    .unwrap_or_else(|error| panic!("hard link: {error}")),
                SidecarAlias::Directory => std::fs::create_dir(&sidecar)
                    .unwrap_or_else(|error| panic!("directory: {error}")),
            }

            let open = SqliteSecurityStateStore::open(&path)
                .map(drop)
                .map_err(|error| error.kind());
            outcomes.push(SidecarOutcome {
                sidecar: suffix,
                alias,
                open,
                victim_unchanged: std::fs::read(&victim).unwrap_or_default() == b"victim contents",
                victim_mode: file_mode(&victim),
                alias_kept: std::fs::symlink_metadata(&sidecar).is_ok(),
            });
        }
    }
    let expected: Vec<_> = outcomes
        .iter()
        .map(|outcome| SidecarOutcome {
            sidecar: outcome.sidecar,
            alias: outcome.alias,
            open: Err(PortErrorKind::InvalidData),
            victim_unchanged: true,
            victim_mode: FileMode(0o644),
            alias_kept: true,
        })
        .collect();
    assert_eq!(outcomes, expected);
}

#[test]
fn a_private_database_reopens_without_its_mode_or_identity_changing() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = closed_store(directory.path());
    let before = std::fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("reopen security state: {error}"));
    let observed = open_database_modes(&path);
    drop(store);

    let after = std::fs::metadata(&path).unwrap_or_else(|error| panic!("metadata: {error}"));
    assert_eq!(observed, PRIVATE_DATABASE);
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
}

#[test]
fn a_new_store_in_a_world_readable_parent_is_private_with_its_sidecars() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = world_readable_parent(directory.path());
    let path = parent.join("security.db");

    let store = SqliteSecurityStateStore::open(&path)
        .unwrap_or_else(|error| panic!("open security state: {error}"));
    let observed = open_database_modes(&path);
    drop(store);

    assert_eq!(observed, PRIVATE_DATABASE);
    assert_eq!(file_mode(&parent), FileMode(0o755));
}

#[test]
fn a_hard_linked_legacy_database_is_refused_without_repairing_the_alias() {
    let directory =
        chio_test_support::private_tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = world_readable_parent(directory.path());
    let path = closed_store(&parent);
    set_file_mode(&path, 0o644);
    let linked = parent.join("linked.db");
    std::fs::hard_link(&path, &linked).unwrap_or_else(|error| panic!("hard link: {error}"));

    assert_eq!(
        SqliteSecurityStateStore::open(&linked)
            .map(drop)
            .map_err(|error| error.kind()),
        Err(PortErrorKind::InvalidData)
    );
    assert_eq!(file_mode(&path), FileMode(0o644));
}
