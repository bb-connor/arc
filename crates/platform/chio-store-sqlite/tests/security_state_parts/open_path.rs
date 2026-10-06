use std::collections::BTreeSet;
use std::path::Path;

use chio_store_sqlite::SqliteSecurityStateStore;
use tempfile::tempdir;

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
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
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
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
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
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
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
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let shared = directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap_or_else(|error| panic!("shared: {error}"));
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777))
        .unwrap_or_else(|error| panic!("chmod: {error}"));
    assert!(SqliteSecurityStateStore::open(shared.join("security.db")).is_err());
    assert!(entries(&shared).is_empty());
}

#[test]
fn a_group_writable_parent_owned_by_the_user_is_accepted() {
    use std::os::unix::fs::PermissionsExt;

    // A umask of 002 with user-private groups creates directories like this.
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let parent = directory.path().join("group-writable");
    std::fs::create_dir(&parent).unwrap_or_else(|error| panic!("parent: {error}"));
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o775))
        .unwrap_or_else(|error| panic!("chmod: {error}"));
    drop(
        SqliteSecurityStateStore::open(parent.join("security.db"))
            .unwrap_or_else(|error| panic!("open security state: {error}")),
    );
}
