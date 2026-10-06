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
