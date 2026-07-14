use super::*;

#[test]
fn partial_provision_fails_closed() {
    let (_temp, database, lock_root) = fixture();
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o500))
        .expect("make lock root read only");
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
        .expect("restore lock root mode");

    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(SqliteBudgetStore::open(&database).is_err());
    assert!(SqliteRevocationStore::open(&database).is_err());
}
