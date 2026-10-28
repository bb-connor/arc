use super::*;
use chio_test_support::prelude::*;

#[test]
fn broker_lifecycle_lock_releases_on_drop_while_a_duplicate_descriptor_stays_open() {
    let directory = crate::private_tempdir().test_expect("IPC directory");
    let socket_path = directory.path().join("broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let held = acquire_broker_socket_lifecycle_lock(&socket_path, uid)
        .test_expect("acquire lifecycle lock");
    let inherited = held
        .file()
        .try_clone()
        .test_expect("duplicate lock descriptor");
    assert!(matches!(
        acquire_broker_socket_lifecycle_lock(&socket_path, uid),
        Err(BrokerError::AuthorityUnavailable(_))
    ));

    drop(held);

    let reacquired = acquire_broker_socket_lifecycle_lock(&socket_path, uid)
        .test_expect("released lock is reacquired while the duplicate stays open");
    drop(reacquired);
    drop(inherited);
}
