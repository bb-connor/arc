use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt as _;

use chio_test_support::prelude::*;

use super::bind_private_unix_listener_with;
use crate::KeyringError;

#[test]
fn a_service_socket_directory_replaced_before_bind_is_detected() {
    let directory = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .test_unwrap();
    let root = std::fs::canonicalize(directory.path()).test_unwrap();
    let run = root.join("run");
    std::fs::create_dir(&run).test_unwrap();
    std::fs::set_permissions(&run, Permissions::from_mode(0o700)).test_unwrap();
    let displaced = root.join("run.displaced");

    let result = bind_private_unix_listener_with(&run.join("witness.sock"), || {
        std::fs::rename(&run, &displaced)?;
        std::fs::create_dir(&run)?;
        std::fs::set_permissions(&run, Permissions::from_mode(0o700))
    })
    .map(drop);
    assert!(
        matches!(result, Err(KeyringError::StateInvariant(_))),
        "{result:?}"
    );
}
