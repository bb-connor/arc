#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use chio_secret_broker::daemon_runtime::secure_inherited_key_file;
use chio_test_support::prelude::*;
use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
use rustix::io::{fcntl_getfd, fcntl_setfd, FdFlags};

fn inherited_sealed_seed() -> File {
    let descriptor =
        memfd_create("broker-inherited-fd-custody", MemfdFlags::ALLOW_SEALING).test_expect("memfd");
    let mut file = File::from(descriptor);
    file.write_all(&[91; 32]).test_expect("write seed");
    file.seek(SeekFrom::Start(0)).test_expect("rewind seed");
    fcntl_add_seals(
        &file,
        SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE,
    )
    .test_expect("seal seed");
    fcntl_setfd(&file, FdFlags::empty()).test_expect("make descriptor inheritable");
    file
}

#[test]
fn secure_inherited_key_file_owns_the_original_descriptor_and_closes_it_on_drop() {
    let inherited = inherited_sealed_seed();
    let raw_fd = inherited.as_raw_fd();
    let inherited_path = PathBuf::from(format!("/proc/self/fd/{raw_fd}"));
    assert!(inherited_path.exists(), "fixture descriptor must be open");

    let adopted =
        secure_inherited_key_file(inherited, "test key").test_expect("secure inherited descriptor");
    assert!(
        fcntl_getfd(&adopted)
            .test_expect("read adopted descriptor flags")
            .contains(FdFlags::CLOEXEC),
        "the broker-owned descriptor must not survive a later exec"
    );

    drop(adopted);

    assert!(
        !inherited_path.exists(),
        "dropping the broker-owned key must close the inherited descriptor itself, not only a /proc duplicate"
    );
}
