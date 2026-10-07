//! Offline enrollment for test clusters with separate signing custody.

use std::path::Path;

use chio_core::crypto::Keypair;
use chio_store_sqlite::SqliteCapabilityAuthority;
use chio_test_support::ctx::TestUnwrap;

pub(super) fn enroll_authorities(directory: &Path, source: &str, followers: &[&str]) -> Keypair {
    let source =
        SqliteCapabilityAuthority::open(directory.join(format!("authority-{source}.sqlite3")))
            .test_unwrap("open signing custodian");
    let recovery = Keypair::generate();
    let stream = format!(
        "test-cluster-{}",
        source
            .local_keypair()
            .test_unwrap("read local signer")
            .public_key()
            .to_hex()
    );
    let anchor = source
        .initialize_replication_with_recovery(&stream, Some(&recovery.public_key()))
        .test_unwrap("provision replication and independent recovery root");
    let envelope = source
        .signed_snapshot()
        .test_unwrap("export initial authenticated envelope");
    for follower in followers {
        let follower = SqliteCapabilityAuthority::open(
            directory.join(format!("authority-{follower}.sqlite3")),
        )
        .test_unwrap("open replica custody");
        follower
            .pin_replication_anchor(&anchor)
            .test_unwrap("pin the public anchor offline");
        follower
            .apply_signed_snapshot(&envelope)
            .test_unwrap("seed relay with an authenticated envelope");
    }
    recovery
}

pub(super) fn enroll_two_nodes(directory: &Path, url_a: &str, url_b: &str) -> Keypair {
    let (source, follower) = if url_a < url_b {
        ("a", "b")
    } else {
        ("b", "a")
    };
    enroll_authorities(directory, source, &[follower])
}
