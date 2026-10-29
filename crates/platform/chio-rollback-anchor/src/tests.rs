use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn secure_root(path: &Path) {
    assert!(fs::set_permissions(path, fs::Permissions::from_mode(0o700)).is_ok());
}

fn counter(generation: u64) -> StoreHead {
    StoreHead::counter_only(generation)
}

fn open_anchor(scope: &[u8]) -> (tempfile::TempDir, RollbackGenerationAnchor) {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    match RollbackGenerationAnchor::open(root.path(), scope) {
        Ok(anchor) => (root, anchor),
        Err(error) => panic!("open anchor: {error}"),
    }
}

#[test]
fn independent_anchors_receive_distinct_global_instance_ids() {
    let Ok(first_root) = tempfile::tempdir() else {
        panic!("create first anchor root");
    };
    let Ok(second_root) = tempfile::tempdir() else {
        panic!("create second anchor root");
    };
    secure_root(first_root.path());
    secure_root(second_root.path());
    let first = match RollbackGenerationAnchor::open(first_root.path(), b"shared-scope") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open first anchor: {error}"),
    };
    let second = match RollbackGenerationAnchor::open(second_root.path(), b"shared-scope") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open second anchor: {error}"),
    };
    assert!(first.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    assert!(second.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    let Ok(first_id) = first.instance_id() else {
        panic!("load first anchor id");
    };
    let Ok(second_id) = second.instance_id() else {
        panic!("load second anchor id");
    };
    assert_ne!(first_id, second_id);
}

#[test]
fn prepared_initial_generation_recovers_only_for_an_empty_store() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"prepared-initial") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    let instance_id = uuid::Uuid::now_v7().to_string();
    let Ok(prepared) = anchor.prepare_next(0, &counter(0), &instance_id) else {
        panic!("prepare initial generation");
    };
    drop(anchor);

    let reopened = match RollbackGenerationAnchor::open(root.path(), b"prepared-initial") {
        Ok(anchor) => anchor,
        Err(error) => panic!("reopen anchor: {error}"),
    };
    assert!(reopened
        .bind_initial_while(|| Ok((counter(0), false)))
        .is_err());
    assert!(reopened
        .bind_initial_while(|| Ok((counter(1), false)))
        .is_err());
    assert!(reopened
        .bind_initial_while(|| Ok((counter(0), true)))
        .is_ok());
    assert_eq!(reopened.instance_id().as_deref(), Ok(instance_id.as_str()));
    let Ok(Some(loaded)) = reopened.load_record() else {
        panic!("load recovered initial generation");
    };
    assert_eq!(loaded.record, prepared);
    assert!(!loaded.corrupt_slot);
    assert!(!loaded.interrupted_slot);
}

#[test]
fn marker_cleared_inactive_slot_recovers_from_surviving_generation() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"interrupted-rewrite") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    let mut store_generation = 0;
    assert!(anchor
        .advance_while(&counter(0), &counter(1), || {
            store_generation = 1;
            Ok(())
        })
        .is_ok());

    assert!(write_all_at(&anchor.file, &[0_u8; COMMIT_MARKER.len()], 0).is_ok());
    assert!(anchor.file.sync_data().is_ok());
    assert!(anchor.verify(&counter(store_generation)).is_ok());
    assert!(anchor
        .advance_while(&counter(1), &counter(2), || {
            store_generation = 2;
            Ok(())
        })
        .is_ok());
    assert!(anchor.verify(&counter(store_generation)).is_ok());
}

#[test]
fn prepared_generation_recovers_after_the_store_commit() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"prepared-store-commit") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    let Ok(instance_id) = anchor.instance_id() else {
        panic!("load anchor instance id");
    };
    assert!(anchor.prepare_next(1, &counter(1), &instance_id).is_ok());

    assert!(anchor.verify(&counter(1)).is_ok());
    let Ok(loaded) = anchor.load_record() else {
        panic!("load recovered anchor");
    };
    let Some(loaded) = loaded else {
        panic!("recovered anchor is absent");
    };
    assert_eq!(loaded.record.store_generation, 1);
    assert!(!loaded.interrupted_slot);
}

#[test]
fn torn_commit_marker_recovers_after_the_store_commit() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"torn-commit-marker") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    let Ok(instance_id) = anchor.instance_id() else {
        panic!("load anchor instance id");
    };
    let Ok(prepared) = anchor.prepare_next(1, &counter(1), &instance_id) else {
        panic!("prepare next generation");
    };
    let slot_index = match usize::try_from((prepared.record_generation - 1) % 2) {
        Ok(index) => index,
        Err(_) => panic!("prepared slot index fits usize"),
    };
    let offset = slot_index * SLOT_SIZE;
    assert!(write_all_at(&anchor.file, &COMMIT_MARKER[..4], offset).is_ok());
    assert!(anchor.file.sync_data().is_ok());

    assert!(anchor.verify(&counter(1)).is_ok());
    let Ok(Some(loaded)) = anchor.load_record() else {
        panic!("load recovered torn-marker anchor");
    };
    assert_eq!(loaded.record, prepared);
    assert!(!loaded.corrupt_slot);
    assert!(!loaded.interrupted_slot);
    let mut committed_marker = [0_u8; COMMIT_MARKER.len()];
    assert!(read_exact_at(&anchor.file, &mut committed_marker, offset).is_ok());
    assert_eq!(&committed_marker, COMMIT_MARKER);
}

#[test]
fn malformed_marker_without_a_valid_prepared_record_remains_corrupt() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"corrupt-marker") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    assert!(write_all_at(&anchor.file, b"CORRUPT!", SLOT_SIZE).is_ok());
    assert!(anchor.file.sync_data().is_ok());

    assert_eq!(
        anchor.verify(&counter(0)),
        Err("rollback anchor contains a corrupt slot".to_string())
    );
}

#[test]
fn failed_store_commit_leaves_the_prior_generation_usable() {
    let Ok(root) = tempfile::tempdir() else {
        panic!("create anchor root");
    };
    secure_root(root.path());
    let anchor = match RollbackGenerationAnchor::open(root.path(), b"failed-store-commit") {
        Ok(anchor) => anchor,
        Err(error) => panic!("open anchor: {error}"),
    };
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    assert!(anchor
        .advance_while(&counter(0), &counter(1), || Err(
            "injected SQLite commit failure".to_string()
        ))
        .is_err());
    assert!(anchor.verify(&counter(0)).is_ok());
    assert!(anchor
        .advance_while(&counter(0), &counter(1), || Ok(()))
        .is_ok());
    assert!(anchor.verify(&counter(1)).is_ok());
}

#[test]
fn chained_anchor_refuses_an_equal_generation_fork() {
    let (_root, anchor) = open_anchor(b"chained-fork");
    let genesis = StoreHead::chained(0, "0".repeat(64));
    let live = StoreHead::chained(1, "a".repeat(64));
    let fork = StoreHead::chained(1, "f".repeat(64));
    assert!(anchor
        .bind_initial_while(|| Ok((genesis.clone(), true)))
        .is_ok());
    assert!(anchor.advance_while(&genesis, &live, || Ok(())).is_ok());
    assert!(anchor.verify(&live).is_ok());
    assert_eq!(
        anchor.verify(&fork),
        Err("store does not match its protected rollback generation".to_string())
    );
    assert!(anchor
        .advance_while(&fork, &StoreHead::chained(2, "b".repeat(64)), || Ok(()))
        .is_err());
    assert!(anchor.verify(&live).is_ok());
}

#[test]
fn anchor_refuses_a_head_binding_change() {
    let (_root, anchor) = open_anchor(b"binding-change");
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    assert!(anchor
        .advance_while(&counter(0), &counter(1), || Ok(()))
        .is_ok());
    assert!(anchor
        .verify(&StoreHead::chained(1, "a".repeat(64)))
        .is_err());
    assert!(anchor
        .advance_while(&counter(1), &StoreHead::chained(2, "a".repeat(64)), || Ok(
            ()
        ))
        .is_err());
    assert!(anchor.verify(&counter(1)).is_ok());
}

#[test]
fn slot_without_a_store_head_is_corrupt() {
    #[derive(Serialize)]
    struct UnboundRecord {
        anchor_instance_id: String,
        format: String,
        record_generation: u64,
        scope_sha256: String,
        store_generation: u64,
    }

    let (_root, anchor) = open_anchor(b"unbound-layout");
    assert!(anchor.bind_initial_while(|| Ok((counter(0), true))).is_ok());
    let Ok(instance_id) = anchor.instance_id() else {
        panic!("load anchor instance id");
    };
    let Ok(payload) = canonical_json_bytes(&UnboundRecord {
        anchor_instance_id: instance_id,
        format: "chio.sqlite-rollback-generation.v1".to_string(),
        record_generation: 2,
        scope_sha256: sha256_hex(b"unbound-layout"),
        store_generation: 1,
    }) else {
        panic!("encode unbound record");
    };
    let Ok(payload_len) = u32::try_from(payload.len()) else {
        panic!("payload length fits u32");
    };
    let mut slot = [0_u8; SLOT_SIZE];
    slot[..COMMIT_MARKER.len()].copy_from_slice(COMMIT_MARKER);
    slot[LENGTH_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&payload_len.to_be_bytes());
    slot[CHECKSUM_OFFSET..PAYLOAD_OFFSET].copy_from_slice(sha256_hex(&payload).as_bytes());
    slot[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
    assert!(write_all_at(&anchor.file, &slot, SLOT_SIZE).is_ok());
    assert!(anchor.file.sync_data().is_ok());

    assert_eq!(
        anchor.verify(&counter(1)),
        Err("rollback anchor contains a corrupt slot".to_string())
    );
}
