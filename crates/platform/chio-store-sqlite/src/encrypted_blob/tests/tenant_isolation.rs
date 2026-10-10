use super::*;

#[test]
fn exact_blob_ids_and_mutation_replays_cannot_cross_tenants_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("tenant-blobs.sqlite");
    let tenant = TenantId::new("tenant-a");
    let foreign = TenantId::new("tenant-b");
    let key = TenantKey::from_bytes([9; 32]);
    let reference = BlobReference::new("signed-test", tenant, [7; 32]).unwrap();
    let foreign_reference = BlobReference::new("signed-test", foreign.clone(), [7; 32]).unwrap();
    let operation = "11".repeat(32);
    let digest = "22".repeat(32);
    let store = SqliteEncryptedBlobStore::open(&path).unwrap();
    let (handle, _) = store
        .write_encrypted_blob_with_reference_once(&reference, &key, b"private", &operation, &digest)
        .unwrap();
    let check = |store: &SqliteEncryptedBlobStore| {
        assert_eq!(
            store.read_encrypted_blob(&handle, &key).unwrap(),
            b"private"
        );
        assert_eq!(store.resolve_blob_reference(&reference).unwrap(), handle);
        let foreign_handle = BlobHandle::new(handle.blob_id().to_owned(), foreign.clone());
        assert!(matches!(
            store.read_encrypted_blob(&foreign_handle, &key),
            Err(BlobStoreError::NotFound)
        ));
        assert!(matches!(
            store.resolve_blob_reference(&foreign_reference),
            Err(BlobStoreError::NotFound)
        ));
        assert!(matches!(
            store.write_encrypted_blob_with_reference_once(
                &foreign_reference,
                &key,
                b"private",
                &operation,
                &digest,
            ),
            Err(BlobStoreError::MutationConflict)
        ));
        assert_eq!(
            store
                .write_encrypted_blob_with_reference_once(
                    &reference, &key, b"private", &operation, &digest,
                )
                .unwrap()
                .1,
            BlobReferenceMutationOutcome::Replayed
        );
    };
    check(&store);
    drop(store);
    check(&SqliteEncryptedBlobStore::open(&path).unwrap());
}
