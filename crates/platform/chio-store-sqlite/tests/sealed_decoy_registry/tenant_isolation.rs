use super::*;

#[test]
fn exact_decoy_tokens_never_grant_cross_tenant_reads_after_restart() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = database(&directory, "exact-tenant-decoys");
    let store = open(&path);
    let owned = tenant("tenant-a");
    let foreign = tenant("tenant-b");
    let artifact = record(&owned, 1, DecoySurface::BrowserCookie, 2, 3, 0, (4, 5));
    let write = request(artifact.clone(), None, 8, 9);
    store.compare_and_swap(&write).test_unwrap();
    let check = |store: &SqliteSealedDecoyRegistryStore| {
        assert_eq!(
            store
                .load_by_id(&DecoyArtifactLookup {
                    tenant_id: owned.clone(),
                    artifact_token: token(1),
                })
                .test_unwrap(),
            Some(artifact.clone())
        );
        assert_eq!(
            store
                .load_by_id(&DecoyArtifactLookup {
                    tenant_id: foreign.clone(),
                    artifact_token: token(1),
                })
                .test_unwrap(),
            None
        );
        assert_eq!(
            store
                .load_by_marker(&SealedMarkerLookup {
                    tenant_id: owned.clone(),
                    surface: DecoySurface::BrowserCookie,
                    marker_token: token(2),
                })
                .test_unwrap(),
            Some(artifact.clone())
        );
        assert_eq!(
            store
                .load_by_marker(&SealedMarkerLookup {
                    tenant_id: foreign.clone(),
                    surface: DecoySurface::BrowserCookie,
                    marker_token: token(2),
                })
                .test_unwrap(),
            None
        );
        assert!(store
            .scan(&DecoyScan {
                tenant_id: foreign.clone(),
                after_artifact_token: None,
                limit: 10
            })
            .test_unwrap()
            .records
            .is_empty());
        assert_eq!(
            store.compare_and_swap(&write).test_unwrap(),
            artifact.clone()
        );
    };
    check(&store);
    drop(store);
    check(&open(&path));
}
