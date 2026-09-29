use super::*;


#[test]
fn periodic_compaction_is_bounded_and_paginates_from_the_last_compacted_key() {
    let first_tenant = TenantId::new("tenant-compaction-a")
        .unwrap_or_else(|error| panic!("first compaction tenant: {error}"));
    let first_grant = GrantId::new("grant-compaction-a")
        .unwrap_or_else(|error| panic!("first compaction grant: {error}"));
    let second_tenant = TenantId::new("tenant-compaction-b")
        .unwrap_or_else(|error| panic!("second compaction tenant: {error}"));
    let second_grant = GrantId::new("grant-compaction-b")
        .unwrap_or_else(|error| panic!("second compaction grant: {error}"));
    let scripted = Arc::new(
        ScriptedDeclassificationOutboxPort::new(
            0,
            0,
            Vec::new(),
            vec![
                Ok(DeclassificationReceiptDrainReport::default()),
                Ok(DeclassificationReceiptDrainReport::default()),
            ],
        )
        .with_compactions(vec![
            Ok(DeclassificationCompactionReport {
                compacted: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                last_tenant_id: Some(first_tenant.clone()),
                last_grant_id: Some(first_grant.clone()),
            }),
            Ok(DeclassificationCompactionReport {
                compacted: 1,
                last_tenant_id: Some(second_tenant),
                last_grant_id: Some(second_grant),
            }),
        ]),
    );
    let port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(port);

    let (_, first) = outbox
        .maintain_one_batch()
        .unwrap_or_else(|error| panic!("first maintenance page: {error}"));
    let (_, second) = outbox
        .maintain_one_batch()
        .unwrap_or_else(|error| panic!("second maintenance page: {error}"));

    assert_eq!(first.compacted, MAX_DECLASSIFICATION_EVIDENCE_BATCH);
    assert_eq!(second.compacted, 1);
    assert_eq!(
        scripted.requested_compactions(),
        vec![
            (None, None, MAX_DECLASSIFICATION_EVIDENCE_BATCH),
            (
                Some(first_tenant),
                Some(first_grant),
                MAX_DECLASSIFICATION_EVIDENCE_BATCH,
            ),
        ]
    );
}
