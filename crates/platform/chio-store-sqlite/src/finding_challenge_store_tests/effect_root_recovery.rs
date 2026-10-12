#[test]
fn anchor_binding_reconciliation_is_exact_and_idempotent() {
    let fixture = fixture();
    let head = Liability::new("anchor-binding", LISTING_ID, &fixture.allocation_id);
    open_liability(&fixture, &head);
    let intent_key = digest("anchor-intent");
    let intent_digest = digest("anchor-commitment");
    let merkle_root = chain_hash("anchor-root");
    let evidence_hash = chain_hash("anchor-evidence");
    fixture
        .store
        .record_effect_intent(
            &intent_key,
            FindingEffectIntentKind::RootIntent,
            &intent_digest,
            Some(&head.liability_key),
            false,
            NOW,
        )
        .expect("record anchor intent");

    assert_eq!(
        fixture
            .store
            .reconcile_anchor_effect_root_binding(
                &intent_key,
                &head.liability_key,
                &intent_digest,
                &merkle_root,
                &evidence_hash,
                NOW + 1,
            )
            .expect("reconstruct exact binding"),
        FindingChallengeWriteOutcome::Inserted
    );
    fixture
        .store
        .advance_effect_intent(
            &intent_key,
            FindingEffectIntentState::Dispatched,
            NOW + 2,
        )
        .expect("dispatch reconstructed anchor");
    fixture
        .store
        .confirm_effect_root(&intent_key, &merkle_root, &evidence_hash, NOW + 3)
        .expect("confirm reconstructed anchor");
    assert_eq!(
        fixture
            .store
            .reconcile_anchor_effect_root_binding(
                &intent_key,
                &head.liability_key,
                &intent_digest,
                &merkle_root,
                &evidence_hash,
                NOW + 4,
            )
            .expect("replay exact recovered binding"),
        FindingChallengeWriteOutcome::ExistingSame
    );
    assert!(matches!(
        fixture.store.reconcile_anchor_effect_root_binding(
            &intent_key,
            &head.liability_key,
            &digest("different-anchor-commitment"),
            &merkle_root,
            &evidence_hash,
            NOW + 5,
        ),
        Err(FindingChallengeStoreError::Conflict(_))
    ));
}
