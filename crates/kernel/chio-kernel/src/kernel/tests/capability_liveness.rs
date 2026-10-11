use super::*;
use chio_core::canonical::canonical_json_bytes;

#[test]
fn retained_capability_liveness_revalidates_signed_subject_time_and_current_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = current_unix_timestamp();
    let issuer = make_keypair();
    let subject = make_keypair().public_key();
    let mut config = make_config();
    config.keypair = issuer.clone();
    let mut kernel = make_kernel(config);
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "retained-liveness-parent".into(),
            issuer: issuer.public_key(),
            subject: subject.clone(),
            scope: make_scope(vec![make_grant("srv-a", "read_file")]),
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(300),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &subject)
        .is_err());
    let path = unique_receipt_db_path("chio-retained-liveness");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    store.record_capability_snapshot(&token, None)?;
    kernel.set_receipt_store_handle(store.clone())?;
    assert_eq!(
        canonical_json_bytes(&kernel.verify_retained_capability_liveness(&token.id, &subject)?)?,
        canonical_json_bytes(&token)?
    );
    assert!(kernel
        .verify_retained_capability_liveness("absent", &subject)
        .is_err());
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &make_keypair().public_key())
        .is_err());
    for mutation in [
        "UPDATE capability_lineage SET signed_capability_json = NULL",
        "UPDATE capability_lineage SET subject_key = 'substituted'",
        "UPDATE capability_lineage SET expires_at = expires_at + 1",
    ] {
        store.connection()?.execute(mutation, [])?;
        assert!(
            kernel
                .verify_retained_capability_liveness(&token.id, &subject)
                .is_err(),
            "{mutation}"
        );
        store.record_capability_snapshot(&token, None)?;
    }
    let mut expired = token.body();
    expired.issued_at = now.saturating_sub(200);
    expired.expires_at = now.saturating_sub(100);
    store.record_capability_snapshot(&CapabilityToken::sign(expired, &issuer)?, None)?;
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &subject)
        .is_err());
    let foreign = make_keypair();
    let mut untrusted = token.body();
    untrusted.issuer = foreign.public_key();
    store.record_capability_snapshot(&CapabilityToken::sign(untrusted, &foreign)?, None)?;
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &subject)
        .is_err());
    store.record_capability_snapshot(&token, None)?;
    kernel.set_capability_crypto_floor(KernelCryptoFloor::PqRequired);
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &subject)
        .is_err());
    kernel.set_capability_crypto_floor(KernelCryptoFloor::AllowClassical);
    assert_eq!(
        canonical_json_bytes(&kernel.verify_retained_capability_liveness(&token.id, &subject)?)?,
        canonical_json_bytes(&token)?
    );
    kernel.with_revocation_store(|revocations| Ok(revocations.revoke(&token.id)?))?;
    assert!(kernel
        .verify_retained_capability_liveness(&token.id, &subject)
        .is_err());
    Ok(())
}

#[test]
fn retained_capability_liveness_rejects_revoked_delegation_ancestors(
) -> Result<(), Box<dyn std::error::Error>> {
    let now = current_unix_timestamp();
    let issuer = make_keypair();
    let parent_subject = make_keypair();
    let child_subject = make_keypair().public_key();
    let mut config = make_config();
    config.keypair = issuer.clone();
    let mut kernel = make_kernel(config);
    let mut grant = make_grant("srv-a", "read_file");
    grant.operations.push(Operation::Delegate);
    let root = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "retained-liveness-root".into(),
            issuer: issuer.public_key(),
            subject: parent_subject.public_key(),
            scope: make_scope(vec![grant]),
            issued_at: now.saturating_sub(1),
            expires_at: now.saturating_add(300),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = chio_core::capability::attenuation::delegate(
        &root,
        &scope,
        &parent_subject,
        &child_subject,
        chio_core_types::ScopeAttenuation::empty(),
        now,
        [21; 16],
    )?;
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "retained-liveness-child".into(),
            issuer: issuer.public_key(),
            subject: child_subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(200),
            delegation_chain: link.complete_chain(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let store = Arc::new(SqliteReceiptStore::open(unique_receipt_db_path(
        "chio-retained-liveness-ancestor",
    ))?);
    store.record_capability_snapshot(&root, None)?;
    store.record_capability_snapshot(&child, Some(&root.id))?;
    kernel.set_receipt_store_handle(store)?;
    set_capability_trust_root_for_scope(&kernel, &root.scope);
    assert_eq!(
        canonical_json_bytes(
            &kernel.verify_retained_capability_liveness(&child.id, &child_subject)?
        )?,
        canonical_json_bytes(&child)?
    );
    kernel.with_revocation_store(|revocations| Ok(revocations.revoke(&root.id)?))?;
    assert!(kernel
        .verify_retained_capability_liveness(&child.id, &child_subject)
        .is_err());
    Ok(())
}
