use super::*;

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "filesystem".into(),
            tool_name: "read_file".into(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    }
}

#[test]
fn aggregate_issuance_retains_policy_refusals() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let receipt_db = directory.path().join("receipts.db");
    let subject = Keypair::generate().public_key();
    for (reputation, assurance) in [
        (Some(test_policy()), None),
        (None, Some(test_runtime_assurance_policy())),
    ] {
        let authority = wrap_capability_authority(
            Box::new(chio_kernel::LocalCapabilityAuthority::new(
                Keypair::generate(),
            )),
            reputation,
            assurance,
            Some(&receipt_db),
            None,
        );
        assert!(matches!(
            authority.issue_aggregate_family_root(&subject, scope(), 300, 2),
            Err(KernelError::CapabilityIssuanceDenied(_))
        ));
    }
    Ok(())
}

#[test]
fn aggregate_issuance_persists_the_actual_signed_family_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let receipt_db = directory.path().join("receipts.db");
    let key = Keypair::generate();
    let subject = Keypair::generate().public_key();
    let authority = wrap_capability_authority(
        Box::new(chio_kernel::LocalCapabilityAuthority::new(key.clone())),
        None,
        None,
        Some(&receipt_db),
        None,
    );
    let scope = scope();
    let root = authority.issue_aggregate_family_root(&subject, scope.clone(), 300, 2)?;
    chio_kernel::authority::validate_issued_aggregate_family_root_response(
        &root,
        &subject,
        &scope,
        300,
        &key.public_key(),
        2,
    )?;
    let stored = SqliteReceiptStore::open(&receipt_db)?
        .get_capability_snapshot(&root.id)?
        .ok_or("missing root snapshot")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&stored.signed_capability.ok_or("missing signed token")?)?,
        chio_core::canonical_json_bytes(&root)?
    );
    Ok(())
}

#[test]
fn legacy_authority_cannot_fall_back_to_an_unbudgeted_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Keypair::generate();
    let subject = Keypair::generate().public_key();
    let plain = chio_kernel::LocalCapabilityAuthority::new(key.clone()).issue_capability(
        &subject,
        scope(),
        300,
    )?;
    let authority = wrap_capability_authority(
        Box::new(FixedResponseAuthority {
            response: plain,
            current_issuer: key.public_key(),
            trusted_issuers: vec![key.public_key()],
        }),
        None,
        None,
        None,
        None,
    );
    assert!(authority
        .issue_aggregate_family_root(&subject, scope(), 300, 2)
        .is_err());
    Ok(())
}
