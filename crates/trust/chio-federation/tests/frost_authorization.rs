use chio_federation::frost::{
    frost_action_registration, registered_frost_actions, FrostActionPreimageV1,
    FrostAuthorizationBodyV1, FrostAuthorizationDomain, FrostAuthorizationError,
    FrostSettleCommitmentActionV1, CHIO_FROST_AUTHORIZATION_BODY_SCHEMA,
    CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA,
};

fn authorization_body() -> FrostAuthorizationBodyV1 {
    let registration = frost_action_registration(FrostAuthorizationDomain::SettleCommitment)
        .unwrap_or_else(|| panic!("settlement authorization domain must be registered"));
    let mut body = FrostAuthorizationBodyV1 {
        schema: CHIO_FROST_AUTHORIZATION_BODY_SCHEMA.to_string(),
        authorization_id: String::new(),
        domain: registration.domain,
        ladder_action_class: registration.ladder_action_class.to_string(),
        ladder_contract_digest: registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("registered ladder entry must canonicalize: {error}")),
        quorum_n: registration.quorum_n,
        quorum_m: registration.quorum_m,
        quorum_scope: registration.quorum_scope.to_string(),
        scope_id: "treaty.atlantic.v1".to_string(),
        resource_id: "settlement.set-974".to_string(),
        resource_version: 7,
        resource_fence: 11,
        action_digest: "22".repeat(32),
        roster_digest: "33".repeat(32),
        key_epoch: 5,
        issued_at: 1_752_000_000,
        expires_at: 1_752_000_300,
    };
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("sample authorization body must canonicalize: {error}"));
    body
}

#[test]
fn action_registry_is_closed_and_covers_every_current_n_of_m_class() {
    let mappings = registered_frost_actions()
        .iter()
        .map(|registration| {
            (
                registration.domain,
                registration.ladder_action_class,
                registration.quorum_n,
                registration.quorum_m,
                registration.quorum_scope,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        mappings,
        vec![
            (
                FrostAuthorizationDomain::SettleCommitment,
                "settle.commitment",
                2,
                3,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::ClearingRoundFinalize,
                "clearing.round_finalize",
                2,
                3,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::ChannelClose,
                "channel.close",
                2,
                3,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::PouncerRevokeCredential,
                "pouncer.revoke_credential",
                2,
                3,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::GovernanceCaseEnforceSanction,
                "governance.case_enforce_sanction",
                3,
                5,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::CredentialsPassportRevoke,
                "credentials.passport_revoke",
                2,
                3,
                "treaty",
            ),
            (
                FrostAuthorizationDomain::RosterRotate,
                "governance.roster_rotate",
                3,
                5,
                "treaty",
            ),
        ]
    );
    assert!(
        frost_action_registration(FrostAuthorizationDomain::AdjudicationPanelDecision).is_none(),
        "the WS7 panel domain must remain disabled until its ladder contract is registered"
    );
    for registration in registered_frost_actions() {
        let digest = registration
            .ladder_contract_digest()
            .unwrap_or_else(|error| panic!("registered ladder entry must canonicalize: {error}"));
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn authorization_id_and_signing_bytes_bind_the_complete_execution_slot() {
    let body = authorization_body();
    let expected_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("authorization id must recompute: {error}"));
    assert_eq!(body.authorization_id, expected_id);
    body.validate()
        .unwrap_or_else(|error| panic!("sample authorization body must validate: {error}"));

    let signing_bytes = body
        .signing_bytes()
        .unwrap_or_else(|error| panic!("authorization body must canonicalize: {error}"));

    let mut changed_domain = body.clone();
    changed_domain.domain = FrostAuthorizationDomain::ClearingRoundFinalize;
    let clearing_registration =
        frost_action_registration(FrostAuthorizationDomain::ClearingRoundFinalize)
            .unwrap_or_else(|| panic!("clearing authorization domain must be registered"));
    changed_domain.ladder_action_class = clearing_registration.ladder_action_class.to_string();
    changed_domain.ladder_contract_digest = clearing_registration
        .ladder_contract_digest()
        .unwrap_or_else(|error| panic!("registered ladder entry must canonicalize: {error}"));
    changed_domain.authorization_id = changed_domain
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed domain must canonicalize: {error}"));
    assert_ne!(
        signing_bytes,
        changed_domain
            .signing_bytes()
            .unwrap_or_else(|error| panic!("changed domain must canonicalize: {error}"))
    );

    let mut changed_action = body.clone();
    changed_action.action_digest = "44".repeat(32);
    changed_action.authorization_id = changed_action
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed action digest must canonicalize: {error}"));
    assert_ne!(
        signing_bytes,
        changed_action
            .signing_bytes()
            .unwrap_or_else(|error| panic!("changed action digest must canonicalize: {error}"))
    );

    let mut changed_version = body.clone();
    changed_version.resource_version += 1;
    changed_version.authorization_id = changed_version
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed resource version must canonicalize: {error}"));
    assert_ne!(
        signing_bytes,
        changed_version
            .signing_bytes()
            .unwrap_or_else(|error| panic!("changed resource version must canonicalize: {error}"))
    );

    let mut changed_fence = body.clone();
    changed_fence.resource_fence += 1;
    changed_fence.authorization_id = changed_fence
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed resource fence must canonicalize: {error}"));
    assert_ne!(
        signing_bytes,
        changed_fence
            .signing_bytes()
            .unwrap_or_else(|error| panic!("changed resource fence must canonicalize: {error}"))
    );
}

#[test]
fn validation_rejects_contract_drift_and_a_stale_stored_id() {
    let body = authorization_body();

    let mut wrong_class = body.clone();
    wrong_class.ladder_action_class = "channel.close".to_string();
    wrong_class.authorization_id = wrong_class
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        wrong_class.validate(),
        Err(FrostAuthorizationError::ContractMismatch(
            "domain and ladder_action_class"
        ))
    );

    let mut wrong_quorum = body.clone();
    wrong_quorum.quorum_n = 3;
    wrong_quorum.authorization_id = wrong_quorum
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        wrong_quorum.validate(),
        Err(FrostAuthorizationError::ContractMismatch(
            "registered quorum"
        ))
    );

    let mut wrong_ladder_digest = body.clone();
    wrong_ladder_digest.ladder_contract_digest = "77".repeat(32);
    wrong_ladder_digest.authorization_id = wrong_ladder_digest
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        wrong_ladder_digest.validate(),
        Err(FrostAuthorizationError::ContractMismatch(
            "ladder_contract_digest"
        ))
    );

    let mut disabled = body.clone();
    disabled.domain = FrostAuthorizationDomain::AdjudicationPanelDecision;
    disabled.authorization_id = disabled
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        disabled.validate(),
        Err(FrostAuthorizationError::DisabledDomain(
            FrostAuthorizationDomain::AdjudicationPanelDecision.as_str()
        ))
    );

    let mut unsupported_schema = body.clone();
    unsupported_schema.schema = "chio.frost.authorization-body.v9".to_string();
    assert_eq!(
        unsupported_schema.validate(),
        Err(FrostAuthorizationError::UnsupportedSchema(
            "chio.frost.authorization-body.v9".to_string()
        ))
    );

    let mut inverted_window = body.clone();
    inverted_window.expires_at = inverted_window.issued_at;
    assert_eq!(
        inverted_window.validate(),
        Err(FrostAuthorizationError::InvalidField {
            field: "expires_at",
            detail: "must be greater than issued_at",
        })
    );

    let mut stale_id = body;
    stale_id.resource_fence += 1;
    assert_eq!(
        stale_id.validate(),
        Err(FrostAuthorizationError::AuthorizationIdMismatch)
    );
}

#[test]
fn decoding_rejects_unknown_fields_and_noncanonical_identifiers() {
    let body = authorization_body();
    let mut value = serde_json::to_value(&body)
        .unwrap_or_else(|error| panic!("sample authorization must serialize: {error}"));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("authorization body must serialize as an object"))
        .insert("unexpected".to_string(), serde_json::json!(true));
    let encoded = serde_json::to_string(&value)
        .unwrap_or_else(|error| panic!("mutated authorization must serialize: {error}"));
    let decode_error = serde_json::from_str::<FrostAuthorizationBodyV1>(&encoded)
        .err()
        .unwrap_or_else(|| panic!("unknown field must be refused at decode"));
    assert!(
        decode_error
            .to_string()
            .contains("unknown field `unexpected`"),
        "{decode_error}"
    );

    let mut padded = body.clone();
    padded.scope_id = format!(" {} ", padded.scope_id);
    padded.authorization_id = padded
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("padded body must canonicalize: {error}"));
    assert_eq!(
        padded.validate(),
        Err(FrostAuthorizationError::InvalidField {
            field: "scope_id",
            detail: "must contain only unpadded printable ASCII",
        })
    );

    let mut uppercase_digest = body;
    uppercase_digest.action_digest = "AB".repeat(32);
    uppercase_digest.authorization_id = uppercase_digest
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("uppercase body must canonicalize: {error}"));
    assert_eq!(
        uppercase_digest.validate(),
        Err(FrostAuthorizationError::InvalidField {
            field: "action_digest",
            detail: "must be 64 lowercase hexadecimal characters",
        })
    );
}

#[test]
fn typed_action_preimage_dispatch_binds_the_registered_domain_and_resource() {
    let preimage = FrostActionPreimageV1::SettleCommitment(FrostSettleCommitmentActionV1 {
        schema: CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA.to_string(),
        settlement_body_digest: "55".repeat(32),
        payer_id: "did:chio:payer-1".to_string(),
        payee_id: "did:chio:payee-1".to_string(),
        amount_base_units: "12500".to_string(),
        asset_id: "usdc:base".to_string(),
        operation_id: "settlement.set-974".to_string(),
        rail_idempotency_key: "rail.set-974.v7".to_string(),
        resource_version: 7,
        resource_fence: 11,
    });
    let mut body = authorization_body();
    body.action_digest = preimage
        .action_digest()
        .unwrap_or_else(|error| panic!("typed action preimage must hash: {error}"));
    body.authorization_id = body
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("authorization body must canonicalize: {error}"));
    body.validate_action_preimage(&preimage)
        .unwrap_or_else(|error| panic!("matching action preimage must validate: {error}"));

    let mut changed_amount = preimage.clone();
    let FrostActionPreimageV1::SettleCommitment(action) = &mut changed_amount else {
        panic!("test preimage must remain a settlement action");
    };
    action.amount_base_units = "12501".to_string();
    assert_ne!(
        body.action_digest,
        changed_amount
            .action_digest()
            .unwrap_or_else(|error| panic!("changed preimage must hash: {error}"))
    );

    let mut wrong_digest = body.clone();
    wrong_digest.action_digest = "66".repeat(32);
    wrong_digest.authorization_id = wrong_digest
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        wrong_digest.validate_action_preimage(&preimage),
        Err(FrostAuthorizationError::ActionDigestMismatch)
    );

    let mut wrong_resource = body;
    wrong_resource.resource_id = "settlement.other".to_string();
    wrong_resource.authorization_id = wrong_resource
        .recompute_authorization_id()
        .unwrap_or_else(|error| panic!("changed body must canonicalize: {error}"));
    assert_eq!(
        wrong_resource.validate_action_preimage(&preimage),
        Err(FrostAuthorizationError::ContractMismatch(
            "action preimage resource_id"
        ))
    );
}
