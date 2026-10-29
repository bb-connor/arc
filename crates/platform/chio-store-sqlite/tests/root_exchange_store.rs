//! Root exchange mint, replay recovery, rebinding, bearer mappings,
//! retention by digest and context openings through the serving authority.
//! Every refusal is pinned to its exact error.

#[path = "root_exchange_support/mod.rs"]
mod support;

use chio_store_sqlite::root_exchange_store::{
    BearerLookup, BearerMapping, ContextOpenings, MintOutcome, MintReplayNamespace,
    MintRequestRefusal, OpeningState, RetainedArtifact, RootExchangeStoreError as E,
};
use support::{
    digest, loaded_policy, snapshot, tags, Admit, Case, Env, Failing, Kind, RevokedTenant,
    TestResult, NOW,
};

#[test]
fn mint_inserts_root_replay_openings_and_retained_artifacts() -> TestResult {
    let env = Env::new()?;
    let case = Case::id_jag("cap-1")?;
    assert_eq!(
        env.minted(&case, &Admit, NOW)?,
        ("cap-1".to_string(), false)
    );
    let stored = env.store.presentation("cap-1")?;
    assert_eq!(stored.capability.id, "cap-1");
    assert_eq!(stored.tags, tags(1));
    assert_eq!(stored.root_policy_digest, *case.policy.digest());
    let context_digest = stored.context.digest()?;
    assert_eq!(
        env.store.delegation_context(&context_digest)?,
        stored.context
    );
    assert_eq!(
        env.store.context_openings(&context_digest)?,
        ContextOpenings::Known(vec![
            ("anchor.sub".into(), OpeningState::Present([7; 32])),
            ("anchor.tenant".into(), OpeningState::Present([8; 32])),
        ])
    );
    assert_eq!(
        env.store.root_policy(case.policy.digest())?.digest()?,
        *case.policy.digest()
    );
    let identity = support::identity()?;
    assert_eq!(env.store.provider_identity(&identity.digest()?)?, identity);
    let snapshot = snapshot()?;
    assert_eq!(env.store.idp_key_snapshot(&snapshot.digest()?)?, snapshot);
    Ok(())
}

#[test]
fn bearer_retry_for_the_same_client_artifact_and_request_recovers_the_root() -> TestResult {
    let env = Env::new()?;
    let case = Case::static_bearer("cap-1")?;
    env.minted(&case, &Admit, NOW)?;
    let retry = Case::static_bearer("cap-2")?;
    assert_eq!(
        env.minted(&retry, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    assert_eq!(
        env.store.presentation("cap-2").err(),
        Some(E::AnchoredRootMissing {
            capability_id: "cap-2".into()
        })
    );
    Ok(())
}

#[test]
fn retry_from_another_client_refuses_replay() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut retry = Case::static_bearer("cap-2")?;
    retry.client_id = "other-client".into();
    assert_eq!(env.refused(&retry, &Admit, NOW + 1)?, E::AssertionReplay);
    Ok(())
}

#[test]
fn retry_with_changed_artifact_refuses_replay() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut retry = Case::static_bearer("cap-2")?;
    retry.artifact = 0x99;
    assert_eq!(env.refused(&retry, &Admit, NOW + 1)?, E::AssertionReplay);
    Ok(())
}

#[test]
fn retry_with_changed_request_refuses_replay() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut retry = Case::static_bearer("cap-2")?;
    retry.request = 0x98;
    assert_eq!(env.refused(&retry, &Admit, NOW + 1)?, E::AssertionReplay);
    Ok(())
}

#[test]
fn bearer_straddle_with_changed_request_refuses_replay() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut straddle = Case::static_bearer("cap-2")?;
    straddle.replay = 0x66;
    straddle.request = 0x98;
    assert_eq!(env.refused(&straddle, &Admit, NOW + 1)?, E::AssertionReplay);
    Ok(())
}

#[test]
fn refusing_checker_denies_with_entry_id_and_binds_nothing() -> TestResult {
    let env = Env::new()?;
    let case = Case::id_jag("cap-1")?;
    assert_eq!(
        env.refused(&case, &RevokedTenant(tags(1)), NOW)?,
        E::Revoked {
            entry_id: "rev-tenant-1".into()
        }
    );
    assert_eq!(
        env.store.presentation("cap-1").err(),
        Some(E::AnchoredRootMissing {
            capability_id: "cap-1".into()
        })
    );
    assert_eq!(
        env.minted(&case, &Admit, NOW + 1)?,
        ("cap-1".to_string(), false)
    );
    Ok(())
}

#[test]
fn checker_error_rolls_back_and_denies() -> TestResult {
    let env = Env::new()?;
    let case = Case::id_jag("cap-1")?;
    assert_eq!(
        env.refused(&case, &Failing, NOW)?,
        E::RevocationCheckUnavailable("revocation store offline".into())
    );
    assert_eq!(
        env.minted(&case, &Admit, NOW + 1)?,
        ("cap-1".to_string(), false)
    );
    Ok(())
}

#[test]
fn recovery_of_a_revoked_root_refuses_with_entry_id() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    assert_eq!(
        env.refused(
            &Case::static_bearer("cap-2")?,
            &RevokedTenant(tags(1)),
            NOW + 1
        )?,
        E::Revoked {
            entry_id: "rev-tenant-1".into()
        }
    );
    Ok(())
}

#[test]
fn recovery_of_an_expired_root_refuses() -> TestResult {
    let env = Env::new()?;
    let mut case = Case::static_bearer("cap-1")?;
    case.expires_at = NOW + 10;
    env.minted(&case, &Admit, NOW)?;
    let mut retry = Case::static_bearer("cap-2")?;
    retry.expires_at = NOW + 300;
    assert_eq!(
        env.refused(&retry, &Admit, NOW + 20)?,
        E::AnchoredRootExpired {
            capability_id: "cap-1".into()
        }
    );
    Ok(())
}

#[test]
fn recovery_under_another_policy_digest_refuses() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut retry = Case::static_bearer("cap-2")?;
    retry.policy = loaded_policy("rp_acme_rotated")?;
    assert_eq!(
        env.refused(&retry, &Admit, NOW + 1)?,
        E::RootPolicyChanged {
            capability_id: "cap-1".into()
        }
    );
    Ok(())
}

#[test]
fn revoke_under_n_then_mint_under_n_plus_1_refuses() -> TestResult {
    let env = Env::new()?;
    let mut case = Case::id_jag("cap-1")?;
    case.tags = tags(2);
    case.candidates = vec![tags(2), tags(1)];
    assert_eq!(
        env.refused(&case, &RevokedTenant(tags(1)), NOW)?,
        E::Revoked {
            entry_id: "rev-tenant-1".into()
        }
    );
    Ok(())
}

#[test]
fn expired_replay_binding_rebinds_to_a_second_root_and_keeps_the_first() -> TestResult {
    let env = Env::new()?;
    let mut first = Case::id_jag("cap-1")?;
    first.expires_at = NOW + 50;
    first.replay_retain_until = NOW + 110;
    env.minted(&first, &Admit, NOW)?;
    let mut second = Case::id_jag("cap-2")?;
    second.expires_at = NOW + 400;
    second.replay_retain_until = NOW + 460;
    assert_eq!(
        env.minted(&second, &Admit, NOW + 120)?,
        ("cap-2".to_string(), false)
    );
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    assert_eq!(env.store.presentation("cap-2")?.minted_at, NOW + 120);
    let mut retry = Case::id_jag("cap-3")?;
    retry.expires_at = NOW + 400;
    assert_eq!(env.refused(&retry, &Admit, NOW + 121)?, E::AssertionReplay);
    Ok(())
}

#[test]
fn expired_replay_binding_is_rebindable_only_after_retention() -> TestResult {
    let env = Env::new()?;
    let mut first = Case::id_jag("cap-1")?;
    first.expires_at = NOW + 50;
    first.replay_retain_until = NOW + 110;
    env.minted(&first, &Admit, NOW)?;
    let mut second = Case::id_jag("cap-2")?;
    second.client_id = "other-client".into();
    second.expires_at = NOW + 400;
    second.replay_retain_until = NOW + 460;
    assert_eq!(env.refused(&second, &Admit, NOW + 109)?, E::AssertionReplay);
    assert_eq!(
        env.minted(&second, &Admit, NOW + 110)?,
        ("cap-2".to_string(), false)
    );
    Ok(())
}

#[test]
fn client_assertion_binds_once_until_retention() -> TestResult {
    let env = Env::new()?;
    let jti = digest(0x55);
    env.store
        .bind_client_assertion(&jti, NOW + 60, &env.fence, env.at(NOW))?;
    assert_eq!(
        env.store
            .bind_client_assertion(&jti, NOW + 61, &env.fence, env.at(NOW + 1))
            .err(),
        Some(E::AssertionReplay)
    );
    env.store
        .bind_client_assertion(&jti, NOW + 120, &env.fence, env.at(NOW + 60))?;
    Ok(())
}

#[test]
fn client_assertion_binding_never_recovers_a_root() -> TestResult {
    let env = Env::new()?;
    let case = Case::id_jag("cap-1")?;
    env.store
        .bind_client_assertion(&digest(case.replay), NOW + 60, &env.fence, env.at(NOW))?;
    assert_eq!(env.refused(&case, &Admit, NOW + 1)?, E::AssertionReplay);
    Ok(())
}

fn refusal(edit: impl FnOnce(&mut Case)) -> TestResult<E> {
    let env = Env::new()?;
    let mut case = Case::id_jag("cap-1")?;
    edit(&mut case);
    env.refused(&case, &Admit, NOW)
}

type CaseEdit = Box<dyn FnOnce(&mut Case)>;

#[test]
fn invalid_mint_requests_refuse_before_any_durable_step() -> TestResult {
    let cases: Vec<(MintRequestRefusal, CaseEdit)> = vec![
        (
            MintRequestRefusal::IssuerNotExchangeKey,
            Box::new(|case| case.signer = support::holder_keypair()),
        ),
        (
            MintRequestRefusal::ScopeHashMismatch,
            Box::new(|case| {
                case.edit_context = |value| {
                    value["effective_root_scope_hash"] = serde_json::json!(support::digest(0x01));
                }
            }),
        ),
        (
            MintRequestRefusal::TagsNotLoaded,
            Box::new(|case| case.candidates = vec![tags(2)]),
        ),
        (
            MintRequestRefusal::TagsSpanGenerations,
            Box::new(|case| {
                case.tags.tenant = tags(2).tenant;
                case.candidates = vec![case.tags];
            }),
        ),
        (
            MintRequestRefusal::OpeningsMismatch,
            Box::new(|case| case.openings.truncate(1)),
        ),
        (
            MintRequestRefusal::DuplicateOpening,
            Box::new(|case| case.openings.push(("anchor.sub".into(), [9; 32]))),
        ),
        (
            MintRequestRefusal::ProviderIdentityPresence,
            Box::new(|case| case.with_identity = false),
        ),
        (
            MintRequestRefusal::KeySnapshotMismatch,
            Box::new(|case| case.with_snapshot = false),
        ),
        (
            MintRequestRefusal::ArtifactMismatch,
            Box::new(|case| {
                case.edit_context = |value| {
                    value["anchor"]["artifact_digest"] = serde_json::json!(support::digest(0x02));
                }
            }),
        ),
        (
            MintRequestRefusal::RootExpired,
            Box::new(|case| case.expires_at = NOW),
        ),
        (
            MintRequestRefusal::ReplayRetentionShort,
            Box::new(|case| case.replay_retain_until = NOW),
        ),
        (
            MintRequestRefusal::ReplayRetentionShort,
            Box::new(|case| case.replay_retain_until = case.expires_at - 1),
        ),
        (
            MintRequestRefusal::UnknownRule,
            Box::new(|case| {
                case.edit_context = |value| {
                    value["root_policy_rule_id"] = serde_json::json!("unknown-rule");
                }
            }),
        ),
        (
            MintRequestRefusal::ClientId,
            Box::new(|case| case.client_id = String::new()),
        ),
    ];
    for (expected, edit) in cases {
        assert_eq!(refusal(edit)?, E::InvalidMintRequest(expected));
    }
    Ok(())
}

#[test]
fn unknown_retained_digests_are_typed_missing_rows() -> TestResult {
    let env = Env::new()?;
    let unknown = digest(0x77);
    assert_eq!(
        env.store.root_policy(&unknown).err(),
        Some(E::RetainedArtifactMissing {
            kind: RetainedArtifact::RootPolicy,
            digest: unknown
        })
    );
    assert_eq!(
        env.store.provider_identity(&unknown).err(),
        Some(E::RetainedArtifactMissing {
            kind: RetainedArtifact::ProviderIdentity,
            digest: unknown
        })
    );
    assert_eq!(
        env.store.idp_key_snapshot(&unknown).err(),
        Some(E::RetainedArtifactMissing {
            kind: RetainedArtifact::KeySnapshot,
            digest: unknown
        })
    );
    assert_eq!(
        env.store.delegation_context(&unknown).err(),
        Some(E::DelegationContextMissing { digest: unknown })
    );
    assert_eq!(
        env.store.context_openings(&unknown)?,
        ContextOpenings::Unknown
    );
    Ok(())
}

#[test]
fn identical_snapshot_records_once() -> TestResult {
    let env = Env::new()?;
    let snapshot = snapshot()?;
    let first = env
        .store
        .record_idp_key_snapshot(&snapshot, &env.fence, env.at(NOW))?;
    let second = env
        .store
        .record_idp_key_snapshot(&snapshot, &env.fence, env.at(NOW + 1))?;
    assert_eq!(first, second);
    assert_eq!(env.store.idp_key_snapshot(&first)?, snapshot);
    Ok(())
}

#[test]
fn erasing_openings_tombstones_them_and_keeps_the_root() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::id_jag("cap-1")?, &Admit, NOW)?;
    env.store
        .erase_root_openings("cap-1", &env.fence, env.at(NOW + 1))?;
    let stored = env.store.presentation("cap-1")?;
    assert_eq!(
        env.store.context_openings(&stored.context.digest()?)?,
        ContextOpenings::Known(vec![
            ("anchor.sub".into(), OpeningState::Erased),
            ("anchor.tenant".into(), OpeningState::Erased),
        ])
    );
    assert_eq!(
        env.store
            .erase_root_openings("cap-9", &env.fence, env.at(NOW + 2))
            .err(),
        Some(E::AnchoredRootMissing {
            capability_id: "cap-9".into()
        })
    );
    Ok(())
}

#[test]
fn bearer_token_maps_to_one_live_root() -> TestResult {
    let env = Env::new()?;
    let case = Case::static_bearer("cap-1")?;
    env.minted(&case, &Admit, NOW)?;
    let mut concurrent = Case::static_bearer("cap-2")?;
    concurrent.replay = 0x66;
    assert_eq!(
        env.minted(&concurrent, &Admit, NOW + 1)?,
        ("cap-1".to_string(), true)
    );
    match env.store.bearer_root(&digest(0x44), env.at(NOW + 2))? {
        BearerLookup::Live(root) => assert_eq!(root.capability.id, "cap-1"),
        other => return Err(format!("unexpected lookup {other:?}").into()),
    }
    assert!(matches!(
        env.store.bearer_root(&digest(0x45), env.at(NOW + 2))?,
        BearerLookup::Unknown
    ));
    Ok(())
}

#[test]
fn static_bearer_expired_root_is_replaced_in_one_transaction() -> TestResult {
    let env = Env::new()?;
    let mut first = Case::static_bearer("cap-1")?;
    first.expires_at = NOW + 50;
    first.bearer = Some(BearerMapping {
        token_digest: digest(0x44),
        retain_until: NOW + 400,
    });
    env.minted(&first, &Admit, NOW)?;
    assert!(matches!(
        env.store.bearer_root(&digest(0x44), env.at(NOW + 60))?,
        BearerLookup::Expired { ref capability_id } if capability_id == "cap-1"
    ));
    let mut fresh = Case::static_bearer("cap-2")?;
    fresh.replay = 0x67;
    fresh.expires_at = NOW + 360;
    assert_eq!(
        env.minted(&fresh, &Admit, NOW + 60)?,
        ("cap-2".to_string(), false)
    );
    match env.store.bearer_root(&digest(0x44), env.at(NOW + 61))? {
        BearerLookup::Live(root) => assert_eq!(root.capability.id, "cap-2"),
        other => return Err(format!("unexpected lookup {other:?}").into()),
    }
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    Ok(())
}

#[test]
fn pruning_removes_expired_bindings_and_mappings_and_keeps_roots() -> TestResult {
    let env = Env::new()?;
    let mut case = Case::static_bearer("cap-1")?;
    case.expires_at = NOW + 50;
    case.replay_retain_until = NOW + 110;
    case.bearer = Some(BearerMapping {
        token_digest: digest(0x44),
        retain_until: NOW + 110,
    });
    env.minted(&case, &Admit, NOW)?;
    env.store.prune_expired(&env.fence, env.at(NOW + 110))?;
    assert!(matches!(
        env.store.bearer_root(&digest(0x44), env.at(NOW + 111))?,
        BearerLookup::Unknown
    ));
    assert_eq!(env.store.presentation("cap-1")?.capability.id, "cap-1");
    Ok(())
}

#[test]
fn revoke_under_n_then_recovery_under_n_plus_1_refuses() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::static_bearer("cap-1")?, &Admit, NOW)?;
    let mut rotated = Case::static_bearer("cap-2")?;
    rotated.candidates = vec![tags(2), tags(1)];
    rotated.tags = tags(1);
    assert_eq!(
        env.refused(&rotated, &RevokedTenant(tags(1)), NOW + 1)?,
        E::Revoked {
            entry_id: "rev-tenant-1".into()
        }
    );
    Ok(())
}

#[test]
fn mint_outcomes_carry_the_checked_root() -> TestResult {
    let env = Env::new()?;
    let case = Case::id_jag("cap-1")?;
    match env.mint(&case, &Admit, NOW)?? {
        MintOutcome::Minted(root) => {
            assert_eq!(root.minted_at, NOW);
            assert_eq!(root.context, case.context()?);
        }
        MintOutcome::Recovered(_) => return Err("fresh mint reported a recovery".into()),
    }
    Ok(())
}

fn local_as_issue(capability_id: &str) -> TestResult<Case> {
    let mut case = Case::non_jws(Kind::LocalAs, capability_id)?;
    case.namespace = MintReplayNamespace::LocalAsIssue;
    case.replay = 0x51;
    case.request = 0x52;
    Ok(case)
}

fn local_reexchange(capability_id: &str) -> TestResult<Case> {
    let mut case = Case::non_jws(Kind::LocalAs, capability_id)?;
    case.replay = 0x53;
    case.request = 0x54;
    Ok(case)
}

fn binding(namespace: &str, capability_id: &str) -> (String, Option<String>) {
    (namespace.to_string(), Some(capability_id.to_string()))
}

#[test]
fn local_as_issue_binds_its_own_replay_namespace() -> TestResult {
    let env = Env::new()?;
    env.minted(&local_as_issue("cap-1")?, &Admit, NOW)?;
    assert_eq!(
        env.replay_bindings()?,
        vec![binding("chio_local_as_issue", "cap-1")]
    );
    Ok(())
}

#[test]
fn local_as_issue_then_first_reexchange_succeeds() -> TestResult {
    let env = Env::new()?;
    assert_eq!(
        env.minted(&local_as_issue("cap-1")?, &Admit, NOW)?,
        ("cap-1".to_string(), false)
    );
    assert_eq!(
        env.minted(&local_reexchange("cap-2")?, &Admit, NOW + 1)?,
        ("cap-2".to_string(), false)
    );
    assert_eq!(
        env.replay_bindings()?,
        vec![
            binding("chio_local_as", "cap-2"),
            binding("chio_local_as_issue", "cap-1"),
        ]
    );
    Ok(())
}

#[test]
fn local_reexchange_twice_refuses() -> TestResult {
    let env = Env::new()?;
    env.minted(&local_reexchange("cap-1")?, &Admit, NOW)?;
    assert_eq!(
        env.refused(&local_reexchange("cap-2")?, &Admit, NOW + 1)?,
        E::AssertionReplay
    );
    assert_eq!(
        env.store.presentation("cap-2").err(),
        Some(E::AnchoredRootMissing {
            capability_id: "cap-2".into()
        })
    );
    Ok(())
}

#[test]
fn local_as_issue_namespace_requires_the_local_as_kind() -> TestResult {
    for kind in [Kind::IdJag, Kind::StaticBearer, Kind::OperatorKey] {
        let env = Env::new()?;
        let mut case = match kind {
            Kind::IdJag => Case::id_jag("cap-1")?,
            Kind::StaticBearer => Case::static_bearer("cap-1")?,
            _ => Case::non_jws(kind, "cap-1")?,
        };
        case.namespace = MintReplayNamespace::LocalAsIssue;
        assert_eq!(
            env.refused(&case, &Admit, NOW)?,
            E::InvalidMintRequest(MintRequestRefusal::ReplayNamespaceKind)
        );
        assert_eq!(env.replay_bindings()?, Vec::new());
    }
    Ok(())
}

#[test]
fn explicit_exchange_identical_repeat_refuses_replay() -> TestResult {
    let env = Env::new()?;
    env.minted(&Case::id_jag("cap-1")?, &Admit, NOW)?;
    assert_eq!(
        env.refused(&Case::id_jag("cap-2")?, &Admit, NOW + 1)?,
        E::AssertionReplay
    );
    assert_eq!(
        env.store.presentation("cap-2").err(),
        Some(E::AnchoredRootMissing {
            capability_id: "cap-2".into()
        })
    );
    Ok(())
}

/// A context of a non-JWS kind that carries `artifact_digest` never reaches
/// the mint: the delegation context decoder refuses it.
#[test]
fn non_jws_context_carrying_artifact_digest_refuses_mint() -> TestResult {
    for (kind, name) in [
        (Kind::LocalAs, "chio_local_as"),
        (Kind::OperatorKey, "chio_operator_key"),
        (Kind::StaticBearer, "operator_static_bearer"),
    ] {
        let mut case = Case::non_jws(kind, "cap-1")?;
        case.edit_context = |value| {
            value["anchor"]["artifact_digest"] = serde_json::json!(support::digest(0x13));
        };
        let refused = case
            .context()
            .err()
            .ok_or("a non-JWS context carrying artifact_digest decoded")?;
        assert_eq!(
            refused.to_string(),
            format!("`artifact_digest` is not allowed for {name}")
        );
    }
    Ok(())
}

#[test]
fn non_jws_roots_pass_the_row_check_without_context_artifact_digest() -> TestResult {
    for kind in [Kind::StaticBearer, Kind::LocalAs, Kind::OperatorKey] {
        let env = Env::new()?;
        let case = match kind {
            Kind::StaticBearer => Case::static_bearer("cap-1")?,
            _ => Case::non_jws(kind, "cap-1")?,
        };
        env.minted(&case, &Admit, NOW)?;
        let fixture = env.fixture;
        drop(env.store);
        drop(env.owner);
        let owner = fixture.open()?;
        let reopened = owner.root_exchange_store();
        let stored = reopened.presentation("cap-1")?;
        assert_eq!(stored.context.anchor.artifact_digest, None);
        assert_eq!(
            stored.context.anchor.kind.as_str(),
            case.context()?.anchor.kind.as_str()
        );
    }
    Ok(())
}
