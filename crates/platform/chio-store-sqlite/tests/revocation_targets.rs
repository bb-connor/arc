//! Revocation by root policy rule, subject tag, tenant tag and replay key:
//! the entry, its fan-out to anchored roots, the mint check and export
//! coverage. Every refusal is pinned to its exact error.

#[path = "root_exchange_support/mod.rs"]
mod support;

use chio_core::root_authority::{
    RevocationCoverageRoot, RevocationEntry, RevocationReason, RevocationTarget, Sha256Digest,
};
use chio_core::tenant_index::{KeyedIndexValue, TenantIndexKey, TenantIndexKeySet};
use chio_kernel::{RevocationStore, RevocationStoreError as R};
use chio_store_sqlite::revocation_store::TargetRevocation;
use chio_store_sqlite::root_exchange_store::{
    RootExchangeStoreError as E, RootTagInputs, RootTags, RootTenantIndex,
};
use chio_store_sqlite::SqliteRevocationStore;
use support::{digest, Admit, Case, Env, Kind, TestResult, ID_JAG_RULE, NOW, OPERATOR_KEY_RULE};

const KEY: u8 = 0xa1;

fn keyed(value: u8) -> KeyedIndexValue {
    KeyedIndexValue {
        key_id: digest(KEY),
        value: digest(value),
    }
}

fn root_tags(subject: u8, tenant: u8) -> RootTags {
    RootTags {
        subject: keyed(subject),
        tenant: keyed(tenant),
    }
}

/// A root of `kind` with its own replay key, request, artifact and tags.
fn case(kind: Kind, capability_id: &str, seed: u8, tags: RootTags) -> TestResult<Case> {
    let mut case = match kind {
        Kind::IdJag => Case::id_jag(capability_id)?,
        other => Case::non_jws(other, capability_id)?,
    };
    case.replay = 0x30 + seed;
    case.request = 0x50 + seed;
    case.artifact = 0x70 + seed;
    case.tags = tags;
    case.candidates = vec![tags];
    Ok(case)
}

/// Mints every case with no revocation check and returns the environment.
fn minted(cases: &[Case]) -> TestResult<Env> {
    let env = Env::new()?;
    for case in cases {
        env.minted(case, &Admit, NOW)?;
    }
    Ok(env)
}

fn revocations(env: &Env) -> SqliteRevocationStore {
    env.owner.revocation_store()
}

fn revoke(
    env: &Env,
    target: &RevocationTarget,
    tags: &[KeyedIndexValue],
    reason: RevocationReason,
) -> TestResult<TargetRevocation> {
    Ok(
        revocations(env).revoke_target(
            target,
            tags,
            tags.first().map(|tag| &tag.key_id),
            reason,
        )?,
    )
}

fn rule(rule_id: &str) -> TestResult<RevocationTarget> {
    Ok(RevocationTarget::root_policy_rule(rule_id)?)
}

fn count(env: &Env, sql: &str) -> TestResult<i64> {
    Ok(env.fixture.raw()?.query_row(sql, [], |row| row.get(0))?)
}

fn revoked_by(env: &Env, capability_id: &str) -> TestResult<Option<String>> {
    Ok(revocations(env)
        .revocation_entry(capability_id)?
        .map(|entry_id| entry_id.to_string()))
}

fn three_roots() -> TestResult<Vec<Case>> {
    Ok(vec![
        case(Kind::IdJag, "cap-a", 1, root_tags(0xb1, 0xc1))?,
        case(Kind::IdJag, "cap-b", 2, root_tags(0xb1, 0xc2))?,
        case(Kind::OperatorKey, "cap-c", 3, root_tags(0xb2, 0xc1))?,
    ])
}

#[test]
fn root_policy_rule_revocation_marks_every_live_root_under_the_rule_only() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = rule(ID_JAG_RULE)?;
    let revocation = revoke(&env, &target, &[], RevocationReason::PolicyWithdrawn)?;
    assert!(revocation.newly_revoked);
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (2, 2));
    assert_eq!(revocation.entry.entry_id, target.id());
    assert_eq!(revocation.entry.reason, RevocationReason::PolicyWithdrawn);
    let entry = Some(target.id().to_string());
    assert_eq!(revoked_by(&env, "cap-a")?, entry);
    assert_eq!(revoked_by(&env, "cap-b")?, entry);
    assert_eq!(revoked_by(&env, "cap-c")?, None);
    Ok(())
}

#[test]
fn anchor_subject_revocation_marks_every_live_root_with_the_tag_only() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = RevocationTarget::subject_tag(digest(0xb1));
    let revocation = revoke(
        &env,
        &target,
        &[keyed(0xb1)],
        RevocationReason::PrincipalOffboarded,
    )?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (2, 2));
    let entry = Some(target.id().to_string());
    assert_eq!(revoked_by(&env, "cap-a")?, entry);
    assert_eq!(revoked_by(&env, "cap-b")?, entry);
    assert_eq!(revoked_by(&env, "cap-c")?, None);
    Ok(())
}

#[test]
fn tenant_revocation_marks_every_live_root_in_the_tenant_only() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = RevocationTarget::tenant_tag(digest(0xc1));
    let revocation = revoke(
        &env,
        &target,
        &[keyed(0xc1)],
        RevocationReason::TenantOffboarded,
    )?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (2, 2));
    let entry = Some(target.id().to_string());
    assert_eq!(revoked_by(&env, "cap-a")?, entry);
    assert_eq!(revoked_by(&env, "cap-b")?, None);
    assert_eq!(revoked_by(&env, "cap-c")?, entry);
    Ok(())
}

#[test]
fn replay_key_revocation_marks_the_one_root() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = RevocationTarget::replay_key(digest(0x32));
    let revocation = revoke(&env, &target, &[], RevocationReason::CredentialCompromise)?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (1, 1));
    assert_eq!(revoked_by(&env, "cap-a")?, None);
    assert_eq!(revoked_by(&env, "cap-b")?, Some(target.id().to_string()));
    assert_eq!(revoked_by(&env, "cap-c")?, None);
    Ok(())
}

#[test]
fn capability_target_records_its_reason_and_marks_the_capability() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = RevocationTarget::capability("cap-c")?;
    let revocation = revoke(&env, &target, &[], RevocationReason::IncidentResponse)?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (1, 1));
    assert_eq!(revocation.entry.reason, RevocationReason::IncidentResponse);
    assert_eq!(revoked_by(&env, "cap-c")?, Some(target.id().to_string()));
    Ok(())
}

#[test]
fn fan_out_marks_expired_matching_roots() -> TestResult {
    let env = minted(&three_roots()?)?;
    env.at(NOW + 10_000);
    let revocation = revoke(
        &env,
        &rule(OPERATOR_KEY_RULE)?,
        &[],
        RevocationReason::PolicyWithdrawn,
    )?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (1, 1));
    assert!(revoked_by(&env, "cap-c")?.is_some());
    Ok(())
}

#[test]
fn repeated_target_revocation_is_idempotent() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = rule(ID_JAG_RULE)?;
    let first = revoke(&env, &target, &[], RevocationReason::PolicyWithdrawn)?;
    let deltas = count(&env, "SELECT COUNT(*) FROM revocation_delta_log")?;
    let commits = count(&env, "SELECT COUNT(*) FROM admission_authority_commits")?;
    let second = revoke(&env, &target, &[], RevocationReason::PolicyWithdrawn)?;
    assert!(!second.newly_revoked);
    assert_eq!(second.entry, first.entry);
    assert_eq!((second.roots_matched, second.roots_revoked), (2, 0));
    assert_eq!(
        count(&env, "SELECT COUNT(*) FROM revocation_delta_log")?,
        deltas
    );
    assert_eq!(
        count(&env, "SELECT COUNT(*) FROM admission_authority_commits")?,
        commits
    );
    Ok(())
}

#[test]
fn retry_with_a_different_reason_keeps_the_first() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = rule(ID_JAG_RULE)?;
    let first = revoke(&env, &target, &[], RevocationReason::PolicyWithdrawn)?;
    env.at(NOW + 5);
    let second = revoke(&env, &target, &[], RevocationReason::IncidentResponse)?;
    assert!(!second.newly_revoked);
    assert_eq!(second.entry.reason, RevocationReason::PolicyWithdrawn);
    assert_eq!(second.entry.revoked_at, first.entry.revoked_at);
    Ok(())
}

#[test]
fn zero_match_revocation_reports_zero_roots() -> TestResult {
    let env = minted(&three_roots()?)?;
    let revocation = revoke(
        &env,
        &rule("unused-rule")?,
        &[],
        RevocationReason::PolicyWithdrawn,
    )?;
    assert!(revocation.newly_revoked);
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (0, 0));
    assert_eq!(count(&env, "SELECT COUNT(*) FROM revoked_capabilities")?, 0);
    Ok(())
}

#[test]
fn already_revoked_roots_count_as_matched_not_revoked() -> TestResult {
    let env = minted(&three_roots()?)?;
    let rule_target = rule(ID_JAG_RULE)?;
    revoke(&env, &rule_target, &[], RevocationReason::PolicyWithdrawn)?;
    let subject = revoke(
        &env,
        &RevocationTarget::subject_tag(digest(0xb1)),
        &[keyed(0xb1)],
        RevocationReason::PrincipalOffboarded,
    )?;
    assert!(subject.newly_revoked);
    assert_eq!((subject.roots_matched, subject.roots_revoked), (2, 0));
    assert_eq!(
        revoked_by(&env, "cap-a")?,
        Some(rule_target.id().to_string())
    );
    Ok(())
}

#[test]
fn tag_targets_refuse_inconsistent_tags_and_other_targets_refuse_tags() -> TestResult {
    let env = minted(&three_roots()?)?;
    let subject = RevocationTarget::subject_tag(digest(0xb1));
    for (target, tags, refusal) in [
        (
            &subject,
            Vec::new(),
            "a tag target needs its tag under every loaded generation",
        ),
        (
            &subject,
            vec![keyed(0xb2)],
            "the first tag is the target value under the active generation",
        ),
        (
            &subject,
            vec![keyed(0xb1), keyed(0xb3)],
            "each generation carries one tag",
        ),
    ] {
        let error = revocations(&env)
            .revoke_target(
                target,
                &tags,
                Some(&digest(KEY)),
                RevocationReason::PrincipalOffboarded,
            )
            .err();
        assert!(
            matches!(&error, Some(R::InvalidTargetTags(text)) if *text == refusal),
            "{error:?}"
        );
    }
    let error = revocations(&env)
        .revoke_target(
            &rule(ID_JAG_RULE)?,
            &[keyed(0xb1)],
            None,
            RevocationReason::PolicyWithdrawn,
        )
        .err();
    assert!(
        matches!(&error, Some(R::InvalidTargetTags(text)) if *text == "only a tag target carries tags"),
        "{error:?}"
    );
    assert_eq!(count(&env, "SELECT COUNT(*) FROM revocation_entries")?, 0);
    Ok(())
}

#[test]
fn a_tag_target_must_lead_with_its_active_generation() -> TestResult {
    let env = minted(&three_roots()?)?;
    let retired = keyed(0xb1);
    let active = KeyedIndexValue {
        key_id: digest(0xa2),
        value: digest(0xd1),
    };
    let target = RevocationTarget::subject_tag(retired.value);
    for (tags, active_key_id, refusal) in [
        (
            vec![retired, active],
            Some(&active.key_id),
            "the first tag is not under the active generation",
        ),
        (
            vec![retired],
            None,
            "a tag target names its active generation",
        ),
    ] {
        let error = revocations(&env)
            .revoke_target(
                &target,
                &tags,
                active_key_id,
                RevocationReason::PrincipalOffboarded,
            )
            .err();
        assert!(
            matches!(&error, Some(R::InvalidTargetTags(text)) if *text == refusal),
            "{error:?}"
        );
    }
    let error = revocations(&env)
        .revoke_target(
            &rule(ID_JAG_RULE)?,
            &[],
            Some(&active.key_id),
            RevocationReason::PolicyWithdrawn,
        )
        .err();
    assert!(
        matches!(&error, Some(R::InvalidTargetTags(text)) if *text == "only a tag target names an active generation"),
        "{error:?}"
    );
    assert_eq!(count(&env, "SELECT COUNT(*) FROM revocation_entries")?, 0);
    Ok(())
}

#[test]
fn a_standalone_store_refuses_root_targets() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteRevocationStore::open(directory.path().join("revocations.db"))?;
    let error = store
        .revoke_target(
            &rule(ID_JAG_RULE)?,
            &[],
            None,
            RevocationReason::PolicyWithdrawn,
        )
        .err();
    assert!(
        matches!(
            &error,
            Some(R::TargetRequiresServingOwner {
                kind: "root_policy_rule"
            })
        ),
        "{error:?}"
    );
    assert_eq!(
        R::TargetRequiresServingOwner {
            kind: "root_policy_rule"
        }
        .to_string(),
        "a root_policy_rule revocation requires the serving-owner state directory"
    );
    let capability = store.revoke_target(
        &RevocationTarget::capability("cap-1")?,
        &[],
        None,
        RevocationReason::OperatorRequest,
    )?;
    assert_eq!((capability.roots_matched, capability.roots_revoked), (1, 1));
    assert!(store.is_revoked("cap-1")?);
    Ok(())
}

#[test]
fn mint_matching_an_entry_is_refused_with_the_entry() -> TestResult {
    let roots = three_roots()?;
    let env = minted(&roots[..1])?;
    let tenant = RevocationTarget::tenant_tag(digest(0xc1));
    revoke(
        &env,
        &tenant,
        &[keyed(0xc1)],
        RevocationReason::TenantOffboarded,
    )?;
    let check = revocations(&env);
    assert_eq!(
        env.refused(&roots[2], &check, NOW)?,
        E::Revoked {
            entry_id: tenant.id().to_string()
        }
    );
    assert_eq!(
        count(
            &env,
            "SELECT COUNT(*) FROM root_exchange_roots WHERE capability_id = 'cap-c'"
        )?,
        0
    );
    env.minted(&roots[1], &check, NOW)?;
    assert_eq!(
        R::TargetRevoked {
            entry_id: tenant.id()
        }
        .to_string(),
        format!("anchored root matches revocation entry {}", tenant.id())
    );
    Ok(())
}

#[test]
fn mint_refusal_names_the_earliest_matching_entry() -> TestResult {
    let roots = three_roots()?;
    let env = Env::new()?;
    let replay = RevocationTarget::replay_key(digest(0x32));
    revoke(&env, &replay, &[], RevocationReason::CredentialCompromise)?;
    revoke(
        &env,
        &rule(ID_JAG_RULE)?,
        &[],
        RevocationReason::PolicyWithdrawn,
    )?;
    revoke(
        &env,
        &RevocationTarget::subject_tag(digest(0xb1)),
        &[keyed(0xb1)],
        RevocationReason::PrincipalOffboarded,
    )?;
    let check = revocations(&env);
    assert_eq!(
        env.refused(&roots[1], &check, NOW)?,
        E::Revoked {
            entry_id: replay.id().to_string()
        }
    );
    assert_eq!(
        env.refused(&roots[0], &check, NOW)?,
        E::Revoked {
            entry_id: rule(ID_JAG_RULE)?.id().to_string()
        }
    );
    Ok(())
}

fn coverage_root(root: &str, ids: &[&str]) -> RevocationCoverageRoot {
    RevocationCoverageRoot {
        root_capability_id: root.into(),
        capability_ids: ids.iter().map(|id| (*id).into()).collect(),
    }
}

fn covering(
    env: &Env,
    roots: &[RevocationCoverageRoot],
) -> TestResult<Vec<(RevocationEntry, Vec<String>)>> {
    Ok(revocations(env)
        .revocations_covering(roots)?
        .into_iter()
        .map(|coverage| (coverage.entry, coverage.covered_capability_ids))
        .collect())
}

#[test]
fn later_rule_entry_covers_a_root_revoked_earlier() -> TestResult {
    let env = minted(&three_roots()?)?;
    let capability = RevocationTarget::capability("cap-a")?;
    assert!(revocations(&env).revoke("cap-a")?);
    let rule_target = rule(ID_JAG_RULE)?;
    revoke(&env, &rule_target, &[], RevocationReason::PolicyWithdrawn)?;
    let coverage = covering(&env, &[coverage_root("cap-a", &["cap-a"])])?;
    let ids: Vec<_> = coverage
        .iter()
        .map(|(entry, covered)| (entry.entry_id.clone(), covered.clone()))
        .collect();
    assert_eq!(
        ids,
        vec![
            (capability.id(), vec!["cap-a".to_string()]),
            (rule_target.id(), vec!["cap-a".to_string()]),
        ]
    );
    Ok(())
}

#[test]
fn coverage_includes_expired_roots_and_ignores_unrelated_entries() -> TestResult {
    let env = minted(&three_roots()?)?;
    env.at(NOW + 10_000);
    let tenant = RevocationTarget::tenant_tag(digest(0xc1));
    revoke(
        &env,
        &tenant,
        &[keyed(0xc1)],
        RevocationReason::TenantOffboarded,
    )?;
    revoke(
        &env,
        &RevocationTarget::subject_tag(digest(0xb9)),
        &[keyed(0xb9)],
        RevocationReason::PrincipalOffboarded,
    )?;
    revoke(
        &env,
        &RevocationTarget::capability("cap-delegated")?,
        &[],
        RevocationReason::OperatorRequest,
    )?;
    let coverage = covering(
        &env,
        &[
            coverage_root("cap-c", &["cap-c", "cap-delegated", "cap-delegated"]),
            coverage_root("cap-a", &["cap-a"]),
            coverage_root("cap-b", &["cap-b"]),
        ],
    )?;
    let ids: Vec<_> = coverage
        .iter()
        .map(|(entry, covered)| (entry.entry_id.clone(), covered.clone()))
        .collect();
    assert_eq!(
        ids,
        vec![
            (tenant.id(), vec!["cap-a".to_string(), "cap-c".to_string()]),
            (
                RevocationTarget::capability("cap-delegated")?.id(),
                vec!["cap-delegated".to_string()]
            ),
        ]
    );
    Ok(())
}

#[test]
fn coverage_refuses_when_anchored_root_row_missing() -> TestResult {
    let env = minted(&three_roots()?)?;
    revoke(
        &env,
        &rule(ID_JAG_RULE)?,
        &[],
        RevocationReason::PolicyWithdrawn,
    )?;
    let error = revocations(&env)
        .revocations_covering(&[
            coverage_root("cap-a", &["cap-a"]),
            coverage_root("cap-missing", &["cap-missing"]),
        ])
        .err();
    assert!(
        matches!(&error, Some(R::AnchoredRootMissing { capability_id }) if capability_id == "cap-missing"),
        "{error:?}"
    );
    assert_eq!(
        R::AnchoredRootMissing {
            capability_id: "cap-missing".into()
        }
        .to_string(),
        "anchored root row missing for cap-missing"
    );
    Ok(())
}

#[test]
fn coverage_on_a_non_joint_store_refuses() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = SqliteRevocationStore::open(directory.path().join("revocations.db"))?;
    let error = store
        .revocations_covering(&[coverage_root("cap-a", &["cap-a"])])
        .err();
    assert!(
        matches!(&error, Some(R::CoverageRequiresServingOwner)),
        "{error:?}"
    );
    assert_eq!(
        R::CoverageRequiresServingOwner.to_string(),
        "revocation coverage requires the serving-owner state directory"
    );
    Ok(())
}

fn open_error(env: Env) -> TestResult<String> {
    let Env {
        fixture,
        owner,
        store,
        fence: _,
    } = env;
    drop(store);
    drop(owner);
    fixture
        .raw()?
        .execute_batch("DELETE FROM revocation_entry_tags")?;
    match fixture.open() {
        Ok(_) => Err("open unexpectedly succeeded".into()),
        Err(error) => Ok(error.to_string()),
    }
}

#[test]
fn tag_entry_without_tag_rows_refuses_open() -> TestResult {
    let env = minted(&three_roots()?)?;
    let target = RevocationTarget::subject_tag(digest(0xb1));
    revoke(
        &env,
        &target,
        &[keyed(0xb1)],
        RevocationReason::PrincipalOffboarded,
    )?;
    let error = open_error(env)?;
    assert!(
        error.contains(&format!(
            "revocation entry {} has inconsistent tag rows",
            target.id()
        )),
        "{error}"
    );
    Ok(())
}

/// A schema change made outside the serving owner fences the next target
/// revocation before it writes: no entry, no tag row and no revoked root.
#[test]
fn an_outside_schema_change_refuses_the_revocation_before_any_write() -> TestResult {
    let env = minted(&three_roots()?)?;
    env.fixture.raw()?.execute_batch(
        "CREATE TRIGGER refuse_revocation BEFORE INSERT ON revoked_capabilities \
         BEGIN SELECT RAISE(ABORT, 'injected fan-out failure'); END;",
    )?;
    let error = revocations(&env)
        .revoke_target(
            &RevocationTarget::subject_tag(digest(0xb1)),
            &[keyed(0xb1)],
            Some(&digest(KEY)),
            RevocationReason::PrincipalOffboarded,
        )
        .err();
    assert!(
        matches!(&error, Some(R::OutcomeUnknown(detail))
            if detail == "authority database changed outside its serving-owner connection"),
        "{error:?}"
    );
    assert_eq!(count(&env, "SELECT COUNT(*) FROM revocation_entries")?, 0);
    assert_eq!(
        count(&env, "SELECT COUNT(*) FROM revocation_entry_tags")?,
        0
    );
    assert_eq!(count(&env, "SELECT COUNT(*) FROM revoked_capabilities")?, 0);
    Ok(())
}

fn generation(byte: u8) -> TestResult<TenantIndexKey> {
    Ok(TenantIndexKey::from_set_key(&[byte; 32])?)
}

fn key_set(active: u8, retired: &[u8]) -> TestResult<TenantIndexKeySet> {
    Ok(TenantIndexKeySet::new(
        generation(active)?,
        retired
            .iter()
            .map(|byte| generation(*byte))
            .collect::<TestResult<Vec<_>>>()?,
    )?)
}

const INPUTS: RootTagInputs<'static> = RootTagInputs {
    issuer: "urn:chio:operator",
    principal: "dev:alice-marker",
    tenant_value: "dev-tenant-marker",
};

/// The subject tag of `INPUTS` under every generation of `keys`, active first.
fn subject_tags(env: &Env, keys: &TenantIndexKeySet) -> TestResult<Vec<KeyedIndexValue>> {
    Ok(RootTenantIndex::open(keys, &env.store)?
        .candidate_tags(&INPUTS)?
        .into_iter()
        .map(|tags| tags.subject)
        .collect())
}

fn revoke_subject(env: &Env, keys: &TenantIndexKeySet) -> TestResult<RevocationTarget> {
    let tags = subject_tags(env, keys)?;
    let target = RevocationTarget::subject_tag(tags[0].value);
    revoke(env, &target, &tags, RevocationReason::PrincipalOffboarded)?;
    Ok(target)
}

fn key_id(byte: u8) -> TestResult<Sha256Digest> {
    Ok(*key_set(byte, &[])?.active_key_id())
}

#[test]
fn startup_refuses_when_only_a_revocation_entry_references_a_generation() -> TestResult {
    let env = Env::new()?;
    revoke_subject(&env, &key_set(1, &[])?)?;
    assert_eq!(
        RootTenantIndex::open(&key_set(2, &[])?, &env.store).err(),
        Some(E::RevocationTagGenerationMissing { key_id: key_id(1)? })
    );
    assert_eq!(
        E::RevocationTagGenerationMissing { key_id: key_id(1)? }.to_string(),
        format!(
            "tenant index key generation {} referenced by a revocation entry is not loaded",
            key_id(1)?
        )
    );
    RootTenantIndex::open(&key_set(2, &[1])?, &env.store)?;
    Ok(())
}

#[test]
fn revoke_under_n_then_admit_under_n_plus_1_denies() -> TestResult {
    let env = Env::new()?;
    let target = revoke_subject(&env, &key_set(1, &[])?)?;
    let rotated = key_set(2, &[1])?;
    let index = RootTenantIndex::open(&rotated, &env.store)?;
    let mut case = Case::non_jws(Kind::OperatorKey, "cap-rotated")?;
    case.tags = index.derive_tags(&INPUTS)?;
    case.candidates = index.candidate_tags(&INPUTS)?;
    assert_eq!(
        env.refused(&case, &revocations(&env), NOW)?,
        E::Revoked {
            entry_id: target.id().to_string()
        }
    );
    Ok(())
}

#[test]
fn entry_written_under_b_covers_a_root_tagged_under_a() -> TestResult {
    let env = Env::new()?;
    let first = key_set(1, &[])?;
    let old = RootTenantIndex::open(&first, &env.store)?;
    let mut case = Case::non_jws(Kind::OperatorKey, "cap-old")?;
    case.tags = old.derive_tags(&INPUTS)?;
    case.candidates = old.candidate_tags(&INPUTS)?;
    env.minted(&case, &Admit, NOW)?;
    let rotated = key_set(2, &[1])?;
    let tags = subject_tags(&env, &rotated)?;
    assert_eq!(tags[0].key_id, key_id(2)?);
    let target = RevocationTarget::subject_tag(tags[0].value);
    let revocation = revoke(&env, &target, &tags, RevocationReason::PrincipalOffboarded)?;
    assert_eq!((revocation.roots_matched, revocation.roots_revoked), (1, 1));
    let coverage = covering(&env, &[coverage_root("cap-old", &["cap-old"])])?;
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].0.entry_id, target.id());
    Ok(())
}

#[test]
fn subject_and_tenant_revocations_store_only_tags() -> TestResult {
    let env = Env::new()?;
    let keys = key_set(1, &[])?;
    revoke_subject(&env, &keys)?;
    let tenant: Vec<KeyedIndexValue> = RootTenantIndex::open(&keys, &env.store)?
        .candidate_tags(&INPUTS)?
        .into_iter()
        .map(|tags| tags.tenant)
        .collect();
    revoke(
        &env,
        &RevocationTarget::tenant_tag(tenant[0].value),
        &tenant,
        RevocationReason::TenantOffboarded,
    )?;
    let database = env.fixture.database.clone();
    for suffix in ["", "-wal", "-shm"] {
        let path = format!("{}{suffix}", database.display());
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        for marker in [INPUTS.principal, INPUTS.tenant_value] {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "{marker} found in {path}"
            );
        }
    }
    Ok(())
}

const INTERLEAVINGS: u8 = 64;

/// A replay-key revocation races the mint of the one root it names. Either
/// the entry commits first and the mint is refused with it, or the root
/// commits first and the fan-out marks it: no schedule leaves a live root
/// matching an entry.
#[test]
fn revocation_and_mint_interleavings_never_leave_a_live_matching_root() -> TestResult {
    let env = Env::new()?;
    let check = revocations(&env);
    for index in 0..INTERLEAVINGS {
        let seed = 0x80 + index;
        let capability_id = format!("cap-race-{index}");
        let mut case = Case::non_jws(Kind::OperatorKey, &capability_id)?;
        case.replay = seed;
        case.request = seed;
        case.artifact = seed;
        let built = case.build()?;
        let target = RevocationTarget::replay_key(digest(seed));
        let barrier = std::sync::Barrier::new(2);
        let (mint, revocation) = std::thread::scope(|scope| {
            let mint = scope.spawn(|| {
                barrier.wait();
                env.store
                    .mint_anchored_root(&built.request(&case), &check, &env.fence, support::ms(NOW))
                    .map(|_| ())
            });
            let revocation = scope.spawn(|| {
                barrier.wait();
                check.revoke_target(&target, &[], None, RevocationReason::CredentialCompromise)
            });
            (mint.join(), revocation.join())
        });
        let mint = mint.map_err(|_| "mint worker panicked")?;
        let revocation = revocation.map_err(|_| "revocation worker panicked")??;
        match mint {
            Ok(()) => {
                assert_eq!(
                    (revocation.roots_matched, revocation.roots_revoked),
                    (1, 1),
                    "{capability_id}"
                );
                assert_eq!(
                    revoked_by(&env, &capability_id)?,
                    Some(target.id().to_string())
                );
            }
            Err(error) => {
                assert_eq!(
                    error,
                    E::Revoked {
                        entry_id: target.id().to_string()
                    }
                );
                assert_eq!((revocation.roots_matched, revocation.roots_revoked), (0, 0));
            }
        }
    }
    Ok(())
}
