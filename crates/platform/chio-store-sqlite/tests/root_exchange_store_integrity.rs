//! Open-time integrity of the root exchange store: the authorization
//! projection, the global commit per root, the opening custody contract,
//! retained digests and the DDL checks. Every refusal is pinned to its exact
//! typed variant.

#[path = "root_exchange_support/mod.rs"]
mod support;

use chio_store_sqlite::root_exchange_store::{
    RetainedArtifact, RootExchangeIntegrityError as I, RootExchangeStoreError as E,
};
use chio_store_sqlite::serving_owner::SqliteServingOwnerError;
use chio_store_sqlite::SchemaVersionError;
use rusqlite::ffi;
use support::{Admit, Case, Env, TestResult, NOW};

fn tampered() -> I {
    I::RootTampered {
        capability_id: "cap-1".into(),
    }
}

/// The extended SQLite code of a statement that must be refused.
fn refusal_code(result: rusqlite::Result<usize>) -> TestResult<i32> {
    match result {
        Ok(rows) => Err(format!("statement unexpectedly changed {rows} rows").into()),
        Err(rusqlite::Error::SqliteFailure(error, _)) => Ok(error.extended_code),
        Err(other) => Err(other.into()),
    }
}

fn minted_env() -> TestResult<Env> {
    let env = Env::new()?;
    env.minted(&Case::id_jag("cap-1")?, &Admit, NOW)?;
    Ok(env)
}

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

#[test]
fn every_projected_root_column_mutation_refuses_open() -> TestResult {
    let mutations = [
        "UPDATE root_exchange_roots SET root_policy_rule_id = 'dev-static'".to_string(),
        format!("UPDATE root_exchange_roots SET tag_key_id = '{}'", hex(0xa2)),
        format!("UPDATE root_exchange_roots SET subject_tag = '{}'", hex(0xb2)),
        format!("UPDATE root_exchange_roots SET tenant_tag = '{}'", hex(0xc2)),
        format!("UPDATE root_exchange_roots SET replay_key_digest = '{}'", hex(0x31)),
        "UPDATE root_exchange_roots SET replay_bound_at = replay_bound_at + 1".to_string(),
        "UPDATE root_exchange_roots SET client_id = 'other-client'".to_string(),
        format!("UPDATE root_exchange_roots SET artifact_digest = '{}'", hex(0x32)),
        format!("UPDATE root_exchange_roots SET request_digest = '{}'", hex(0x33)),
        "UPDATE root_exchange_roots SET expires_at = expires_at + 1".to_string(),
        "UPDATE root_exchange_roots SET holder = 'caller'".to_string(),
        "UPDATE root_exchange_roots SET anchor_kind = 'oidc_jwt'".to_string(),
        format!("UPDATE root_exchange_roots SET root_policy_digest = '{}'", hex(0x34)),
        format!(
            "UPDATE root_exchange_roots SET provider_identity_digest = '{}'",
            hex(0x35)
        ),
        format!("UPDATE root_exchange_roots SET key_snapshot_digest = '{}'", hex(0x36)),
        format!("UPDATE root_exchange_roots SET context_digest = '{}'", hex(0x37)),
        "UPDATE root_exchange_roots SET minted_at = minted_at - 1".to_string(),
        "UPDATE root_exchange_roots SET delegation_context = CAST(delegation_context || x'20' AS BLOB)"
            .to_string(),
        "UPDATE root_exchange_roots SET root_capability = CAST(root_capability || x'20' AS BLOB)"
            .to_string(),
        format!(
            "UPDATE root_exchange_roots SET authorization_projection_digest = '{}'",
            hex(0x38)
        ),
    ];
    for mutation in mutations {
        let env = minted_env()?;
        let (_, reopened) = env.tamper_and_reopen(
            Some("root_exchange_roots_immutable"),
            &format!("{mutation};"),
        )?;
        assert_eq!(reopened, tampered(), "{mutation}");
    }
    Ok(())
}

#[test]
fn committed_root_without_global_commit_refuses_open_and_keeps_rows() -> TestResult {
    let env = minted_env()?;
    let (fixture, reopened) = env.tamper_and_reopen(
        None,
        &format!(
            "INSERT INTO root_exchange_roots
             SELECT 'cap-forged', root_policy_rule_id, tag_key_id, subject_tag, tenant_tag,
                    replay_key_digest, replay_bound_at + 1, client_id, artifact_digest,
                    request_digest, expires_at, anchor_kind, holder, root_policy_digest,
                    provider_identity_digest, key_snapshot_digest, '{}', delegation_context,
                    root_capability, minted_at, authorization_projection_digest
             FROM root_exchange_roots WHERE capability_id = 'cap-1';",
            hex(0x39)
        ),
    )?;
    assert_eq!(
        reopened,
        I::RootWithoutGlobalCommit {
            capability_id: "cap-forged".into()
        }
    );
    let raw = fixture.raw()?;
    let roots: i64 = raw.query_row("SELECT COUNT(*) FROM root_exchange_roots", [], |row| {
        row.get(0)
    })?;
    let bindings: i64 = raw.query_row("SELECT COUNT(*) FROM root_exchange_replay", [], |row| {
        row.get(0)
    })?;
    assert_eq!((roots, bindings), (2, 1));
    Ok(())
}

#[test]
fn present_opening_without_root_refuses_open() -> TestResult {
    let env = minted_env()?;
    let (_, reopened) = env.tamper_and_reopen(
        None,
        &format!(
            "INSERT INTO root_exchange_openings VALUES
             ('cap-ghost', 'anchor.sub', 'present', x'{}', {NOW});",
            hex(0x01)
        ),
    )?;
    assert_eq!(
        reopened,
        I::OpeningWithoutRoot {
            capability_id: "cap-ghost".into()
        }
    );
    Ok(())
}

#[test]
fn opening_insert_over_a_tombstone_refuses() -> TestResult {
    let Env {
        fixture,
        owner,
        store,
        ..
    } = minted_env()?;
    drop(store);
    drop(owner);
    fixture.raw()?.execute(
        "INSERT INTO root_exchange_openings VALUES ('cap-ghost', 'anchor.sub', 'erased', NULL, ?1)",
        [i64::try_from(NOW)?],
    )?;
    let owner = fixture.open()?;
    let store = owner.root_exchange_store();
    let fence = store.mutation_fence();
    let mut case = Case::id_jag("cap-ghost")?;
    case.replay = 0x61;
    let built = case.build()?;
    let refused = store
        .mint_anchored_root(
            &built.request(&case),
            &Admit,
            &fence,
            fixture.at(support::ms(NOW + 1)),
        )
        .err();
    assert_eq!(
        refused,
        Some(E::RootOpeningErased {
            capability_id: "cap-ghost".into(),
            salt_ref: "anchor.sub".into(),
        })
    );
    Ok(())
}

#[test]
fn erased_tombstones_and_roots_refuse_deletion() -> TestResult {
    let env = minted_env()?;
    env.store
        .erase_root_openings("cap-1", &env.fence, env.at(NOW + 1))?;
    let Env {
        fixture,
        owner,
        store,
        ..
    } = env;
    drop(store);
    drop(owner);
    let raw = fixture.raw()?;
    for sql in [
        "DELETE FROM root_exchange_openings WHERE capability_id = 'cap-1'",
        "DELETE FROM root_exchange_roots WHERE capability_id = 'cap-1'",
    ] {
        assert_eq!(
            refusal_code(raw.execute(sql, []))?,
            ffi::SQLITE_CONSTRAINT_TRIGGER,
            "{sql}"
        );
    }
    Ok(())
}

#[test]
fn retained_bytes_mutated_under_their_digest_refuse_open() -> TestResult {
    let cases = [
        (
            "root_exchange_policies_immutable",
            "UPDATE root_exchange_policies SET policy = x'7b7d';",
            RetainedArtifact::RootPolicy,
        ),
        (
            "root_exchange_provider_identities_immutable",
            "UPDATE root_exchange_provider_identities SET identity = x'7b7d';",
            RetainedArtifact::ProviderIdentity,
        ),
        (
            "root_exchange_key_snapshots_immutable",
            "UPDATE root_exchange_key_snapshots SET snapshot = x'7b7d';",
            RetainedArtifact::KeySnapshot,
        ),
        (
            "root_exchange_policies_immutable",
            "UPDATE root_exchange_policies SET root_policy_digest = '3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a';",
            RetainedArtifact::RootPolicy,
        ),
    ];
    for (trigger, sql, kind) in cases {
        let env = minted_env()?;
        let (_, reopened) = env.tamper_and_reopen(Some(trigger), sql)?;
        assert_eq!(reopened, I::RetainedDigestMismatch { kind }, "{sql}");
    }
    Ok(())
}

fn refused_insert(sql: &str) -> TestResult<i32> {
    let catalog = rusqlite::Connection::open_in_memory()?;
    catalog.execute_batch(include_str!("../src/root_exchange_store.sql"))?;
    refusal_code(catalog.execute(sql, []))
}

#[test]
fn ddl_checks_refuse_malformed_rows() -> TestResult {
    let upper = "A".repeat(64);
    let lower = hex(0x01);
    let cases = [
        format!(
            "INSERT INTO root_exchange_replay VALUES ('{upper}', 'client_assertion', 1, 2, NULL);"
        ),
        format!("INSERT INTO root_exchange_replay VALUES ('{lower}', 'saml', 1, 2, 'cap-1');"),
        format!(
            "INSERT INTO root_exchange_replay VALUES ('{lower}', 'client_assertion', 1, 2, 'cap-1');"
        ),
        format!("INSERT INTO root_exchange_replay VALUES ('{lower}', 'oidc_jwt', 1, 2, NULL);"),
        format!("INSERT INTO root_exchange_replay VALUES ('{lower}', 'oidc_jwt', 2, 2, 'cap-1');"),
        format!(
            "INSERT INTO root_exchange_openings VALUES ('cap-1', 'anchor.sub', 'present', x'{}', 1);",
            "00".repeat(31)
        ),
        format!(
            "INSERT INTO root_exchange_openings VALUES ('cap-1', 'anchor.sub', 'erased', x'{}', 1);",
            "00".repeat(32)
        ),
        "INSERT INTO root_exchange_openings VALUES ('cap-1', 'Anchor.sub', 'erased', NULL, 1);"
            .to_string(),
        format!("INSERT INTO root_exchange_events VALUES (1, 'rotate', 'cap-1', '{lower}');"),
    ];
    for sql in cases {
        assert_eq!(refused_insert(&sql)?, ffi::SQLITE_CONSTRAINT_CHECK, "{sql}");
    }
    Ok(())
}

/// One otherwise valid root row with `tenant_tag` set to `tenant`.
fn root_insert(tenant: &str) -> String {
    let h = hex(0x01);
    format!(
        "INSERT INTO root_exchange_roots VALUES ('cap-1', 'rule-1', '{h}', '{h}', {tenant}, \
         '{h}', 1, 'client-1', '{h}', '{h}', 10, 'chio_local_as', 'edge_session', '{h}', NULL, \
         NULL, '{h}', x'7b7d', x'7b7d', 1, '{h}');"
    )
}

#[test]
fn null_tenant_tag_refuses() -> TestResult {
    let catalog = rusqlite::Connection::open_in_memory()?;
    catalog.execute_batch(include_str!("../src/root_exchange_store.sql"))?;
    catalog.execute(&root_insert(&format!("'{}'", hex(0x02))), [])?;
    assert_eq!(
        refused_insert(&root_insert("NULL"))?,
        ffi::SQLITE_CONSTRAINT_NOTNULL
    );
    Ok(())
}

#[test]
fn replay_namespaces_admit_local_as_issue_and_re_exchange() -> TestResult {
    let catalog = rusqlite::Connection::open_in_memory()?;
    catalog.execute_batch(include_str!("../src/root_exchange_store.sql"))?;
    for (byte, namespace) in [(0x01, "chio_local_as_issue"), (0x02, "chio_local_as")] {
        catalog.execute(
            &format!(
                "INSERT INTO root_exchange_replay VALUES ('{}', '{namespace}', 1, 2, 'cap-1');",
                hex(byte)
            ),
            [],
        )?;
    }
    assert_eq!(
        refused_insert(&format!(
            "INSERT INTO root_exchange_replay VALUES ('{}', 'chio_local_as.re_exchange', 1, 2, 'cap-1');",
            hex(0x03)
        ))?,
        ffi::SQLITE_CONSTRAINT_CHECK
    );
    Ok(())
}

#[test]
fn foreign_catalog_layout_refuses_open() -> TestResult {
    for sql in [
        "CREATE INDEX root_exchange_roots_client ON root_exchange_roots(client_id);",
        "DROP INDEX root_exchange_roots_generation;",
        "DROP TRIGGER root_exchange_replay_immutable;",
        "CREATE TABLE root_exchange_extra (id INTEGER PRIMARY KEY);",
    ] {
        let env = minted_env()?;
        let fixture = env.fixture;
        drop(env.store);
        drop(env.owner);
        fixture.raw()?.execute_batch(sql)?;
        let error = match fixture.open() {
            Ok(_) => return Err(format!("open accepted {sql}").into()),
            Err(error) => error,
        };
        assert!(
            matches!(
                error.downcast_ref::<SqliteServingOwnerError>(),
                Some(SqliteServingOwnerError::Schema(
                    SchemaVersionError::CatalogMismatch
                ))
            ),
            "{sql}: {error}"
        );
        let raw = fixture.raw()?;
        let roots: i64 = raw.query_row("SELECT COUNT(*) FROM root_exchange_roots", [], |row| {
            row.get(0)
        })?;
        assert_eq!(roots, 1, "{sql}");
    }
    Ok(())
}
