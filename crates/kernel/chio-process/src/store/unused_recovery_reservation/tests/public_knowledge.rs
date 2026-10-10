//! Public checkpoint projection and activation retain authentic closed custody.
use super::*;
use serde_json::Value;

fn fixture_with_a_retained_public_checkpoint() -> TestResult<(Fixture, Value)> {
    let seed = Fixture::new()?;
    let root = seed.runtime.with_store(|store| store.process("root"))?;
    let path = seed._directory.path().join("public-checkpoint-process.db");
    let runtime = ProcessRuntime::open(&path, seed.runtime.kernel.clone())?.with_security_profile(
        ProcessSecurityProfile {
            tenant_id: "retained-checkpoint-tenant".into(),
            isolation_epoch_id: "retained-checkpoint-epoch".into(),
            generation: 1,
        },
    )?;
    runtime.create_root("root", &root.capability, root.limits)?;
    let fixture = Fixture {
        _directory: seed._directory,
        path,
        runtime,
        authority: seed.authority,
        kernel_key: seed.kernel_key,
    };
    assert_eq!(fixture.snapshot()?.version, 1);
    assert!(!fixture
        .runtime
        .enforcement
        .enforced(&fixture.runtime.namespace)?);
    let value = serde_json::json!({"retained": "actual-public-checkpoint-content"});
    let checkpoint = fixture.runtime.checkpoint("root", 0, value.clone())?;
    assert_eq!(checkpoint.revision, 1);
    assert_eq!(checkpoint.value, value);
    assert_eq!(fixture.runtime.process("root")?.checkpoint.value, value);
    fixture
        .runtime
        .with_store(|store| store.require_raw_knowledge())?;

    // Activation changes the real journal through the public owning API.
    // Native enforcement remains independently observable for this namespace.
    fixture.runtime.enable_durable_knowledge()?;
    assert_eq!(fixture.snapshot()?.version, 5);
    assert!(!fixture
        .runtime
        .enforcement
        .enforced(&fixture.runtime.namespace)?);
    assert_eq!(
        fixture.runtime.process("root")?.checkpoint.value,
        Value::Null
    );
    assert_eq!(retained_checkpoint(&fixture)?, value);
    Ok((fixture, value))
}

fn retained_checkpoint(fixture: &Fixture) -> TestResult<Value> {
    Ok(fixture
        .runtime
        .with_store(|store| Ok(store.process("root")?.checkpoint.value))?)
}

fn catalog_snapshot(fixture: &Fixture) -> TestResult<Vec<(String, String, Option<String>)>> {
    Ok(fixture.runtime.with_store(|store| {
        Ok(store
            .connection
            .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?)
    })?)
}

fn forge_raw_predecessor_without_changing_custody(fixture: &Fixture) -> TestResult<Snapshot> {
    let mut retained = fixture.snapshot()?;
    assert_eq!(retained.version, 6);
    assert_eq!(retained.tree_calls, 1);
    assert_eq!(retained.closures.len(), 1);
    assert!(retained.calls.is_empty());
    let catalog = catalog_snapshot(fixture)?;
    fixture.runtime.with_store(|store| {
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let guards = [
            "process_recovery_version_monotone",
            "process_knowledge_no_downgrade",
            "process_unused_recovery_version_no_downgrade",
        ];
        let definitions = guards
            .iter()
            .map(|name| {
                tx.query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        for guard in guards {
            tx.execute_batch(&format!("DROP TRIGGER {guard}"))?;
        }
        assert_eq!(
            tx.execute(
                "UPDATE process_runtime SET version=2 WHERE singleton=1 AND version=6",
                [],
            )?,
            1
        );
        for definition in definitions {
            tx.execute_batch(&definition)?;
        }
        super::super::catalog::verify(&tx)?;
        tx.commit()?;
        Ok(())
    })?;
    retained.version = 2;
    assert_eq!(fixture.snapshot()?, retained);
    assert_eq!(catalog_snapshot(fixture)?, catalog);
    Ok(retained)
}

#[test]
fn public_checkpoint_projection_refuses_a_forged_predecessor_over_retained_closed_custody(
) -> TestResult {
    let (fixture, checkpoint) = fixture_with_a_retained_public_checkpoint()?;
    let unused = fixture.reserve("retained-checkpoint-public-projection")?;
    let role = fixture
        .runtime
        .close_unused_recovery_reservation(&unused.reservation)?;
    role.verify_for(&unused.reservation, &fixture.authority)?;
    assert_eq!(
        fixture.runtime.process("root")?.checkpoint.value,
        Value::Null
    );
    assert!(fixture
        .runtime
        .with_store(|store| store.require_raw_knowledge())
        .is_err());
    let retained = forge_raw_predecessor_without_changing_custody(&fixture)?;
    assert!(Store::open(&fixture.path, &fixture.authority, &fixture.kernel_key).is_err());
    assert!(role
        .verify_for(&unused.reservation, &fixture.authority)
        .is_err());
    assert!(!fixture
        .runtime
        .enforcement
        .enforced(&fixture.runtime.namespace)?);
    let catalog = catalog_snapshot(&fixture)?;
    let projection = fixture.runtime.process("root");
    let raw_gate = fixture
        .runtime
        .with_store(|store| store.require_raw_knowledge());
    assert_eq!(fixture.snapshot()?, retained);
    assert_eq!(catalog_snapshot(&fixture)?, catalog);
    assert_eq!(retained_checkpoint(&fixture)?, checkpoint);
    let projected_value = projection.map(|process| process.checkpoint.value);
    let redacted = match &projected_value {
        Err(_) => true,
        Ok(value) => value == &Value::Null,
    };
    assert!(
        redacted,
        "the public warm projection exposed an actual retained checkpoint under a forged raw predecessor: projection={projected_value:?}; raw gate={raw_gate:?}"
    );
    assert!(raw_gate.is_err());
    Ok(())
}

#[test]
fn knowledge_activation_refuses_inconsistent_retained_custody_before_any_header_mutation(
) -> TestResult {
    let (fixture, checkpoint) = fixture_with_a_retained_public_checkpoint()?;
    let unused = fixture.reserve("retained-checkpoint-knowledge-activation")?;
    let role = fixture
        .runtime
        .close_unused_recovery_reservation(&unused.reservation)?;
    role.verify_for(&unused.reservation, &fixture.authority)?;
    let closed = fixture.snapshot()?;
    let catalog = catalog_snapshot(&fixture)?;
    fixture.runtime.enable_durable_knowledge()?;
    assert_eq!(fixture.snapshot()?, closed);
    assert_eq!(catalog_snapshot(&fixture)?, catalog);
    assert_eq!(retained_checkpoint(&fixture)?, checkpoint);
    let retained = forge_raw_predecessor_without_changing_custody(&fixture)?;
    assert!(Store::open(&fixture.path, &fixture.authority, &fixture.kernel_key).is_err());
    assert!(role
        .verify_for(&unused.reservation, &fixture.authority)
        .is_err());
    let catalog = catalog_snapshot(&fixture)?;
    let activation = fixture.runtime.enable_durable_knowledge();
    let after = fixture.snapshot()?;
    assert_eq!(catalog_snapshot(&fixture)?, catalog);
    assert_eq!(retained_checkpoint(&fixture)?, checkpoint);
    assert!(
        activation.is_err(),
        "inconsistent retained custody cannot enable a Knowledge broker"
    );
    assert_eq!(
        after, retained,
        "public Knowledge activation refused only after committing a journal mutation"
    );
    Ok(())
}
