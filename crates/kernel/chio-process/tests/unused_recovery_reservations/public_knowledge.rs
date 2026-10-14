//! Public checkpoint projection and activation retain authentic closed custody.
use super::*;
use chio_process::admission_test_support::{admission_catalog_verify, AdmissionJournalWriter};
use serde_json::Value;

fn raw_journal_fixture(journal: &str, tenant: &str, epoch: &str) -> TestResult<Fixture> {
    let seed = Fixture::new()?;
    let root = seed
        .runtime
        .admission_inspect(|store| store.process("root"))?;
    let path = seed._directory.path().join(journal);
    let runtime = ProcessRuntime::open(&path, seed.kernel.clone())?.with_security_profile(
        ProcessSecurityProfile {
            tenant_id: tenant.into(),
            isolation_epoch_id: epoch.into(),
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
        kernel: seed.kernel,
    };
    assert_eq!(fixture.snapshot()?.version, 1);
    assert!(!fixture
        .runtime
        .admission_knowledge_enforcement()
        .enforced(fixture.runtime.admission_namespace())?);
    Ok(fixture)
}

fn fixture_with_a_retained_public_checkpoint() -> TestResult<(Fixture, Value)> {
    let fixture = raw_journal_fixture(
        "public-checkpoint-process.db",
        "retained-checkpoint-tenant",
        "retained-checkpoint-epoch",
    )?;
    let value = serde_json::json!({"retained": "actual-public-checkpoint-content"});
    let checkpoint = fixture.runtime.checkpoint("root", 0, value.clone())?;
    assert_eq!(checkpoint.revision, 1);
    assert_eq!(checkpoint.value, value);
    assert_eq!(fixture.runtime.process("root")?.checkpoint.value, value);
    fixture
        .runtime
        .admission_inspect(|store| store.require_raw_knowledge())?;

    // Activation changes the real journal through the public owning API.
    // Native enforcement remains independently observable for this namespace.
    fixture.runtime.enable_durable_knowledge()?;
    assert_eq!(fixture.snapshot()?.version, 5);
    assert!(!fixture
        .runtime
        .admission_knowledge_enforcement()
        .enforced(fixture.runtime.admission_namespace())?);
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
        .admission_inspect(|store| Ok(store.process("root")?.checkpoint.value))?)
}

fn catalog_snapshot(fixture: &Fixture) -> TestResult<Vec<(String, String, Option<String>)>> {
    Ok(fixture.runtime.admission_inspect(|store| {
        Ok(store
            .connection()
            .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY type,name")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    })?)
}

fn forge_raw_predecessor_without_changing_custody(fixture: &Fixture) -> TestResult<Snapshot> {
    let mut retained = fixture.snapshot()?;
    assert_eq!(retained.version, 6);
    assert_eq!(retained.tree_calls, 1);
    assert_eq!(retained.closures.len(), 1);
    assert!(retained.calls.is_empty());
    let catalog = catalog_snapshot(fixture)?;
    fixture.runtime.admission_inspect(|store| {
        let tx = store.corruption_transaction(rusqlite::TransactionBehavior::Immediate)?;
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
            .collect::<std::result::Result<Vec<_>, _>>()?;
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
        admission_catalog_verify(&tx)?;
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
        .admission_inspect(|store| store.require_raw_knowledge())
        .is_err());
    let retained = forge_raw_predecessor_without_changing_custody(&fixture)?;
    assert!(
        AdmissionJournalWriter::open(&fixture.path, &fixture.authority, &fixture.kernel_key)
            .is_err()
    );
    assert!(role
        .verify_for(&unused.reservation, &fixture.authority)
        .is_err());
    assert!(!fixture
        .runtime
        .admission_knowledge_enforcement()
        .enforced(fixture.runtime.admission_namespace())?);
    let catalog = catalog_snapshot(&fixture)?;
    let projection = fixture.runtime.process("root");
    let raw_gate = fixture
        .runtime
        .admission_inspect(|store| store.require_raw_knowledge());
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
    assert!(
        AdmissionJournalWriter::open(&fixture.path, &fixture.authority, &fixture.kernel_key)
            .is_err()
    );
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

#[test]
fn mediated_staging_never_adopts_or_reveals_a_quarantined_raw_state_blob() -> TestResult {
    use chio_core_types::recovery::knowledge_content_digest;
    use chio_kernel::knowledge::ArtifactBlobPort;
    use chio_security_types::recovery::ArtifactObjectId;

    let fixture = raw_journal_fixture(
        "quarantined-blob-process.db",
        "quarantined-blob-tenant",
        "quarantined-blob-epoch",
    )?;
    let bytes = b"raw bytes written before mediated release".as_slice();
    let legacy = fixture.runtime.put_blob("root", bytes)?;
    let legacy_row = |fixture: &Fixture| -> TestResult<(String, i64, Vec<u8>)> {
        Ok(fixture.runtime.admission_inspect(|store| {
            Ok(store.connection().query_row(
                "SELECT knowledge_generation,legacy_quarantined,data FROM process_state_blobs
                 WHERE process_id='root' AND sha256=?1",
                [&legacy.sha256],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?)
        })?)
    };
    let before = legacy_row(&fixture)?;
    assert_eq!(before.1, 1);

    let broker = fixture.runtime.enable_durable_knowledge()?;
    let process = ProcessId::new("root")?;
    assert_eq!(broker.storage_usage(&process)?.tree_blobs, 1);

    // The raw routes disappear for the whole journal, so no raw dedup, size or
    // existence answer remains observable for a quarantined row.
    assert!(fixture.runtime.put_blob("root", bytes).is_err());
    assert!(fixture.runtime.read_blob("root", &legacy.sha256).is_err());
    assert!(fixture.runtime.storage("root").is_err());

    let object = ArtifactObjectId::new("mediated-copy")?;
    let seal = broker.stage(&object, &process, bytes)?;
    assert_eq!(seal.content, knowledge_content_digest(bytes));
    assert!(seal.generation.as_str().starts_with("object:"));
    assert_ne!(
        seal.generation.as_str().trim_start_matches("object:"),
        before.0,
        "mediated staging adopted the quarantined row's generation"
    );
    assert_eq!(
        broker.storage_usage(&process)?.tree_blobs,
        2,
        "mediated staging must charge its own row instead of deduplicating into the raw row"
    );
    assert_eq!(legacy_row(&fixture)?, before);
    assert_eq!(broker.stage(&object, &process, bytes)?, seal);
    Ok(())
}
