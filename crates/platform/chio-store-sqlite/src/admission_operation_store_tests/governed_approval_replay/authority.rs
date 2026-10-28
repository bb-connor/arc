use super::*;

fn installs(fixture: &Fixture) -> AnchoredTestResult<i64> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM governed_approval_replay_authorities",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn install_is_idempotent_and_conflicting_installs_refuse_before_mutation() -> AnchoredTestResult {
    let fixture = fixture();
    let before = global_count(&fixture);
    let binding = install(&fixture)?;
    assert_eq!(global_count(&fixture), before + 1);
    install(&fixture)?;
    assert_eq!(global_count(&fixture), before + 1);
    let conflicts = [
        (binding.clone(), CAPACITY + 1),
        (
            GovernedApprovalAuthorityBindingV1::new(
                binding.approval_authority_id().clone(),
                identifier("expectation", "other-generation"),
            ),
            CAPACITY,
        ),
        (
            GovernedApprovalAuthorityBindingV1::new(
                identifier("authority", "other-authority"),
                binding.expectation_id().clone(),
            ),
            CAPACITY,
        ),
        (
            GovernedApprovalAuthorityBindingV1::new(
                identifier("authority", "zero-capacity"),
                identifier("expectation", "zero-capacity"),
            ),
            0,
        ),
    ];
    for (candidate, capacity) in conflicts {
        assert!(
            fixture
                .store
                .install_governed_approval_authority(&candidate, capacity, &fixture.fence, now_ms())
                .is_err(),
            "{candidate:?} {capacity}"
        );
        assert_eq!(global_count(&fixture), before + 1);
        assert_eq!(installs(&fixture)?, 1);
    }
    verify_admission_operation_invariants(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn load_requires_the_exact_installed_generation() -> AnchoredTestResult {
    let fixture = fixture();
    assert!(fixture
        .store
        .load_governed_approval_authority(&binding(), &fixture.fence, now_ms())
        .is_err());
    let binding = install(&fixture)?;
    let installed =
        fixture
            .store
            .load_governed_approval_authority(&binding, &fixture.fence, now_ms())?;
    assert_eq!(installed.binding(), &binding);
    assert_eq!(installed.capacity(), CAPACITY);
    assert_eq!(installed.destination_store_uuid(), fixture.fence.store_uuid);
    let wrong = GovernedApprovalAuthorityBindingV1::new(
        binding.approval_authority_id().clone(),
        identifier("expectation", "other-generation"),
    );
    assert!(fixture
        .store
        .load_governed_approval_authority(&wrong, &fixture.fence, now_ms())
        .is_err());
    Ok(())
}

#[test]
fn install_rows_are_immutable_and_tampering_is_detected() -> AnchoredTestResult {
    let fixture = fixture();
    let binding = install(&fixture)?;
    for statement in [
        "UPDATE governed_approval_replay_authorities SET capacity = 1",
        "DELETE FROM governed_approval_replay_authorities",
        "INSERT OR REPLACE INTO governed_approval_replay_authorities
         SELECT * FROM governed_approval_replay_authorities",
    ] {
        assert!(
            fixture
                .store
                .connection()?
                .execute_batch(statement)
                .is_err(),
            "{statement}"
        );
    }
    fixture.store.connection()?.execute_batch(
        "DROP TRIGGER governed_approval_replay_authorities_immutable;
         UPDATE governed_approval_replay_authorities SET capacity = capacity + 1",
    )?;
    assert!(fixture
        .store
        .load_governed_approval_authority(&binding, &fixture.fence, now_ms())
        .is_err());
    assert!(verify_admission_operation_invariants(&*fixture.store.connection()?).is_err());
    Ok(())
}

#[test]
fn install_copied_from_another_store_is_refused() -> AnchoredTestResult {
    let source = fixture();
    install(&source)?;
    let destination = fixture();
    assert_ne!(source.fence.store_uuid, destination.fence.store_uuid);
    let row: (
        String,
        String,
        String,
        i64,
        i64,
        String,
        String,
        String,
        i64,
    ) = source.store.connection()?.query_row(
        "SELECT * FROM governed_approval_replay_authorities",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    let raw = Connection::open(&destination.database)?;
    raw.execute_batch("PRAGMA foreign_keys = OFF;")?;
    raw.execute(
        "INSERT INTO governed_approval_replay_authorities VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![row.0, row.1, row.2, row.3, row.4, row.5, row.6, row.7, row.8],
    )?;
    drop(raw);
    assert!(destination
        .store
        .load_governed_approval_authority(&binding(), &destination.fence, now_ms())
        .is_err());
    assert!(destination
        .store
        .install_governed_approval_authority(&binding(), CAPACITY, &destination.fence, now_ms())
        .is_err());
    Ok(())
}

#[test]
fn authority_clock_before_the_install_is_refused() -> AnchoredTestResult {
    let fixture = fixture();
    let binding = install(&fixture)?;
    let earlier = now_ms() / 1000 - 60;
    let _clock = chio_test_support::clock::scope_unix_secs(earlier);
    assert!(fixture
        .store
        .load_governed_approval_authority(&binding, &fixture.fence, earlier * 1000)
        .is_err());
    Ok(())
}
