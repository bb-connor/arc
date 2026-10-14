//! The scoped imported-influence reader against the original full-scan formula,
//! on a real imported and hydrated authority.
use super::*;
use chio_security_types::ports::{FlowStateKey, IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::PrincipalId;
use chio_semantic_contracts::VerificationBudget;

const INDEX_TABLE: &str = "security_participant_state_imported_scope_index";

fn flow(
    tenant: &str,
    principal: &str,
    lineage: &str,
    epoch: &str,
    session: &str,
) -> AnchoredTestResult<FlowStateKey> {
    Ok(FlowStateKey {
        tenant_id: TenantId::new(tenant)?,
        principal_id: PrincipalId::new(principal)?,
        lineage_id: LineageId::new(lineage)?,
        isolation_epoch_id: IsolationEpochId::new(epoch)?,
        session_id: SessionId::new(session)?,
    })
}

fn hydrated(
    fixture: &Fixture,
) -> AnchoredTestResult<(
    SecurityParticipantStateInitialization,
    chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
)> {
    let source = imported(fixture, "source")?;
    let initialized = hydrate(fixture, &source)?;
    let binding = initialized.admission_binding()?;
    Ok((initialized, binding))
}

fn scoped(
    fixture: &Fixture,
    binding: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    key: &FlowStateKey,
    units: u32,
) -> AnchoredTestResult<Option<chio_security_types::recovery::CanonicalPayloadDigest>> {
    let connection = fixture.store.connection()?;
    let mut budget = VerificationBudget::new(units)?;
    Ok(
        native::knowledge::budgeted_observed_influence(&connection, binding, key, &mut budget)?
            .map(|influence| influence.commitment),
    )
}

/// Drop every immutability guard of one table, apply the damage, and restore
/// each guard from its own captured definition so the intended integrity check
/// runs instead of a trigger refusal.
fn damaged(database: &std::path::Path, table: &str, damage: &str) -> AnchoredTestResult {
    let connection = Connection::open(database)?;
    connection.pragma_update(None, "foreign_keys", false)?;
    apply_damage(&connection, table, damage)
}

fn apply_damage(connection: &Connection, table: &str, damage: &str) -> AnchoredTestResult {
    let guards: Vec<(String, String)> = {
        let mut statement = connection.prepare(
            "SELECT name, sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=?1 ORDER BY name",
        )?;
        let rows = statement.query_map([table], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    for (name, _) in &guards {
        connection.execute_batch(&format!("DROP TRIGGER \"{name}\""))?;
    }
    let changed = connection.execute(damage, [])?;
    for (_, sql) in &guards {
        connection.execute_batch(sql)?;
    }
    assert!(changed >= 1, "nothing to damage: {damage}");
    Ok(())
}

/// Damage a clean hydrated authority while no owner serves it, then report
/// whether the public serving open refuses it. Opening the undamaged authority
/// first proves the refusal comes from the damage. Damaging a closed database
/// reaches the deep validation instead of the live owner's external-write guard.
fn damaged_authority_refuses_reopen(table: &str, damage: &str) -> AnchoredTestResult<bool> {
    let fixture = fixture();
    hydrated(&fixture)?;
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    drop(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    damaged(&database, table, damage)?;
    Ok(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err())
}

#[test]
fn scoped_reader_equals_the_full_scan_formula_for_every_inherited_scope() -> AnchoredTestResult {
    let fixture = fixture();
    let (initialized, binding) = hydrated(&fixture)?;
    let exact = flow("tenant", "principal", "lineage", "epoch", "session")?;
    let lineage_only = flow(
        "tenant",
        "other-principal",
        "lineage",
        "other-epoch",
        "other",
    )?;
    let principal_only = flow("tenant", "principal", "other-lineage", "epoch", "other")?;
    let tenant_only = flow(
        "tenant",
        "other-principal",
        "other-lineage",
        "other-epoch",
        "other",
    )?;
    let absent = flow("absent-tenant", "principal", "lineage", "epoch", "session")?;
    for key in [
        &exact,
        &lineage_only,
        &principal_only,
        &tenant_only,
        &absent,
    ] {
        let oracle = {
            let connection = fixture.store.connection()?;
            native::knowledge::full_scan_commitment(&connection, &initialized, key)?
        };
        assert_eq!(scoped(&fixture, &binding, key, 4096)?, oracle);
    }
    // The matching flow reaches real imported history, and a flow of an absent
    // tenant stays inside a small fixed budget however much history exists.
    assert!(scoped(&fixture, &binding, &exact, 4096)?.is_some());
    assert!(scoped(&fixture, &binding, &absent, 200)?.is_none());
    crate::admission_operation_store::verify_initialized_scope_projections(
        &*fixture.store.connection()?,
    )?;
    Ok(())
}

/// One hydrated tree serves every position. Each interior leaf is deleted
/// inside a savepoint on the fixture connection and rolled back afterwards, so
/// every position is tested against the same leaf order. The seeded exact and
/// new-epoch flows together with the tenant-wide flow read every scope the
/// seeded history populates, so an interior leaf that is missing must break an
/// authenticated read. Every flow either still reads exactly its pre-damage
/// full-scan answer (it never used that leaf) or refuses, and at least one flow
/// refuses for every interior position: no absence is ever forged.
#[test]
fn deleting_an_interior_leaf_never_forges_an_absence_proof() -> AnchoredTestResult {
    let fixture = fixture();
    let (initialized, binding) = hydrated(&fixture)?;
    let flows = [
        flow("tenant", "principal", "lineage", "epoch", "session")?,
        flow("tenant", "principal", "lineage", "new-epoch", "new-session")?,
        flow(
            "tenant",
            "other-principal",
            "other-lineage",
            "other-epoch",
            "other",
        )?,
        flow(
            "tenant",
            "other-principal",
            "lineage",
            "other-epoch",
            "other",
        )?,
    ];
    let mut baseline = Vec::new();
    for key in &flows {
        let oracle = {
            let connection = fixture.store.connection()?;
            native::knowledge::full_scan_commitment(&connection, &initialized, key)?
        };
        assert_eq!(scoped(&fixture, &binding, key, 4096)?, oracle);
        baseline.push(oracle);
    }
    assert!(
        baseline[0].is_some(),
        "the exact seeded flow has no history"
    );
    let layout: Vec<(i64, i64)> = {
        let connection = fixture.store.connection()?;
        let mut statement = connection.prepare(&format!(
            "SELECT leaf_index, member_count FROM {INDEX_TABLE} ORDER BY leaf_index"
        ))?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    let leaves = i64::try_from(layout.len())?;
    assert!(
        layout
            .iter()
            .zip(0..)
            .all(|((index, _), position)| *index == position),
        "index leaves are not contiguous: {layout:?}"
    );
    assert!(leaves >= 3, "no interior leaf to delete: {layout:?}");
    // The fixture connection is held for the rest of the test; the readers below
    // take the savepoint directly instead of locking the fixture again.
    let mut connection = fixture.store.connection()?;
    for index in 1..leaves - 1 {
        let mut savepoint = connection.savepoint()?;
        apply_damage(
            &savepoint,
            INDEX_TABLE,
            &format!("DELETE FROM {INDEX_TABLE} WHERE leaf_index = {index}"),
        )?;
        let mut refused = false;
        for (key, oracle) in flows.iter().zip(&baseline) {
            let mut budget = VerificationBudget::new(4096)?;
            match native::knowledge::budgeted_observed_influence(
                &savepoint,
                &binding,
                key,
                &mut budget,
            ) {
                Ok(influence) => assert_eq!(
                    influence.map(|influence| influence.commitment),
                    *oracle,
                    "interior leaf {index} forged an answer: {layout:?}"
                ),
                Err(_) => refused = true,
            }
        }
        assert!(
            refused,
            "no seeded flow read interior leaf {index}: {layout:?}"
        );
        assert!(
            crate::admission_operation_store::verify_initialized_scope_projections(&savepoint)
                .is_err(),
            "interior leaf {index}"
        );
        savepoint.rollback()?;
    }
    drop(connection);
    drop(fixture);
    assert!(
        damaged_authority_refuses_reopen(
            INDEX_TABLE,
            &format!("DELETE FROM {INDEX_TABLE} WHERE leaf_index = 1"),
        )?,
        "public reopen accepted a deleted interior leaf"
    );
    Ok(())
}

#[test]
fn damaged_source_rows_index_leaves_or_root_refuse_the_scoped_read() -> AnchoredTestResult {
    let root = "UPDATE admission_operation_recovery_records SET payload = X'7b7d'
                WHERE record_key GLOB 'knowledge-imported-influence-root:*'";
    let relevant = "UPDATE security_participant_migration_rows SET canonical_row = X'007b7d'
                    WHERE table_name IN ('security_transitions', 'security_lineage_flow_state',
                                         'security_principal_flow_state')";
    let digest = format!("UPDATE {INDEX_TABLE} SET member_digest = printf('%064d', 0)");
    let proof = format!("UPDATE {INDEX_TABLE} SET inclusion_proof = X'7b7d'");
    let members = format!("UPDATE {INDEX_TABLE} SET members = X'5b5d'");
    let falsely_absent = format!("DELETE FROM {INDEX_TABLE}");
    // The retained recovery events and global commits of the root remain.
    let root_deleted = "DELETE FROM admission_operation_recovery_records
                        WHERE record_key GLOB 'knowledge-imported-influence-root:*'";
    for (table, damage) in [
        ("security_participant_migration_rows", relevant),
        (INDEX_TABLE, digest.as_str()),
        (INDEX_TABLE, proof.as_str()),
        (INDEX_TABLE, members.as_str()),
        (INDEX_TABLE, falsely_absent.as_str()),
        ("admission_operation_recovery_records", root),
        ("admission_operation_recovery_records", root_deleted),
    ] {
        let fixture = fixture();
        let (_, binding) = hydrated(&fixture)?;
        let exact = flow("tenant", "principal", "lineage", "epoch", "session")?;
        assert!(scoped(&fixture, &binding, &exact, 4096)?.is_some());
        damaged(&fixture.database, table, damage)?;
        assert!(
            scoped(&fixture, &binding, &exact, 4096).is_err(),
            "{damage}"
        );
        if table == "security_participant_migration_rows" {
            // Reader unit behavior only: the damaged rows belong to the tenant
            // under test, so a flow of another tenant selects none of them and
            // still reads its authenticated absence after direct connection
            // damage. The public path fails closed on the same damage through
            // the owner's external-write protection and cold source rehash.
            let absent = flow("absent-tenant", "principal", "lineage", "epoch", "session")?;
            assert_eq!(scoped(&fixture, &binding, &absent, 200)?, None);
        }
        if damage == root_deleted {
            assert!(
                damaged_authority_refuses_reopen(table, damage)?,
                "public reopen accepted a deleted root with retained custody"
            );
        }
        assert!(
            crate::admission_operation_store::verify_initialized_scope_projections(
                &*fixture.store.connection()?
            )
            .is_err(),
            "{damage}"
        );
    }
    Ok(())
}
