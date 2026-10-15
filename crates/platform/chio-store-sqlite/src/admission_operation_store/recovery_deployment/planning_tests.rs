//! Planning allocation algebra and its authenticated presence boundary.

use rusqlite::Connection;

use super::super::tests::{authority, deployment, TestResult};
use super::*;

const RECORDS: &str = include_str!("../../admission_operation_recovery.sql");

fn domain() -> TestResult<AuthorityDomainId> {
    Ok(AuthorityDomainId::new("planning-authority")?)
}

fn budget(tenant: Option<&str>, writes: u64) -> TestResult<PlanningBudget> {
    Ok(PlanningBudget {
        schema: PlanningBudgetSchema::V1,
        authority_domain: domain()?,
        tenant_id: tenant.map(RecoveryTenantId::new).transpose()?,
        writes: SafeInteger::new(writes)?,
    })
}

fn catalog_without_global_chain() -> TestResult<Connection> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(RECORDS)?;
    Ok(connection)
}

#[test]
fn pristine_pre_global_bootstrap_has_no_planning_history() -> TestResult {
    let connection = catalog_without_global_chain()?;
    assert!(!any_planning_history(&connection)?);
    verify_planning_allocations(&connection)?;
    connection.execute_batch(
        "CREATE TABLE chio_serving_owner(
            singleton INTEGER PRIMARY KEY, owner_epoch INTEGER NOT NULL, lease_id TEXT);
         INSERT INTO chio_serving_owner VALUES(1, 0, NULL);",
    )?;
    assert!(!any_planning_history(&connection)?);
    verify_planning_allocations(&connection)?;
    Ok(())
}

#[test]
fn established_owner_without_global_chain_refuses() -> TestResult {
    let connection = catalog_without_global_chain()?;
    connection.execute_batch(
        "CREATE TABLE chio_serving_owner(
            singleton INTEGER PRIMARY KEY, owner_epoch INTEGER NOT NULL, lease_id TEXT);
         INSERT INTO chio_serving_owner VALUES(1, 1, NULL);",
    )?;
    let refused = || {
        Err(invariant(
            "established recovery owner lost its global authority chain",
        ))
    };
    assert_eq!(any_planning_history(&connection), refused());
    connection.execute(
        "UPDATE chio_serving_owner SET owner_epoch = 0, lease_id = 'active-owner'",
        [],
    )?;
    assert_eq!(any_planning_history(&connection), refused());
    Ok(())
}

#[test]
fn retained_or_partial_recovery_without_global_chain_refuses() -> TestResult {
    let retained = catalog_without_global_chain()?;
    retained.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('deployment:retained', ?1, 'deployment', 1, X'7B7D')",
        ["ab".repeat(32)],
    )?;
    let partial = catalog_without_global_chain()?;
    partial.execute_batch(
        "CREATE TABLE authority_global_commit_meta(
            singleton INTEGER PRIMARY KEY, head_sequence INTEGER NOT NULL,
            head_chain_digest TEXT NOT NULL);",
    )?;
    for connection in [retained, partial] {
        assert_eq!(
            any_planning_history(&connection),
            Err(invariant(
                "recovery history lost its global authority chain"
            ))
        );
        assert_eq!(
            verify_planning_allocations(&connection),
            Err(invariant(
                "recovery history lost its global authority chain"
            ))
        );
    }
    Ok(())
}

#[test]
fn allocations_start_empty() -> TestResult {
    let tenant = RecoveryTenantId::new("late-tenant")?;
    let fresh = new_budget(&domain()?, Some(&tenant), &Usage::default())?;
    assert_eq!(fresh.writes, SafeInteger::ZERO);
    for usage in [
        Usage {
            bytes: 100,
            events: 0,
        },
        Usage {
            bytes: 0,
            events: 1,
        },
    ] {
        assert!(matches!(
            new_budget(&domain()?, Some(&tenant), &usage),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message == "recovery planning tenant lost its allocation"
        ));
    }
    Ok(())
}

#[test]
fn global_and_tenant_ceilings_refuse_the_next_write_without_counting_it() -> TestResult {
    for (tenant, bytes, events, exhausted) in [
        (
            None,
            GLOBAL_BYTES,
            GLOBAL_EVENTS,
            "recovery planning resource exhausted",
        ),
        (
            Some("tenant"),
            TENANT_BYTES,
            TENANT_EVENTS,
            "recovery tenant planning resource exhausted",
        ),
    ] {
        let mut current = budget(tenant, 1)?;
        let full = Usage { bytes, events: 1 };
        next_budget(&mut current, &full, 100, 100)?;
        assert_eq!(current.writes.get(), 2, "freed bytes are reusable");
        for (usage, old, new) in [
            (full, 100, 101),
            (full, 0, 1),
            (Usage { bytes: 0, events }, 0, 1),
        ] {
            assert!(matches!(
                next_budget(&mut current, &usage, old, new),
                Err(AdmissionOperationStoreError::Invariant(message)) if message == exhausted
            ));
            assert_eq!(current.writes.get(), 2);
        }
        let below = Usage {
            bytes: 0,
            events: events - 1,
        };
        next_budget(&mut current, &below, 0, 1)?;
        assert_eq!(current.writes.get(), 3);
    }
    Ok(())
}

/// The real retained allocations of an installed deployment refuse a usage
/// above their ceiling, a changed authenticated count and a lost first write.
#[test]
fn retained_allocations_bind_their_authenticated_usage() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    let raw = Connection::open(&fixture.database)?;
    let physical = physical_domain(&raw)?;
    let tenant = profile.scope.tenant_id.clone();
    let inventory = inventory(&raw, &physical)?;
    assert_eq!(inventory.global.events, 2);
    assert_eq!(inventory.tenants.get(&tenant), Some(&inventory.global));
    let global = load(&raw, &physical, None, &inventory.global)?.ok_or("global allocation")?;
    assert_eq!(global.writes.get(), 2);
    let tenant_budget =
        load(&raw, &physical, Some(&tenant), &inventory.global)?.ok_or("tenant allocation")?;
    assert_eq!(tenant_budget.writes.get(), 2);
    let counters = || Err(invariant("recovery planning quota counters changed"));
    for usage in [
        Usage {
            bytes: GLOBAL_BYTES + 1,
            events: 2,
        },
        Usage {
            bytes: inventory.global.bytes,
            events: 3,
        },
    ] {
        assert_eq!(load(&raw, &physical, None, &usage).map(|_| ()), counters());
    }
    assert_eq!(
        load(
            &raw,
            &physical,
            Some(&tenant),
            &Usage {
                bytes: TENANT_BYTES + 1,
                events: 2
            }
        )
        .map(|_| ()),
        counters()
    );
    let tampered = Connection::open(&fixture.database)?;
    let guard: String = tampered.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
         AND name = 'admission_operation_recovery_event_no_delete'",
        [],
        |row| row.get(0),
    )?;
    tampered.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_delete;")?;
    tampered.execute(
        "DELETE FROM admission_operation_recovery_events
         WHERE record_key = ?1 AND record_version = 1",
        [metadata_key(&physical, None)?],
    )?;
    tampered.execute_batch(&guard)?;
    assert_eq!(
        load(&raw, &physical, None, &inventory.global).map(|_| ()),
        Err(invariant("recovery planning baseline changed"))
    );
    Ok(())
}
