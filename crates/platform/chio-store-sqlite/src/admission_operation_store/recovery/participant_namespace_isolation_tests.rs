//! The generic participant writer cannot enter recovery-owned namespaces.
//! Foreign semantic, knowledge, confinement, product and setup families keep
//! their exact owning writer; command, workflow, quota, planning, capacity and
//! original-ownership keys refuse before any payload or quota is consulted.
use super::*;
use crate::serving_owner::ProvisionedAuthority;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    store: SqliteAdmissionOperationStore,
    scope: RecoveryScopeV1,
    foreign_scope: RecoveryScopeV1,
    provisioned_records: i64,
    _authority: ProvisionedAuthority,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let authority = ProvisionedAuthority::open();
        let store = authority.authority.admission_operation_store();
        let provisioned_records: i64 = {
            let mut connection = store.connection()?;
            let read = store.begin_read(&mut connection)?;
            let records: i64 = read.query_row(
                "SELECT count(*) FROM admission_operation_recovery_records",
                [],
                |row| row.get(0),
            )?;
            read.commit()?;
            records
        };
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("participant-isolation-authority")?,
            tenant_id: RecoveryTenantId::new("participant-isolation-tenant")?,
            process_id: ProcessId::new("participant-isolation-process")?,
        };
        let foreign_scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("participant-isolation-authority")?,
            tenant_id: RecoveryTenantId::new("participant-isolation-foreign-tenant")?,
            process_id: ProcessId::new("participant-isolation-foreign-process")?,
        };
        Ok(Self {
            _authority: authority,
            store,
            scope,
            foreign_scope,
            provisioned_records,
        })
    }

    /// One refused participant write leaves no row, event or global commit.
    fn refuse(&self, key: &str, kind: &str, payload: &[u8], reason: &str) -> TestResult {
        let expected = format!("admission operation invariant failed: {reason}");
        let mut connection = self.store.connection()?;
        let before = connection.total_changes();
        let tx = self
            .store
            .begin_write(&mut connection, Some(&self.store.serving_owner.fence))?;
        let error = save(
            &tx,
            &self.store.serving_owner,
            key,
            &scope_key(&self.scope)?,
            kind,
            payload,
            None,
        )
        .err()
        .ok_or("the generic participant writer accepted a recovery-owned key")?;
        assert_eq!(error.to_string(), expected);
        assert!(raw(&tx, key)?.is_none());
        let events: i64 = tx.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events WHERE record_key=?1",
            params![key],
            |row| row.get(0),
        )?;
        assert_eq!(events, 0);
        tx.rollback()?;
        assert_eq!(connection.total_changes(), before);
        Ok(())
    }
}

#[test]
fn participant_writer_refuses_recovery_owned_record_namespaces() -> TestResult {
    let fixture = Fixture::new()?;
    let scope = scope_key(&fixture.scope)?;
    let workflow = WorkflowId::new("participant-isolation-workflow")?;
    let payload = encode(&serde_json::json!({"fixture": "participant isolation"}))?;
    for (key, kind) in [
        (
            format!("command:{}", sha256_hex(&encode(&"participant-command")?)),
            "command",
        ),
        (workflow_key(&fixture.scope, &workflow)?, "workflow"),
        (
            format!("workflow-quota:{scope}:{}", workflow.as_str()),
            "command",
        ),
        (
            format!(
                "recovery-planning-quota:{}:tenant:{}",
                sha256_hex(&encode(&"participant-planning-owner")?),
                sha256_hex(&encode(&"participant-planning-tenant")?)
            ),
            "command",
        ),
        (format!("recovery-workflow-capacity:{scope}"), "command"),
        (
            format!("recovery-workflow-allocation:{scope}:{}", workflow.as_str()),
            "command",
        ),
        (
            format!("recovery-original-owner:{}", "0".repeat(64)),
            "command",
        ),
    ] {
        fixture.refuse(
            &key,
            kind,
            &payload,
            "protected record namespace or kind refused",
        )?;
    }
    Ok(())
}

#[test]
fn participant_writer_refuses_foreign_scoped_deployment_custody() -> TestResult {
    let fixture = Fixture::new()?;
    let foreign = scope_key(&fixture.foreign_scope)?;
    let payload = encode(&serde_json::json!({"fixture": "participant isolation"}))?;
    fixture.refuse(
        &format!("deployment:{foreign}"),
        "deployment",
        &payload,
        "protected record namespace or kind refused",
    )?;
    fixture.refuse(
        &format!("deployment-history:{foreign}:{}", "0".repeat(64)),
        "deployment",
        &payload,
        "protected record namespace or kind refused",
    )?;
    Ok(())
}

#[test]
fn participant_writer_refuses_untyped_planning_family_substitutes() -> TestResult {
    let fixture = Fixture::new()?;
    let scope = scope_key(&fixture.scope)?;
    let forged_origin = encode(&serde_json::json!({
        "origin_claim": "forged participant claim"
    }))?;
    fixture.refuse(
        &format!("recovery-origin:{}", "0".repeat(64)),
        "command",
        &forged_origin,
        "recovery record is corrupt",
    )?;
    let substitute_deployment = encode(&serde_json::json!({
        "participant": "deployment substitute"
    }))?;
    fixture.refuse(
        &format!("deployment:{scope}"),
        "deployment",
        &substitute_deployment,
        "recovery record is corrupt",
    )?;
    Ok(())
}

#[test]
fn participant_writer_retains_the_exact_foreign_family_owner() -> TestResult {
    let fixture = Fixture::new()?;
    let scope = scope_key(&fixture.scope)?;
    let key = format!("knowledge-pin:{scope}:participant-isolation-owner");
    let payload = encode(&serde_json::json!({"fixture": "participant isolation"}))?;
    {
        let mut connection = fixture.store.connection()?;
        let tx = fixture
            .store
            .begin_write(&mut connection, Some(&fixture.store.serving_owner.fence))?;
        save(
            &tx,
            &fixture.store.serving_owner,
            &key,
            &scope,
            "command",
            &payload,
            None,
        )?;
        assert_eq!(
            raw(&tx, &key)?
                .ok_or("accepted participant row is absent")?
                .version,
            1
        );
        save(
            &tx,
            &fixture.store.serving_owner,
            &key,
            &scope,
            "command",
            &payload,
            None,
        )?;
        assert_eq!(
            raw(&tx, &key)?
                .ok_or("accepted participant row is absent")?
                .version,
            2
        );
        let foreign_scope = scope_key(&fixture.foreign_scope)?;
        for (replacement_scope, replacement_kind) in [
            (foreign_scope.as_str(), "command"),
            (scope.as_str(), "workflow"),
        ] {
            let before = tx.total_changes();
            let error = persist_record(
                &tx,
                &fixture.store.serving_owner,
                &key,
                replacement_scope,
                replacement_kind,
                &payload,
                None,
            )
            .err()
            .ok_or("participant record ownership was rebound")?;
            assert_eq!(
                error.to_string(),
                "admission operation invariant failed: protected record ownership changed"
            );
            assert_eq!(tx.total_changes(), before);
        }
        fixture.store.commit_write(tx)?;
        fixture.store.sync_after_write(&connection)?;
    }
    let mut connection = fixture.store.connection()?;
    let read = fixture.store.begin_read(&mut connection)?;
    let records: i64 = read.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records",
        [],
        |row| row.get(0),
    )?;
    let events: i64 = read.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events WHERE record_key=?1",
        params![&key],
        |row| row.get(0),
    )?;
    assert_eq!(records, fixture.provisioned_records + 1);
    assert_eq!(events, 2);
    schema::verify_admission_operation_invariants(&read)?;
    read.commit()?;
    Ok(())
}
