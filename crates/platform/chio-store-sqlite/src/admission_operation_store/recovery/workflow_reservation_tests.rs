use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// This fixture tests reservation algebra and the authenticated first-record
// digest. Full owner/global-chain custody is exercised by the native tests.
fn first_allocation_fixture() -> Result<(Connection, WorkflowQuota), Box<dyn std::error::Error>> {
    let tx = Connection::open_in_memory()?;
    tx.execute_batch(
        "CREATE TABLE admission_operation_recovery_records (
            record_key TEXT PRIMARY KEY, version INTEGER NOT NULL, payload BLOB NOT NULL,
            scope_key TEXT NOT NULL, kind TEXT NOT NULL, native_namespace TEXT, native_request TEXT
        );
        CREATE TABLE authority_global_commits (
            projection_kind TEXT NOT NULL, projection_key TEXT NOT NULL
        );
        CREATE INDEX authority_global_commits_projection
            ON authority_global_commits(projection_kind,projection_key);
        CREATE TABLE admission_operation_recovery_events (
            record_key TEXT NOT NULL, record_version INTEGER NOT NULL,
            record_digest TEXT NOT NULL, PRIMARY KEY(record_key,record_version)
        )",
    )?;
    let quota = WorkflowQuota {
        schema: WorkflowQuotaSchema::V1,
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("reservation-authority")?,
            tenant_id: RecoveryTenantId::new("reservation-tenant")?,
            process_id: ProcessId::new("reservation-process")?,
        },
        workflow_id: WorkflowId::new("reserved-workflow")?,
        baseline_revision: SafeInteger::new(5)?,
        baseline_commands: SafeInteger::new(7)?,
        planning: SafeInteger::new(1)?,
        control: SafeInteger::new(0)?,
        native: SafeInteger::new(0)?,
        commands: [SafeInteger::new(0)?; 6],
        native_archive: None,
        native_hold: None,
        native_terminal: None,
        native_release: None,
    };
    let key = quota_key(&quota.scope, &quota.workflow_id)?;
    tx.execute(
        "INSERT INTO admission_operation_recovery_events VALUES(?1,1,?2)",
        params![
            key,
            record_digest(
                &key,
                &scope_key(&quota.scope)?,
                "command",
                1,
                &encode(&quota)?,
                None,
                None
            )?
        ],
    )?;
    Ok((tx, quota))
}

fn later_allocation(mut quota: WorkflowQuota) -> Result<WorkflowQuota, Box<dyn std::error::Error>> {
    quota.planning = SafeInteger::new(3)?;
    quota.commands[0] = SafeInteger::new(2)?;
    Ok(quota)
}

#[test]
fn workflow_reservation_retains_exact_first_baseline_as_counts_advance() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let current = later_allocation(first)?;
    current.validate(&tx, &current.scope, &current.workflow_id, 8, 9, 5)?;
    Ok(())
}

#[test]
fn workflow_reservation_rejects_self_consistent_baseline_swaps() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let mut changed = later_allocation(first)?;
    changed.baseline_revision = SafeInteger::new(6)?;
    changed.baseline_commands = SafeInteger::new(6)?;
    changed.planning = SafeInteger::new(2)?;
    changed.commands[0] = SafeInteger::new(3)?;
    assert!(
        changed
            .validate(&tx, &changed.scope, &changed.workflow_id, 8, 9, 5)
            .is_err(),
        "unchanged counter sum must not authorize moving the protected legacy baseline"
    );
    Ok(())
}

#[test]
fn workflow_reservation_rejects_lost_first_allocation_history() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    tx.execute("DELETE FROM admission_operation_recovery_events", [])?;
    let current = later_allocation(first)?;
    assert!(
        current
            .validate(&tx, &current.scope, &current.workflow_id, 8, 9, 5)
            .is_err(),
        "a current projection cannot reallocate after losing its first protected history"
    );
    Ok(())
}

// Reservation codec/algebra tests do not claim a real physical capture.
// Native owner/event/operation custody is exercised by authority_holds.rs.
fn auxiliary_hold_wire(version: u64) -> serde_json::Value {
    let digest = vec![255_u8; 32];
    serde_json::json!({
        "workflow_record_version": version,
        "workflow_record_digest": digest,
        "hold": {
            "operation": {
                "operation_id": "f".repeat(128),
                "native_admission_digest": digest,
                "operation_version": 9007199254740991_u64
            },
            "reason": "frozen_output_verifier_unavailable"
        }
    })
}

#[test]
fn workflow_reservation_auxiliary_hold_codec_is_bounded_and_accounted() -> TestResult {
    let (_tx, first) = first_allocation_fixture()?;
    let mut value = serde_json::to_value(first)?;
    let maximum = 9007199254740991_u64;
    for field in ["authority_domain", "tenant_id", "process_id"] {
        value["scope"][field] = serde_json::Value::String("z".repeat(128));
    }
    value["workflow_id"] = serde_json::Value::String("z".repeat(128));
    value["baseline_revision"] = serde_json::json!(maximum - 138);
    value["baseline_commands"] = serde_json::json!(maximum - 64);
    value["planning"] = serde_json::json!(8);
    value["control"] = serde_json::json!(2);
    value["native"] = serde_json::json!(128);
    value["commands"] = serde_json::json!([8, 8, 8, 24, 8, 8]);
    let digest = vec![255_u8; 32];
    value["native_archive"] = serde_json::json!({
        "record_key":format!("deployment-history:{}:{}","f".repeat(64),"f".repeat(64)),
        "deployment_digest":digest,
        "record_version":1
    });
    value["native_hold"] = auxiliary_hold_wire(maximum);
    let bytes = canonical_json_bytes(&value)?;
    assert!(bytes.len() <= MAX_WORKFLOW_QUOTA_BYTES);
    let parsed = decode::<WorkflowQuota>(&bytes);
    assert!(
        parsed.is_ok(),
        "closed auxiliary hold metadata codec was refused"
    );
    let parsed = parsed?;
    assert_eq!(encode(&parsed)?, bytes);
    assert_eq!(parsed.workflow_units()?, 138);
    assert_eq!(parsed.command_units()?, 64);
    assert_eq!(
        parsed.units()?,
        204,
        "native hold did not consume exactly one metadata unit"
    );
    Ok(())
}

#[test]
fn workflow_reservation_absent_auxiliary_hold_keeps_legacy_canonical_bytes() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let bytes = encode(&first)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(
        value.get("native_hold").is_none(),
        "absent hold rewrote a legacy quota payload"
    );
    let parsed = decode::<WorkflowQuota>(&bytes)?;
    assert_eq!(encode(&parsed)?, bytes);
    parsed.verify_first_allocation(&tx)?;
    Ok(())
}

#[test]
fn workflow_reservation_auxiliary_hold_preserves_exhausted_native_128_allocation() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let mut value = serde_json::to_value(first)?;
    value["native"] = serde_json::json!(128);
    value["native_hold"] = auxiliary_hold_wire(134);
    let parsed = decode::<WorkflowQuota>(&canonical_json_bytes(&value)?);
    assert!(
        parsed.is_ok(),
        "valid closed hold shape did not reach allowance validation"
    );
    let parsed = parsed?;
    // A predecessor can already own all 128 native workflow units. The owed
    // metadata-only hold has its own fixed unit and cannot reset that baseline.
    assert_eq!(parsed.workflow_units()?, 129);
    assert_eq!(parsed.units()?, 130);
    parsed.verify_first_allocation(&tx)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS admission_operation_recovery_records (
            record_key TEXT PRIMARY KEY,version INTEGER NOT NULL,payload BLOB NOT NULL,
            scope_key TEXT NOT NULL,kind TEXT NOT NULL,native_namespace TEXT,native_request TEXT
        )",
    )?;
    let failure = parsed.validate(&tx, &parsed.scope, &parsed.workflow_id, 134, 7, 130);
    assert!(
        matches!(failure,Err(AdmissionOperationStoreError::Invariant(ref message)) if message=="recovery historical hold workflow absent"),
        "the independent owed hold failed accounting before physical owner verification"
    );
    // The fixture deliberately has no workflow/native owner; this proves
    // accounting reaches that refusal, not authenticated hold allocation.
    value["native"] = serde_json::json!(129);
    let excess = decode::<WorkflowQuota>(&canonical_json_bytes(&value)?)?;
    let failure = excess.validate(&tx, &excess.scope, &excess.workflow_id, 135, 7, 131);
    assert!(
        matches!(failure,Err(AdmissionOperationStoreError::Invariant(ref message)) if message=="recovery workflow quota is corrupt"),
        "an auxiliary hold authorized a 129th native workflow write"
    );
    Ok(())
}

#[test]
fn absent_terminal_and_release_keep_legacy_quota_bytes() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let bytes = encode(&first)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert!(value.get("native_terminal").is_none());
    assert!(value.get("native_release").is_none());
    assert_eq!(encode(&decode::<WorkflowQuota>(&bytes)?)?, bytes);
    first.verify_first_allocation(&tx)?;
    Ok(())
}

#[test]
fn terminal_and_release_leave_native_128_and_first_baseline_unchanged() -> TestResult {
    let (tx, first) = first_allocation_fixture()?;
    let mut value = serde_json::to_value(first)?;
    value["native"] = serde_json::json!(128);
    for field in ["native_terminal", "native_release"] {
        value[field] = serde_json::json!({"record_digest":vec![255_u8;32]});
    }
    let parsed = decode::<WorkflowQuota>(&canonical_json_bytes(&value)?)?;
    assert_eq!(parsed.workflow_units()?, 129);
    assert_eq!(parsed.units()?, 131);
    assert_eq!(parsed.baseline_revision.get(), 5);
    assert_eq!(parsed.baseline_commands.get(), 7);
    parsed.verify_first_allocation(&tx)?;
    // This is counter algebra, not a fabricated native-terminal owner.
    value["native"] = serde_json::json!(129);
    let excess = decode::<WorkflowQuota>(&canonical_json_bytes(&value)?)?;
    assert!(matches!(
        excess.validate(&tx, &excess.scope, &excess.workflow_id, 135, 7, 132),
        Err(AdmissionOperationStoreError::Invariant(ref message))
            if message == "recovery workflow quota is corrupt"
    ));
    Ok(())
}

#[test]
fn terminal_first_allocation_authenticates_its_old_workflow_baseline() -> TestResult {
    let (tx, mut first) = first_allocation_fixture()?;
    first.planning = SafeInteger::ZERO;
    first.native_terminal = Some(WorkflowTerminalAllocation {
        record_digest: ProjectionDigest::from_bytes([255; 32]),
    });
    let key = quota_key(&first.scope, &first.workflow_id)?;
    tx.execute(
        "UPDATE admission_operation_recovery_events SET record_digest=?2 WHERE record_key=?1 AND record_version=1",
        params![&key, record_digest(&key, &scope_key(&first.scope)?, "command", 1, &encode(&first)?, None, None)?],
    )?;
    assert_eq!(first.units()?, 1);
    assert_eq!(first.workflow_units()?, 0);
    first.verify_first_allocation(&tx)?;
    first.baseline_revision = SafeInteger::new(6)?;
    assert!(matches!(
        first.verify_first_allocation(&tx),
        Err(AdmissionOperationStoreError::Invariant(ref message))
            if message == "recovery workflow quota baseline changed"
    ));
    Ok(())
}

#[test]
fn release_pointer_cannot_omit_its_terminal_owner() -> TestResult {
    let (tx, mut first) = first_allocation_fixture()?;
    first.native_release = Some(WorkflowReleaseAllocation {
        record_digest: ProjectionDigest::from_bytes([255; 32]),
    });
    assert!(matches!(
        first.validate(&tx, &first.scope, &first.workflow_id, 6, 7, 2),
        Err(AdmissionOperationStoreError::Invariant(ref message))
            if message == "recovery workflow quota is corrupt"
    ));
    Ok(())
}

#[test]
fn maximal_closed_terminal_and_release_quota_codec_stays_bounded() -> TestResult {
    let (_tx, first) = first_allocation_fixture()?;
    let mut value = serde_json::to_value(first)?;
    let maximum = 9007199254740991_u64;
    for field in ["authority_domain", "tenant_id", "process_id"] {
        value["scope"][field] = serde_json::Value::String("z".repeat(128));
    }
    value["workflow_id"] = serde_json::Value::String("z".repeat(128));
    value["baseline_revision"] = serde_json::json!(maximum - 138);
    value["baseline_commands"] = serde_json::json!(maximum - 64);
    value["planning"] = serde_json::json!(8);
    value["control"] = serde_json::json!(2);
    value["native"] = serde_json::json!(128);
    value["commands"] = serde_json::json!([8, 8, 8, 24, 8, 8]);
    value["native_archive"] = serde_json::json!({
        "record_key":format!("deployment-history:{}:{}","f".repeat(64),"f".repeat(64)),
        "deployment_digest":vec![255_u8;32],"record_version":1
    });
    value["native_hold"] = auxiliary_hold_wire(maximum);
    for field in ["native_terminal", "native_release"] {
        value[field] = serde_json::json!({"record_digest":vec![255_u8;32]});
    }
    let bytes = canonical_json_bytes(&value)?;
    assert!(bytes.len() <= MAX_WORKFLOW_QUOTA_BYTES);
    let parsed = decode::<WorkflowQuota>(&bytes)?;
    assert_eq!(encode(&parsed)?, bytes);
    assert_eq!(parsed.workflow_units()?, 138);
    assert_eq!(parsed.command_units()?, 64);
    assert_eq!(parsed.units()?, 206);
    Ok(())
}
