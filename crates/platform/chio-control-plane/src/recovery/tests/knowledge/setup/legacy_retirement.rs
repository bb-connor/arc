//! Real predecessor bytes must retire through current, effect-free authority.
use super::*;
use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
use chio_store_sqlite::admission_operation_store::{
    NativeSetupRetirementAuthorizationV1, NativeSetupRetirementBodyV1,
};
mod native_authority;

fn retained_records(path: &std::path::Path) -> TestResult<Vec<(String, u64, Vec<u8>)>> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare("SELECT record_key,version,payload FROM admission_operation_recovery_records ORDER BY record_key")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let values = rows.collect::<Result<Vec<_>, _>>()?;
    values
        .into_iter()
        .map(|(key, version, payload)| Ok((key, u64::try_from(version)?, payload)))
        .collect()
}

fn retained_effect_count(path: &std::path::Path) -> TestResult<usize> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("effects.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let count: i64 = connection.query_row("SELECT count(*) FROM effects", [], |row| row.get(0))?;
    Ok(usize::try_from(count)?)
}

type RecoveryEvent = (i64, String, i64, String, String, String, i64);
type GlobalCommit = (
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
);

#[derive(Debug, PartialEq, Eq)]
struct RetainedHistory {
    recovery: Vec<RecoveryEvent>,
    global: Vec<GlobalCommit>,
}

fn retained_history(path: &std::path::Path) -> TestResult<RetainedHistory> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT sequence,record_key,record_version,record_digest,previous_digest,event_digest,observed_at
         FROM admission_operation_recovery_events ORDER BY sequence",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
        ))
    })?;
    let recovery = rows.collect::<Result<Vec<_>, _>>()?;
    let mut statement = connection.prepare(
        "SELECT commit_sequence,mutation_kind,projection_kind,projection_key,projection_sequence,
                projection_reference_digest,authority_projection_digest,previous_chain_digest,
                chain_digest,store_uuid,store_lease_id,store_owner_epoch
         FROM authority_global_commits ORDER BY commit_sequence",
    )?;
    let rows = statement.query_map([], |row| {
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
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
        ))
    })?;
    let global = rows.collect::<Result<Vec<_>, _>>()?;
    Ok(RetainedHistory { recovery, global })
}

fn require_history_prefix(original: &RetainedHistory, current: &RetainedHistory) {
    assert!(
        current.recovery.starts_with(&original.recovery),
        "the predecessor recovery event prefix must remain byte-identical"
    );
    assert!(
        current.global.starts_with(&original.global),
        "the predecessor global commit prefix must remain byte-identical"
    );
}

#[cfg(unix)]
fn require_original_namespace_custody(source: &std::path::Path) -> TestResult {
    use std::os::unix::fs::MetadataExt;
    let custody = std::path::PathBuf::from(std::env::var("CHIO_RECOVERY_LEGACY_SETUP_CUSTODY")?);
    let pinned = std::env::var("CHIO_RECOVERY_LEGACY_SETUP_CUSTODY_SHA256")?;
    assert!(
        pinned.len() == 64
            && pinned
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let bytes = std::fs::read(custody)?;
    assert_eq!(chio_core_types::sha256_hex(&bytes), pinned);
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(
        value["original_serving_namespace"].as_str(),
        source.to_str()
    );
    assert_eq!(value["current_consumer_run"], serde_json::json!(false));
    let files = value["files"]
        .as_object()
        .ok_or("original custody file roles")?;
    for role in [
        "admission.db",
        "effects.db",
        "fixture.json",
        "process.db",
        "receipts.db",
        "source.db",
    ] {
        assert!(
            files.contains_key(role),
            "independent custody lacks original role {role}"
        );
    }
    for (relative, expected) in files {
        let relative = std::path::Path::new(relative);
        assert!(relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_))));
        let role = source.join(relative);
        let metadata = std::fs::symlink_metadata(&role)?;
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        assert_eq!(
            metadata.dev(),
            expected["dev"].as_u64().ok_or("custody device")?
        );
        assert_eq!(
            metadata.ino(),
            expected["ino"].as_u64().ok_or("custody inode")?
        );
        assert_eq!(
            u64::from(metadata.mode()),
            expected["mode"].as_u64().ok_or("custody mode")?
        );
        assert_eq!(
            metadata.len(),
            expected["size"].as_u64().ok_or("custody size")?
        );
        assert_eq!(
            chio_core_types::sha256_hex(&std::fs::read(&role)?),
            expected["sha256"].as_str().ok_or("custody role bytes")?
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_original_namespace_custody(_source: &std::path::Path) -> TestResult {
    Err("this genuine namespace acceptance requires Unix file identities".into())
}

#[test]
#[ignore = "requires a pinned genuine predecessor authority through CHIO_RECOVERY_LEGACY_SETUP_ROOT"]
fn setup_genuine_legacy_completion_retires_without_renewing_old_process_credentials() -> TestResult
{
    let source = std::path::PathBuf::from(std::env::var("CHIO_RECOVERY_LEGACY_SETUP_ROOT")?);
    // The serving namespace binds absolute paths and provisioned file roles.
    // Independent custody pins the producer, controller and physical identities
    // before this ignored test. Never transplant or reseal the predecessor.
    assert!(source.is_absolute() && source.is_dir());
    require_original_namespace_custody(&source)?;
    let path = source.as_path();
    let records = retained_records(path)?;
    let predecessor_history = retained_history(path)?;
    let old_setups: Vec<_> = records
        .iter()
        .filter(|(key, _, _)| key.starts_with("protected-setup:"))
        .collect();
    assert_eq!(old_setups.len(), 1);
    let selection_bytes = &old_setups[0].2;
    let selection: serde_json::Value = serde_json::from_slice(selection_bytes)?;
    assert_eq!(selection["command_bound"], serde_json::json!(true));
    let old_workflows: Vec<_> = records
        .iter()
        .filter(|(key, _, _)| key.starts_with("workflow:"))
        .collect();
    assert_eq!(old_workflows.len(), 1);
    let old_workflow: serde_json::Value = serde_json::from_slice(&old_workflows[0].2)?;
    assert!(old_workflow
        .get("origin")
        .is_none_or(serde_json::Value::is_null));
    assert_eq!(old_workflow["captured"], serde_json::json!(true));
    assert_eq!(
        old_workflow["effect"]["kind"],
        serde_json::json!("complete")
    );
    assert_eq!(old_workflow["effect"]["effect_count"], serde_json::json!(1));
    assert_eq!(
        old_workflow["release"]["kind"],
        serde_json::json!("released")
    );
    let probe: SignedRecoverySetupProbeV1 =
        serde_json::from_value(selection["evidence"]["probe"].clone())?;
    let report: chio_core_types::recovery::SignedRecoverySetupReportV1 =
        serde_json::from_value(selection["report"].clone())?;
    assert!(probe.verify_signature()? && report.verify_signature()?);
    assert_eq!(report.body().probe, *probe.body());
    assert_eq!(
        selection["previous_fence"],
        serde_json::to_value(&report.body().previous_serving_fence)?
    );
    assert_ne!(
        report.body().previous_serving_fence,
        report.body().current_serving_fence
    );
    assert!(report.body().qualified_at_unix_ms >= probe.body().issued_at_unix_ms);
    assert!(
        report.body().qualified_at_unix_ms < probe.body().expires_at_unix_ms,
        "the genuine predecessor first acceptance was inside its initial window"
    );
    let old_operator = Keypair::from_seed(&[211; 32]).public_key();
    assert_eq!(probe.authority_key(), &old_operator);
    assert_eq!(report.authority_key(), &old_operator);
    assert_eq!(selection["operator"], serde_json::to_value(&old_operator)?);
    assert_eq!(selection["probe"], serde_json::to_value(probe.body())?);
    assert_eq!(selection["probe"]["scope"], old_workflow["scope"]);
    assert_eq!(
        selection["probe"]["benign_workflow"],
        old_workflow["workflow_id"]
    );
    assert_eq!(
        selection["evidence"]["operation"],
        serde_json::to_value(&report.body().benign_operation)?
    );
    assert_eq!(
        selection["evidence"]["benign_receipt"],
        serde_json::to_value(&report.body().benign_receipt)?
    );
    assert_eq!(
        selection["evidence"]["denied_command"],
        serde_json::to_value(&report.body().denied_command_digest)?
    );
    assert_eq!(
        selection["receipt_key"],
        serde_json::to_value(Keypair::from_seed(&[140; 32]).public_key())?
    );
    assert_eq!(
        old_workflow["native_link"],
        serde_json::to_value(&report.body().benign_operation)?
    );
    assert_eq!(retained_effect_count(path)?, 1);

    let original: ToolCallRequest = chio_core_types::recovery::decode_contract(
        old_workflow["creation_seed"]
            .as_str()
            .ok_or("retained original seed")?
            .as_bytes(),
    )?;
    let validation_secs = (now_ms()? / 1_000).max(
        original
            .capability
            .expires_at
            .checked_add(1)
            .ok_or("original expiry overflow")?,
    );
    let validation_ms = validation_secs
        .checked_mul(1_000)
        .ok_or("validation clock overflow")?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        validation_secs,
        std::iter::empty::<String>(),
    );
    assert!(original.capability.is_expired_at(validation_secs));
    let old_process_bytes = std::fs::read(path.join("process.db"))?;
    let old_credential_bytes = std::fs::read(path.join("fixture.json"))?;
    let authority =
        SqliteAuthorityStore::open_serving(path.join("admission.db"), path.join("locks")).map_err(
            |error| format!("legacy retirement phase=current native serving open: {error}"),
        )?;
    let store = authority.admission_operation_store();
    let operation = store
        .load_by_operation_id(&AdmissionOperationId::from_persisted(
            report.body().benign_operation.as_str(),
        )?)?
        .ok_or("genuine predecessor completion missing")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(matches!(
        operation.terminal_replay(),
        Some(AdmissionTerminalReplay::Receipt { .. })
    ));
    let Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) = operation.terminal_replay()
    else {
        return Err("genuine terminal receipt identity missing".into());
    };
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (receipt_bytes, receipt_digest): (Vec<u8>, String) = connection.query_row(
        "SELECT record_json,record_digest FROM admission_operation_terminal_records
         WHERE operation_id=?1 AND record_kind='receipt' AND record_id=?2",
        rusqlite::params![
            operation.binding().operation_id().as_str(),
            receipt_id.as_str()
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let receipt: chio_core_types::receipt::body::ChioReceipt =
        serde_json::from_slice(&receipt_bytes)?;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&receipt)?,
        receipt_bytes
    );
    assert_eq!(chio_core_types::sha256_hex(&receipt_bytes), receipt_digest);
    assert_eq!(receipt.id, receipt_id.as_str());
    assert!(receipt.is_allowed() && receipt.verify_signature()? && receipt.action.verify_hash()?);
    assert_eq!(
        receipt.kernel_key,
        Keypair::from_seed(&[140; 32]).public_key()
    );
    assert_eq!(
        report.body().benign_receipt,
        SourceDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::SetupBenignReceipt,
            &receipt,
        )?)
    );
    let dispatch = operation
        .dispatch_commit()
        .ok_or("genuine native dispatch binding absent")?;
    assert_eq!(
        report.body().previous_serving_fence,
        SourceDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ServingFence,
            &dispatch.store_fence,
        )?)
    );
    let seed: (ToolCallRequest, CapabilityToken) =
        serde_json::from_slice(&std::fs::read(path.join("fixture.json"))?)?;
    let fence = authority.mutation_fence();
    let mut current_deployment = store
        .deployment(&probe.body().scope, &fence, validation_ms)
        .map_err(|error| format!("legacy retirement phase=retained deployment: {error}"))?;
    let old_deployment = current_deployment.clone();
    let original_deployment_bytes = chio_core_types::canonical_json_bytes(&old_deployment)?;
    let old_deployment_rows: Vec<_> = records
        .iter()
        .filter(|(key, _, _)| key.starts_with("deployment:"))
        .collect();
    assert_eq!(old_deployment_rows.len(), 1);
    assert_eq!(old_deployment_rows[0].2, original_deployment_bytes);
    let source = store
        .observe_security_participant_flow(
            &current_deployment.native_authority,
            &recovery_flow_key(&current_deployment.security_context),
            &fence,
            validation_ms,
        )
        .map_err(|error| {
            format!("legacy retirement phase=current finite native source: {error}")
        })?;
    let observed = source.snapshot().ok_or("old native source is absent")?;
    let clearance = observed
        .principal_label
        .join_restrictions(&observed.lineage_label)?
        .join_restrictions(&observed.session_label)?;
    assert!(
        !matches!(clearance, InformationLabel::Top),
        "an unknown old source cannot become fresh inspection authority"
    );
    let mut actors = current_deployment.actors.as_slice().to_vec();
    assert_eq!(actors.len(), 1);
    assert_eq!(
        actors[0].subject,
        Keypair::from_seed(&[142; 32]).public_key()
    );
    assert!(
        matches!(&actors[0].preview_clearance, InformationLabel::Top),
        "the genuine historical reviewer must exercise the Top-to-current finite authority cutover"
    );
    let mut expected_deployment = old_deployment.clone();
    let mut expected_actors = expected_deployment.actors.as_slice().to_vec();
    expected_actors[0].preview_clearance = clearance.clone();
    expected_deployment.actors = NonEmptyBoundedList::new(expected_actors)?;
    expected_deployment.authority_scope = recovery_authority_scope_digest(&expected_deployment)?;
    actors[0].preview_clearance = clearance;
    current_deployment.actors = NonEmptyBoundedList::new(actors)?;
    current_deployment.authority_scope = recovery_authority_scope_digest(&current_deployment)?;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&current_deployment)?,
        chio_core_types::canonical_json_bytes(&expected_deployment)?
    );
    store
        .configure_recovery_deployment(&current_deployment)
        .map_err(|error| {
            format!("legacy retirement phase=current finite deployment cutover: {error}")
        })?;
    assert_eq!(
        current_deployment.native_authority,
        old_deployment.native_authority
    );
    assert_eq!(
        current_deployment.security_context,
        old_deployment.security_context
    );
    assert_ne!(
        current_deployment.authority_scope,
        old_deployment.authority_scope
    );
    let deployment_digest = DeploymentDigest::from_bytes(recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::Deployment,
        &old_deployment,
    )?);
    let historical_key = format!(
        "deployment-history:{}:{}",
        chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(
            &old_deployment.scope
        )?),
        deployment_digest
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let historical: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&historical_key],
        |row| row.get(0),
    )?;
    assert_eq!(historical, original_deployment_bytes);
    require_history_prefix(&predecessor_history, &retained_history(path)?);
    assert_eq!(std::fs::read(path.join("process.db"))?, old_process_bytes);
    assert_eq!(
        std::fs::read(path.join("fixture.json"))?,
        old_credential_bytes
    );
    let (mut kernel, _) = open_kernel(path, &authority, &Keypair::from_seed(&[140; 32]))?;
    native_authority::install_retained_setup_authority(&mut kernel, path, &current_deployment)
        .map_err(|error| {
            format!(
                "legacy retirement phase=current retained native authority installation: {error}"
            )
        })?;
    // Renew only current local control authority. No old process capability,
    // broker handle or expired original readiness is revived for retirement.
    let capability = kernel.issue_capability(
        &Keypair::from_seed(&[142; 32]).public_key(),
        seed.1.scope,
        1_200,
    )?;
    let actor = kernel
        .authenticate_recovery_actor(
            &probe.body().scope,
            &capability,
            RecoveryPermission::Inspect,
        )
        .map_err(|error| format!("legacy retirement phase=fresh current inspector: {error}"))?;
    let body = NativeSetupRetirementBodyV1 {
        domain_version: VersionV1,
        scope: probe.body().scope.clone(),
        selection_digest: CanonicalPayloadDigest::from_bytes(
            *chio_core::sha256(selection_bytes).as_bytes(),
        ),
        workflow_id: probe.body().benign_workflow.clone(),
        operation_id: report.body().benign_operation.clone(),
        request_namespace: operation.binding().request_namespace_digest().clone(),
        original_request: AdmissionIdentifier::try_new("original_request", original.request_id)?,
        serving_fence: fence.clone(),
    };
    let authorization =
        NativeSetupRetirementAuthorizationV1::sign(body.clone(), &Keypair::from_seed(&[211; 32]))?;
    assert!(authorization.verify_signature()?);
    let wrong_operator =
        NativeSetupRetirementAuthorizationV1::sign(body.clone(), &Keypair::from_seed(&[212; 32]))?;
    let before = retained_records(path)?;
    let before_history = retained_history(path)?;
    assert!(store
        .retire_legacy_setup(&actor, &wrong_operator, &fence, validation_ms)
        .is_err());
    assert_eq!(retained_records(path)?, before);
    assert_eq!(retained_history(path)?, before_history);
    for binding in 0..7 {
        let mut foreign = body.clone();
        match binding {
            0 => foreign.scope.process_id = ProcessId::new("foreign-legacy-process")?,
            1 => foreign.selection_digest = CanonicalPayloadDigest::from_bytes([9; 32]),
            2 => foreign.operation_id = OperationId::new("foreign-legacy-operation")?,
            3 => foreign.serving_fence.owner_epoch += 1,
            4 => {
                foreign.original_request =
                    AdmissionIdentifier::try_new("original_request", "foreign-original")?
            }
            5 => foreign.workflow_id = WorkflowId::new("foreign-legacy-workflow")?,
            _ => {
                foreign.request_namespace =
                    chio_kernel::admission_operation::RequestNamespaceDigest::from_persisted(
                        "9".repeat(64),
                    )?
            }
        }
        let foreign =
            NativeSetupRetirementAuthorizationV1::sign(foreign, &Keypair::from_seed(&[211; 32]))?;
        assert!(store
            .retire_legacy_setup(&actor, &foreign, &fence, validation_ms)
            .is_err());
        assert_eq!(
            retained_records(path)?,
            before,
            "foreign retirement binding {binding} must not write"
        );
        assert_eq!(
            retained_history(path)?,
            before_history,
            "foreign retirement binding {binding} must not append native custody"
        );
    }
    assert_eq!(
        store
            .retire_legacy_setup(&actor, &authorization, &fence, validation_ms)
            .map_err(|error| format!(
                "legacy retirement phase=exact verified predecessor retirement target: {error}"
            ))?,
        body,
        "the exact signed, completed predecessor setup must retire without old credentials"
    );
    let retired = retained_records(path)?;
    let retired_history = retained_history(path)?;
    require_history_prefix(&predecessor_history, &retired_history);
    assert_eq!(
        store.retire_legacy_setup(&actor, &authorization, &fence, validation_ms)?,
        body
    );
    assert_eq!(
        retained_records(path)?,
        retired,
        "exact retirement replay must not write"
    );
    assert_eq!(
        retained_history(path)?,
        retired_history,
        "exact retirement replay must not append native custody"
    );
    assert_eq!(retained_effect_count(path)?, 1);
    assert_eq!(std::fs::read(path.join("process.db"))?, old_process_bytes);
    assert_eq!(
        std::fs::read(path.join("fixture.json"))?,
        old_credential_bytes
    );
    for (key, version, payload) in records {
        if key.starts_with("deployment:") {
            assert_eq!(payload, original_deployment_bytes);
            continue;
        }
        assert!(
            retired.contains(&(key, version, payload)),
            "historical custody must remain byte-identical"
        );
    }
    Ok(())
}
