//! Genuine current-format custody and public owner reopen for reader compatibility.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::ToolCallResponse;

const CAPTURE_REPORT: &str = "CHIO_RECOVERY_NATIVE_INPUT_COMPAT_CAPTURE_REPORT";
const EXISTING_ROOT: &str = "CHIO_RECOVERY_NATIVE_INPUT_COMPAT_ROOT";

fn read_only_admission(path: &std::path::Path) -> TestResult<rusqlite::Connection> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    Ok(connection)
}

fn current_format_header(path: &std::path::Path) -> TestResult<Value> {
    let connection = read_only_admission(path)?;
    let version: i64 = connection.query_row(
        "SELECT version FROM main.chio_store_schema_versions
         WHERE store_key='admission_operation'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        version, 40,
        "compatibility requires the actual same current database stamp"
    );
    let (bytes, digest, sequence, authority): (Vec<u8>, String, i64, String) = connection
        .query_row(
            "SELECT canonical_record,mutation_digest,sequence,security_authority_id
             FROM main.security_participant_state_mutations
             WHERE length(canonical_record) BETWEEN 1 AND 16777216
             ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let record: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(chio_core::canonical_json_bytes(&record)?, bytes);
    let format = record["schema"]
        .as_str()
        .ok_or("native Input format absent")?;
    assert!(matches!(
        format,
        "chio.native-security-flow-join.v2" | "chio.native-security-flow-join.v3"
    ));
    assert!(record.get("input").is_some_and(Value::is_object));
    let mut committed = b"chio.native-security-mutation.commit.v1\0".to_vec();
    committed.extend_from_slice(&bytes);
    assert_eq!(chio_core::sha256_hex(&committed), digest);
    let global: i64 = connection.query_row(
        "SELECT commit_sequence FROM main.authority_global_commits
         WHERE projection_kind='security_participant_state' AND projection_key=?1
           AND projection_sequence=?2 AND projection_reference_digest=?3",
        rusqlite::params![authority, sequence, digest],
        |row| row.get(0),
    )?;
    assert!(global > 0);
    Ok(serde_json::json!({
        "database_stamp": version,
        "native_format": format,
        "native_record_sha256": chio_core::sha256_hex(&bytes),
        "native_mutation_digest": digest,
        "native_sequence": sequence,
        "native_global_commit": global,
        "native_record": record,
    }))
}

fn assert_first_input_custody(
    f: &RecoveryFixture,
    request: &ToolCallRequest,
    response: &ToolCallResponse,
) -> TestResult<Value> {
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        response.receipt.kernel_key,
        f.kernel.receipt_signing_public_key()
    );
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    assert_eq!(response.receipt.action.parameters, request.arguments);
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("genuine compatibility Input original absent")?;
    original.validate_binding(operation.binding())?;
    original.validate_request_material(request)?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(&deployment.security_context)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert_eq!(
        response.receipt.action.parameter_hash,
        operation.binding().action_parameter_hash().as_str()
    );
    let (loaded, input) = store
        .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("genuine compatibility Input operation absent")?;
    let input = input.ok_or("genuine compatibility Input journal absent")?;
    input.validate()?;
    assert_eq!(loaded, operation);
    assert_eq!(
        input.input.operation_id(),
        operation.binding().operation_id()
    );
    assert_eq!(
        input.input.key(),
        &recovery_flow_key(&deployment.security_context)
    );
    assert_eq!(input.join.binding, deployment.native_authority);
    let header = current_format_header(&f.path)?;
    assert_eq!(
        header["native_mutation_digest"],
        input.join.mutation_digest.as_str()
    );
    assert_eq!(
        header["native_record"]["input"],
        serde_json::to_value(&input.input)?
    );
    assert_eq!(
        header["native_record"]["result"],
        serde_json::to_value(&input.join.snapshot)?
    );
    assert!(header["native_record"]
        .get("semantic_input_evidence")
        .is_none());
    assert!(store
        .load_security_participant_output(operation.binding().operation_id(), &fence, now_ms()?)?
        .is_none());
    assert!(f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_none());
    assert!(store
        .observe_knowledge_influence(f.runtime.scope(), &fence, now_ms()?)?
        .is_none());
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(serde_json::json!({
        "fixture_root": f.path,
        "header": header,
        "operation": operation.to_persisted(),
        "original_request_sha256": chio_core::sha256_hex(original.canonical_bytes()),
        "native_input": {
            "input": input.input,
            "binding": input.join.binding,
            "operation_id": input.join.operation_id,
            "command": input.join.command,
            "snapshot": input.join.snapshot,
            "mutation_digest": input.join.mutation_digest,
        },
        "signed_deny": response.receipt,
        "native_security_context": deployment.security_context,
        "native_authority": deployment.native_authority,
        "effects": 0,
    }))
}

/// No native/database owner survives this fixture handoff. Keeping the temporary
/// directory preserves real files; it cannot mint a source role or mutate rows.
fn close_fixture(f: RecoveryFixture) -> (std::path::PathBuf, Option<tempfile::TempDir>) {
    let path = f.path.clone();
    let directory = f._directory;
    drop(f.runtime);
    drop(f.kernel);
    drop(f.process);
    drop(f.authority);
    (path, directory)
}

#[tokio::test]
async fn native_input_compatibility_preserves_its_genuine_current_format_source() -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("trusted-history").await?;
    let request = f.process.tool_request(
        "root",
        "native-input-genesis",
        &f.seed.server_id,
        &f.seed.tool_name,
        f.seed.arguments.clone(),
    )?;
    let replay = Box::pin(
        f.process
            .invoke_known_only("root", "native-input-genesis", &request),
    )
    .await?;
    let evidence = assert_first_input_custody(&f, &request, &replay)?;
    let (path, directory) = close_fixture(f);
    let after = current_format_header(&path)?;
    assert_eq!(evidence["header"], after);
    if let Some(report_path) = std::env::var_os(CAPTURE_REPORT) {
        let report_path = std::path::PathBuf::from(report_path);
        if report_path.exists() {
            return Err("compatibility capture report already exists".into());
        }
        let directory = directory.ok_or("compatibility capture directory custody absent")?;
        assert_eq!(directory.path(), path);
        let retained = directory.keep();
        assert_eq!(retained, path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(report_path)?;
        std::io::Write::write_all(&mut file, &chio_core::canonical_json_bytes(&evidence)?)?;
        file.sync_all()?;
    } else {
        drop(directory);
    }
    Ok(())
}

#[tokio::test]
async fn native_input_compatibility_reopens_its_genuine_current_format_owner() -> TestResult {
    let (path, directory) = match std::env::var_os(EXISTING_ROOT) {
        Some(path) => (std::path::PathBuf::from(path), None),
        None => {
            let fixture = empty_import::native_fixture_from_empty_import("trusted-history").await?;
            close_fixture(fixture)
        }
    };
    let before = current_format_header(&path)?;
    eprintln!(
        "native Input compatibility: same current stamp40, retained format {}",
        before["native_format"]
    );
    // This public open and observation remain real fallible operations. A
    // preserved reader returns its actual error on incompatible native bytes;
    // no expected-refusal flag or alternate decoder changes that outcome.
    let reopened = RecoveryFixture::open(path.clone(), None, false)?;
    let observed = reopened
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(
            reopened.runtime.scope(),
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(observed.is_none());
    assert_eq!(reopened.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&path)?, 0);
    let after = current_format_header(&path)?;
    assert_eq!(after, before);
    drop(reopened);
    drop(directory);
    Ok(())
}
