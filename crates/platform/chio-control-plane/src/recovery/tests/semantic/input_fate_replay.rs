//! A durable refused Input keeps its retained fate across retry, lost
//! acknowledgement and restart; genuine prior-writer bytes never become
//! eligible and no taint is lowered.
use super::*;
use chio_kernel::admission_operation::NativeSecurityInputFateV1;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_kernel::ToolCallResponse;
use std::path::{Path, PathBuf};

struct DurableRecord {
    bytes: Vec<u8>,
    record: serde_json::Value,
    mutations: i64,
    commits: i64,
}

fn durable_record(path: &Path, operation: &str) -> TestResult<DurableRecord> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    let bytes: Vec<u8> = connection.query_row(
        "SELECT canonical_record FROM main.security_participant_state_mutations
         WHERE operation_id = ?1",
        [operation],
        |row| row.get(0),
    )?;
    let mutations: i64 = connection.query_row(
        "SELECT COUNT(*) FROM main.security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let commits: i64 = connection.query_row(
        "SELECT COUNT(*) FROM main.authority_global_commits",
        [],
        |row| row.get(0),
    )?;
    Ok(DurableRecord {
        record: serde_json::from_slice(&bytes)?,
        bytes,
        mutations,
        commits,
    })
}

fn retained_mutation_count(path: &Path, operation: &str) -> TestResult<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM main.security_participant_state_mutations
         WHERE operation_id = ?1",
        [operation],
        |row| row.get(0),
    )?)
}

fn assert_signed_deny(
    f: &RecoveryFixture,
    request: &ToolCallRequest,
    response: &ToolCallResponse,
) -> TestResult {
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
    Ok(())
}

async fn install_changed_selected_answer(
    f: &RecoveryFixture,
    request: &mut ToolCallRequest,
    profile: &mut SemanticFixture,
) -> TestResult {
    let neutral = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: profile.plan.scope.clone(),
            input: profile.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: false,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10_000)?,
            issued_at_unix_ms: profile.invocation.action.issued_at_unix_ms,
            valid_until_unix_ms: profile.invocation.action.valid_until_unix_ms,
        },
        &profile.annotator,
    )?;
    let store = f.authority.admission_operation_store();
    store.install_semantic_annotation(&neutral)?;
    profile.invocation.action.influence = chio_semantic_contracts::semantic_annotated_influence(
        profile.invocation.action.influence,
        std::slice::from_ref(&neutral),
    )?;
    profile.invocation.annotations = BoundedList::new(vec![neutral.clone()])?;
    request.arguments = serde_json::to_value(&profile.invocation)?;
    assert!(!profile.invocation.action.externally_influenced);
    assert!(request.model_metadata.is_none());
    let issued = now_ms()?.max(
        neutral
            .body()
            .issued_at_unix_ms
            .get()
            .checked_add(1)
            .ok_or("annotation clock overflow")?,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while now_ms()? < issued {
        if std::time::Instant::now() >= deadline {
            return Err("annotation authority clock did not advance".into());
        }
        tokio::task::yield_now().await;
    }
    let mut current = neutral.body().clone();
    current.externally_influenced = true;
    current.issued_at_unix_ms = SafeInteger::new(issued)?;
    current.valid_until_unix_ms = SafeInteger::new(
        issued
            .checked_add(50_000)
            .ok_or("annotation deadline overflow")?,
    )?;
    let current = SignedSemanticAnnotationV1::sign(current, &profile.annotator)?;
    assert_ne!(
        chio_core::canonical_json_bytes(&current)?,
        chio_core::canonical_json_bytes(&neutral)?
    );
    store.install_semantic_annotation(&current)?;
    assert!(now_ms()? < profile.invocation.action.valid_until_unix_ms.get());
    Ok(())
}

/// No native/database owner survives this fixture handoff. Keeping the temporary
/// directory preserves real files; it cannot mint a source role or mutate rows.
fn close_fixture(f: RecoveryFixture) -> (PathBuf, Option<tempfile::TempDir>) {
    let path = f.path.clone();
    let directory = f._directory;
    drop(f.runtime);
    drop(f.kernel);
    drop(f.process);
    drop(f.authority);
    (path, directory)
}

/// The fate the real SQLite readback exposes for an operation's retained
/// Input join, derived from its retained bytes.
fn retained_fate(
    f: &RecoveryFixture,
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
) -> TestResult<NativeSecurityInputFateV1> {
    let (_, input) = f
        .authority
        .admission_operation_store()
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("retained Input operation absent")?;
    Ok(input.ok_or("retained Input journal absent")?.fate)
}

fn durable_input_operation(
    f: &RecoveryFixture,
    request_id: &str,
) -> TestResult<chio_kernel::admission_operation::AdmissionOperationV1> {
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("durable Input original absent")?;
    original.validate_binding(operation.binding())?;
    Ok(operation)
}

#[tokio::test]
async fn refused_input_replay_denies_with_zero_dispatch_and_equal_history() -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
    let key = "refused-fate-replay";
    let (runtime, mut request, mut profile) =
        prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
    install_changed_selected_answer(&f, &mut request, &mut profile).await?;
    let response = runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    assert_signed_deny(&f, &request, &response)?;
    let operation = durable_input_operation(&f, &request.request_id)?;
    let operation_id = operation.binding().operation_id();
    let durable = durable_record(&f.path, operation_id.as_str())?;
    assert_eq!(
        durable.record["schema"],
        "chio.native-security-flow-join.v3"
    );
    assert_eq!(durable.record["input_fate"]["fate"], "refused");
    assert!(durable.record["input_fate"]["origin"].is_object());
    assert_eq!(
        chio_core::canonical_json_bytes(&durable.record)?,
        durable.bytes
    );
    // The retained refused source restriction flows into every joined label.
    let source: InformationLabel =
        serde_json::from_value(durable.record["input_fate"]["origin"]["source_label"].clone())?;
    for field in ["principal_label", "lineage_label", "session_label"] {
        let label: InformationLabel =
            serde_json::from_value(durable.record["result"][field].clone())?;
        assert!(
            source.flows_to(&label),
            "the refused source restriction was lowered for {field}"
        );
    }
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    assert_eq!(
        retained_fate(&f, &operation)?,
        NativeSecurityInputFateV1::Refused
    );
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(store
        .load_security_participant_output(operation_id, &fence, now_ms()?)?
        .is_none());
    assert!(f
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation_id)?
        .is_none());
    let calls = f.process.process("root")?.tree_calls;
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&f.path)?, 0);
    // A terminal compensated retry cannot re-admit the refused Input, repeat
    // an effect or rewrite any retained history. The classified replay
    // branch itself is exercised by the lost-acknowledgement test below.
    let replay = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    assert!(
        !matches!(&replay, Ok(response) if response.verdict == Verdict::Allow),
        "a durable refused Input replayed as allowed"
    );
    assert!(!format!("{replay:?}").contains("provider-output-canary"));
    let after = durable_record(&f.path, operation_id.as_str())?;
    assert_eq!(
        after.bytes, durable.bytes,
        "replay changed retained history"
    );
    assert_eq!(after.mutations, durable.mutations);
    assert_eq!(after.commits, durable.commits);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn lost_ack_refused_input_retry_reads_retained_fate_and_kernel_refuses() -> TestResult {
    // Both supported Input record shapes retry the same kernel-minted
    // classification through the real writer: the current v3 shape retains
    // a Refused fate, and the genuine prior v2 shape retains no fate, so its
    // retry must read Unproved. Neither shape can classify Eligible.
    for prior_writer in [false, true] {
        let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
        let store = f.authority.admission_operation_store();
        let key = "lost-ack-refused";
        let (runtime, mut request, mut profile) =
            prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
        install_changed_selected_answer(&f, &mut request, &mut profile).await?;
        // The prior-writer variant holds the real writer under its retained
        // prior Input format (v2 schema, no retained fate) for this store.
        let prior_guard = match prior_writer {
            true => Some(store.retained_prior_input_writer_for_test()?),
            false => None,
        };
        // Arm one genuine lost acknowledgement at the classified join
        // boundary: the real SQLite classified writer commits the refused
        // Input durably, its first acknowledgement is discarded, and the
        // same legitimate kernel-minted classification retries the real
        // writer before the kernel consumes any result.
        store.arm_lost_ack_classified_input_retry_for_test()?;
        let response = runtime
            .execute_step(&f.process, "root", key, &request)
            .await?;
        drop(prior_guard);
        // The kernel consumed the retried classification and refused before
        // any dispatch.
        assert_signed_deny(&f, &request, &response)?;
        assert!(
            store.lost_ack_classified_input_retry_consumed_for_test(),
            "the armed retry must consume the real classified join"
        );
        assert!(
            store.lost_ack_classified_input_retry_first_refused_for_test(),
            "the discarded first acknowledgement must be a real Refused commit"
        );
        assert!(
            store.lost_ack_classified_input_retry_replay_refused_for_test(),
            "the retry must classify Refused from retained history"
        );
        // Exact fate evidence for each supported shape: the current writer
        // retains Refused for the first join and the retry, the real prior
        // writer retains none so both read Unproved. Neither is Eligible.
        let expected_fate = if prior_writer {
            NativeSecurityInputFateV1::Unproved
        } else {
            NativeSecurityInputFateV1::Refused
        };
        assert_eq!(
            store.lost_ack_classified_input_retry_fates_for_test(),
            Some((expected_fate, expected_fate)),
            "prior_writer={prior_writer}: the first join and the retry must read the retained fate"
        );
        // Zero-write history equality measured inside the armed seam. The
        // first observation follows the real committed refused join, the
        // second follows the immediate same-classification replay, and
        // nothing else can run between them, so equal native record bytes
        // and equal global journal state prove the retry read the retained
        // history and wrote nothing.
        let first_join = store
            .lost_ack_classified_input_retry_first_join_for_test()
            .ok_or("the armed retry must observe the first committed join")?;
        let replay_join = store
            .lost_ack_classified_input_retry_replay_join_for_test()
            .ok_or("the armed retry must observe the immediate replay")?;
        assert_eq!(
            replay_join.0, first_join.0,
            "the immediate replay rewrote the retained native record"
        );
        assert_eq!(
            replay_join.1, first_join.1,
            "the immediate replay appended a global journal commit"
        );
        let operation = durable_input_operation(&f, &request.request_id)?;
        let operation_id = operation.binding().operation_id().clone();
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert!(operation.dispatch_commit().is_none());
        assert!(operation.native_dispatch_ledger_digest().is_none());
        let durable = durable_record(&f.path, operation_id.as_str())?;
        assert_eq!(
            chio_core::canonical_json_bytes(&durable.record)?,
            durable.bytes
        );
        // The real readback exposes the retained fate: the prior writer's
        // bytes name none (Unproved), the current writer's name Refused.
        assert_eq!(
            retained_fate(&f, &operation)?,
            if prior_writer {
                NativeSecurityInputFateV1::Unproved
            } else {
                NativeSecurityInputFateV1::Refused
            }
        );
        if prior_writer {
            // The genuine prior shape: no retained fate, so the immediate
            // retry read Unproved and still classified Refused.
            assert_eq!(
                durable.record["schema"],
                "chio.native-security-flow-join.v2"
            );
            assert!(
                durable.record.get("input_fate").is_none(),
                "a prior writer Input record retains no fate"
            );
        } else {
            // The current shape: the retained Refused fate decided.
            assert_eq!(
                durable.record["schema"],
                "chio.native-security-flow-join.v3"
            );
            assert_eq!(durable.record["input_fate"]["fate"], "refused");
            assert!(durable.record["input_fate"]["origin"].is_object());
        }
        // Exactly one native Input mutation exists for this operation: the
        // first committed join. The retry's zero writes are proven above
        // inside the seam; admission, lease and compensation commits stay
        // outside this operation-scoped count.
        assert_eq!(
            retained_mutation_count(&f.path, operation_id.as_str())?,
            1,
            "the classified retry wrote a second native Input mutation"
        );
        let fence = f.authority.mutation_fence();
        assert!(store
            .load_security_participant_output(&operation_id, &fence, now_ms()?)?
            .is_none());
        assert!(f
            .authority
            .tool_outcome_store()
            .load_raw_invocation_by_operation(&operation_id)?
            .is_none());
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
        assert_eq!(external_count(&f.path)?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn refused_input_fate_survives_cold_restart_and_stays_refused() -> TestResult {
    let (path, directory, request_id, operation_id, durable_bytes) = {
        let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
        let key = "refused-fate-restart";
        let (runtime, mut request, mut profile) =
            prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
        install_changed_selected_answer(&f, &mut request, &mut profile).await?;
        let response = runtime
            .execute_step(&f.process, "root", key, &request)
            .await?;
        assert_signed_deny(&f, &request, &response)?;
        let operation = durable_input_operation(&f, &request.request_id)?;
        let operation_id = operation.binding().operation_id().as_str().to_owned();
        let durable = durable_record(&f.path, operation_id.as_str())?;
        assert_eq!(durable.record["input_fate"]["fate"], "refused");
        let request_id = request.request_id.clone();
        let (path, directory) = close_fixture(f);
        (path, directory, request_id, operation_id, durable.bytes)
    };
    // The cold reopen authenticates the retained refused origin against its
    // actual retained global commit, before-images and influence at the cut.
    let reopened = RecoveryFixture::open(path.clone(), None, false)?;
    let store = reopened.authority.admission_operation_store();
    let fence = reopened.authority.mutation_fence();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("refused Input original absent after restart")?;
    original.validate_binding(operation.binding())?;
    let (loaded, input) = store
        .load_native_security_input_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("refused Input operation absent after restart")?;
    let input = input.ok_or("refused Input journal absent after restart")?;
    input.validate()?;
    assert_eq!(input.fate, NativeSecurityInputFateV1::Refused);
    assert_eq!(loaded, operation);
    let after = durable_record(&path, operation_id.as_str())?;
    assert_eq!(after.bytes, durable_bytes);
    assert_eq!(after.record["input_fate"]["fate"], "refused");
    assert_eq!(reopened.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&path)?, 0);
    drop(reopened);
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn prior_writer_v2_refused_input_replay_stays_refused() -> TestResult {
    let (path, directory, request_id, operation_id, durable_bytes) = {
        let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
        let store = f.authority.admission_operation_store();
        let key = "prior-writer-refused";
        let guard = store.retained_prior_input_writer_for_test()?;
        let (runtime, mut request, mut profile) =
            prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
        install_changed_selected_answer(&f, &mut request, &mut profile).await?;
        let response = runtime
            .execute_step(&f.process, "root", key, &request)
            .await?;
        drop(guard);
        assert_signed_deny(&f, &request, &response)?;
        let operation = durable_input_operation(&f, &request.request_id)?;
        let operation_id = operation.binding().operation_id().as_str().to_owned();
        let durable = durable_record(&f.path, operation_id.as_str())?;
        // The real prior writer emitted v2 bytes with no retained fate.
        assert_eq!(
            durable.record["schema"],
            "chio.native-security-flow-join.v2"
        );
        assert!(
            durable.record.get("input_fate").is_none(),
            "prior writer bytes cannot carry a retained fate"
        );
        assert_eq!(
            chio_core::canonical_json_bytes(&durable.record)?,
            durable.bytes
        );
        assert_eq!(
            retained_fate(&f, &operation)?,
            NativeSecurityInputFateV1::Unproved
        );
        // An unproved retry cannot become eligible or repeat an effect.
        let replay = runtime
            .execute_step(&f.process, "root", key, &request)
            .await;
        assert!(
            !matches!(&replay, Ok(response) if response.verdict == Verdict::Allow),
            "prior unproved Input replayed as allowed"
        );
        assert!(!format!("{replay:?}").contains("provider-output-canary"));
        let after = durable_record(&f.path, operation_id.as_str())?;
        assert_eq!(after.bytes, durable.bytes);
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
        assert_eq!(external_count(&f.path)?, 0);
        let request_id = request.request_id.clone();
        let (path, directory) = close_fixture(f);
        (path, directory, request_id, operation_id, durable.bytes)
    };
    // A cold restart keeps the same prior bytes refused, never upgraded.
    let reopened = RecoveryFixture::open(path.clone(), None, false)?;
    let reopened_store = reopened.authority.admission_operation_store();
    let reopened_fence = reopened.authority.mutation_fence();
    let (operation, _) = reopened_store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request_id)?,
            &reopened_fence,
            now_ms()?,
        )?
        .ok_or("prior Input original absent after restart")?;
    let (_, input) = reopened_store
        .load_native_security_input_join(
            operation.binding().operation_id(),
            &reopened_fence,
            now_ms()?,
        )?
        .ok_or("prior Input operation absent after restart")?;
    let input = input.ok_or("prior Input journal absent after restart")?;
    input.validate()?;
    assert_eq!(input.fate, NativeSecurityInputFateV1::Unproved);
    let after_restart = durable_record(&path, operation_id.as_str())?;
    assert_eq!(after_restart.bytes, durable_bytes);
    assert!(after_restart.record.get("input_fate").is_none());
    assert_eq!(reopened.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&path)?, 0);
    drop(reopened);
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn eligible_selected_and_unselected_inputs_retain_eligible_fate_before_any_effect(
) -> TestResult {
    let f = empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
    // Owning selected-scope positive: the real call path classifies Eligible
    // and retains the fate at the input join, before the later finishing
    // boundary this fixture cannot cross. The later stage is deliberately
    // not asserted here.
    let key = "eligible-pre-effect";
    let (runtime, mut request, mut profile) =
        prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    attach_neutral_annotation(&f, &mut request, &mut profile)?;
    let _later_stage = runtime
        .execute_step(&f.process, "root", key, &request)
        .await;
    let operation = durable_input_operation(&f, &request.request_id)?;
    let operation_id = operation.binding().operation_id().as_str().to_owned();
    let durable = durable_record(&f.path, operation_id.as_str())?;
    assert_eq!(
        durable.record["schema"],
        "chio.native-security-flow-join.v3"
    );
    assert_eq!(durable.record["input_fate"]["fate"], "eligible");
    assert!(durable.record["input_fate"].get("origin").is_none());
    assert_eq!(
        retained_fate(&f, &operation)?,
        NativeSecurityInputFateV1::Eligible
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&durable.record)?,
        durable.bytes
    );
    // Matched unselected-scope positive on the same real call path: with no
    // selected semantic route the input still joins and classifies Eligible
    // pre-effect, with the established compensated denial outcome.
    let seed_request = f.process.tool_request(
        "root",
        "unselected-eligible",
        &f.seed.server_id,
        &f.seed.tool_name,
        f.seed.arguments.clone(),
    )?;
    let seed_response = Box::pin(f.process.invoke_known_only(
        "root",
        "unselected-eligible",
        &seed_request,
    ))
    .await?;
    assert_signed_deny(&f, &seed_request, &seed_response)?;
    let seed_operation = durable_input_operation(&f, &seed_request.request_id)?;
    assert_eq!(
        seed_operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(seed_operation.dispatch_commit().is_none());
    let seed_durable = durable_record(&f.path, seed_operation.binding().operation_id().as_str())?;
    assert_eq!(
        seed_durable.record["schema"],
        "chio.native-security-flow-join.v3"
    );
    assert_eq!(seed_durable.record["input_fate"]["fate"], "eligible");
    assert_eq!(
        retained_fate(&f, &seed_operation)?,
        NativeSecurityInputFateV1::Eligible
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&seed_durable.record)?,
        seed_durable.bytes
    );
    Ok(())
}

#[tokio::test]
async fn tampered_refused_origin_bindings_fail_cold_recovery() -> TestResult {
    for damage in ["wrong-operation", "wrong-input"] {
        // Start from a real, valid refused origin and alter only its binding
        // to another well-formed value, preserving every other field.
        let (path, directory, operation_id) = {
            let f =
                empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
            let key = "origin-binding";
            let (runtime, mut request, mut profile) =
                prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
            install_changed_selected_answer(&f, &mut request, &mut profile).await?;
            let response = runtime
                .execute_step(&f.process, "root", key, &request)
                .await?;
            assert_signed_deny(&f, &request, &response)?;
            let operation = durable_input_operation(&f, &request.request_id)?;
            let operation_id = operation.binding().operation_id().as_str().to_owned();
            let (path, directory) = close_fixture(f);
            (path, directory, operation_id)
        };
        let connection = rusqlite::Connection::open(path.join("admission.db"))?;
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
             AND name = 'security_participant_state_mutations_no_update'",
            [],
            |row| row.get(0),
        )?;
        let bytes: Vec<u8> = connection.query_row(
            "SELECT canonical_record FROM main.security_participant_state_mutations
             WHERE operation_id = ?1",
            [&operation_id],
            |row| row.get(0),
        )?;
        let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert!(record["input_fate"]["origin"].is_object());
        match damage {
            "wrong-operation" => {
                // Another well-formed operation identifier of the same
                // shape; every other origin field stays intact.
                let original = record["input_fate"]["origin"]["operation"]
                    .as_str()
                    .ok_or("origin operation absent")?
                    .to_owned();
                let tail = if original.ends_with('0') { "1" } else { "0" };
                let head = original
                    .len()
                    .checked_sub(1)
                    .ok_or("origin operation is empty")?;
                let mut forged = original.clone();
                forged.truncate(head);
                forged.push_str(tail);
                assert_ne!(forged, original);
                record["input_fate"]["origin"]["operation"] = forged.into();
            }
            "wrong-input" => {
                // Another well-formed Input transition binding for the same
                // origin shape; the record's own Input binding is unchanged.
                record["input_fate"]["origin"]["input"]["transition_id"] =
                    "forged-transition".into();
            }
            _ => return Err("unknown origin binding damage".into()),
        }
        let bytes = chio_core::canonical_json_bytes(&record)?;
        let mut preimage = b"chio.native-security-mutation.commit.v1\0".to_vec();
        preimage.extend_from_slice(&bytes);
        connection.execute_batch("DROP TRIGGER security_participant_state_mutations_no_update")?;
        connection.execute(
            "UPDATE main.security_participant_state_mutations
             SET canonical_record = ?1, mutation_digest = ?2 WHERE operation_id = ?3",
            rusqlite::params![bytes, chio_core::sha256_hex(&preimage), operation_id],
        )?;
        connection.execute_batch(&trigger)?;
        drop(connection);
        assert!(
            RecoveryFixture::open(path.clone(), None, false).is_err(),
            "{damage}: a real refused origin with an altered binding must not reopen"
        );
        drop(directory);
    }
    Ok(())
}

/// The retained native mutation rows and native global commits of a store,
/// the durable footprint of every native Input write.
fn native_footprint(path: &Path) -> TestResult<(i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    let mutations = connection.query_row(
        "SELECT COUNT(*) FROM main.security_participant_state_mutations",
        [],
        |row| row.get(0),
    )?;
    let commits = connection.query_row(
        "SELECT COUNT(*) FROM main.authority_global_commits
         WHERE projection_kind = 'security_participant_state'",
        [],
        |row| row.get(0),
    )?;
    Ok((mutations, commits))
}

#[tokio::test]
async fn refused_input_whose_record_clock_precedes_its_origin_rolls_back_whole_and_a_valid_one_reopens(
) -> TestResult {
    for inverted in [true, false] {
        // The runtime, store handle and fixture hold the serving lock. They
        // live only in this block, so the reopen below is the first owner.
        let (path, directory, operation_id) = {
            let f =
                empty_import::native_fixture_from_empty_import("trusted-annotated-read").await?;
            let store = f.authority.admission_operation_store();
            let fence = f.authority.mutation_fence();
            let key = "clock-ordered-refusal";
            let (runtime, mut request, mut profile) =
                prepare(&f, key, SemanticOutputDispositionV1::Withhold)?;
            install_changed_selected_answer(&f, &mut request, &mut profile).await?;
            let deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
            let flow_key = recovery_flow_key(&deployment.security_context);
            let before = store
                .observe_security_participant_flow(
                    &deployment.native_authority,
                    &flow_key,
                    &fence,
                    now_ms()?,
                )?
                .snapshot()
                .ok_or("native source absent before the refused Input")?
                .clone();
            let footprint = native_footprint(&f.path)?;
            if inverted {
                // The real writer observes the record's time before the origin's
                // own observation. The cold open refuses that relation, so the
                // writer must refuse it before anything commits.
                store.arm_record_clock_inversion_for_test()?;
            }
            let response = runtime
                .execute_step(&f.process, "root", key, &request)
                .await;
            let operation = durable_input_operation(&f, &request.request_id)?;
            let operation_id = operation.binding().operation_id().as_str().to_owned();
            assert!(operation.dispatch_commit().is_none());
            assert!(operation.native_dispatch_ledger_digest().is_none());
            assert_eq!(f.effects.load(Ordering::SeqCst), 0);
            assert_eq!(external_count(&f.path)?, 0);
            if inverted {
                assert!(
                    store.record_clock_inversion_applied_for_test(),
                    "the armed inversion must reach a real refused write"
                );
                assert!(
                    !matches!(&response, Ok(response) if response.verdict == Verdict::Allow),
                    "an unreadable refused Input must never admit"
                );
                // The same inverted write reached the post-append full
                // validation, which refused it while the structure and lease
                // phase alone still held: the cold origin and time relation
                // refused it, not an earlier predicate.
                let validation = store
                    .record_clock_inversion_validation_for_test()
                    .ok_or("the inverted write never reached the post-append full validation")?;
                assert!(
                    validation.origin_observed_at > validation.record_observed_at,
                    "{validation:?}: the record observation must precede the origin's"
                );
                assert!(
                    validation.structure_valid,
                    "{validation:?}: an earlier structure or lease refusal masks the cold relation"
                );
                assert!(
                    !validation.retained_valid,
                    "{validation:?}: the full validation must refuse the inverted origin and time"
                );
                // No durable footprint: no native mutation for the operation, no
                // native mutation or global commit anywhere, and the flow labels
                // and generation are exactly those before the attempt.
                assert_eq!(retained_mutation_count(&f.path, operation_id.as_str())?, 0);
                assert_eq!(native_footprint(&f.path)?, footprint);
                let after = store.observe_security_participant_flow(
                    &deployment.native_authority,
                    &flow_key,
                    &fence,
                    now_ms()?,
                )?;
                assert_eq!(after.snapshot(), Some(&before));
                let (_, input) = store
                    .load_native_security_input_join(
                        operation.binding().operation_id(),
                        &fence,
                        now_ms()?,
                    )?
                    .ok_or("rolled back Input operation absent")?;
                assert!(input.is_none(), "the rolled back Input left a journal");
            } else {
                assert!(!store.record_clock_inversion_applied_for_test());
                assert!(store.record_clock_inversion_validation_for_test().is_none());
                assert_signed_deny(&f, &request, &response?)?;
                assert_eq!(retained_mutation_count(&f.path, operation_id.as_str())?, 1);
                assert_eq!(
                    durable_record(&f.path, operation_id.as_str())?.record["input_fate"]["fate"],
                    "refused"
                );
            }
            let (path, directory) = close_fixture(f);
            (path, directory, operation_id)
        };
        // The store reopens, so no unreadable history was committed.
        let reopened = RecoveryFixture::open(path.clone(), None, false)?;
        let reopened_store = reopened.authority.admission_operation_store();
        let reopened_fence = reopened.authority.mutation_fence();
        let (_, input) = reopened_store
            .load_native_security_input_join(
                &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                    &operation_id,
                )?,
                &reopened_fence,
                now_ms()?,
            )?
            .ok_or("Input operation absent after restart")?;
        assert_eq!(input.is_some(), !inverted);
        assert_eq!(reopened.effects.load(Ordering::SeqCst), 0);
        drop(reopened);
        drop(directory);
    }
    Ok(())
}
