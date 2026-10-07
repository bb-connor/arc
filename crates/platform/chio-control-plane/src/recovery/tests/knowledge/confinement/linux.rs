//! Required real Linux acceptance. Missing measured executables are failures.
use super::*;
use chio_cage::{CompiledCage, ExecutionIdentity, OperatorCeilings, RuntimeResourcePaths};
use chio_manifest::{
    sign_manifest, NativeSyscallProfile, RequiredPermissions, RuntimeToolTopology, ToolAnnotations,
    ToolDefinition, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn compiled(f: &ConfinedFixture, target: &Path) -> TestResult<CompiledCage> {
    compiled_with_environment(f, target, &BTreeMap::new(), BTreeSet::new())
}
fn compiled_with_environment(
    f: &ConfinedFixture,
    target: &Path,
    parent: &BTreeMap<String, String>,
    allowed: BTreeSet<chio_manifest::EnvironmentVariableName>,
) -> TestResult<CompiledCage> {
    compiled_with_channels(f, target, parent, allowed, BTreeSet::new())
}
fn compiled_with_channels(
    f: &ConfinedFixture,
    target: &Path,
    parent: &BTreeMap<String, String>,
    allowed: BTreeSet<chio_manifest::EnvironmentVariableName>,
    runtime_files: BTreeSet<PathBuf>,
) -> TestResult<CompiledCage> {
    let signer = Keypair::from_seed(&[235; 32]);
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: "confined-reader".into(),
        name: "Confined reader".into(),
        description: None,
        version: "1".into(),
        tools: vec![ToolDefinition {
            name: "read".into(),
            description: "Bounded projection".into(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: true,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: vec![],
        required_permissions: Some(RequiredPermissions {
            read_paths: if runtime_files.is_empty() {
                None
            } else {
                Some(
                    runtime_files
                        .iter()
                        .map(|path| path.to_str().map(str::to_owned).ok_or("runtime file text"))
                        .collect::<Result<_, _>>()?,
                )
            },
            write_paths: None,
            network_destinations: None,
            environment_variables: (!allowed.is_empty()).then(|| allowed.iter().cloned().collect()),
            native_syscall_profile: NativeSyscallProfile::NativeMinimalV1,
        }),
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer)?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())?;
    let ceilings = OperatorCeilings::new(
        runtime_files.clone(),
        BTreeSet::new(),
        BTreeSet::new(),
        allowed,
        BTreeSet::from([NativeSyscallProfile::NativeMinimalV1]),
    )
    .with_forbidden_paths(BTreeSet::from([f.knowledge.f.path.clone()]));
    let admitted = chio_cage::admit(
        registry.authorize_cage_manifest("confined-reader")?,
        &ceilings,
    )?;
    let helper = PathBuf::from(
        std::env::var_os("CHIO_CAGE_TEST_HELPER").ok_or("missing measured cage-init")?,
    );
    let identity = if nix::unistd::geteuid().is_root() {
        ExecutionIdentity::new(65534, 65534, vec![])?
    } else {
        ExecutionIdentity::from_observed_credentials(
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
            nix::unistd::getgroups()?
                .into_iter()
                .map(|gid| gid.as_raw())
                .collect(),
        )?
    };
    let runtime = chio_cage::retain_runtime_resources(&RuntimeResourcePaths::new(
        helper,
        target.to_path_buf(),
        std::fs::canonicalize(std::env::temp_dir())?,
        runtime_files,
        identity,
    ))?;
    Ok(chio_cage::compile(admitted, runtime, parent, None)?)
}
fn measured_fixture(target: &Path) -> TestResult<(ConfinedFixture, CompiledCage)> {
    measured_fixture_with_storage(target, false)
}
fn measured_fixture_with_storage(
    target: &Path,
    bounded: bool,
) -> TestResult<(ConfinedFixture, CompiledCage)> {
    let mut f = ConfinedFixture::with_bounded_storage(bounded)?;
    let cage = compiled(&f, target)?;
    f.profile.generation = SafeInteger::new(2)?;
    f.profile.execution = crate::confinement::confined_execution_profile(&cage)?;
    f.runtime = NativeConfinedRuntime::new(
        f.knowledge.f.kernel.clone(),
        Arc::new(f.knowledge.f.authority.admission_operation_store()),
        f.knowledge.broker.clone(),
        f.profile.clone(),
        f.knowledge.f.authority.mutation_fence(),
    )?;
    Ok((f, cage))
}
fn reader() -> TestResult<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("CHIO_CONFINED_READER").ok_or("missing measured reader")?,
    ))
}
fn approve(
    body: ConfinedReturnEvidenceV1,
) -> TestResult<(SignedConfinedDisclosureV1, SignedConfinedEndorsementV1)> {
    Ok((
        SignedConfinedDisclosureV1::sign(body.clone(), &Keypair::from_seed(&[233; 32]))?,
        SignedConfinedEndorsementV1::sign(body, &Keypair::from_seed(&[234; 32]))?,
    ))
}

fn set_preview_clearance(f: &ConfinedFixture, clearance: InformationLabel) -> TestResult {
    let mut deployment = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = clearance;
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.knowledge
        .f
        .authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(())
}

#[test]
fn linux_staging_receipt_and_return_preparation_enforce_source_audience() -> TestResult {
    let canaries = PathBuf::from(
        std::env::var_os("CHIO_CONFINED_CANARY_DIR").ok_or("missing measured canary images")?,
    );
    let mut violations = Vec::new();
    let mut refusals = Vec::new();
    let mut launch_refusals = Vec::new();
    // A low caller cannot learn whether a classified observation satisfies
    // the projection schema through reservation or launch success/failure.
    for (name, value) in [
        ("valid", serde_json::json!(true)),
        ("malformed", serde_json::json!("PRIVATE-SCHEMA-CANARY")),
    ] {
        let (mut f, cage) = measured_fixture(&reader()?)?;
        f.observation = f.knowledge.publish(
            "audience-classified-schema",
            &chio_core::canonical_json_bytes(&serde_json::json!({
                "eligible": value, "secret": "PRIVATE-SCHEMA-CANARY",
            }))?,
        )?;
        let request = RequestId::new("audience-schema-return")?;
        let capability = child(&f.knowledge, "audience-schema-child", 201)?;
        set_preview_clearance(&f, InformationLabel::bottom())?;
        let before = f.storage()?;
        if f.reserve(request.as_str(), &capability).is_ok() {
            violations.push(format!(
                "low-clearance reservation processed private {name} input"
            ));
        }
        let after = f.storage()?;
        if after.tree_bytes != before.tree_bytes || after.tree_blobs != before.tree_blobs {
            violations.push(format!(
                "low-clearance reservation charged private {name} input"
            ));
        }
        // The independently cleared host can reserve the exact work. Revoke
        // preview clearance again before entering the secret-dependent path.
        set_preview_clearance(&f, restricted_label())?;
        f.reserve(request.as_str(), &capability)?;
        let store = f.knowledge.f.authority.admission_operation_store();
        let fence = f.knowledge.f.authority.mutation_fence();
        let cleared = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
        store.confined_launch_reservation(&cleared, &request, &fence, now_ms()?)?;
        set_preview_clearance(&f, InformationLabel::bottom())?;
        let withdrawn = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
        if store
            .confined_launch_reservation(&withdrawn, &request, &fence, now_ms()?)
            .is_ok()
        {
            violations.push(format!(
                "low-clearance native reservation revealed private {name} input"
            ));
        }
        match f.runtime.launch(&f.knowledge.f.control, &request, cage) {
            Ok(execution) => {
                violations.push(format!(
                    "low-clearance launch accepted private {name} input"
                ));
                drop(execution);
            }
            Err(error) => launch_refusals.push(error.to_string()),
        }
        let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
        let observed: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.observation_release') IS NOT NULL",
            [], |row| row.get(0),
        )?;
        if observed != 0 {
            violations.push(format!(
                "low-clearance launch admitted private {name} input"
            ));
        }
        if f.knowledge.f.effects.load(Ordering::SeqCst) != 0 {
            violations.push("classified schema refusal caused an external effect".into());
        }
    }
    if launch_refusals.len() != 2
        || launch_refusals.windows(2).any(|pair| pair[0] != pair[1])
        || launch_refusals
            .iter()
            .any(|message| message.contains("PRIVATE-SCHEMA-CANARY"))
    {
        violations.push("low-clearance launch distinguished the private schema".into());
    }
    // This image always writes false. Accepting it for one private predicate
    // and rejecting it for the other would reveal the predicate without approval.
    for boolean in [true, false] {
        let (mut f, cage) = measured_fixture(&canaries.join("wrong-predicate"))?;
        f.observation = f.knowledge.publish(
            "audience-private-predicate",
            &chio_core::canonical_json_bytes(&serde_json::json!({
                "eligible": boolean, "secret": "PRIVATE-RETURN-CANARY",
            }))?,
        )?;
        let request = RequestId::new("audience-confined-return")?;
        f.reserve(
            request.as_str(),
            &child(&f.knowledge, "audience-child", 201)?,
        )?;
        let execution = f.runtime.launch(&f.knowledge.f.control, &request, cage)?;
        let store = f.knowledge.f.authority.admission_operation_store();
        let fence = f.knowledge.f.authority.mutation_fence();
        let cleared = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
        store.confined_input_inventory(&cleared, &request, &fence, now_ms()?)?;
        set_preview_clearance(&f, InformationLabel::bottom())?;
        let withdrawn = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
        let before = f.storage()?;
        if store
            .confined_input_inventory(&withdrawn, &request, &fence, now_ms()?)
            .is_ok()
        {
            violations.push("low-clearance native inventory revealed private inputs".into());
        }
        match execution.stage(&f.knowledge.f.control) {
            Ok(()) => {
                violations.push(format!("low-clearance staging accepted private {boolean}"));
            }
            Err(error) => refusals.push(error.to_string()),
        }
        let after = f.storage()?;
        if after.tree_bytes != before.tree_bytes || after.tree_blobs != before.tree_blobs {
            violations.push(format!(
                "low-clearance private {boolean} changed parent storage"
            ));
        }
        let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
        let retained: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.return_metadata') IS NOT NULL",
            [], |row| row.get(0),
        )?;
        if retained != 0 {
            violations.push(format!(
                "low-clearance staging processed private {boolean} metadata"
            ));
        }
        if f.runtime
            .review_return(&f.knowledge.f.control, &request)
            .is_ok()
        {
            violations.push("low-clearance return review exposed evidence".into());
        }
        if f.runtime
            .prepare_return(&f.knowledge.f.control, &request)
            .is_ok()
        {
            violations.push("low-clearance return preparation resolved private bytes".into());
        }
    }
    if refusals.len() != 2 || refusals.windows(2).any(|pair| pair[0] != pair[1]) {
        violations.push("low-clearance staging distinguished the private predicates".into());
    }
    if refusals
        .iter()
        .any(|message| message.contains("PRIVATE-RETURN-CANARY"))
    {
        violations.push("classified error body reached the staging caller".into());
    }

    // A cleared caller can complete staging. Evidence comes only from the
    // separately authorized review, and later clearance changes revoke access.
    let (f, cage) = measured_fixture(&reader()?)?;
    let request = RequestId::new("cleared-confined-return")?;
    f.reserve(
        request.as_str(),
        &child(&f.knowledge, "cleared-child", 201)?,
    )?;
    f.runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    let cleared_return = f.knowledge.actor(RecoveryPermission::ConfinedReturn)?;
    let (seal, _) = store.prepare_confined_return(&cleared_return, &request, &fence, now_ms()?)?;
    let cleared_launch = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    // This exact native replay succeeds with actual staged bytes and custody.
    // Later refusals therefore cannot be credited to a missing seal or exit.
    store.stage_confined_return(&cleared_launch, &request, &seal, b"true", &fence, now_ms()?)?;
    let (disclosure, endorsement) =
        approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let retained_version = |connection: &rusqlite::Connection| -> TestResult<i64> {
        Ok(connection.query_row(
            "SELECT version FROM admission_operation_recovery_records
             WHERE record_key GLOB 'confined-boundary:*'",
            [],
            |row| row.get(0),
        )?)
    };
    let version = retained_version(&connection)?;
    let before = f.storage()?;
    set_preview_clearance(&f, InformationLabel::bottom())?;
    let withdrawn_launch = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let withdrawn_return = f.knowledge.actor(RecoveryPermission::ConfinedReturn)?;
    let mut native_refusals = Vec::new();
    for candidate in [b"true".as_slice(), b"not-json".as_slice()] {
        match store.stage_confined_return(
            &withdrawn_launch,
            &request,
            &seal,
            candidate,
            &fence,
            now_ms()?,
        ) {
            Ok(()) => violations.push("low-clearance native staging inspected a candidate".into()),
            Err(error) => native_refusals.push(error.to_string()),
        }
    }
    if native_refusals.len() != 2 || native_refusals[0] != native_refusals[1] {
        violations.push("low-clearance native staging distinguished candidate validity".into());
    }
    if store
        .confined_return_evidence(&withdrawn_return, &request, &fence, now_ms()?)
        .is_ok()
    {
        violations.push("low-clearance native review returned classified evidence".into());
    }
    if store
        .prepare_confined_return(&withdrawn_return, &request, &fence, now_ms()?)
        .is_ok()
    {
        violations.push("low-clearance native preparation returned classified custody".into());
    }
    if store
        .admit_confined_return(
            &withdrawn_return,
            ConfinedReturnAdmissionInput {
                request: &request,
                seal: &seal,
                parent: &f.profile.contract.parent,
                disclosure: Some(&disclosure),
                endorsement: Some(&endorsement),
            },
            &fence,
            now_ms()?,
        )
        .is_ok()
    {
        violations.push("low-clearance native admission returned classified metadata".into());
    }
    if retained_version(&connection)? != version || f.storage()? != before {
        violations
            .push("low-clearance native return access changed retained state or quota".into());
    }
    if f.runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_ok()
    {
        violations.push("fresh preparation ignored source clearance".into());
    }
    set_preview_clearance(&f, restricted_label())?;
    let prepared = f.runtime.prepare_return(&f.knowledge.f.control, &request)?;
    set_preview_clearance(&f, InformationLabel::bottom())?;
    let sink = f.knowledge.sink();
    if f.runtime
        .deliver(
            &f.knowledge.f.control,
            prepared,
            &sink,
            Some(&disclosure),
            Some(&endorsement),
        )
        .is_ok()
    {
        violations
            .push("fresh admission exposed classified metadata to a low-clearance caller".into());
    }
    if !sink.delivered.lock().map_err(|_| "sink")?.is_empty() {
        violations.push("low-clearance admission delivered after source access was revoked".into());
    }
    // Restore the independently cleared host's exact original role and prove
    // that the same retained artifact and approvals can still be admitted.
    set_preview_clearance(&f, restricted_label())?;
    f.runtime.deliver(
        &f.knowledge.f.control,
        f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
        &sink,
        Some(&disclosure),
        Some(&endorsement),
    )?;
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), 1);
    assert!(violations.is_empty(), "{}", violations.join("; "));
    Ok(())
}

#[test]
fn linux_staged_return_survives_execution_deadline() -> TestResult {
    let (mut f, cage) = measured_fixture(&reader()?)?;
    f.profile.generation = SafeInteger::new(3)?;
    f.profile.limits.wall_clock_ms = SafeInteger::new(2500)?;
    f.runtime = NativeConfinedRuntime::new(
        f.knowledge.f.kernel.clone(),
        Arc::new(f.knowledge.f.authority.admission_operation_store()),
        f.knowledge.broker.clone(),
        f.profile.clone(),
        f.knowledge.f.authority.mutation_fence(),
    )?;
    let request = RequestId::new("late-confined-approval")?;
    let reservation = f.reserve(
        request.as_str(),
        &child(&f.knowledge, "late-approval-child", 201)?,
    )?;
    f.runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)?;
    std::thread::sleep(std::time::Duration::from_millis(
        reservation
            .boundary
            .deadline_unix_ms
            .get()
            .saturating_sub(now_ms()?)
            .saturating_add(50),
    ));
    assert!(now_ms()? >= reservation.boundary.deadline_unix_ms.get());
    let (disclosure, endorsement) =
        approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
    let sink = f.knowledge.sink();
    let admission = f.runtime.deliver(
        &f.knowledge.f.control,
        f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
        &sink,
        Some(&disclosure),
        Some(&endorsement),
    )?;
    assert_eq!(admission.admitted.state, ArtifactDeliveryStateV1::Delivered);
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"true".to_vec()]
    );
    Ok(())
}

#[test]
fn linux_acknowledgement_retains_delivery_after_cancel_and_authority_change() -> TestResult {
    use crate::confinement::ConfinedCutpoint;
    for change in [
        "child-cancel",
        "installation",
        "launch-capability",
        "return-capability",
    ] {
        let (f, cage) = measured_fixture(&reader()?)?;
        let request = RequestId::new("delivery-outcome-retention")?;
        f.reserve(
            request.as_str(),
            &child(&f.knowledge, "outcome-child", 201)?,
        )?;
        f.runtime
            .launch(&f.knowledge.f.control, &request, cage)?
            .stage(&f.knowledge.f.control)?;
        let (disclosure, endorsement) =
            approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
        let prepared = f.runtime.prepare_return(&f.knowledge.f.control, &request)?;
        let control = f.knowledge.f.control.clone();
        let root_capability = f.knowledge.f.seed.capability.clone();
        let kernel = f.knowledge.f.kernel.clone();
        let process = f.knowledge.f.process.clone();
        let store = f.knowledge.f.authority.admission_operation_store();
        let native = f.runtime.clone();
        let mut rotated = f.profile.clone();
        rotated.generation = SafeInteger::new(3)?;
        let captured_request = request.clone();
        let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage != ConfinedCutpoint::DeliveryCompleted {
                return Ok(());
            }
            match change {
                "child-cancel" => native.cancel(&control, &process, &captured_request)?,
                "installation" => store
                    .configure_confinement(&rotated)
                    .map_err(|_| KernelError::Internal("rotate confinement".into()))?,
                "launch-capability" => kernel.revoke_capability(&root_capability.id)?,
                "return-capability" => kernel.revoke_capability(&control.id)?,
                _ => return Err(KernelError::Internal("unknown outcome test change".into())),
            }
            Ok(())
        }));
        let sink = f.knowledge.sink();
        let admission = runtime.deliver(
            &f.knowledge.f.control,
            prepared,
            &sink,
            Some(&disclosure),
            Some(&endorsement),
        )?;
        assert_eq!(
            admission.admitted.state,
            ArtifactDeliveryStateV1::Delivered,
            "{change}"
        );
        assert_eq!(
            sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
            &[b"true".to_vec()],
            "{change}"
        );
        let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
        let (state, disposition): (String, String) = connection.query_row(
            "SELECT json_extract(payload,'$.return_admission.admitted.state'), json_extract(payload,'$.reservation.state') FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(state, "delivered", "{change}");
        assert_eq!(
            disposition,
            if change == "child-cancel" {
                "cancelled"
            } else {
                "closed"
            },
            "{change}"
        );
    }
    Ok(())
}

#[test]
fn linux_rejected_projection_leaves_no_candidate_blob_or_extra_charge() -> TestResult {
    let root = PathBuf::from(
        std::env::var_os("CHIO_CONFINED_CANARY_DIR").ok_or("missing measured canary images")?,
    );
    let (f, cage) = measured_fixture(&root.join("wrong-predicate"))?;
    let request = RequestId::new("reject-unrecomputed-candidate")?;
    let reservation = f.reserve(
        request.as_str(),
        &child(&f.knowledge, "wrong-candidate", 201)?,
    )?;
    let before = f.storage()?;
    assert!(f
        .runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)
        .is_err());
    let after = f.storage()?;
    assert_eq!(
        after.tree_bytes, before.tree_bytes,
        "invalid private output changed parent storage availability"
    );
    assert_eq!(after.tree_blobs, before.tree_blobs);
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("process.db"))?;
    let (legacy, objects, filled_slots): (i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT count(*) FROM process_state_blobs WHERE process_id=?1),
            (SELECT count(*) FROM process_artifact_objects WHERE process_id=?1),
            (SELECT count(*) FROM process_confined_return_slots WHERE child_id=?1 AND (data IS NOT NULL OR sha256 IS NOT NULL))",
        [reservation.boundary.child.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        (legacy, objects, filled_slots),
        (0, 0, 0),
        "rejected candidate retained an orphaned immutable object or filled slot"
    );
    let empty_slots: i64 = connection.query_row(
        "SELECT count(*) FROM process_confined_return_slots
         WHERE child_id=?1 AND parent_id=?2 AND boundary_id=?3 AND data IS NULL AND sha256 IS NULL",
        rusqlite::params![
            reservation.boundary.child.as_str(),
            reservation.boundary.scope.process_id.as_str(),
            reservation.boundary.boundary.as_str(),
        ],
        |row| row.get(0),
    )?;
    assert_eq!(
        empty_slots, 1,
        "the fixed reservation must remain retained and unfilled"
    );
    assert!(f
        .runtime
        .review_return(&f.knowledge.f.control, &request)
        .is_err());
    Ok(())
}

#[test]
fn linux_true_and_false_returns_preserve_identical_parent_storage_availability() -> TestResult {
    let target = reader()?;
    let mut charges = Vec::new();
    for boolean in [true, false] {
        let (mut f, cage) = measured_fixture_with_storage(&target, true)?;
        f.observation = f.knowledge.publish(
            "quota-observation",
            &chio_core::canonical_json_bytes(
                &serde_json::json!({"eligible":boolean,"secret":"PRIVATE-RETURN-CANARY"}),
            )?,
        )?;
        let request = RequestId::new("fixed-return-parent-quota")?;
        f.reserve(request.as_str(), &child(&f.knowledge, "quota-return", 201)?)?;
        let allocated = f.storage()?;
        let mut left = u64::from(allocated.limits.max_bytes)
            .checked_sub(allocated.tree_bytes)
            .and_then(|available| available.checked_sub(7))
            .ok_or("not enough storage for fixed-return quota test")?;
        let mut index = 0u64;
        while left != 0 {
            let size = usize::try_from(left.min(u64::from(allocated.max_blob_bytes)))?;
            let mut filler = vec![b'x'; size];
            for (destination, byte) in filler.iter_mut().zip(index.to_be_bytes()) {
                *destination = byte;
            }
            f.knowledge.broker.stage(
                &ArtifactObjectId::new(&format!("quota-fill-{index}"))?,
                &f.profile.scope.process_id,
                &filler,
            )?;
            left -= u64::try_from(size)?;
            index += 1;
        }
        let before = f.storage()?;
        assert_eq!(u64::from(before.limits.max_bytes) - before.tree_bytes, 7);
        f.runtime
            .launch(&f.knowledge.f.control, &request, cage)?
            .stage(&f.knowledge.f.control)?;
        let after = f.storage()?;
        assert_eq!(
            after.tree_bytes, before.tree_bytes,
            "predicate length changed the remaining storage quota"
        );
        assert_eq!(after.tree_blobs, before.tree_blobs);
        f.knowledge
            .publish("parent-after-private-return", b"parent")?;
        let remaining = f.storage()?;
        charges.push((
            after.tree_bytes - before.tree_bytes,
            after.tree_blobs - before.tree_blobs,
            u64::from(remaining.limits.max_bytes) - remaining.tree_bytes,
        ));
    }
    assert_eq!(charges, vec![(0, 0, 1), (0, 0, 1)]);
    Ok(())
}

#[test]
fn linux_sink_attempt_is_durably_uncertain_before_first_byte() -> TestResult {
    use crate::confinement::ConfinedCutpoint;
    let (f, cage) = measured_fixture(&reader()?)?;
    let request = RequestId::new("uncertain-before-sink")?;
    f.reserve(
        request.as_str(),
        &child(&f.knowledge, "uncertain-child", 201)?,
    )?;
    f.runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)?;
    let (disclosure, endorsement) =
        approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
    let before_sink = f.knowledge.f.path.join("admission.db");
    let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage != ConfinedCutpoint::DeliveryOrdered {
            return Ok(());
        }
        let connection = rusqlite::Connection::open(&before_sink)
            .map_err(|_| KernelError::Internal("inspect delivery ordering".into()))?;
        let state: String = connection.query_row(
            "SELECT json_extract(payload,'$.return_admission.admitted.state') FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
            [], |row| row.get(0),
        ).map_err(|_| KernelError::Internal("inspect delivery state".into()))?;
        assert_eq!(state, "uncertain", "a crash after sink IO must not forget a possible delivery");
        Ok(())
    }));
    let sink = f.knowledge.sink();
    let delivered = runtime.deliver(
        &f.knowledge.f.control,
        f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
        &sink,
        Some(&disclosure),
        Some(&endorsement),
    )?;
    assert_eq!(delivered.admitted.state, ArtifactDeliveryStateV1::Delivered);
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"true".to_vec()]
    );
    Ok(())
}

#[test]
fn linux_cancellation_reports_an_already_ordered_parent_return() -> TestResult {
    use crate::confinement::ConfinedCutpoint;
    for cancel_parent in [false, true] {
        let (f, cage) = measured_fixture(&reader()?)?;
        let request = RequestId::new("cancel-ordered-return")?;
        let reservation = f.reserve(
            request.as_str(),
            &child(&f.knowledge, "ordered-return-child", 201)?,
        )?;
        f.runtime
            .launch(&f.knowledge.f.control, &request, cage)?
            .stage(&f.knowledge.f.control)?;
        let (disclosure, endorsement) =
            approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
        let process = f.knowledge.f.process.clone();
        let target = if cancel_parent {
            "root".to_owned()
        } else {
            reservation.boundary.child.as_str().to_owned()
        };
        let observed = Arc::new(Mutex::new(None));
        let recorded = observed.clone();
        let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == ConfinedCutpoint::DeliveryOrdered {
                let cancellation = process.cancel(&target);
                let was_successful = cancellation.is_ok();
                assert!(
                    !was_successful,
                    "cancellation reported success despite an already ordered return"
                );
                assert_eq!(
                    process
                        .process(&target)
                        .map_err(|_| KernelError::Internal("inspect cancelled process".into()))?
                        .state,
                    chio_process::ProcessState::Cancelled
                );
                *recorded
                    .lock()
                    .map_err(|_| KernelError::Internal("cancellation evidence".into()))? =
                    Some(was_successful);
            }
            Ok(())
        }));
        let sink = f.knowledge.sink();
        runtime.deliver(
            &f.knowledge.f.control,
            f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
            &sink,
            Some(&disclosure),
            Some(&endorsement),
        )?;
        assert_eq!(
            sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
            &[b"true".to_vec()]
        );
        assert_eq!(
            *observed.lock().map_err(|_| "cancellation evidence")?,
            Some(false),
            "cancellation must report the already ordered return for either endpoint"
        );
    }
    Ok(())
}

#[test]
fn linux_terminal_dispositions_survive_cancellation() -> TestResult {
    use crate::confinement::ConfinedCutpoint;
    let (f, cage) = measured_fixture(&reader()?)?;
    let cap = child(&f.knowledge, "quarantined-child", 201)?;
    let request = RequestId::new("quarantined-boundary")?;
    f.reserve(request.as_str(), &cap)?;
    let failed = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        if stage == ConfinedCutpoint::LaunchPrepared {
            Err(KernelError::Internal("lost launch custody".into()))
        } else {
            Ok(())
        }
    }));
    assert!(failed
        .launch(&f.knowledge.f.control, &request, cage)
        .is_err());
    assert_eq!(
        f.reserve(request.as_str(), &cap)?.state,
        IsolationStateV1::Quarantined
    );
    f.runtime
        .cancel(&f.knowledge.f.control, &f.knowledge.f.process, &request)?;
    assert_eq!(
        f.reserve(request.as_str(), &cap)?.state,
        IsolationStateV1::Quarantined
    );
    let canary = PathBuf::from(
        std::env::var_os("CHIO_CONFINED_CANARY_DIR").ok_or("missing measured canary images")?,
    )
    .join("error");
    let (f, cage) = measured_fixture(&canary)?;
    let cap = child(&f.knowledge, "failed-child", 201)?;
    let request = RequestId::new("failed-boundary")?;
    f.reserve(request.as_str(), &cap)?;
    assert!(f
        .runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)
        .is_err());
    assert_eq!(
        f.reserve(request.as_str(), &cap)?.state,
        IsolationStateV1::Failed
    );
    f.runtime
        .cancel(&f.knowledge.f.control, &f.knowledge.f.process, &request)?;
    assert_eq!(
        f.reserve(request.as_str(), &cap)?.state,
        IsolationStateV1::Failed
    );
    Ok(())
}
#[test]
fn linux_fixed_environment_rejects_parent_controlled_channels() -> TestResult {
    let f = ConfinedFixture::new()?;
    let target = reader()?;
    let clean = compiled(&f, &target)?;
    let parent = BTreeMap::from([
        ("LANG".into(), "PARENT-CHANNEL-CANARY".into()),
        ("LC_ALL".into(), "PARENT-CHANNEL-CANARY".into()),
        ("TZ".into(), "PARENT-CHANNEL-CANARY".into()),
        ("HOME".into(), "PARENT-CHANNEL-CANARY".into()),
        ("APP_MODE".into(), "PARENT-CHANNEL-CANARY".into()),
    ]);
    let isolated = compiled_with_environment(&f, &target, &parent, BTreeSet::new())?;
    assert_eq!(
        clean.plan().environment,
        BTreeMap::from([
            ("LANG".into(), "C".into()),
            ("LC_ALL".into(), "C".into()),
            ("TZ".into(), "UTC".into()),
        ])
    );
    assert_eq!(clean.plan().environment, isolated.plan().environment);
    let profile = crate::confinement::confined_execution_profile(&clean)?;
    assert_eq!(
        profile,
        crate::confinement::confined_execution_profile(&isolated)?
    );
    let exposed = compiled_with_environment(
        &f,
        &target,
        &parent,
        BTreeSet::from([chio_manifest::EnvironmentVariableName::new("APP_MODE")?]),
    )?;
    assert!(crate::confinement::confined_execution_profile(&exposed).is_err());
    let runtime_directory = tempfile::tempdir()?;
    let runtime_file = runtime_directory
        .path()
        .join("additional-readable-runtime-file");
    std::fs::write(&runtime_file, b"RUNTIME-FILE-CHANNEL-CANARY")?;
    let exposed_runtime = compiled_with_channels(
        &f,
        &target,
        &BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::from([runtime_file]),
    )?;
    assert!(exposed_runtime
        .plan()
        .fd_table
        .iter()
        .any(|entry| matches!(entry.purpose, chio_cage::FdPurpose::RuntimeFile { .. })));
    assert!(!exposed_runtime
        .plan()
        .fd_table
        .iter()
        .any(|entry| matches!(entry.purpose, chio_cage::FdPurpose::ReadGrant { .. })));
    assert!(crate::confinement::confined_execution_profile(&exposed_runtime).is_err());
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let reservations: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(reservations, 0);
    Ok(())
}
#[test]
fn linux_unknown_input_provenance_withholds_a_correct_projection() -> TestResult {
    let (mut top, top_cage) = measured_fixture(&reader()?)?;
    let published_top = publish_label(
        &top.knowledge,
        "top-confined-input",
        br#"{"eligible":true,"secret":"TOP-INPUT-CANARY"}"#,
        InformationLabel::Top,
    );
    let mut violations = Vec::new();
    match published_top {
        Ok(observation) => {
            top.observation = observation;
            let top_request = RequestId::new("top-confined-return")?;
            top.reserve(
                top_request.as_str(),
                &child(&top.knowledge, "top-child", 202)?,
            )?;
            let before = top.storage()?;
            match top
                .runtime
                .launch(&top.knowledge.f.control, &top_request, top_cage)
            {
                Ok(execution) => {
                    violations.push("a Top-labeled observation reached an operational child");
                    drop(execution);
                }
                Err(_) => (),
            }
            let after = top.storage()?;
            if after.tree_bytes != before.tree_bytes || after.tree_blobs != before.tree_blobs {
                violations.push("withheld Top input changed parent storage");
            }
            let connection = rusqlite::Connection::open(top.knowledge.f.path.join("admission.db"))?;
            let observed: i64 = connection.query_row(
                "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.observation_release') IS NOT NULL",
                [], |row| row.get(0),
            )?;
            if observed != 0 {
                violations.push("Top input obtained native observation admission");
            }
        }
        Err(_) => {
            // Fresh operational clearances are finite. Their upstream refusal
            // is checked explicitly, and does not stand for a child-gate run.
            let connection = rusqlite::Connection::open(top.knowledge.f.path.join("admission.db"))?;
            let boundaries: i64 = connection.query_row(
                "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
                [], |row| row.get(0),
            )?;
            assert_eq!(
                boundaries, 0,
                "upstream Top refusal must precede a child boundary"
            );
        }
    }
    if top.knowledge.f.effects.load(Ordering::SeqCst) != 0 {
        violations.push("withheld Top input caused an external effect");
    }

    // Finite confidentiality does not imply known integrity. The measured
    // reader still completes before unknown provenance withholds its output.
    let (mut f, cage) = measured_fixture(&reader()?)?;
    f.observation = publish_label(
        &f.knowledge,
        "unknown-confined-input",
        br#"{"eligible":true,"secret":"UNKNOWN-INPUT-CANARY"}"#,
        restricted_label(),
    )?;
    let actor = f.knowledge.actor(RecoveryPermission::KnowledgeRead)?;
    let inventory = f
        .knowledge
        .f
        .authority
        .admission_operation_store()
        .artifact_transfer_inventory(
            &actor,
            &f.observation,
            &f.knowledge.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(
        f.knowledge
            .metadata(inventory.last().ok_or("observation")?)?
            .influence
            .unknown
    );
    let request = RequestId::new("unknown-confined-return")?;
    f.reserve(
        request.as_str(),
        &child(&f.knowledge, "unknown-child", 201)?,
    )?;
    let execution = f.runtime.launch(&f.knowledge.f.control, &request, cage)?;
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let payload: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    let retained: Value = serde_json::from_slice(&payload)?;
    let admitted_input: ArtifactReleaseIntentV1 = serde_json::from_value(
        retained
            .get("observation_release")
            .ok_or("missing admitted input")?
            .clone(),
    )?;
    if admitted_input.recipient.clearance == InformationLabel::Top {
        violations.push("a genuine native input admission selected operational Top clearance");
    }
    if admitted_input.recipient.clearance != admitted_input.admitted_label {
        violations.push("child input clearance exceeded its independently admitted label");
    }
    assert_eq!(admitted_input.source_label, admitted_input.admitted_label);
    assert_eq!(f.profile.contract.source_ceiling, InformationLabel::Top);
    assert!(execution.stage(&f.knowledge.f.control).is_err());
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let exit: i64 = connection.query_row(
        "SELECT json_extract(payload,'$.terminal.exit.exit_code') FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        exit, 0,
        "projection worker failed before provenance refusal"
    );
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    assert_eq!(f.count()?, 1);
    let admitted: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.return_admission') IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(admitted, 0);
    assert!(violations.is_empty(), "{}", violations.join("; "));
    Ok(())
}
#[test]
fn linux_useful_decision_exact_authority_and_parent_join_before_first_byte() -> TestResult {
    let (f, cage) = measured_fixture(&reader()?)?;
    let cap = child(&f.knowledge, "measured-child", 201)?;
    let reservation = f.reserve("real-spawn", &cap)?;
    let before = f
        .knowledge
        .f
        .authority
        .admission_operation_store()
        .observe_security_participant_flow(
            &f.knowledge.profile.native_authority,
            &recovery_flow_key(&f.knowledge.profile.producer_context),
            &f.knowledge.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    let execution =
        f.runtime
            .launch(&f.knowledge.f.control, &RequestId::new("real-spawn")?, cage)?;
    let context = f
        .knowledge
        .f
        .process
        .recovery_security_context(reservation.boundary.child.as_str())?;
    assert_eq!(
        context.as_v1().lineage_root_id().as_str(),
        reservation.boundary.lineage.as_str()
    );
    execution.stage(&f.knowledge.f.control)?;
    let request = RequestId::new("real-spawn")?;
    let body = f.runtime.review_return(&f.knowledge.f.control, &request)?;
    assert!(!body.source.flows_to(&InformationLabel::bottom()));
    let sink = f.knowledge.sink();
    assert!(f
        .runtime
        .deliver(
            &f.knowledge.f.control,
            f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
            &sink,
            None,
            None
        )
        .is_err());
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let (disclosure, endorsement) = approve(body)?;
    assert!(f
        .runtime
        .deliver(
            &f.knowledge.f.control,
            f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
            &sink,
            Some(&disclosure),
            None
        )
        .is_err());
    let admitted = f.runtime.deliver(
        &f.knowledge.f.control,
        f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
        &sink,
        Some(&disclosure),
        Some(&endorsement),
    )?;
    assert_eq!(
        sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
        &[b"true".to_vec()]
    );
    let after = f
        .knowledge
        .f
        .authority
        .admission_operation_store()
        .observe_security_participant_flow(
            &f.knowledge.profile.native_authority,
            &recovery_flow_key(&f.knowledge.profile.producer_context),
            &f.knowledge.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert_eq!(
        before.snapshot().ok_or("before")?.principal_label,
        after.snapshot().ok_or("after")?.principal_label
    );
    let again = f.runtime.deliver(
        &f.knowledge.f.control,
        f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
        &sink,
        None,
        None,
    )?;
    assert_eq!(admitted.admitted.release, again.admitted.release);
    assert_eq!(f.count()?, 1);
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let boundary_key: String = connection.query_row(
        "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    let retained = |connection: &rusqlite::Connection| -> TestResult<(Vec<u8>, i64)> {
        Ok(connection.query_row(
            "SELECT payload, version FROM admission_operation_recovery_records
             WHERE record_key=?1",
            [&boundary_key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    };
    let (before_stop, version) = retained(&connection)?;
    let before_record: Value = serde_json::from_slice(&before_stop)?;
    assert_eq!(before_record["reservation"]["state"], "closed");
    assert!(
        before_record.get("stop_requested").is_none(),
        "an unstopped boundary must retain the legacy canonical payload shape"
    );
    assert!(
        before_stop == chio_core::canonical_json_bytes(&before_record)?,
        "unstopped boundary must use the canonical legacy representation"
    );
    let quota = f.storage()?;
    let sink_count = sink.delivered.lock().map_err(|_| "sink")?.len();

    f.runtime
        .cancel(&f.knowledge.f.control, &f.knowledge.f.process, &request)?;
    let (after_stop, stopped_version) = retained(&connection)?;
    let stopped: Value = serde_json::from_slice(&after_stop)?;
    assert_eq!(
        stopped["reservation"]["state"], "closed",
        "a stop request must preserve an established delivery disposition"
    );
    assert_eq!(stopped["stop_requested"], true);
    let mut expected = before_record;
    expected["stop_requested"] = Value::Bool(true);
    assert!(
        after_stop == chio_core::canonical_json_bytes(&expected)?,
        "stop must change only the monotone private stop bit"
    );
    assert_eq!(stopped_version, version.checked_add(1).ok_or("version")?);
    assert_eq!(f.storage()?, quota);
    assert_eq!(f.count()?, 1);
    assert_eq!(sink.delivered.lock().map_err(|_| "sink")?.len(), sink_count);
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    assert!(f
        .runtime
        .review_return(&f.knowledge.f.control, &request)
        .is_err());

    // A retry accepts the same stop identity without consuming another record
    // revision, forgetting delivery, freeing the return slot or reopening data.
    f.runtime
        .cancel(&f.knowledge.f.control, &f.knowledge.f.process, &request)?;
    assert!(
        retained(&connection)? == (after_stop, stopped_version),
        "repeated stop must preserve the exact retained payload and version"
    );
    assert_eq!(f.storage()?, quota);
    assert_eq!(f.count()?, 1);
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    Ok(())
}
#[test]
fn linux_channel_canaries_never_reach_parent_or_bypass_projection() -> TestResult {
    let root = PathBuf::from(
        std::env::var_os("CHIO_CONFINED_CANARY_DIR").ok_or("missing measured canary images")?,
    );
    for mode in [
        "error",
        "log",
        "progress",
        "stream",
        "file",
        "callback",
        "wrong-predicate",
        "overflow",
    ] {
        let (mut f, cage) = measured_fixture(&root.join(mode))?;
        // Make ordinary Unix permissions and endpoint availability permissive.
        // A missing socket/private directory must not make the probe pass.
        use std::os::unix::fs::PermissionsExt;
        let probe = tempfile::tempdir()?;
        std::fs::set_permissions(probe.path(), std::fs::Permissions::from_mode(0o777))?;
        let file = probe.path().join("forbidden-canary-file");
        let socket = probe.path().join("forbidden-callback.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        let input = chio_core::canonical_json_bytes(
            &serde_json::json!({"eligible":true,"secret":"PRIVATE-RETURN-CANARY","probe_file":file.to_str().ok_or("file")?,"probe_socket":socket.to_str().ok_or("socket")?}),
        )?;
        f.observation = f.knowledge.publish(&format!("probe-{mode}"), &input)?;
        let cap = child(&f.knowledge, "canary-child", 201)?;
        f.reserve("canary-spawn", &cap)?;
        let staged = f
            .runtime
            .launch(
                &f.knowledge.f.control,
                &RequestId::new("canary-spawn")?,
                cage,
            )
            .and_then(|execution| execution.stage(&f.knowledge.f.control));
        let sink = f.knowledge.sink();
        if matches!(mode, "log" | "file") {
            staged?;
            let request = RequestId::new("canary-spawn")?;
            let (disclosure, endorsement) =
                approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
            f.runtime.deliver(
                &f.knowledge.f.control,
                f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
                &sink,
                Some(&disclosure),
                Some(&endorsement),
            )?;
            assert_eq!(
                sink.delivered.lock().map_err(|_| "sink")?.as_slice(),
                &[b"true".to_vec()]
            );
        } else {
            let error = staged.err().ok_or("canary unexpectedly admitted")?;
            assert!(!error.to_string().contains("PRIVATE-RETURN-CANARY"));
            assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
        }
        assert!(!file.exists(), "{mode}: filesystem bypass");
        match listener.accept() {
            Ok(_) => return Err("callback escaped the cage".into()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error.into()),
        }
        let db = std::fs::read(f.knowledge.f.path.join("admission.db"))?;
        assert!(!db
            .windows(b"PRIVATE-RETURN-CANARY".len())
            .any(|b| b == b"PRIVATE-RETURN-CANARY"));
    }
    Ok(())
}

#[test]
fn linux_parent_cancellation_withholds_returns_before_and_after_native_join() -> TestResult {
    use crate::confinement::ConfinedCutpoint::{BeforeAdmission, BeforeDelivery, ReturnCommitted};
    for (cut, label) in [
        (BeforeAdmission, "before native admission"),
        (ReturnCommitted, "after native join"),
        (BeforeDelivery, "before delivery"),
    ] {
        let (f, cage) = measured_fixture(&reader()?)
            .map_err(|error| format!("{label}: measured fixture: {error}"))?;
        let request = RequestId::new("cancel-parent-return")?;
        f.reserve(
            request.as_str(),
            &child(&f.knowledge, "cancelled-parent-child", 201)?,
        )
        .map_err(|error| format!("{label}: reservation: {error}"))?;
        let execution = f
            .runtime
            .launch(&f.knowledge.f.control, &request, cage)
            .map_err(|error| format!("{label}: launch: {error}"))?;
        execution
            .stage(&f.knowledge.f.control)
            .map_err(|error| format!("{label}: stage: {error}"))?;
        let (disclosure, endorsement) =
            approve(f.runtime.review_return(&f.knowledge.f.control, &request)?)?;
        let sink = f.knowledge.sink();
        let process = f.knowledge.f.process.clone();
        let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == cut {
                process
                    .cancel("root")
                    .map_err(|_| KernelError::DurableAdmission("cancel parent".into()))?;
            }
            Ok(())
        }));
        let prepared = runtime
            .prepare_return(&f.knowledge.f.control, &request)
            .map_err(|error| format!("{label}: preparation: {error}"))?;
        // Already prepared host custody cannot turn a later cancelled process
        // into a live recipient. Cancellation also correctly refuses new blob
        // reads, so retain this separate affine handle before the cutpoint.
        let replay = if cut == BeforeAdmission {
            None
        } else {
            Some(f.runtime.prepare_return(&f.knowledge.f.control, &request)?)
        };
        assert!(
            runtime
                .deliver(
                    &f.knowledge.f.control,
                    prepared,
                    &sink,
                    Some(&disclosure),
                    Some(&endorsement)
                )
                .is_err(),
            "{label}"
        );
        assert!(
            sink.delivered.lock().map_err(|_| "sink")?.is_empty(),
            "{label}"
        );
        assert_eq!(f.count()?, 1);
        let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
        let consumed: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-evidence:*'",
            [],
            |row| row.get(0),
        )?;
        let admissions: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.return_admission') IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(consumed, if cut == BeforeAdmission { 0 } else { 2 });
        assert_eq!(admissions, if cut == BeforeAdmission { 0 } else { 1 });
        // Cancellation never rolls back the join or spent evidence. An admitted
        // value remains classified and replay must still refuse the dead parent.
        if let Some(retained) = replay {
            assert!(f
                .runtime
                .deliver(&f.knowledge.f.control, retained, &sink, None, None)
                .is_err());
            assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
        }
    }
    Ok(())
}
#[test]
fn linux_duplicate_launch_and_cancel_preserve_the_observation_and_consumed_slot() -> TestResult {
    let (f, cage) = measured_fixture(&reader()?)?;
    let cap = child(&f.knowledge, "measured-child", 201)?;
    f.reserve("real-spawn", &cap)?;
    let request = RequestId::new("real-spawn")?;
    let execution = f.runtime.launch(&f.knowledge.f.control, &request, cage)?;
    assert!(f
        .runtime
        .launch(&f.knowledge.f.control, &request, compiled(&f, &reader()?)?)
        .is_err());
    execution.cancel(&f.knowledge.f.control, &f.knowledge.f.process)?;
    assert_eq!(
        f.reserve("real-spawn", &cap)?.state,
        IsolationStateV1::Cancelled
    );
    assert_eq!(f.count()?, 1);
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    Ok(())
}

#[test]
fn linux_launch_cutpoints_never_duplicate_measurement_or_reset_observation() -> TestResult {
    use crate::confinement::ConfinedCutpoint::*;
    for cutpoint in [LaunchPrepared, Enforced, ObservationCommitted, BeforeInput] {
        let (f, cage) = measured_fixture(&reader()?)?;
        let cap = child(&f.knowledge, "measured-child", 201)?;
        let original = f.reserve("cut-launch", &cap)?;
        let request = RequestId::new("cut-launch")?;
        let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == cutpoint {
                return Err(KernelError::Internal("lost acknowledgement".into()));
            }
            Ok(())
        }));
        assert!(faulty
            .launch(&f.knowledge.f.control, &request, cage)
            .is_err());
        let recovered = f.reserve("cut-launch", &cap)?;
        assert_eq!(original.boundary, recovered.boundary);
        assert_eq!(f.count()?, 1);
        assert!(f
            .runtime
            .launch(&f.knowledge.f.control, &request, compiled(&f, &reader()?)?)
            .is_err());
        let observed = f
            .knowledge
            .f
            .authority
            .admission_operation_store()
            .observe_security_participant_flow(
                &f.knowledge.profile.native_authority,
                &recovery_flow_key(&recovered.child_context),
                &f.knowledge.f.authority.mutation_fence(),
                now_ms()?,
            )?;
        assert_eq!(
            observed.snapshot().is_some(),
            matches!(cutpoint, ObservationCommitted | BeforeInput)
        );
        f.runtime
            .cancel(&f.knowledge.f.control, &f.knowledge.f.process, &request)?;
    }
    Ok(())
}

#[test]
fn linux_return_cutpoints_reopen_the_native_writer_without_second_disclosure() -> TestResult {
    use crate::confinement::ConfinedCutpoint::*;
    for cutpoint in [
        ReturnStaged,
        BeforeAdmission,
        ReturnCommitted,
        BeforeDelivery,
        DeliveryCompleted,
    ] {
        let (mut f, cage) = measured_fixture(&reader()?)?;
        let cap = child(&f.knowledge, "measured-child", 201)?;
        f.reserve("cut-return", &cap)?;
        let request = RequestId::new("cut-return")?;
        let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == cutpoint {
                return Err(KernelError::Internal("lost acknowledgement".into()));
            }
            Ok(())
        }));
        let staged = faulty
            .launch(&f.knowledge.f.control, &request, cage)?
            .stage(&f.knowledge.f.control);
        if cutpoint == ReturnStaged {
            assert!(staged.is_err());
        } else {
            staged?;
        }
        let body = f.runtime.review_return(&f.knowledge.f.control, &request)?;
        let (disclosure, endorsement) = approve(body)?;
        let sink = f.knowledge.sink();
        if cutpoint != ReturnStaged {
            assert!(faulty
                .deliver(
                    &f.knowledge.f.control,
                    faulty.prepare_return(&f.knowledge.f.control, &request)?,
                    &sink,
                    Some(&disclosure),
                    Some(&endorsement)
                )
                .is_err());
            assert_eq!(
                sink.delivered.lock().map_err(|_| "sink")?.len(),
                usize::from(cutpoint == DeliveryCompleted)
            );
        }
        let installation = f.profile.clone();
        let deployment = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
        let control = f.knowledge.f.control.clone();
        let path = f.knowledge.f.path.clone();
        let directory = f.knowledge.f._directory.take();
        drop(faulty);
        drop(f);
        let reopened = RecoveryFixture::open(path, directory, false)?;
        reopened.kernel.set_capability_trust_root(
            reopened.seed.capability.issuer.clone(),
            scope_hash(&reopened.seed.capability.scope)?,
        );
        reopened
            .authority
            .admission_operation_store()
            .configure_recovery_deployment(&deployment)?;
        let broker = Arc::new(reopened.process.enable_durable_knowledge()?);
        let runtime = NativeConfinedRuntime::new(
            reopened.kernel.clone(),
            Arc::new(reopened.authority.admission_operation_store()),
            broker,
            installation,
            reopened.authority.mutation_fence(),
        )?;
        let admitted = runtime.deliver(
            &control,
            runtime.prepare_return(&control, &request)?,
            &sink,
            Some(&disclosure),
            Some(&endorsement),
        )?;
        assert_eq!(
            sink.delivered
                .lock()
                .map_err(|_| "sink")?
                .last()
                .ok_or("value")?,
            b"true"
        );
        let again = runtime.deliver(
            &control,
            runtime.prepare_return(&control, &request)?,
            &sink,
            None,
            None,
        )?;
        assert_eq!(admitted.admitted.release, again.admitted.release);
        let connection = rusqlite::Connection::open(reopened.path.join("admission.db"))?;
        let consumed:i64=connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-evidence:*'",[],|row|row.get(0))?;
        assert_eq!(consumed, 2);
    }
    Ok(())
}

#[test]
fn linux_valid_signatures_cannot_authorize_cross_parent_epoch_or_stale_returns() -> TestResult {
    let (f, cage) = measured_fixture(&reader()?)?;
    let cap = child(&f.knowledge, "measured-child", 201)?;
    f.reserve("binding", &cap)?;
    let request = RequestId::new("binding")?;
    f.runtime
        .launch(&f.knowledge.f.control, &request, cage)?
        .stage(&f.knowledge.f.control)?;
    let body = f.runtime.review_return(&f.knowledge.f.control, &request)?;
    let sink = f.knowledge.sink();
    for n in 0..7 {
        let mut substituted = body.clone();
        match n {
            0 => substituted.boundary = CanonicalPayloadDigest::from_bytes([0; 32]),
            1 => substituted.launch = CanonicalPayloadDigest::from_bytes([0; 32]),
            2 => substituted.parent.principal = PrincipalId::new("another-parent")?,
            3 => substituted.parent.isolation_epoch = ProtectedText::new("another-epoch")?,
            4 => substituted.content = CanonicalPayloadDigest::from_bytes([0; 32]),
            5 => substituted.policy = PolicyDigest::from_bytes([0; 32]),
            _ => {
                let now = now_ms()?;
                substituted.issued_at_unix_ms = SafeInteger::new(now - 60001)?;
                substituted.expires_at_unix_ms = SafeInteger::new(now - 1)?;
            }
        }
        let (disclosure, endorsement) = approve(substituted)?;
        assert!(f
            .runtime
            .deliver(
                &f.knowledge.f.control,
                f.runtime.prepare_return(&f.knowledge.f.control, &request)?,
                &sink,
                Some(&disclosure),
                Some(&endorsement)
            )
            .is_err());
    }
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    let mut changed = f.profile.clone();
    changed.generation = SafeInteger::new(3)?;
    changed.contract.field = ProtectedText::new("rotated")?;
    f.knowledge
        .f
        .authority
        .admission_operation_store()
        .configure_confinement(&changed)?;
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    Ok(())
}

#[test]
fn linux_absolute_deadline_kills_a_held_handle_without_parent_io() -> TestResult {
    let image =
        PathBuf::from(std::env::var_os("CHIO_CONFINED_CANARY_DIR").ok_or("missing canary images")?)
            .join("hang");
    let (mut f, cage) = measured_fixture(&image)?;
    f.profile.generation = SafeInteger::new(3)?;
    f.profile.limits.wall_clock_ms = SafeInteger::new(2500)?;
    f.runtime = NativeConfinedRuntime::new(
        f.knowledge.f.kernel.clone(),
        Arc::new(f.knowledge.f.authority.admission_operation_store()),
        f.knowledge.broker.clone(),
        f.profile.clone(),
        f.knowledge.f.authority.mutation_fence(),
    )?;
    let cap = child(&f.knowledge, "held-child", 201)?;
    let reserved = f.reserve("deadline", &cap)?;
    let request = RequestId::new("deadline")?;
    let execution = f.runtime.launch(&f.knowledge.f.control, &request, cage)?;
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let pid: u32 = connection.query_row(
        "SELECT json_extract(payload,'$.enforcement.prepared.process_id') FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*' AND json_extract(payload,'$.reservation.boundary.child') = ?1",
        [reserved.boundary.child.as_str()],
        |row| row.get(0),
    )?;
    let process = rustix::process::Pid::from_raw(i32::try_from(pid)?)
        .ok_or("enforced child has no positive process identity")?;
    let observe_exit = || {
        rustix::process::waitid(
            rustix::process::WaitId::Pid(process),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
    };
    let deadline = reserved.boundary.deadline_unix_ms.get();
    let live_until = now_ms()?.checked_add(100).ok_or("live child probe clock")?;
    assert!(
        live_until < deadline,
        "no live-child observation window remains"
    );
    let mut observed_running = false;
    while now_ms()? < live_until {
        assert!(
            observe_exit()?.is_none(),
            "configured hang child exited before its original deadline"
        );
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
        observed_running |= status.lines().any(|line| {
            line.strip_prefix("State:")
                .and_then(|state| state.split_whitespace().next())
                == Some("R")
        });
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(
        observed_running,
        "hang child never demonstrated actual execution"
    );
    // Keep affine execution custody alive beyond the reserved absolute deadline.
    // NOWAIT observes SIGKILL before stage/Drop can terminate or reap the child.
    std::thread::sleep(std::time::Duration::from_millis(
        deadline.saturating_sub(now_ms()?).saturating_add(300),
    ));
    let terminal = observe_exit()?.ok_or("deadline left the held child alive")?;
    assert!(
        terminal.killed(),
        "held child did not terminate by a signal"
    );
    assert_eq!(terminal.terminating_signal(), Some(libc::SIGKILL));
    assert!(f
        .knowledge
        .f
        .process
        .recovery_security_context(reserved.boundary.child.as_str())
        .is_err());
    assert!(execution.stage(&f.knowledge.f.control).is_err());
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &request)
        .is_err());
    assert_eq!(f.count()?, 1);
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "deadline left the child running"
    );
    Ok(())
}
