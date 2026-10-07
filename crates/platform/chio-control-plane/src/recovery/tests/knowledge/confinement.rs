//! Actual fenced reservation/refusal tests. These do not claim cage enforcement.
use super::*;
use crate::confinement::NativeConfinedRuntime;
use chio_core_types::capability::attenuation::{
    compute_attenuation_witness, delegate, scope_hash, AttenuationProof,
};
use chio_core_types::capability::token::{CapabilityTokenAttenuationBody, CapabilityTokenBody};
use chio_core_types::delegation_receipt::ScopeAttenuation;
use chio_security_types::confinement::*;

struct ConfinedFixture {
    knowledge: KnowledgeFixture,
    runtime: NativeConfinedRuntime,
    profile: NativeConfinedInstallationV1,
    observation: ArtifactVersionRefV1,
}
fn child(f: &KnowledgeFixture, id: &str, seed: u8) -> TestResult<CapabilityToken> {
    let parent = &f.f.seed.capability;
    signed_child(parent, id, seed, &Keypair::from_seed(&[140; 32]))
}
fn signed_child(
    parent: &CapabilityToken,
    id: &str,
    seed: u8,
    issuer: &Keypair,
) -> TestResult<CapabilityToken> {
    let scope = ChioScope::default();
    let subject = Keypair::from_seed(&[seed; 32]);
    let receipt = delegate(
        parent,
        &scope,
        &Keypair::from_seed(&[141; 32]),
        &subject.public_key(),
        ScopeAttenuation {
            budget_share_bps: Some(625),
            ..Default::default()
        },
        parent.issued_at,
        [seed; 16],
    )?;
    Ok(CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.into(),
                issuer: parent.issuer.clone(),
                subject: subject.public_key(),
                issued_at: parent.issued_at,
                expires_at: parent.expires_at,
                delegation_chain: receipt.complete_chain(),
                aggregate_invocation_budget: parent.aggregate_invocation_budget.clone(),
                scope: scope.clone(),
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&parent.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &scope)?,
            },
            budget_share_bps: Some(625),
        },
        issuer,
    )?)
}
impl ConfinedFixture {
    fn new() -> TestResult<Self> {
        Self::with_bounded_storage(false)
    }
    fn with_bounded_storage(bounded: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        std::fs::write(
            directory.path().join("confined-profile"),
            b"delegate-only-fixture",
        )?;
        if bounded {
            std::fs::write(
                directory.path().join("bounded-artifact-storage"),
                b"128 KiB, 32 blobs",
            )?;
        }
        let mut knowledge = KnowledgeFixture::from(RecoveryFixture::open(
            directory.path().to_path_buf(),
            Some(directory),
            false,
        )?)?;
        knowledge.f.kernel.set_capability_trust_root(
            knowledge.f.seed.capability.issuer.clone(),
            scope_hash(&knowledge.f.seed.capability.scope)?,
        );
        let mut deployment = knowledge
            .f
            .kernel
            .recovery_deployment(&knowledge.profile.scope)?;
        let mut actors = deployment.actors.as_slice().to_vec();
        let mut permissions = actors[0].permissions.as_slice().to_vec();
        permissions.extend([
            RecoveryPermission::ConfinedLaunch,
            RecoveryPermission::ConfinedReturn,
            RecoveryPermission::ConfinedCancel,
        ]);
        permissions.sort();
        permissions.dedup();
        actors[0].permissions = BoundedList::new(permissions.clone())?;
        deployment.actors = NonEmptyBoundedList::new(actors)?;
        deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
        knowledge
            .f
            .authority
            .admission_operation_store()
            .configure_recovery_deployment(&deployment)?;
        knowledge.f.control = knowledge.f.kernel.issue_capability(
            &knowledge.f.approval_key.public_key(),
            ChioScope {
                grants: permissions
                    .iter()
                    .map(|p| ToolGrant {
                        server_id: "chio.recovery".into(),
                        tool_name: p.wire_name().into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    })
                    .collect(),
                ..Default::default()
            },
            1200,
        )?;
        // Publish from the imported, already restricted native parent context.
        // Adoption intentionally retains unknown influence and cannot serve as
        // a known-provenance positive control for a confined return.
        let observation = knowledge.publish(
            "confined-private",
            br#"{"eligible":true,"secret":"PRIVATE-RETURN-CANARY"}"#,
        )?;
        let profile = NativeConfinedInstallationV1 {
            scope: knowledge.profile.scope.clone(),
            generation: SafeInteger::new(1)?,
            contract: ReturnContractV1 {
                domain_version: VersionV1,
                contract: ReturnContractDigest::from_bytes([1; 32]),
                schema: knowledge_content_digest(CONFINED_BOOLEAN_SCHEMA),
                implementation: knowledge_content_digest(CONFINED_BOOLEAN_IMPLEMENTATION),
                field: ProtectedText::new("eligible")?,
                parent: knowledge.profile.recipients.as_slice()[0].recipient.clone(),
                source_ceiling: InformationLabel::Top,
                target: InformationLabel::bottom(),
                require_integrity: true,
                max_bytes: SafeInteger::new(8)?,
                max_values: SafeInteger::new(1)?,
                channels: NonEmptyBoundedList::new(vec![ConfinedChannelV1::Value])?,
                expires_at_unix_ms: SafeInteger::new(now_ms()? + 600_000)?,
                policy: knowledge.profile.policy,
            },
            execution: ConfinedExecutionProfileV1 {
                manifest: CageMeasurementDigest::from_bytes([2; 32]),
                profile: CageMeasurementDigest::from_bytes([3; 32]),
                configuration: CageMeasurementDigest::from_bytes([4; 32]),
                helper: CageMeasurementDigest::from_bytes([5; 32]),
                image: CageMeasurementDigest::from_bytes([6; 32]),
                provider: ConfinedProviderV1::Disabled,
            },
            limits: ConfinedLimitsV1 {
                children: SafeInteger::new(16)?,
                depth: SafeInteger::new(8)?,
                input_bytes: SafeInteger::new(65536)?,
                diagnostic_bytes: SafeInteger::new(16384)?,
                launches: SafeInteger::new(1)?,
                tool_calls: SafeInteger::new(0)?,
                model_calls: SafeInteger::new(0)?,
                wall_clock_ms: SafeInteger::new(30000)?,
            },
            disclosure_root: Keypair::from_seed(&[233; 32]).public_key(),
            endorsement_root: Keypair::from_seed(&[234; 32]).public_key(),
        };
        let runtime = NativeConfinedRuntime::new(
            knowledge.f.kernel.clone(),
            Arc::new(knowledge.f.authority.admission_operation_store()),
            knowledge.broker.clone(),
            profile.clone(),
            knowledge.f.authority.mutation_fence(),
        )?;
        Ok(Self {
            knowledge,
            runtime,
            profile,
            observation,
        })
    }
    fn reserve(&self, key: &str, cap: &CapabilityToken) -> TestResult<NativeConfinedReservationV1> {
        Ok(self.runtime.reserve(
            &self.knowledge.f.control,
            &self.knowledge.f.process,
            &RequestId::new(key)?,
            cap,
            &[],
            &self.observation,
        )?)
    }
    fn storage(&self) -> TestResult<chio_process::ProcessStorage> {
        Ok(self
            .knowledge
            .broker
            .storage_usage(&self.profile.scope.process_id)?)
    }
    fn count(&self) -> TestResult<u64> {
        let connection = rusqlite::Connection::open(self.knowledge.f.path.join("admission.db"))?;
        let count:i64=connection.query_row("SELECT json_extract(payload,'$') FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-count:*'",[],|r|r.get(0))?;
        Ok(u64::try_from(count)?)
    }
}

#[test]
fn native_modeled_historical_top_parent_cannot_install_a_confined_return() -> TestResult {
    let f = ConfinedFixture::new()?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    assert_ne!(f.profile.contract.parent.clearance, InformationLabel::Top);
    assert_eq!(f.profile.contract.source_ceiling, InformationLabel::Top);
    store.configure_confinement(&f.profile)?;
    let legacy = retain_knowledge_fixture_legacy_top_recipient(
        &store,
        &fence,
        &f.profile.scope,
        &f.profile.contract.parent.recipient,
    )?;
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let installed = store.knowledge_installation(&actor, &fence, now_ms()?)?;
    assert_eq!(installed.generation, legacy.generation);
    let parent = installed
        .recipients
        .as_slice()
        .iter()
        .find(|entry| entry.recipient.recipient == f.profile.contract.parent.recipient)
        .ok_or("modeled historical parent absent")?
        .recipient
        .clone();
    assert_eq!(parent.clearance, InformationLabel::Top);
    let mut candidate = f.profile.clone();
    candidate.generation = SafeInteger::new(candidate.generation.get() + 1)?;
    candidate.contract.parent = parent;
    let bytes = chio_core_types::canonical_json_bytes(&candidate)?;
    let decoded: NativeConfinedInstallationV1 = serde_json::from_slice(&bytes)?;
    assert_eq!(decoded.contract.parent.clearance, InformationLabel::Top);
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let events = || -> TestResult<i64> {
        Ok(connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?)
    };
    let before = events()?;
    let storage = f.storage()?;
    assert!(
        store.configure_confinement(&candidate).is_err(),
        "a historical Top data value cannot become live public return clearance"
    );
    assert_eq!(events()?, before);
    assert_eq!(f.storage()?, storage);
    let retained: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-profile:*'",
        [],
        |row| row.get(0),
    )?;
    let retained: NativeConfinedInstallationV1 = serde_json::from_slice(&retained)?;
    assert_eq!(retained.generation, f.profile.generation);
    assert_eq!(retained.contract.parent, f.profile.contract.parent);
    Ok(())
}

#[test]
fn native_confined_reservation_charges_a_fixed_return_slot_once() -> TestResult {
    let f = ConfinedFixture::new()?;
    let before = f.storage()?;
    let cap = child(&f.knowledge, "fixed-return-charge", 201)?;
    let reserved = f.reserve("fixed-return-charge", &cap)?;
    let after = f.storage()?;
    assert_eq!(
        after.tree_bytes - before.tree_bytes,
        f.profile.contract.max_bytes.get(),
        "return storage must be charged before the child observes private input"
    );
    assert_eq!(after.tree_blobs - before.tree_blobs, 1);
    let replay = f.reserve("fixed-return-charge", &cap)?;
    assert_eq!(replay.boundary, reserved.boundary);
    assert_eq!(f.storage()?, after);
    f.runtime.cancel(
        &f.knowledge.f.control,
        &f.knowledge.f.process,
        &RequestId::new("fixed-return-charge")?,
    )?;
    assert_eq!(
        f.storage()?.tree_bytes,
        after.tree_bytes,
        "cancellation must retain the constant reserved charge"
    );
    assert_eq!(f.storage()?.tree_blobs, after.tree_blobs);
    Ok(())
}

#[test]
fn native_reservation_replay_and_reopened_journal_keep_one_host_identity() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    let first = f.reserve("spawn-a", &cap)?;
    let again = f.reserve("spawn-a", &cap)?;
    assert_eq!(first.boundary, again.boundary);
    assert_eq!(f.count()?, 1);
    assert_ne!(
        first.boundary.lineage.as_str(),
        first.boundary.parent.lineage.as_str()
    );
    assert_ne!(
        first.boundary.isolation_epoch,
        first.boundary.parent.isolation_epoch
    );
    let root = f.knowledge.f.process.recovery_security_context("root")?;
    let reopened = ProcessRuntime::open(
        f.knowledge.f.path.join("process.db"),
        f.knowledge.f.kernel.clone(),
    )?
    .with_security_profile(ProcessSecurityProfile {
        tenant_id: root.as_v1().tenant_id().as_str().into(),
        isolation_epoch_id: root.as_v1().isolation_epoch_id().as_str().into(),
        generation: root.as_v1().context_generation(),
    })?;
    let recovered = f.runtime.reserve(
        &f.knowledge.f.control,
        &reopened,
        &RequestId::new("spawn-a")?,
        &cap,
        &[],
        &f.observation,
    )?;
    assert_eq!(recovered.boundary, first.boundary);
    assert_eq!(f.count()?, 1);
    assert!(reopened
        .recovery_security_context(first.boundary.child.as_str())
        .is_err());
    Ok(())
}
#[test]
fn native_forged_seed_and_capability_substitution_cannot_fork_context() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    let first = f.reserve("spawn-a", &cap)?;
    let different = child(&f.knowledge, "child-b", 202)?;
    assert!(f.reserve("spawn-a", &different).is_err());
    let mut foreign = f.observation.clone();
    foreign.scope.tenant_id = RecoveryTenantId::new("other-tenant")?;
    assert!(f
        .runtime
        .reserve(
            &f.knowledge.f.control,
            &f.knowledge.f.process,
            &RequestId::new("spawn-a")?,
            &cap,
            &[],
            &foreign
        )
        .is_err());
    assert!(f
        .knowledge
        .f
        .process
        .recovery_security_context(first.boundary.child.as_str())
        .is_err());
    assert_eq!(f.count()?, 1);
    Ok(())
}
#[test]
fn native_sensitive_observation_waits_for_real_enforcement() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    let reservation = f.reserve("spawn-a", &cap)?;
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    assert!(store
        .confined_input_inventory(&actor, &RequestId::new("spawn-a")?, &fence, now_ms()?)
        .is_err());
    let packet = encode_confined_input("eligible", br#"{"eligible":true}"#, &[])?;
    assert!(store
        .admit_confined_input(
            &actor,
            &RequestId::new("spawn-a")?,
            &packet,
            &fence,
            now_ms()?
        )
        .is_err());
    assert!(f
        .knowledge
        .broker
        .stage(
            &ArtifactObjectId::new("forged-child-return")?,
            &reservation.boundary.child,
            b"true",
        )
        .is_err());
    // A real ordinary object can supply a well-formed descriptive seal. A
    // caller's forged child locator still cannot substitute for enforcement.
    let mut seal = f.knowledge.broker.stage(
        &ArtifactObjectId::new("forged-return")?,
        &f.profile.scope.process_id,
        b"true",
    )?;
    seal.process = reservation.boundary.child;
    assert!(store
        .stage_confined_return(
            &actor,
            &RequestId::new("spawn-a")?,
            &seal,
            b"true",
            &fence,
            now_ms()?
        )
        .is_err());
    assert!(f
        .runtime
        .prepare_return(&f.knowledge.f.control, &RequestId::new("spawn-a")?)
        .is_err());
    Ok(())
}
#[test]
fn native_cancellation_without_source_clearance_reveals_no_input_metadata() -> TestResult {
    let f = ConfinedFixture::new()?;
    let seed = f
        .knowledge
        .publish("cancel-private-seed", b"PRIVATE-CANCELLATION-SEED")?;
    let cap = child(&f.knowledge, "cancel-private-child", 201)?;
    let request = RequestId::new("cancel-private-child")?;
    let reservation = f.runtime.reserve(
        &f.knowledge.f.control,
        &f.knowledge.f.process,
        &request,
        &cap,
        core::slice::from_ref(&seed),
        &f.observation,
    )?;
    assert_eq!(
        reservation.boundary.seed_artifacts.as_slice(),
        core::slice::from_ref(&seed)
    );
    assert_eq!(reservation.boundary.observation, f.observation);
    assert!(!reservation
        .boundary
        .seed_label
        .flows_to(&InformationLabel::bottom()));

    let mut deployment = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    let store = f.knowledge.f.authority.admission_operation_store();
    store.configure_recovery_deployment(&deployment)?;
    let current = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
    assert_eq!(
        current.actors.as_slice()[0].preview_clearance,
        InformationLabel::bottom()
    );
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedCancel)?;
    assert_eq!(actor.permission(), RecoveryPermission::ConfinedCancel);
    let storage = f.storage()?;
    let effects = external_count(&f.knowledge.f.path)?;

    // Stopping remains available after source clearance is withdrawn. The
    // actual native result is part of that actor's observable Rust API.
    let stopped = store.cancel_confined_child(
        &actor,
        &request,
        &f.knowledge.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    f.knowledge
        .f
        .process
        .cancel(reservation.boundary.child.as_str())?;
    assert_eq!(
        f.knowledge
            .f
            .process
            .process(reservation.boundary.child.as_str())?
            .state,
        chio_process::ProcessState::Cancelled
    );
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let retained: Vec<u8> = connection.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    let retained: serde_json::Value = serde_json::from_slice(&retained)?;
    assert_eq!(
        retained["reservation"]["state"],
        serde_json::to_value(IsolationStateV1::Cancelled)?
    );
    assert_eq!(f.storage()?, storage);
    assert_eq!(external_count(&f.knowledge.f.path)?, effects);

    assert_eq!(stopped.child(), &reservation.boundary.child);
    assert!(stopped.request_accepted());
    let allowed = serde_json::json!({
        "child": reservation.boundary.child,
        "request_accepted": true,
    });
    assert_eq!(
        serde_json::to_value(&stopped)?,
        allowed,
        "stop authority must expose only the requested stop identity and constant acknowledgement"
    );
    assert_eq!(
        chio_core_types::canonical_json_bytes(&stopped)?,
        chio_core_types::canonical_json_bytes(&allowed)?
    );
    assert_eq!(
        format!("{stopped:?}"),
        "NativeConfinedCancellation([redacted])"
    );
    Ok(())
}

#[test]
fn native_cancel_revokes_context_and_keeps_inputs_pinned_and_slot_consumed() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    let reservation = f.reserve("spawn-a", &cap)?;
    f.runtime.cancel(
        &f.knowledge.f.control,
        &f.knowledge.f.process,
        &RequestId::new("spawn-a")?,
    )?;
    assert_eq!(
        f.reserve("spawn-a", &cap)?.state,
        IsolationStateV1::Cancelled
    );
    assert_eq!(f.count()?, 1);
    assert!(f
        .knowledge
        .f
        .process
        .recovery_security_context(reservation.boundary.child.as_str())
        .is_err());
    assert!(f
        .knowledge
        .runtime
        .collect(&f.knowledge.f.control, &f.observation)
        .is_err());
    assert!(f.reserve("new-epoch-same-cap", &cap).is_err());
    Ok(())
}
#[test]
fn native_ordinary_fork_retains_root_lineage_and_tainted_parent_control() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "ordinary-child", 201)?;
    f.knowledge
        .f
        .process
        .spawn("root", "ordinary-child", &cap)?;
    let root = f.knowledge.f.process.recovery_security_context("root")?;
    let ordinary = f
        .knowledge
        .f
        .process
        .recovery_security_context("ordinary-child")?;
    assert_eq!(
        root.as_v1().lineage_root_id(),
        ordinary.as_v1().lineage_root_id()
    );
    assert_eq!(
        root.as_v1().isolation_epoch_id(),
        ordinary.as_v1().isolation_epoch_id()
    );
    let handle = f.knowledge.runtime.handle(
        &f.knowledge.f.control,
        &f.observation,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let sink = f.knowledge.sink();
    f.knowledge.runtime.release_into(
        &f.knowledge.f.control,
        &RequestId::new("taint-parent")?,
        f.knowledge
            .runtime
            .prepare_read(&f.knowledge.f.control, &handle)?,
        &sink,
    )?;
    let confined = f.reserve("tainted-control", &child(&f.knowledge, "fresh-child", 202)?)?;
    assert!(!confined
        .boundary
        .seed_label
        .flows_to(&InformationLabel::bottom()));
    assert!(confined.boundary.seed_influence.externally_influenced);
    Ok(())
}
#[test]
fn native_profile_downgrade_and_integrity_root_alias_refuse() -> TestResult {
    let f = ConfinedFixture::new()?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let mut p = f.profile.clone();
    p.endorsement_root = p.disclosure_root.clone();
    assert!(store.configure_confinement(&p).is_err());
    let mut p = f.profile.clone();
    p.contract.channels =
        NonEmptyBoundedList::new(vec![ConfinedChannelV1::Value, ConfinedChannelV1::Stream])?;
    assert!(store.configure_confinement(&p).is_err());
    let mut p = f.profile.clone();
    p.limits.model_calls = SafeInteger::new(1)?;
    assert!(store.configure_confinement(&p).is_err());
    let cap = child(&f.knowledge, "child-a", 201)?;
    f.reserve("spawn-a", &cap)?;
    let mut p = f.profile.clone();
    p.generation = SafeInteger::new(2)?;
    p.contract.field = ProtectedText::new("different")?;
    store.configure_confinement(&p)?;
    assert!(f.reserve("spawn-a", &cap).is_err());
    Ok(())
}
#[test]
fn native_permanent_counts_stop_epoch_churn_at_tree_limit() -> TestResult {
    let f = ConfinedFixture::new()?;
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    for n in 0..16u8 {
        let cap = child(&f.knowledge, &format!("child-{n}"), 150 + n)?;
        store.reserve_confined_child(
            &actor,
            ConfinedChildReservationInput {
                request: &RequestId::new(&format!("spawn-{n}"))?,
                parent: &f.knowledge.f.seed.capability,
                child: &cap,
                seeds: &[],
                observation: &f.observation,
            },
            &fence,
            now_ms()?,
        )?;
    }
    let cap = child(&f.knowledge, "overflow", 200)?;
    assert!(store
        .reserve_confined_child(
            &actor,
            ConfinedChildReservationInput {
                request: &RequestId::new("overflow")?,
                parent: &f.knowledge.f.seed.capability,
                child: &cap,
                seeds: &[],
                observation: &f.observation
            },
            &fence,
            now_ms()?
        )
        .is_err());
    assert_eq!(f.count()?, 16);
    Ok(())
}
#[test]
fn native_protected_boundary_and_quota_tampering_cannot_reactivate_context() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    f.reserve("spawn-a", &cap)?;
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    assert!(connection.execute("UPDATE admission_operation_recovery_records SET payload='0' WHERE record_key GLOB 'confined-count:*'",[]).is_err());
    assert_eq!(f.count()?, 1);
    // Simulate a raw writer following the SQL version rule but bypassing the
    // immutable digest history and independent serving commit chain.
    connection.execute("UPDATE admission_operation_recovery_records SET payload='0', version=version+1 WHERE record_key GLOB 'confined-count:*'",[])?;
    assert!(f.reserve("spawn-a", &cap).is_err());
    Ok(())
}

#[test]
fn native_lost_reservation_and_attachment_acknowledgements_keep_original_slot() -> TestResult {
    use crate::confinement::ConfinedCutpoint;
    for cutpoint in [ConfinedCutpoint::Reserved, ConfinedCutpoint::Attached] {
        let f = ConfinedFixture::new()?;
        let cap = child(&f.knowledge, "child-a", 201)?;
        let faulty = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
            if stage == cutpoint {
                return Err(KernelError::Internal("lost acknowledgement".into()));
            }
            Ok(())
        }));
        let request = RequestId::new("lost-ack")?;
        assert!(faulty
            .reserve(
                &f.knowledge.f.control,
                &f.knowledge.f.process,
                &request,
                &cap,
                &[],
                &f.observation
            )
            .is_err());
        let recovered = f.reserve("lost-ack", &cap)?;
        let replay = f.reserve("lost-ack", &cap)?;
        assert_eq!(recovered.boundary, replay.boundary);
        assert_eq!(f.count()?, 1);
        assert_eq!(
            f.knowledge
                .f
                .process
                .process(recovered.boundary.child.as_str())?
                .capability
                .id,
            cap.id
        );
    }
    Ok(())
}
#[test]
fn native_capability_issuer_and_actual_delegation_right_are_required() -> TestResult {
    let f = ConfinedFixture::new()?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let fence = f.knowledge.f.authority.mutation_fence();
    let issuer = Keypair::from_seed(&[211; 32]);
    let mut body = f.knowledge.f.seed.capability.body();
    body.issuer = issuer.public_key();
    let parent = CapabilityToken::sign(body, &issuer)?;
    let cap = signed_child(&parent, "foreign-issuer", 201, &issuer)?;
    assert!(store
        .reserve_confined_child(
            &actor,
            ConfinedChildReservationInput {
                request: &RequestId::new("foreign")?,
                parent: &parent,
                child: &cap,
                seeds: &[],
                observation: &f.observation
            },
            &fence,
            now_ms()?
        )
        .is_err());
    let cap = child(&f.knowledge, "legitimate-child", 201)?;
    let mut body = f.knowledge.f.seed.capability.body();
    body.scope.grants[0].operations = vec![Operation::Invoke];
    let parent = CapabilityToken::sign(body, &Keypair::from_seed(&[140; 32]))?;
    assert!(store
        .reserve_confined_child(
            &actor,
            ConfinedChildReservationInput {
                request: &RequestId::new("no-delegate")?,
                parent: &parent,
                child: &cap,
                seeds: &[],
                observation: &f.observation
            },
            &fence,
            now_ms()?
        )
        .is_err());
    Ok(())
}
#[test]
fn native_cancelled_principal_cannot_be_reissued_into_a_fresh_observation() -> TestResult {
    let f = ConfinedFixture::new()?;
    let first = child(&f.knowledge, "child-a", 201)?;
    f.reserve("spawn-a", &first)?;
    f.runtime.cancel(
        &f.knowledge.f.control,
        &f.knowledge.f.process,
        &RequestId::new("spawn-a")?,
    )?;
    let reissued = child(&f.knowledge, "new-cap-same-principal", 201)?;
    assert!(f.reserve("new-boundary", &reissued).is_err());
    assert_eq!(f.count()?, 1);
    Ok(())
}

#[test]
fn native_confined_capability_cannot_attach_a_duplicate_process() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "one-confined-capability", 201)?;
    let reservation = f.reserve("one-confined-boundary", &cap)?;
    assert!(f
        .knowledge
        .f
        .process
        .spawn("root", "duplicate-confined-process", &cap)
        .is_err());
    assert!(f
        .knowledge
        .f
        .process
        .process("duplicate-confined-process")
        .is_err());
    assert_eq!(
        f.knowledge
            .f
            .process
            .process(reservation.boundary.child.as_str())?
            .capability
            .id,
        cap.id
    );
    assert_eq!(f.count()?, 1);
    Ok(())
}

#[test]
fn native_confined_capability_cannot_be_registered_as_a_foreign_root() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "confined-root-substitution", 201)?;
    f.reserve("confined-root-substitution", &cap)?;
    assert!(!cap.delegation_chain.is_empty());
    let limits = f.knowledge.f.process.process("root")?.limits;
    let journal_charge = |path: &std::path::Path| -> TestResult<(i64, i64, i64, i64, i64)> {
        let journal = rusqlite::Connection::open(path)?;
        Ok(journal.query_row(
            "SELECT count(*), COALESCE(sum(tree_calls),0), COALESCE(sum(revision),0),
                (SELECT count(*) FROM process_calls),
                (SELECT count(*) FROM process_recovery_calls) FROM processes",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?)
    };
    let journal = f.knowledge.f.path.join("process.db");
    let before = journal_charge(&journal)?;
    let storage = f.storage()?;
    assert!(f
        .knowledge
        .f
        .process
        .create_root("foreign-confined-root", &cap, limits)
        .is_err());
    assert!(f
        .knowledge
        .f
        .process
        .process("foreign-confined-root")
        .is_err());
    assert_eq!(journal_charge(&journal)?, before);
    assert_eq!(f.storage()?, storage);

    let foreign_path = f.knowledge.f.path.join("foreign-process.db");
    let foreign = ProcessRuntime::open(&foreign_path, f.knowledge.f.kernel.clone())?;
    assert_ne!(foreign.runtime_id(), f.knowledge.f.process.runtime_id());
    let before = journal_charge(&foreign_path)?;
    assert_eq!(before, (0, 0, 0, 0, 0));
    assert!(foreign
        .create_root("foreign-runtime-confined-root", &cap, limits)
        .is_err());
    assert!(foreign.process("foreign-runtime-confined-root").is_err());
    assert_eq!(journal_charge(&foreign_path)?, before);
    foreign.create_root(
        "ordinary-root-control",
        &f.knowledge.f.seed.capability,
        limits,
    )?;
    assert_eq!(journal_charge(&foreign_path)?, (1, 0, 0, 0, 0));
    assert_eq!(f.storage()?, storage);
    assert_eq!(f.count()?, 1);
    Ok(())
}

#[test]
fn native_confined_child_cannot_attach_a_signed_descendant() -> TestResult {
    use chio_core_types::capability::attenuation::{DelegationLink, DelegationLinkBody};
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "non-delegating-confined-capability", 201)?;
    let reservation = f.reserve("non-delegating-confined-boundary", &cap)?;
    let subject = Keypair::from_seed(&[202; 32]);
    let scope = ChioScope::default();
    let mut chain = cap.delegation_chain.clone();
    // A signed, attenuation-valid hop does not create a Delegate permission.
    // Construct the hostile hop directly: the normal delegate helper correctly
    // refuses to mint it from this grant-free confined parent.
    chain.push(DelegationLink::sign(
        DelegationLinkBody {
            capability_id: cap.id.clone(),
            delegator: cap.subject.clone(),
            delegatee: subject.public_key(),
            attenuations: vec![],
            timestamp: cap.issued_at,
            scope_hash: Some(scope_hash(&cap.scope)?),
            aggregate_budget: None,
            cumulative_approval: None,
        },
        &Keypair::from_seed(&[201; 32]),
    )?);
    let descendant = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "signed-confined-descendant".into(),
                issuer: cap.issuer.clone(),
                subject: subject.public_key(),
                issued_at: cap.issued_at,
                expires_at: cap.expires_at,
                delegation_chain: chain,
                aggregate_invocation_budget: cap.aggregate_invocation_budget.clone(),
                scope: scope.clone(),
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: AttenuationProof {
                parent_scope_hash: scope_hash(&cap.scope)?,
                child_scope_hash: scope_hash(&scope)?,
                normalized_subset_proof: compute_attenuation_witness(&cap.scope, &scope)?,
            },
            budget_share_bps: Some(100),
        },
        &Keypair::from_seed(&[140; 32]),
    )?;
    assert!(f
        .knowledge
        .f
        .process
        .spawn(
            reservation.boundary.child.as_str(),
            "signed-confined-descendant",
            &descendant,
        )
        .is_err());
    assert!(f
        .knowledge
        .f
        .process
        .process("signed-confined-descendant")
        .is_err());
    assert_eq!(f.count()?, 1);
    Ok(())
}

#[test]
fn native_ordinary_root_ignores_another_scopes_confined_capability_id() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "colliding-capability-id", 201)?;
    let reservation = f.reserve("confined-scope", &cap)?;
    let mut body = f.knowledge.f.seed.capability.body();
    body.id = cap.id.clone();
    let other = CapabilityToken::sign(body, &Keypair::from_seed(&[140; 32]))?;
    // Ordinary journal IDs support a wider bound than recovery scope IDs.
    // Deriving a native owner must preserve that ordinary compatibility.
    let root = format!("ordinary-{}", "r".repeat(160));
    assert!(ProcessId::new(&root).is_err());
    f.knowledge.f.process.create_root(
        &root,
        &other,
        f.knowledge.f.process.process("root")?.limits,
    )?;
    let context = f.knowledge.f.process.recovery_security_context(&root);
    assert!(
        context.is_ok(),
        "an ordinary token sharing a textual ID must retain its ordinary context"
    );
    let context = context?;
    assert_eq!(
        context.as_v1().principal_id().as_str(),
        other.subject.to_hex()
    );
    assert_eq!(context.as_v1().lineage_root_id().as_str(), other.id);
    assert_ne!(
        context.as_v1().lineage_root_id().as_str(),
        reservation.boundary.lineage.as_str()
    );
    assert_eq!(f.count()?, 1);
    Ok(())
}

#[test]
fn native_observed_ordinary_principal_cannot_become_a_fresh_confined_child() -> TestResult {
    let f = ConfinedFixture::new()?;
    let ordinary = child(&f.knowledge, "ordinary-observed-capability", 201)?;
    f.knowledge
        .f
        .process
        .spawn("root", "ordinary-observed-process", &ordinary)?;
    let context = f
        .knowledge
        .f
        .process
        .recovery_security_context("ordinary-observed-process")?;
    let mut profile = f.knowledge.profile.clone();
    profile.generation = SafeInteger::new(profile.generation.get() + 1)?;
    let recipient = ArtifactRecipientV1 {
        recipient: ArtifactRecipientId::new("ordinary-observed-recipient")?,
        scope: profile.scope.clone(),
        runtime: ProtectedText::new(f.knowledge.f.process.runtime_id())?,
        principal: context.as_v1().principal_id().clone(),
        lineage: IsolationLineageId::new(context.as_v1().lineage_root_id().as_str())?,
        isolation_epoch: ProtectedText::new(context.as_v1().isolation_epoch_id().as_str())?,
        context_generation: SafeInteger::new(context.as_v1().context_generation())?,
        clearance: f.knowledge.profile.recipients.as_slice()[0]
            .recipient
            .clearance
            .clone(),
        sink: ArtifactSinkV1::Agent,
    };
    let mut recipients = profile.recipients.as_slice().to_vec();
    recipients.push(NativeKnowledgeRecipientV1 {
        recipient: recipient.clone(),
        context: context.clone(),
    });
    profile.recipients = NonEmptyBoundedList::new(recipients)?;
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    store.configure_knowledge(&profile)?;
    let actor = f.knowledge.actor(RecoveryPermission::KnowledgeRead)?;
    let handle = store.issue_artifact_handle(
        &actor,
        &f.observation,
        &recipient.recipient,
        &fence,
        now_ms()?,
    )?;
    let (record, _) = store.prepare_artifact_read(&actor, &handle, &fence, now_ms()?)?;
    store.admit_artifact_release(
        &actor,
        &handle,
        &RequestId::new("ordinary-native-observation")?,
        &record.seal.ok_or("observation seal")?,
        &fence,
        now_ms()?,
    )?;
    assert!(store
        .observe_security_participant_flow(
            &profile.native_authority,
            &recovery_flow_key(&context),
            &fence,
            now_ms()?,
        )?
        .snapshot()
        .is_some());
    let reissued = child(&f.knowledge, "fresh-capability-old-principal", 201)?;
    assert!(f
        .reserve("fresh-confined-old-principal", &reissued)
        .is_err());
    let connection = rusqlite::Connection::open(f.knowledge.f.path.join("admission.db"))?;
    let boundaries: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'confined-boundary:*'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(boundaries, 0);
    Ok(())
}

#[test]
fn native_reserved_confined_child_rejects_generic_blob_staging() -> TestResult {
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "fixed-return-slot-child", 201)?;
    let reservation = f.reserve("fixed-return-slot-boundary", &cap)?;
    assert!(f
        .knowledge
        .broker
        .stage(
            &ArtifactObjectId::new("wrong-confined-staging-route")?,
            &reservation.boundary.child,
            b"false",
        )
        .is_err());
    let ordinary = f.knowledge.broker.stage(
        &ArtifactObjectId::new("ordinary-staging-positive-control")?,
        &ProcessId::new("root")?,
        b"ordinary-parent-bytes",
    )?;
    assert_eq!(
        f.knowledge.broker.read_private(&ordinary)?,
        b"ordinary-parent-bytes"
    );
    Ok(())
}

#[test]
fn native_attachment_requires_live_journal_ancestry_and_retained_signed_capability() -> TestResult {
    use chio_kernel::knowledge::ArtifactBlobPort;
    let f = ConfinedFixture::new()?;
    let cap = child(&f.knowledge, "child-a", 201)?;
    let reserved = f.reserve("spawn-a", &cap)?;
    f.knowledge
        .broker
        .validate_confined_attachment(&reserved.boundary)?;
    f.knowledge
        .f
        .kernel
        .verify_retained_capability_liveness(&cap.id, &cap.subject)?;
    let mut substituted = reserved.boundary.clone();
    substituted.parent_capability = ConfinedCapabilityDigest::from_bytes([0; 32]);
    assert!(f
        .knowledge
        .broker
        .validate_confined_attachment(&substituted)
        .is_err());
    f.knowledge.f.process.cancel("root")?;
    assert!(f
        .knowledge
        .broker
        .validate_confined_attachment(&reserved.boundary)
        .is_err());
    assert_eq!(f.count()?, 1);
    Ok(())
}
#[test]
fn native_original_tree_quota_denies_attachment_without_refunding_native_slot() -> TestResult {
    use chio_kernel::knowledge::ArtifactBlobPort;
    let f = ConfinedFixture::new()?;
    for n in 0..7u8 {
        f.reserve(
            &format!("tree-{n}"),
            &child(&f.knowledge, &format!("tree-child-{n}"), 150 + n)?,
        )?;
    }
    let cap = child(&f.knowledge, "tree-overflow", 200)?;
    assert!(f.reserve("tree-overflow", &cap).is_err());
    assert_eq!(f.count()?, 8);
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let reservation = f
        .knowledge
        .f
        .authority
        .admission_operation_store()
        .confined_launch_reservation(
            &actor,
            &RequestId::new("tree-overflow")?,
            &f.knowledge.f.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(f
        .knowledge
        .broker
        .validate_confined_attachment(&reservation.boundary)
        .is_err());
    Ok(())
}

#[test]
fn native_reservation_and_replay_require_current_source_audience() -> TestResult {
    let mut violations = Vec::new();
    for replay in [false, true] {
        let f = ConfinedFixture::new()?;
        let seed = f
            .knowledge
            .publish("private-reservation-seed", b"PRIVATE-SEED")?;
        let original = RequestId::new("audience-reservation-original")?;
        let original_child = child(&f.knowledge, "audience-original-child", 201)?;
        let reserved = f.runtime.reserve(
            &f.knowledge.f.control,
            &f.knowledge.f.process,
            &original,
            &original_child,
            core::slice::from_ref(&seed),
            &f.observation,
        )?;
        assert!(!reserved
            .boundary
            .seed_label
            .flows_to(&InformationLabel::bottom()));
        assert_eq!(
            reserved.boundary.seed_artifacts.as_slice(),
            core::slice::from_ref(&seed)
        );
        let parent = f
            .knowledge
            .f
            .process
            .process(f.profile.scope.process_id.as_str())?;
        let mut deployment = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
        let mut actors = deployment.actors.as_slice().to_vec();
        actors[0].preview_clearance = InformationLabel::bottom();
        deployment.actors = NonEmptyBoundedList::new(actors)?;
        deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
        let store = f.knowledge.f.authority.admission_operation_store();
        store.configure_recovery_deployment(&deployment)?;
        let current = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
        assert_eq!(
            current.actors.as_slice()[0].preview_clearance,
            InformationLabel::bottom()
        );
        let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
        assert_eq!(actor.permission(), RecoveryPermission::ConfinedLaunch);
        let fence = f.knowledge.f.authority.mutation_fence();
        // Prove the changed actor still reaches current native composition and
        // readiness before crediting a refusal at the reservation boundary.
        let installed = store.knowledge_installation(&actor, &fence, now_ms()?)?;
        assert_eq!(installed.scope, f.profile.scope);
        assert_eq!(installed.policy, f.profile.contract.policy);
        let count = f.count()?;
        let storage = f.storage()?;
        let effects = external_count(&f.knowledge.f.path)?;
        let fresh = RequestId::new("audience-reservation-fresh")?;
        let fresh_child = child(&f.knowledge, "audience-fresh-child", 202)?;
        let (request, capability) = if replay {
            (&original, &original_child)
        } else {
            (&fresh, &fresh_child)
        };
        let result = store.reserve_confined_child(
            &actor,
            chio_store_sqlite::admission_operation_store::ConfinedChildReservationInput {
                request,
                parent: &parent.capability,
                child: capability,
                seeds: core::slice::from_ref(&seed),
                observation: &f.observation,
            },
            &fence,
            now_ms()?,
        );
        if result.is_ok() {
            violations.push(if replay {
                "low-clearance replay returned classified boundary metadata"
            } else {
                "low-clearance fresh reservation returned classified boundary metadata"
            });
        }
        if f.count()? != count {
            violations.push("low-clearance reservation consumed a native child slot");
        }
        assert_eq!(f.storage()?, storage);
        assert_eq!(external_count(&f.knowledge.f.path)?, effects);
    }
    assert!(violations.is_empty(), "{}", violations.join("; "));
    Ok(())
}

#[test]
fn native_launch_reservation_requires_current_source_audience() -> TestResult {
    let f = ConfinedFixture::new()?;
    let request = RequestId::new("audience-launch-reservation")?;
    let capability = child(&f.knowledge, "audience-launch-child", 203)?;
    let reserved = f.reserve(request.as_str(), &capability)?;
    assert!(!reserved
        .boundary
        .seed_label
        .flows_to(&InformationLabel::bottom()));
    let store = f.knowledge.f.authority.admission_operation_store();
    let fence = f.knowledge.f.authority.mutation_fence();
    let cleared = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let ready = store.confined_launch_reservation(&cleared, &request, &fence, now_ms()?)?;
    assert_eq!(ready.boundary.boundary, reserved.boundary.boundary);
    assert_eq!(ready.state, IsolationStateV1::Reserved);
    let mut deployment = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let current = f.knowledge.f.kernel.recovery_deployment(&f.profile.scope)?;
    assert_eq!(
        current.actors.as_slice()[0].preview_clearance,
        InformationLabel::bottom()
    );
    let actor = f.knowledge.actor(RecoveryPermission::ConfinedLaunch)?;
    let installed = store.knowledge_installation(&actor, &fence, now_ms()?)?;
    assert_eq!(installed.scope, f.profile.scope);
    assert_eq!(installed.policy, f.profile.contract.policy);
    let count = f.count()?;
    let storage = f.storage()?;
    let effects = external_count(&f.knowledge.f.path)?;
    let result = store.confined_launch_reservation(&actor, &request, &fence, now_ms()?);
    assert!(
        result.is_err(),
        "low-clearance launch reservation returned classified boundary metadata"
    );
    assert_eq!(f.count()?, count);
    assert_eq!(f.storage()?, storage);
    assert_eq!(external_count(&f.knowledge.f.path)?, effects);
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;
