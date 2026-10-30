//! Semantic installation uses the provisioned authority and shared planning allocation.
use super::*;
use crate::admission_operation_store::NativeSemanticInstallation;
use chio_core::recovery::{
    semantic_content_digest, semantic_key_digest, semantic_package_digest,
    SignedSemanticDeploymentV1, SignedSemanticPackageV1,
};
use chio_security_types::recovery::{
    CanonicalPayloadDigest, ProviderAccountId, ProviderId, ProviderResourceId,
    SemanticDestinationId, SemanticFieldId, SemanticOperationId, SemanticPackageId, VersionV1,
};
use chio_security_types::semantic::{
    SemanticChannelRuleV1, SemanticChannelV1, SemanticDeploymentV1, SemanticDestinationV1,
    SemanticOperationContractV1, SemanticOperationKindV1, SemanticPackageV1, SemanticRouteV1,
};
use chio_semantic_contracts::ExposedSemanticToolV1;

fn operator() -> Keypair {
    Keypair::from_seed(&[211; 32])
}

fn channels() -> TestResult<NonEmptyBoundedList<SemanticChannelRuleV1, 13>> {
    Ok(NonEmptyBoundedList::new(
        [
            SemanticChannelV1::Input,
            SemanticChannelV1::Success,
            SemanticChannelV1::Error,
            SemanticChannelV1::NoValue,
            SemanticChannelV1::Nested,
            SemanticChannelV1::Batch,
            SemanticChannelV1::Pagination,
            SemanticChannelV1::Redirect,
            SemanticChannelV1::Stream,
            SemanticChannelV1::File,
            SemanticChannelV1::Log,
            SemanticChannelV1::Shell,
            SemanticChannelV1::Model,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, channel)| SemanticChannelRuleV1 {
            channel,
            enabled: index < 4,
        })
        .collect(),
    )?)
}

fn installation(
    owner: &Authority,
    binding: &NativeSecurityAuthorityBindingV1,
    process: &str,
    tools: &[&str],
) -> TestResult<NativeSemanticInstallation> {
    let profile = deployment(&owner.fence, binding, process)?;
    let publisher = Keypair::from_seed(&[210; 32]);
    let contract = SemanticOperationContractV1 {
        operation: SemanticOperationId::new("read-support")?,
        kind: SemanticOperationKindV1::SupportRead,
        input_schema: CanonicalPayloadDigest::from_bytes([1; 32]),
        output_schema: CanonicalPayloadDigest::from_bytes([2; 32]),
        implementation: CanonicalPayloadDigest::from_bytes([3; 32]),
        channels: channels()?,
        input_fields: BoundedList::new(vec![SemanticFieldId::new("query")?])?,
        selectors: BoundedList::new(vec![])?,
        required_assertions: BoundedList::new(vec![])?,
        prerequisites: BoundedList::new(vec![])?,
        projection_fields: BoundedList::new(vec![])?,
        source_label: InformationLabel::bottom(),
        external_influence: false,
        withheld_status: None,
    };
    let mut operations = Vec::new();
    for tool in tools {
        let mut operation = contract.clone();
        operation.operation = SemanticOperationId::new(tool)?;
        operations.push(operation);
    }
    let package = SignedSemanticPackageV1::sign(
        SemanticPackageV1 {
            domain_version: VersionV1,
            package: SemanticPackageId::new("support")?,
            dependencies: BoundedList::new(vec![])?,
            operations: NonEmptyBoundedList::new(operations.clone())?,
        },
        &publisher,
    )?;
    let mut routes = Vec::new();
    let mut exposed = Vec::new();
    for (tool, contract) in tools.iter().zip(operations.iter()) {
        let route = SemanticRouteV1 {
            server: ProtectedText::new("support-server")?,
            tool: ProtectedText::new(tool)?,
            package: semantic_package_digest(package.body())?,
            operation: contract.operation.clone(),
            implementation: contract.implementation,
            input_schema: contract.input_schema,
            output_schema: contract.output_schema,
            destinations: NonEmptyBoundedList::new(vec![SemanticDestinationV1 {
                destination: SemanticDestinationId::new("support-queue")?,
                provider: ProviderId::new("support-provider")?,
                account: ProviderAccountId::new("tenant-account")?,
                resource: ProviderResourceId::new("support-queue")?,
                endpoint: ProtectedText::new("https://fixture.invalid/support")?,
                audience: InformationLabel::bottom(),
                purpose: ProtectedText::new("support")?,
                subject_mapping: CanonicalPayloadDigest::from_bytes([4; 32]),
                acl_query: CanonicalPayloadDigest::from_bytes([5; 32]),
                require_provider_precondition: true,
            }])?,
            operator_selectors: BoundedList::new(vec![])?,
            reviewed_overrides: BoundedList::new(vec![])?,
            resolver_key: semantic_key_digest(&operator().public_key())?,
            endorsement_key: semantic_key_digest(&operator().public_key())?,
            prerequisite_key: semantic_key_digest(&operator().public_key())?,
            transformation_key: semantic_key_digest(&operator().public_key())?,
            annotators: BoundedList::new(vec![])?,
        };
        exposed.push(ExposedSemanticToolV1 {
            server: route.server.clone(),
            tool: route.tool.clone(),
            implementation: contract.implementation,
            input_schema: contract.input_schema,
            output_schema: contract.output_schema,
            channels: contract.channels.clone(),
        });
        routes.push(route);
    }
    let body = SemanticDeploymentV1 {
        domain_version: VersionV1,
        scope: profile.scope.clone(),
        generation: SafeInteger::new(1)?,
        native_binding: semantic_content_digest(binding)?,
        context_binding: semantic_content_digest(&(
            chio_kernel::recovery::recovery_flow_key(&profile.security_context),
            profile.security_context.as_v1().context_generation(),
        ))?,
        exposure_binding: semantic_content_digest(&exposed)?,
        packages: NonEmptyBoundedList::new(vec![semantic_package_digest(package.body())?])?,
        routes: NonEmptyBoundedList::new(routes)?,
    };
    let value = NativeSemanticInstallation {
        deployment: SignedSemanticDeploymentV1::sign(body, &operator())?,
        packages: NonEmptyBoundedList::new(vec![package])?,
        operator_root: operator().public_key(),
        publisher_roots: NonEmptyBoundedList::new(vec![publisher.public_key()])?,
        exposed: NonEmptyBoundedList::new(exposed)?,
        native_authority: binding.clone(),
        security_context: profile.security_context,
    };
    chio_semantic_contracts::compile_semantic_registry(
        &value.deployment,
        &value.deployment.body().scope,
        value.packages.as_slice(),
        &value.operator_root,
        value.publisher_roots.as_slice(),
        value.exposed.as_slice(),
        &mut chio_security_types::work::VerificationBudget::new(
            4096,
            chio_security_types::recovery::MAX_RECOVERY_VERIFICATION_WORK,
        )?,
    )?;
    Ok(value)
}

fn install(
    owner: &Authority,
    value: &NativeSemanticInstallation,
) -> Result<(), AdmissionOperationStoreError> {
    owner
        .store
        .configure_semantic_deployment(&value.deployment.body().scope, value)
}

fn read(
    owner: &Authority,
    value: &NativeSemanticInstallation,
) -> TestResult<NativeSemanticInstallation> {
    Ok(owner.store.read_semantic_installation(
        &value.deployment.body().scope,
        &owner.fence,
        now_ms()?,
    )?)
}

fn rotate(value: &mut NativeSemanticInstallation, generation: u64) -> TestResult {
    let mut body = value.deployment.body().clone();
    body.generation = SafeInteger::new(generation)?;
    value.deployment = SignedSemanticDeploymentV1::sign(body, &operator())?;
    Ok(())
}

#[test]
fn semantic_installation_replays_without_writes_and_reopens() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let value = installation(&owner, &binding, "semantic-process", &["read"])?;
    install(&owner, &value)?;
    let counts = owner.counts()?;
    assert_eq!(counts, (5, 9, 9));
    assert_eq!(
        encode_protected(&read(&owner, &value)?)?,
        encode_protected(&value)?
    );
    install(&owner, &value)?;
    assert_eq!(owner.counts()?, counts);
    let owner = owner.reopened()?;
    assert_eq!(
        encode_protected(&read(&owner, &value)?)?,
        encode_protected(&value)?
    );
    install(&owner, &value)?;
    assert_eq!(owner.counts()?, counts);
    Ok(())
}

#[test]
fn semantic_rotation_retains_history_and_removed_route_ownership() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let first = installation(&owner, &binding, "semantic-process", &["read"])?;
    install(&owner, &first)?;
    let mut second = installation(&owner, &binding, "semantic-process", &["lookup"])?;
    rotate(&mut second, 2)?;
    install(&owner, &second)?;
    assert_eq!(owner.counts()?, (7, 18, 18));
    let raw = Connection::open(&owner.database)?;
    let retained: i64 = raw.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE (record_key GLOB 'semantic-route:*' OR record_key GLOB 'semantic-deployment-history:*')
           AND version = 1", [], |row| row.get(0),
    )?;
    assert_eq!(retained, 4);
    let other = installation(&owner, &binding, "other-process", &["read"])?;
    let before = owner.counts()?;
    assert_eq!(
        install(&owner, &other),
        Err(invariant("semantic protected record ownership differs"))
    );
    assert_eq!(owner.counts()?, before);
    let mut third = first.clone();
    rotate(&mut third, 3)?;
    install(&owner, &third)?;
    assert_eq!(owner.counts()?, (8, 24, 24));
    let owner = owner.reopened()?;
    assert_eq!(read(&owner, &third)?.deployment.body().generation.get(), 3);
    Ok(())
}

#[test]
fn semantic_late_route_conflict_rolls_back_every_planned_write() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let first = installation(&owner, &binding, "first-process", &["taken"])?;
    install(&owner, &first)?;
    let conflict = installation(&owner, &binding, "second-process", &["free", "taken"])?;
    let before = owner.counts()?;
    assert_eq!(
        install(&owner, &conflict),
        Err(invariant("semantic protected record ownership differs"))
    );
    assert_eq!(owner.counts()?, before);
    let third = installation(&owner, &binding, "third-process", &["free"])?;
    install(&owner, &third)?;
    let owner = owner.reopened()?;
    assert_eq!(
        encode_protected(&read(&owner, &third)?)?,
        encode_protected(&third)?
    );
    Ok(())
}

#[test]
fn semantic_and_recovery_deployments_share_both_planning_allocations() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    owner.store.configure_recovery_deployment(&deployment(
        &owner.fence,
        &binding,
        "recovery-process",
    )?)?;
    let value = installation(&owner, &binding, "semantic-process", &["read"])?;
    install(&owner, &value)?;
    let raw = Connection::open(&owner.database)?;
    let mut statement = raw.prepare(
        "SELECT payload, version FROM admission_operation_recovery_records
         WHERE record_key GLOB 'recovery-planning-quota:*' ORDER BY record_key",
    )?;
    let allocations = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(allocations.len(), 2);
    for (payload, version) in allocations {
        let budget: serde_json::Value = serde_json::from_slice(&payload)?;
        assert_eq!(version, 5);
        assert_eq!(budget["writes"], 5);
    }
    super::super::planning::verify_planning_allocations(&raw)?;
    drop(statement);
    drop(raw);
    owner.reopened()?;
    Ok(())
}

#[test]
fn semantic_untrusted_roots_scope_manifest_and_bindings_refuse_without_writes() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let good = installation(&owner, &binding, "semantic-process", &["read"])?;
    let before = owner.counts()?;
    let mut wrong_scope = good.deployment.body().scope.clone();
    wrong_scope.process_id = ProcessId::new("other-process")?;
    assert_eq!(
        owner
            .store
            .configure_semantic_deployment(&wrong_scope, &good),
        Err(invariant("semantic deployment registry refused")),
    );
    let mut cases = Vec::new();
    let mut value = good.clone();
    value.operator_root = Keypair::from_seed(&[77; 32]).public_key();
    cases.push((value, "semantic deployment registry refused"));
    let mut value = good.clone();
    value.publisher_roots =
        NonEmptyBoundedList::new(vec![Keypair::from_seed(&[78; 32]).public_key()])?;
    cases.push((value, "semantic deployment registry refused"));
    let mut value = good.clone();
    let mut tool = value.exposed.as_slice()[0].clone();
    tool.implementation = CanonicalPayloadDigest::from_bytes([99; 32]);
    value.exposed = NonEmptyBoundedList::new(vec![tool])?;
    cases.push((value, "semantic deployment registry refused"));
    for (field, message) in [
        ("native", "semantic deployment native binding differs"),
        ("context", "semantic deployment context binding differs"),
        ("domain", "semantic deployment scope differs"),
        ("tenant", "semantic deployment scope differs"),
    ] {
        let mut value = good.clone();
        let mut body = value.deployment.body().clone();
        match field {
            "native" => body.native_binding = CanonicalPayloadDigest::from_bytes([90; 32]),
            "context" => body.context_binding = CanonicalPayloadDigest::from_bytes([91; 32]),
            "domain" => body.scope.authority_domain = AuthorityDomainId::new("other-authority")?,
            _ => body.scope.tenant_id = RecoveryTenantId::new("other-tenant")?,
        }
        value.deployment = SignedSemanticDeploymentV1::sign(body, &operator())?;
        cases.push((value, message));
    }
    for (value, message) in cases {
        assert_eq!(install(&owner, &value), Err(invariant(message)));
        assert_eq!(owner.counts()?, before);
    }
    install(&owner, &good)?;
    Ok(())
}

#[test]
fn semantic_generation_and_operator_rotation_refuse_without_writes() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let mut current = installation(&owner, &binding, "semantic-process", &["read"])?;
    rotate(&mut current, 2)?;
    install(&owner, &current)?;
    let before = owner.counts()?;
    let mut lower = current.clone();
    rotate(&mut lower, 1)?;
    let mut same_generation = installation(&owner, &binding, "semantic-process", &["lookup"])?;
    rotate(&mut same_generation, 2)?;
    let mut replacement = current.clone();
    let other = Keypair::from_seed(&[80; 32]);
    let mut body = replacement.deployment.body().clone();
    body.generation = SafeInteger::new(3)?;
    replacement.operator_root = other.public_key();
    replacement.deployment = SignedSemanticDeploymentV1::sign(body, &other)?;
    for value in [lower, same_generation, replacement] {
        assert_eq!(
            install(&owner, &value),
            Err(invariant("semantic deployment generation or owner differs"))
        );
        assert_eq!(owner.counts()?, before);
    }
    Ok(())
}

#[test]
fn semantic_readback_refuses_foreign_fence_and_stale_time() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let value = installation(&owner, &binding, "semantic-process", &["read"])?;
    install(&owner, &value)?;
    let mut fence = owner.fence.clone();
    fence.owner_epoch += 1;
    assert_eq!(
        owner
            .store
            .read_semantic_installation(&value.deployment.body().scope, &fence, now_ms()?)
            .err(),
        Some(AdmissionOperationStoreError::Fenced),
    );
    assert_eq!(
        owner
            .store
            .read_semantic_installation(&value.deployment.body().scope, &owner.fence, 1)
            .err(),
        Some(invariant(
            "trusted_now_unix_ms exceeds the permitted system-clock skew"
        )),
    );
    Ok(())
}

#[test]
fn semantic_missing_projections_refuse_planning_and_poison_live_owner() -> TestResult {
    for prefix in [
        "semantic-deployment:",
        "semantic-deployment-history:",
        "semantic-route:",
        "recovery-planning-quota:",
    ] {
        let owner = authority()?;
        let binding = owner.initialized_binding("semantic-security")?;
        let value = installation(&owner, &binding, "semantic-process", &["read"])?;
        install(&owner, &value)?;
        let raw = Connection::open(&owner.database)?;
        let guard: String = raw.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
             AND name = 'admission_operation_recovery_records_no_delete'",
            [],
            |row| row.get(0),
        )?;
        raw.execute_batch(
            "PRAGMA foreign_keys = OFF;
             DROP TRIGGER admission_operation_recovery_records_no_delete;",
        )?;
        raw.execute(
            "DELETE FROM admission_operation_recovery_records WHERE record_key = (
              SELECT record_key FROM admission_operation_recovery_records
              WHERE record_key GLOB ?1 ORDER BY record_key LIMIT 1)",
            [format!("{prefix}*")],
        )?;
        raw.execute_batch(&guard)?;
        let before = owner.counts()?;
        let message = if prefix == "recovery-planning-quota:" {
            "recovery record disappeared with retained history"
        } else {
            "recovery planning quota counters changed"
        };
        assert_eq!(
            super::super::planning::verify_planning_allocations(&raw),
            Err(invariant(message)),
        );
        assert_eq!(
            install(&owner, &value),
            Err(AdmissionOperationStoreError::OutcomeUnknown(
                "authority database changed outside its serving-owner connection".into(),
            )),
        );
        assert_eq!(
            owner.store.read_semantic_installation(
                &value.deployment.body().scope, &owner.fence, now_ms()?,
            ).err(),
            Some(AdmissionOperationStoreError::OutcomeUnknown(
                "sqlite authority owner is poisoned after an outcome-unknown anchor sync".into(),
            )),
        );
        assert_eq!(owner.counts()?, before);
    }
    Ok(())
}

#[test]
fn semantic_modified_signed_bodies_refuse_without_writes() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let good = installation(&owner, &binding, "semantic-process", &["read"])?;
    let before = owner.counts()?;
    let mut deployment_json = serde_json::to_value(&good.deployment)?;
    deployment_json["body"]["generation"] = serde_json::json!(2);
    let mut altered_deployment = good.clone();
    altered_deployment.deployment = serde_json::from_value(deployment_json)?;
    assert!(!altered_deployment
        .deployment
        .verify_integrity_embedded_key()?);
    let mut package_json = serde_json::to_value(&good.packages.as_slice()[0])?;
    package_json["body"]["operations"][0]["external_influence"] = serde_json::json!(true);
    let altered_package: SignedSemanticPackageV1 = serde_json::from_value(package_json)?;
    assert!(!altered_package.verify_integrity_embedded_key()?);
    let mut package = good.clone();
    package.packages = NonEmptyBoundedList::new(vec![altered_package])?;
    for value in [altered_deployment, package] {
        assert_eq!(
            install(&owner, &value),
            Err(invariant("semantic deployment registry refused"))
        );
        assert_eq!(owner.counts()?, before);
    }
    install(&owner, &good)?;
    Ok(())
}

#[test]
fn semantic_history_and_route_records_refuse_a_second_planned_version() -> TestResult {
    let owner = authority()?;
    let binding = owner.initialized_binding("semantic-security")?;
    let value = installation(&owner, &binding, "semantic-process", &["read"])?;
    install(&owner, &value)?;
    let before = owner.counts()?;
    for prefix in ["semantic-deployment-history:", "semantic-route:"] {
        let mut connection = owner.store.connection()?;
        let tx = owner.store.begin_write(&mut connection, None)?;
        let key: String = tx.query_row(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1 ORDER BY record_key LIMIT 1",
            [format!("{prefix}*")],
            |row| row.get(0),
        )?;
        let record = load_record(&tx, &key)?.ok_or("fixture record absent")?;
        assert_eq!(
            super::super::planning::save_planned(
                &tx,
                &owner.store.serving_owner,
                &ProtectedWrite {
                    key: &key,
                    scope: &record.scope,
                    kind: ProtectedRecordKind::Deployment,
                    payload: &record.payload,
                },
            ),
            Err(invariant("recovery planning immutable identity changed")),
        );
        drop(tx);
        assert_eq!(owner.counts()?, before);
    }
    owner.reopened()?;
    Ok(())
}
