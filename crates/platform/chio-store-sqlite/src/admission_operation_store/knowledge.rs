//! Durable knowledge is owned by the existing fenced serving authority.
use super::recovery::storage as protected;
use super::*;
use chio_core::recovery::*;
use chio_core::PublicKey;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::{knowledge::*, recovery::*, SecurityInvocationContext};
use chio_security_types::{knowledge::*, recovery::*, InformationLabel};

mod checkpoints;
mod confinement;
pub(in crate::admission_operation_store) mod encoding;
mod lifecycle;
mod pins;
mod product_artifact_selection;
mod product_evidence;
mod publication;
pub(in crate::admission_operation_store) mod publication_capacity;
pub(super) mod publication_census;
pub(super) mod publication_source;
pub(in crate::admission_operation_store) mod reference_activation;
pub(in crate::admission_operation_store) mod reference_baseline;
pub(in crate::admission_operation_store) mod reference_census;
pub(in crate::admission_operation_store) mod reference_custody;
pub(in crate::admission_operation_store) mod reference_ready;
pub(in crate::admission_operation_store) mod reference_retirement;
pub(super) mod reference_source;
pub(in crate::admission_operation_store) mod references;
mod release;
#[cfg(feature = "admission-test-support")]
mod release_basis_observation;
#[cfg(feature = "admission-test-support")]
pub use release_basis_observation::{
    observe_artifact_release_basis, ArtifactReleaseBasisObservation,
    ArtifactReleaseBasisObservationScope,
};
mod transfer;
mod traversal;
pub(in crate::admission_operation_store) use checkpoints::AuthenticatedCheckpointRestoreEncodingSource;
pub use checkpoints::NativeCheckpointRestore;
pub(in crate::admission_operation_store) use checkpoints::VerifiedCheckpointHeadWrite;
#[cfg(feature = "admission-test-support")]
pub use checkpoints::{
    construct_legacy_checkpoint_restore_fixture, LegacyCheckpointRestoreFixtureScope,
};
pub(in crate::admission_operation_store) use confinement::setup_confinement_inventory;
pub use confinement::*;
pub(in crate::admission_operation_store) use product_artifact_selection::{
    retained_product_artifact, selected_product_artifact,
};
pub(in crate::admission_operation_store) use product_evidence::{
    retain_product_evidence, retire_product_evidence, verify_product_reference_available,
};
pub(in crate::admission_operation_store) use reference_activation::{
    verify_reference_baseline, verify_reference_ready,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKnowledgeRecipientV1 {
    pub recipient: ArtifactRecipientV1,
    pub context: SecurityInvocationContext,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeKnowledgeInstallationV1 {
    pub scope: RecoveryScopeV1,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub producer_context: SecurityInvocationContext,
    pub recipients: NonEmptyBoundedList<NativeKnowledgeRecipientV1, 16>,
    pub certificate_root: PublicKey,
    pub classifier_implementation: CanonicalPayloadDigest,
    pub classifier_configuration: CanonicalPayloadDigest,
    pub archive_root: PublicKey,
    pub generation: SafeInteger,
    pub policy: PolicyDigest,
    pub contract: ContractDigest,
}
/// Bounded checkpoint update data. The native writer authenticates the caller
/// and resolves every reference; this description grants no restore authority.
pub struct NativeCheckpointUpdate<'a> {
    pub checkpoint: &'a CheckpointId,
    pub expected_revision: u64,
    pub artifacts: &'a [ArtifactVersionRefV1],
    pub model_contexts: &'a [ModelContextV1],
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPublicationInputV1 {
    pub publication: CommandId,
    pub producer: ArtifactProducerV1,
    pub content: CanonicalPayloadDigest,
    pub size_bytes: SafeInteger,
    pub media_type: ProtectedText<128>,
    pub schema: CanonicalPayloadDigest,
    pub dependencies: BoundedList<ArtifactVersionRefV1, 16>,
    pub retention: ArtifactRetentionV1,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactRecordV1 {
    pub input: ArtifactPublicationInputV1,
    pub metadata: ArtifactVersionV1,
    pub object: ArtifactObjectId,
    pub seal: Option<ArtifactBlobSealV1>,
    pub state: ArtifactPublicationStateV1,
    pub installation_generation: SafeInteger,
    pub certificate: Option<SignedArtifactCertificateV1>,
    pub location: ProtectedText<128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_principal: Option<chio_security_types::PrincipalId>,
}
/// Audience-checked publication state. Private storage custody stays with the host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPublicationViewV1 {
    pub metadata: ArtifactVersionV1,
    pub state: ArtifactPublicationStateV1,
}
impl From<NativeArtifactRecordV1> for ArtifactPublicationViewV1 {
    fn from(record: NativeArtifactRecordV1) -> Self {
        Self {
            metadata: record.metadata,
            state: record.state,
        }
    }
}
macro_rules! protected_debug {
    ($($name:ident),+ $(,)?) => { $(impl std::fmt::Debug for $name {
        fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result { f.write_str(concat!(stringify!($name),"([redacted])")) }
    })+ };
}
protected_debug!(
    NativeKnowledgeInstallationV1,
    NativeKnowledgeRecipientV1,
    ArtifactPublicationInputV1,
    NativeArtifactRecordV1,
    ArtifactPublicationViewV1
);

fn refused(_error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    invariant("durable knowledge unavailable")
}
fn scope_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    protected::scope_key(scope)
}
fn profile_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!("knowledge-profile:{}", scope_key(scope)?))
}
fn physical_owner_key(
    profile: &NativeKnowledgeInstallationV1,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-owner:{}",
        sha256_hex(&protected::encode(&(
            profile.producer_context.as_v1().session_id(),
            &profile.scope.process_id,
        ))?)
    ))
}
fn publication_key(
    scope: &RecoveryScopeV1,
    principal: &chio_security_types::PrincipalId,
    id: &CommandId,
) -> Result<String, AdmissionOperationStoreError> {
    actor_request_key("knowledge-publication", scope, principal, id)
}

fn actor_request_key(
    namespace: &str,
    scope: &RecoveryScopeV1,
    principal: &chio_security_types::PrincipalId,
    request: &impl Serialize,
) -> Result<String, AdmissionOperationStoreError> {
    let actor = knowledge_digest(
        RecoveryDigestDomain::KnowledgeActorIdentity,
        &(scope, principal),
    )
    .map_err(refused)?;
    Ok(format!(
        "{namespace}:v2:{}:{}:{}",
        scope_key(scope)?,
        hex::encode(actor),
        sha256_hex(&protected::encode(request)?),
    ))
}

fn legacy_publication_key(
    scope: &RecoveryScopeV1,
    id: &CommandId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-publication:{}:{}",
        scope_key(scope)?,
        id.as_str()
    ))
}

fn record_publication_key(
    record: &NativeArtifactRecordV1,
) -> Result<String, AdmissionOperationStoreError> {
    match &record.publication_principal {
        Some(principal) => {
            publication_key(&record.metadata.scope, principal, &record.input.publication)
        }
        None => legacy_publication_key(&record.metadata.scope, &record.input.publication),
    }
}
fn version_key(reference: &ArtifactVersionRefV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "knowledge-version:{}",
        sha256_hex(&protected::encode(&(
            &reference.scope,
            &reference.artifact,
            &reference.version
        ))?)
    ))
}
fn load<T: serde::de::DeserializeOwned + Serialize>(
    tx: &Connection,
    key: &str,
) -> Result<Option<T>, AdmissionOperationStoreError> {
    protected::raw_checked(tx, key)?
        .map(|row| protected::decode(&row.payload))
        .transpose()
}
fn save<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    key: &str,
    value: &T,
) -> Result<(), AdmissionOperationStoreError> {
    protected::save(
        tx,
        owner,
        key,
        &scope_key(scope)?,
        "command",
        &protected::encode(value)?,
        None,
    )
}
pub(super) fn installation(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<NativeKnowledgeInstallationV1, AdmissionOperationStoreError> {
    load(tx, &profile_key(scope)?)?.ok_or_else(|| refused("profile"))
}

/// Structural historical profiles remain decodable. An actual recipient
/// selection must have finite clearance before new handles or delivery.
pub(super) fn require_finite_recipient(
    recipient: &ArtifactRecipientV1,
) -> Result<(), AdmissionOperationStoreError> {
    if recipient.clearance == InformationLabel::Top {
        return Err(refused("recipient clearance is unbounded"));
    }
    Ok(())
}
pub(super) fn artifact(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    let key: String = load(tx, &version_key(reference)?)?.ok_or_else(|| refused("version"))?;
    let record: NativeArtifactRecordV1 = load(tx, &key)?.ok_or_else(|| refused("record"))?;
    if record_publication_key(&record)? != key
        || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
        || record.state != ArtifactPublicationStateV1::Available
    {
        return Err(refused("unavailable"));
    }
    Ok(record)
}
pub(super) fn source(
    tx: &Transaction<'_>,
    binding: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    let key = recovery_flow_key(context);
    let (snapshot, _) = crate::security_state::observe_native_flow_state(
        tx,
        binding.security_authority_id().as_str(),
        &key,
    )
    .map_err(refused)?;
    let snapshot = snapshot.ok_or_else(|| refused("source absent"))?;
    snapshot
        .principal_label
        .join_restrictions(&snapshot.lineage_label)
        .and_then(|label| label.join_restrictions(&snapshot.session_label))
        .map_err(refused)
}

fn mutate<T>(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    fence: &StoreMutationFence,
    now: u64,
    apply: impl for<'a> FnOnce(
        Transaction<'a>,
        &NativeKnowledgeInstallationV1,
        u64,
    ) -> Result<(Transaction<'a>, T), AdmissionOperationStoreError>,
) -> Result<T, AdmissionOperationStoreError> {
    mutate_with_purpose(store, actor, fence, now, MutationPurpose::Execution, apply)
}

enum MutationPurpose {
    Execution,
    RetainedAdministration,
}

/// Fresh native storage authority does not renew an ended producer's execution.
fn mutate_retained_admin<T>(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    fence: &StoreMutationFence,
    now: u64,
    apply: impl for<'a> FnOnce(
        Transaction<'a>,
        &NativeKnowledgeInstallationV1,
        u64,
    ) -> Result<(Transaction<'a>, T), AdmissionOperationStoreError>,
) -> Result<T, AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::KnowledgeAdmin {
        return Err(refused("retained storage authority"));
    }
    mutate_with_purpose(
        store,
        actor,
        fence,
        now,
        MutationPurpose::RetainedAdministration,
        apply,
    )
}

fn validate_installation(
    tx: &Connection,
    recovery: &RecoveryDeploymentV1,
    profile: &NativeKnowledgeInstallationV1,
) -> Result<(), AdmissionOperationStoreError> {
    security_participant_state::verify_recovery_initialization(tx, &profile.native_authority)?;
    if load::<RecoveryScopeV1>(tx, &physical_owner_key(profile)?)?.as_ref() != Some(&profile.scope)
        || recovery.native_authority != profile.native_authority
        || recovery.policy_digest != profile.policy
        || recovery.scope != profile.scope
        || recovery_flow_key(&recovery.security_context)
            != recovery_flow_key(&profile.producer_context)
    {
        return Err(refused("current installation"));
    }
    Ok(())
}

fn mutate_with_purpose<T>(
    store: &SqliteAdmissionOperationStore,
    actor: &AuthenticatedRecoveryActor,
    fence: &StoreMutationFence,
    now: u64,
    purpose: MutationPurpose,
    apply: impl for<'a> FnOnce(
        Transaction<'a>,
        &NativeKnowledgeInstallationV1,
        u64,
    ) -> Result<(Transaction<'a>, T), AdmissionOperationStoreError>,
) -> Result<T, AdmissionOperationStoreError> {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let now = schema::authority_validation_time(&tx, now)?;
    let recovery = protected::deployment_tx(&tx, actor.scope())?;
    super::recovery::verify_actor(&tx, actor, &recovery, now)?;
    match purpose {
        MutationPurpose::Execution => super::setup::require_ready(&tx, actor.scope(), fence)?,
        MutationPurpose::RetainedAdministration => {
            if actor.permission() != RecoveryPermission::KnowledgeAdmin {
                return Err(refused("retained storage authority"));
            }
        }
    }
    let profile = installation(&tx, actor.scope())?;
    validate_installation(&tx, &recovery, &profile)?;
    let (tx, result) = apply(tx, &profile, now)?;
    let later = schema::authority_validation_time(&tx, now)?;
    super::recovery::verify_actor(&tx, actor, &recovery, later)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(result)
}

impl SqliteAdmissionOperationStore {
    /// Effect-free closure comparison against the current complete installation.
    /// This avoids recursively invoking the setup readiness gate it supports.
    pub fn validate_current_knowledge_installation(
        &self,
        expected: &NativeKnowledgeInstallationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        if expected.scope.authority_domain.as_str() != fence.store_uuid {
            return Err(refused("knowledge installation authority"));
        }
        let recovery = protected::deployment_tx(&tx, &expected.scope)?;
        let current = installation(&tx, &expected.scope)?;
        validate_installation(&tx, &recovery, &current)?;
        if protected::encode(&current)? != protected::encode(expected)? {
            return Err(refused("knowledge installation changed"));
        }
        tx.commit().map_err(sqlite_error)
    }

    /// Effect-free test inspection of protected product reference-owner rows.
    /// This does not establish retention eligibility or grant cleanup authority.
    #[cfg(feature = "admission-test-support")]
    pub fn inspect_product_evidence_owner_count(
        &self,
        reference: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<usize, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        if reference.scope.authority_domain.as_str() != fence.store_uuid {
            return Err(refused("reference owner authority"));
        }
        let count = references::active_product_evidence_owner_count(&tx, reference)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(count)
    }

    /// Complete host-selected profile. Removing recipients revokes future reads.
    pub fn configure_knowledge(
        &self,
        profile: &NativeKnowledgeInstallationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if profile.generation.get() == 0
            || profile.scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || profile.scope.tenant_id.as_str()
                != profile.producer_context.as_v1().tenant_id().as_str()
        {
            return Err(refused("profile scope"));
        }
        for (index, entry) in profile.recipients.as_slice().iter().enumerate() {
            let recipient = &entry.recipient;
            let context = entry.context.as_v1();
            require_finite_recipient(recipient)?;
            if recipient.scope != profile.scope
                || recipient.runtime.as_str() != context.session_id().as_str()
                || recipient.principal != *context.principal_id()
                || recipient.lineage.as_str() != context.lineage_root_id().as_str()
                || recipient.isolation_epoch.as_str() != context.isolation_epoch_id().as_str()
                || recipient.context_generation.get() != context.context_generation()
                || profile.recipients.as_slice()[..index]
                    .iter()
                    .any(|prior| prior.recipient.recipient == recipient.recipient)
            {
                return Err(refused("recipient binding"));
            }
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        security_participant_state::verify_recovery_initialization(&tx, &profile.native_authority)?;
        let physical_key = physical_owner_key(profile)?;
        let physical_owner = load::<RecoveryScopeV1>(&tx, &physical_key)?;
        if physical_owner
            .as_ref()
            .is_some_and(|owner| owner != &profile.scope)
        {
            return Err(refused(
                "physical process belongs to a different tenant scope",
            ));
        }
        if let Some(old) =
            load::<NativeKnowledgeInstallationV1>(&tx, &profile_key(&profile.scope)?)?
        {
            if protected::encode(&old)? == protected::encode(profile)? {
                if physical_owner.is_none() {
                    return Err(refused("physical process ownership absent"));
                }
                let _reference_delta = reference_activation::activate_installation_references(
                    &tx,
                    &self.serving_owner,
                    profile,
                )?;
                publication_capacity::activate_installation_publications(
                    &tx,
                    &self.serving_owner,
                    profile,
                )?;
                return self.commit_write(tx);
            }
            if profile.generation <= old.generation
                || profile.native_authority != old.native_authority
                || profile.certificate_root != old.certificate_root
                || profile.archive_root != old.archive_root
                || profile.classifier_implementation != old.classifier_implementation
                || profile.classifier_configuration != old.classifier_configuration
            {
                return Err(refused("generation"));
            }
        }
        if physical_owner.is_none() {
            save(
                &tx,
                &self.serving_owner,
                &profile.scope,
                &physical_key,
                &profile.scope,
            )?;
        }
        save(
            &tx,
            &self.serving_owner,
            &profile.scope,
            &profile_key(&profile.scope)?,
            profile,
        )?;
        save(
            &tx,
            &self.serving_owner,
            &profile.scope,
            &format!(
                "knowledge-runtime:{}",
                sha256_hex(
                    profile
                        .producer_context
                        .as_v1()
                        .session_id()
                        .as_str()
                        .as_bytes()
                )
            ),
            &true,
        )?;
        let _reference_delta = reference_activation::activate_installation_references(
            &tx,
            &self.serving_owner,
            profile,
        )?;
        publication_capacity::activate_installation_publications(
            &tx,
            &self.serving_owner,
            profile,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
    pub fn knowledge_installation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeKnowledgeInstallationV1, AdmissionOperationStoreError> {
        mutate(self, actor, fence, now, |tx, profile, _| {
            Ok((tx, profile.clone()))
        })
    }
    pub fn retained_knowledge_installation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeKnowledgeInstallationV1, AdmissionOperationStoreError> {
        mutate_retained_admin(self, actor, fence, now, |tx, profile, _| {
            Ok((tx, profile.clone()))
        })
    }
    /// Descriptive framing data. Effect capture independently recomputes the
    /// same scoped influence under its own writer and fresh authority checks.
    pub fn observe_knowledge_influence(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ArtifactInfluenceV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, scope)?;
        let result = {
            let current = security_participant_state::knowledge::CurrentNativeInfluenceAuthority::authenticate(
                &tx,
                &self.serving_owner,
                &deployment.native_authority,
            )?;
            current.observe(&recovery_flow_key(&deployment.security_context))?
        };
        tx.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}

pub(super) fn enforced(
    tx: &Connection,
    runtime: &str,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(load::<bool>(
        tx,
        &format!("knowledge-runtime:{}", sha256_hex(runtime.as_bytes())),
    )?
    .unwrap_or(false))
}
