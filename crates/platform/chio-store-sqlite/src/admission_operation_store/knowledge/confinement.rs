//! Confined lifecycle records and observations share the existing native writer.
use super::*;
use chio_core::capability::token::CapabilityToken;
use chio_security_types::confinement::*;

mod cancellation;
mod context;
mod identity;
mod launch;
mod reference_source;
mod returns;
pub use cancellation::NativeConfinedCancellation;
pub(in crate::admission_operation_store::knowledge) use reference_source::{
    input_reference_source, ConfinedInputReferenceSource,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfinedInstallationV1 {
    pub scope: RecoveryScopeV1,
    pub generation: SafeInteger,
    pub contract: ReturnContractV1,
    pub execution: ConfinedExecutionProfileV1,
    pub limits: ConfinedLimitsV1,
    pub disclosure_root: PublicKey,
    pub endorsement_root: PublicKey,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfinedReservationV1 {
    pub boundary: IsolationBoundaryV1,
    pub child_context: SecurityInvocationContext,
    pub state: IsolationStateV1,
}
pub struct ConfinedChildReservationInput<'a> {
    pub request: &'a RequestId,
    pub parent: &'a CapabilityToken,
    pub child: &'a CapabilityToken,
    pub seeds: &'a [ArtifactVersionRefV1],
    pub observation: &'a ArtifactVersionRefV1,
}
pub struct ConfinedReturnAdmissionInput<'a> {
    pub request: &'a RequestId,
    pub seal: &'a ArtifactBlobSealV1,
    pub parent: &'a ArtifactRecipientV1,
    pub disclosure: Option<&'a SignedConfinedDisclosureV1>,
    pub endorsement: Option<&'a SignedConfinedEndorsementV1>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryRecord {
    reservation: NativeConfinedReservationV1,
    #[serde(default, skip_serializing_if = "stop_not_requested")]
    stop_requested: bool,
    installation: NativeConfinedInstallationV1,
    initiator: CapabilityToken,
    initiating_principal: chio_security_types::PrincipalId,
    parent_capability: CapabilityToken,
    child_capability: CapabilityToken,
    prepared: Option<CageMeasurementDigest>,
    prepared_profile: Option<CageMeasurementDigest>,
    launch: Option<CanonicalPayloadDigest>,
    enforcement: Option<chio_cage::FullyEnforcedEvidence>,
    terminal: Option<chio_cage::CageEnforcementRecord>,
    input_packet: Option<CanonicalPayloadDigest>,
    expected_return: Option<CanonicalPayloadDigest>,
    observation_release: Option<ArtifactReleaseIntentV1>,
    return_seal: Option<ArtifactBlobSealV1>,
    return_artifact: Option<ArtifactVersionRefV1>,
    return_metadata: Option<ArtifactVersionV1>,
    return_admission: Option<ReturnAdmissionV1>,
    return_authority: Option<ConfinedCapabilityDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    return_origin: Option<returns::OriginalReturnOrigin>,
}
impl core::fmt::Debug for NativeConfinedInstallationV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeConfinedInstallationV1([redacted])")
    }
}
impl core::fmt::Debug for NativeConfinedReservationV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NativeConfinedReservationV1([redacted])")
    }
}

fn key(
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "confined-boundary:{}:{}",
        scope_key(scope)?,
        request.as_str()
    ))
}
fn config_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!("confined-profile:{}", scope_key(scope)?))
}
fn capability_digest(
    cap: &CapabilityToken,
) -> Result<ConfinedCapabilityDigest, AdmissionOperationStoreError> {
    confined_capability_digest(cap).map_err(refused)
}
fn current(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<NativeConfinedInstallationV1, AdmissionOperationStoreError> {
    load(tx, &config_key(scope)?)?.ok_or_else(|| refused("confined profile"))
}
/// Return the exact configured profile for a pure setup inventory. This
/// authenticates retained configuration, not launch or disclosure authority.
pub(in crate::admission_operation_store) fn setup_confinement_inventory(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<Option<NativeConfinedInstallationV1>, AdmissionOperationStoreError> {
    let record_key = config_key(scope)?;
    let Some(row) = protected::raw_checked(tx, &record_key)? else {
        return Ok(None);
    };
    let source = protected::source_reference(tx, &record_key)?;
    if row.scope != scope_key(scope)? || row.kind != "command" || row.version == 0 {
        return Err(refused("confined setup profile envelope"));
    }
    if source.scope_key() != row.scope
        || source.kind() != row.kind
        || source.version() != row.version
    {
        return Err(refused("confined setup source binding"));
    }
    let profile: NativeConfinedInstallationV1 = protected::decode(&row.payload)?;
    profile.contract.validate().map_err(refused)?;
    profile.limits.validate().map_err(refused)?;
    if profile.scope != *scope
        || profile.contract.parent.scope != *scope
        || profile.generation.get() == 0
        || profile.disclosure_root == profile.endorsement_root
        || profile.contract.schema != knowledge_content_digest(CONFINED_BOOLEAN_SCHEMA)
        || profile.contract.implementation
            != knowledge_content_digest(CONFINED_BOOLEAN_IMPLEMENTATION)
        || !matches!(profile.contract.parent.sink, ArtifactSinkV1::Agent)
    {
        return Err(refused("confined setup profile binding"));
    }
    Ok(Some(profile))
}
fn record(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    request: &RequestId,
) -> Result<BoundaryRecord, AdmissionOperationStoreError> {
    load(tx, &key(scope, request)?)?.ok_or_else(|| refused("confined boundary"))
}
fn retain(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &BoundaryRecord,
) -> Result<(), AdmissionOperationStoreError> {
    save(
        tx,
        owner,
        &record.reservation.boundary.scope,
        &key(
            &record.reservation.boundary.scope,
            &record.reservation.boundary.request,
        )?,
        record,
    )
}
fn stop_not_requested(requested: &bool) -> bool {
    !*requested
}

fn validate_current(
    tx: &Connection,
    record: &BoundaryRecord,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    if record.stop_requested {
        return Err(refused("confined stop requested"));
    }
    validate_current_authority(tx, record, profile, now)
}

// Exact identity replay retains current authority checks without issuing any
// launch, input or return admission. Fresh operations also require no stop.
fn validate_current_authority(
    tx: &Connection,
    record: &BoundaryRecord,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let boundary = &record.reservation.boundary;
    if protected::encode(&record.installation)?
        != protected::encode(&current(tx, &boundary.scope)?)?
        || boundary.policy != profile.policy
        || boundary.parent != record.installation.contract.parent
        || profile.producer_context.as_v1().principal_id().as_str()
            != record.parent_capability.subject.to_hex()
        || now >= record.installation.contract.expires_at_unix_ms.get()
    {
        return Err(refused("confined current authority"));
    }
    context::verify_retained(tx, record, now)?;
    Ok(())
}

/// Resolve the current parent restrictions before private boundary or state
/// lookup. A withdrawn preview cannot distinguish classified lifecycle work.
fn require_parent_source_audience(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    let label = source(tx, &profile.native_authority, &profile.producer_context)?;
    traversal::ensure_audience(tx, actor, &label)?;
    Ok(label)
}

/// Every retained control seed and observed dependency contributes to the
/// audience. Resolving labels grants no bytes, recipient or execution right.
fn require_input_source_audience(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    parent: InformationLabel,
    boundary: &IsolationBoundaryV1,
) -> Result<InformationLabel, AdmissionOperationStoreError> {
    if boundary.scope != *actor.scope() {
        return Err(refused("input audience scope"));
    }
    let retained = parent
        .join_restrictions(&boundary.seed_label)
        .map_err(refused)?;
    traversal::ensure_audience(tx, actor, &retained)?;
    let mut roots = boundary.seed_artifacts.as_slice().to_vec();
    roots.push(boundary.observation.clone());
    let dependencies = traversal::dependencies(tx, actor.scope(), &roots)?;
    let input = traversal::join_metadata(retained, &dependencies)?;
    traversal::ensure_audience(tx, actor, &input)?;
    Ok(input)
}

/// Check live child observations and retained artifact classification before
/// processing values, exits or returning rich evidence and admission metadata.
fn require_child_source_audience(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    record: &BoundaryRecord,
    input: InformationLabel,
) -> Result<(), AdmissionOperationStoreError> {
    let observed = source(
        tx,
        &profile.native_authority,
        &record.reservation.child_context,
    )?;
    let mut label = input.join_restrictions(&observed).map_err(refused)?;
    if let Some(metadata) = &record.return_metadata {
        label = label.join_restrictions(&metadata.label).map_err(refused)?;
    }
    traversal::ensure_audience(tx, actor, &label)
}
impl SqliteAdmissionOperationStore {
    /// Operator-only installation. A stripped/rotated profile invalidates pending
    /// releases; it never removes retained ownership or consumed resources.
    pub fn configure_confinement(
        &self,
        installation: &NativeConfinedInstallationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        installation.contract.validate().map_err(refused)?;
        installation.limits.validate().map_err(refused)?;
        super::require_finite_recipient(&installation.contract.parent)?;
        if installation.scope != installation.contract.parent.scope
            || installation.generation.get() == 0
            || installation.disclosure_root == installation.endorsement_root
            || installation.contract.schema != knowledge_content_digest(CONFINED_BOOLEAN_SCHEMA)
            || installation.contract.implementation
                != knowledge_content_digest(CONFINED_BOOLEAN_IMPLEMENTATION)
            || !matches!(installation.contract.parent.sink, ArtifactSinkV1::Agent)
        {
            return Err(refused("confined installation"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, None)?;
        let profile = super::installation(&tx, &installation.scope)?;
        let deployment = protected::deployment_tx(&tx, &installation.scope)?;
        security_participant_state::verify_recovery_initialization(&tx, &profile.native_authority)?;
        if profile.policy != installation.contract.policy
            || deployment.policy_digest != profile.policy
            || !profile
                .recipients
                .as_slice()
                .iter()
                .any(|r| r.recipient == installation.contract.parent)
            || !installation
                .contract
                .target
                .flows_to(&installation.contract.parent.clearance)
        {
            return Err(refused("confined recipient"));
        }
        if let Some(old) =
            load::<NativeConfinedInstallationV1>(&tx, &config_key(&installation.scope)?)?
        {
            if protected::encode(&old)? == protected::encode(installation)? {
                return self.commit_write(tx);
            }
            if installation.generation <= old.generation {
                return Err(refused("confined generation"));
            }
        }
        save(
            &tx,
            &self.serving_owner,
            &installation.scope,
            &config_key(&installation.scope)?,
            installation,
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }

    /// The host supplies exact signed parent/child capabilities. The authority
    /// allocates all boundary/process/lineage/epoch IDs and accounts once.
    pub fn reserve_confined_child(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: ConfinedChildReservationInput<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeConfinedReservationV1, AdmissionOperationStoreError> {
        let ConfinedChildReservationInput {
            request,
            parent,
            child,
            seeds,
            observation,
        } = input;
        if actor.permission() != RecoveryPermission::ConfinedLaunch || seeds.len() > 8 {
            return Err(refused("launch authority"));
        }
        context::validate_delegation(parent, child)?;
        mutate(self, actor, fence, now, |tx, profile, now| {
            // Parent-selected input and the complete reservation response remain
            // classified. Refuse before resolving a private boundary or slot.
            let parent_label = source(&tx, &profile.native_authority, &profile.producer_context)?;
            traversal::ensure_audience(&tx, actor, &parent_label)?;
            let installation = current(&tx, actor.scope())?;
            let parent_digest = capability_digest(parent)?;
            let child_digest = capability_digest(child)?;
            if let Some(old) = load::<BoundaryRecord>(&tx, &key(actor.scope(), request)?)? {
                // A matched replay recovers the existing terminal identity.
                // The caller cannot use it to reopen stopped observation.
                validate_current_authority(&tx, &old, profile, now)?;
                let b = &old.reservation.boundary;
                if b.parent_capability != parent_digest
                    || b.child_capability != child_digest
                    || b.seed_artifacts.as_slice() != seeds
                    || b.observation != *observation
                    || capability_digest(&old.initiator)? != capability_digest(actor.capability())?
                {
                    return Err(refused("spawn conflict"));
                }
                // Exact replay recovers identity, not permission to bypass a
                // newly withdrawn audience or an input's retained source join.
                let source_label = parent_label
                    .join_restrictions(&b.seed_label)
                    .map_err(refused)?;
                traversal::ensure_audience(&tx, actor, &source_label)?;
                let mut roots = seeds.to_vec();
                roots.push(observation.clone());
                let dependencies = traversal::dependencies(&tx, actor.scope(), &roots)?;
                let input_label = traversal::join_metadata(source_label, &dependencies)?;
                traversal::ensure_audience(&tx, actor, &input_label)?;
                super::reference_custody::retain_confined_input_references(
                    &tx,
                    &self.serving_owner,
                    &key(actor.scope(), request)?,
                )?;
                return Ok((tx, old.reservation));
            }
            if parent.subject.to_hex() != profile.producer_context.as_v1().principal_id().as_str()
                || parent.issuer != actor.capability().issuer
                || !parent.delegation_chain.is_empty()
                || !child.scope.grants.is_empty()
                || !child.scope.resource_grants.is_empty()
                || !child.scope.prompt_grants.is_empty()
                || child.subject == parent.subject
                || child.budget_share_bps != Some(625)
            {
                return Err(refused("root confined delegation"));
            }
            let rows = traversal::dependencies(&tx, actor.scope(), seeds)?;
            let observed =
                traversal::dependencies(&tx, actor.scope(), core::slice::from_ref(observation))?;
            let seed_label = traversal::join_metadata(parent_label, &rows)?;
            let input_label = traversal::join_metadata(seed_label.clone(), &observed)?;
            traversal::ensure_audience(&tx, actor, &input_label)?;
            let size = rows.iter().chain(&observed).try_fold(0u64, |total, r| {
                total
                    .checked_add(r.metadata.size_bytes.get())
                    .ok_or_else(|| refused("input overflow"))
            })?;
            if size > installation.limits.input_bytes.get() {
                return Err(refused("input bound"));
            }
            let counter_key = format!("confined-count:{}", scope_key(actor.scope())?);
            let count = load::<u64>(&tx, &counter_key)?.unwrap_or(0);
            if count >= installation.limits.children.get() {
                return Err(refused("child bound"));
            }
            let seed_influence = traversal::influence(
                &tx,
                &profile.native_authority,
                &profile.producer_context,
                &rows,
                false,
            )?;
            context::require_unobserved_principal(&tx, profile, child)?;
            let id = uuid::Uuid::new_v4().to_string();
            let child_id = ProcessId::new(&format!("confined_{id}")).map_err(refused)?;
            let lineage = IsolationLineageId::new(&format!("confined:{id}")).map_err(refused)?;
            let epoch = ProtectedText::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?;
            let context = context::make(profile, child, &lineage, &epoch)?;
            let boundary = IsolationBoundaryV1 {
                domain_version: VersionV1,
                boundary: EvidenceRef::new(&id).map_err(refused)?,
                request: request.clone(),
                scope: actor.scope().clone(),
                parent_capability: parent_digest,
                parent: installation.contract.parent.clone(),
                child: child_id,
                child_principal: context.as_v1().principal_id().clone(),
                child_capability: child_digest,
                ancestry: NonEmptyBoundedList::new(vec![actor.scope().process_id.clone()])
                    .map_err(refused)?,
                lineage,
                isolation_epoch: epoch,
                seed_artifacts: BoundedList::new(seeds.to_vec()).map_err(refused)?,
                observation: observation.clone(),
                parent_control: CanonicalPayloadDigest::from_bytes(
                    knowledge_digest(
                        RecoveryDigestDomain::ConfinedParentControl,
                        &(
                            request,
                            seeds,
                            observation,
                            &installation.contract.contract,
                            &profile.producer_context,
                            &seed_label,
                            &seed_influence,
                        ),
                    )
                    .map_err(refused)?,
                ),
                seed_label,
                seed_influence,
                execution: installation.execution.clone(),
                return_contract: installation.contract.contract,
                limits: installation.limits.clone(),
                deadline_unix_ms: SafeInteger::new(
                    now.checked_add(installation.limits.wall_clock_ms.get())
                        .ok_or_else(|| refused("deadline"))?,
                )
                .map_err(refused)?,
                policy: profile.policy,
            };
            boundary.validate().map_err(refused)?;
            let record = BoundaryRecord {
                stop_requested: false,
                reservation: NativeConfinedReservationV1 {
                    boundary,
                    child_context: context,
                    state: IsolationStateV1::Reserved,
                },
                installation,
                initiator: actor.capability().clone(),
                initiating_principal: actor.principal().clone(),
                parent_capability: parent.clone(),
                child_capability: child.clone(),
                prepared: None,
                prepared_profile: None,
                launch: None,
                enforcement: None,
                terminal: None,
                input_packet: None,
                expected_return: None,
                observation_release: None,
                return_seal: None,
                return_artifact: None,
                return_metadata: None,
                return_admission: None,
                return_authority: None,
                return_origin: None,
            };
            validate_current(&tx, &record, profile, now)?;
            identity::require_unused(&tx, actor.scope(), child)?;
            let cap_key = identity::capability_key(actor.scope(), child)?;
            let token_key = identity::token_key(child)?;
            let principal_key = format!(
                "confined-principal:{}:{}",
                scope_key(actor.scope())?,
                sha256_hex(child.subject.to_hex().as_bytes())
            );
            if load::<String>(&tx, &principal_key)?.is_some() {
                return Err(refused("child principal reused"));
            }
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &cap_key,
                &key(actor.scope(), request)?,
            )?;
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &token_key,
                &key(actor.scope(), request)?,
            )?;
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &principal_key,
                &key(actor.scope(), request)?,
            )?;
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &counter_key,
                &(count + 1),
            )?;
            // Native reservations permanently pin original immutable inputs.
            // The separate process/blob journal cannot collect them on restart.
            for (i, reference) in seeds
                .iter()
                .chain(core::iter::once(observation))
                .enumerate()
            {
                save(
                    &tx,
                    &self.serving_owner,
                    actor.scope(),
                    &format!(
                        "knowledge-pin:{}:confined:{}:{i}",
                        scope_key(actor.scope())?,
                        record.reservation.boundary.boundary.as_str()
                    ),
                    &Some(reference.clone()),
                )?;
            }
            retain(&tx, &self.serving_owner, &record)?;
            super::reference_custody::retain_confined_input_references(
                &tx,
                &self.serving_owner,
                &key(actor.scope(), request)?,
            )?;
            Ok((tx, record.reservation))
        })
    }
}
