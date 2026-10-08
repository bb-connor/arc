//! Distinct pin owners retain custody without interpreting caller text as authority.
use super::*;

#[cfg(feature = "admission-test-support")]
mod legacy_custody_test_support;

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PinOwner {
    Operator {
        principal: chio_security_types::PrincipalId,
        evidence: EvidenceRef,
    },
    NativeOperation {
        operation: OperationId,
    },
    PendingApproval {
        workflow: WorkflowId,
    },
}

impl PinOwner {
    fn namespace(&self) -> &'static str {
        match self {
            Self::Operator { .. } => "operator",
            Self::NativeOperation { .. } => "native-operation",
            Self::PendingApproval { .. } => "pending-approval",
        }
    }

    pub(super) fn key(
        &self,
        scope: &RecoveryScopeV1,
    ) -> Result<String, AdmissionOperationStoreError> {
        let identity = knowledge_digest(
            RecoveryDigestDomain::KnowledgeReferenceOwner,
            &(scope, self),
        )
        .map_err(refused)?;
        Ok(format!(
            "knowledge-pin:{}:v2:{}:{}",
            self.namespace(),
            scope_key(scope)?,
            hex::encode(identity),
        ))
    }
}

/// Authenticated modern custody data. Its active state is not caller selected.
pub(super) struct ModernPinSource {
    scope: RecoveryScopeV1,
    owner: PinOwner,
    reference: ArtifactVersionRefV1,
    active: bool,
    source: protected::ProtectedSourceReference,
}

impl ModernPinSource {
    pub(super) fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    pub(super) fn owner(&self) -> &PinOwner {
        &self.owner
    }
    pub(super) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.reference
    }
    pub(super) fn active(&self) -> bool {
        self.active
    }
    pub(super) fn source(&self) -> &protected::ProtectedSourceReference {
        &self.source
    }
}

pub(super) fn modern_reference_source(
    tx: &Connection,
    key: &str,
) -> Result<Option<ModernPinSource>, AdmissionOperationStoreError> {
    if ![
        "knowledge-pin:operator:v2:",
        "knowledge-pin:native-operation:v2:",
        "knowledge-pin:pending-approval:v2:",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
    {
        return Ok(None);
    }
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("modern pin disappeared"))?;
    let source = protected::source_reference(tx, key)?;
    let pin: PinRecord = protected::decode(&row.payload)?;
    if row.kind != "command"
        || row.scope != scope_key(&pin.scope)?
        || pin.reference.scope != pin.scope
        || pin.owner.key(&pin.scope)? != key
    {
        return Err(refused("modern pin source changed its purpose"));
    }
    validate_state(&pin)?;
    Ok(Some(ModernPinSource {
        scope: pin.scope,
        owner: pin.owner,
        reference: pin.reference,
        active: pin.state == PinState::Active,
        source,
    }))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRecord {
    schema: PinSchema,
    scope: RecoveryScopeV1,
    owner: PinOwner,
    reference: ArtifactVersionRefV1,
    #[serde(default, skip_serializing_if = "PinState::is_active")]
    state: PinState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retirement: Option<PinRetirement>,
}

#[derive(Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PinState {
    #[default]
    Active,
    Retired,
}

impl PinState {
    fn is_active(&self) -> bool {
        *self == Self::Active
    }
}

/// An administrative disposition records fresh storage authority. It cannot
/// authorize a native-operation or approval release, or revive this pin.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinRetirement {
    principal: chio_security_types::PrincipalId,
    installation_generation: SafeInteger,
    policy: PolicyDigest,
    retired_at: SafeInteger,
}

#[derive(Serialize, Deserialize)]
enum PinSchema {
    #[serde(rename = "chio.knowledge.pin.v1")]
    V1,
}

/// Only the owning native pin operation calls this after it has authenticated
/// the operator, captured operation or actual pending approval in this writer.
pub(super) fn retain(
    tx: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    owner: PinOwner,
    reference: &ArtifactVersionRefV1,
) -> Result<(), AdmissionOperationStoreError> {
    if reference.scope != *scope {
        return Err(refused("pin source changed its scope"));
    }
    let key = owner.key(scope)?;
    if let Some(existing) = load::<PinRecord>(tx, &key)? {
        if self::reference(tx, &key)?.as_ref() != Some(reference)
            || existing.scope != *scope
            || existing.owner != owner
            || existing.reference != *reference
        {
            return Err(refused("pin owner was rebound"));
        }
        return super::reference_custody::retain_pin_references(tx, serving_owner, &key);
    }
    save(
        tx,
        serving_owner,
        scope,
        &key,
        &PinRecord {
            schema: PinSchema::V1,
            scope: scope.clone(),
            owner,
            reference: reference.clone(),
            state: PinState::Active,
            retirement: None,
        },
    )?;
    super::reference_custody::retain_pin_references(tx, serving_owner, &key)
}

/// Historical flat pins remain conservative collection barriers. Their text
/// never supplies native-operation or approval authority to a new writer.
pub(super) fn reference(
    tx: &Connection,
    key: &str,
) -> Result<Option<ArtifactVersionRefV1>, AdmissionOperationStoreError> {
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("pin disappeared"))?;
    let source = protected::source_reference(tx, key)?;
    if row.kind != "command" || row.version == 0 {
        return Err(refused("pin protected identity changed"));
    }
    let typed = [
        "knowledge-pin:operator:v2:",
        "knowledge-pin:native-operation:v2:",
        "knowledge-pin:pending-approval:v2:",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix));
    if typed {
        let pin: PinRecord = protected::decode(&row.payload)?;
        if pin.scope != pin.reference.scope
            || row.scope != scope_key(&pin.scope)?
            || pin.owner.key(&pin.scope)? != key
        {
            return Err(refused("pin purpose changed"));
        }
        validate_state(&pin)?;
        return Ok((pin.state == PinState::Active).then_some(pin.reference));
    }
    let reference: Option<ArtifactVersionRefV1> = protected::decode(&row.payload)?;
    if !key.starts_with(&format!("knowledge-pin:{}:", row.scope)) {
        return Err(refused("historical pin source changed its scope"));
    }
    if let Some(reference) = &reference {
        let scope = scope_key(&reference.scope)?;
        if row.scope != scope || !key.starts_with(&format!("knowledge-pin:{scope}:")) {
            return Err(refused("historical pin scope changed"));
        }
    }
    // The closed predecessor writer never cleared or rebound a flat pin.
    // Matching only the first and current values would conceal A -> B -> A.
    // Authenticate every retained version without a lifetime scan ceiling.
    for version in 1..=source.version() {
        if !protected::matches_historical_source_command_payload(
            tx,
            &source,
            version,
            &row.payload,
        )? {
            return Err(refused("historical pin changed its original custody"));
        }
    }
    Ok(reference)
}

fn validate_state(pin: &PinRecord) -> Result<(), AdmissionOperationStoreError> {
    match (&pin.state, &pin.retirement, &pin.owner) {
        (PinState::Active, None, _) => Ok(()),
        (PinState::Retired, Some(retirement), PinOwner::Operator { principal, .. })
            if retirement.principal == *principal
                && retirement.installation_generation.get() != 0
                && retirement.retired_at.get() != 0 =>
        {
            Ok(())
        }
        _ => Err(refused("pin retirement changed its owner")),
    }
}

/// The caller has authenticated a current KnowledgeAdmin in this same fenced
/// writer. Only its own exact modern operator pin can enter a terminal state.
pub(super) fn retire_operator(
    tx: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    evidence: &EvidenceRef,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let owner = PinOwner::Operator {
        principal: actor.principal().clone(),
        evidence: evidence.clone(),
    };
    let key = owner.key(actor.scope())?;
    let previous = protected::source_reference(tx, &key)?;
    let row = protected::raw_checked(tx, &key)?.ok_or_else(|| refused("operator pin absent"))?;
    let mut pin: PinRecord = protected::decode(&row.payload)?;
    if previous.kind() != "command"
        || previous.scope_key() != scope_key(actor.scope())?
        || pin.owner != owner
        || pin.scope != *actor.scope()
        || pin.reference != *reference
        || pin.owner.key(&pin.scope)? != key
    {
        return Err(refused("operator pin retirement changed its exact source"));
    }
    validate_state(&pin)?;
    if pin.state == PinState::Retired {
        return Ok(());
    }
    pin.state = PinState::Retired;
    pin.retirement = Some(PinRetirement {
        principal: actor.principal().clone(),
        installation_generation: profile.generation,
        policy: profile.policy,
        retired_at: SafeInteger::new(now).map_err(refused)?,
    });
    protected::verify_source_reference(tx, &previous)?;
    save(tx, serving_owner, actor.scope(), &key, &pin)?;
    super::reference_retirement::retire_pin_references(tx, serving_owner, &key)
}
