//! Distinct pin owners retain custody without interpreting caller text as authority.
use super::*;

#[cfg(feature = "admission-test-support")]
mod test_support;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
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

/// Authenticated custody data. Its active state is not caller selected.
pub(super) struct PinSource {
    scope: RecoveryScopeV1,
    owner: PinOwner,
    reference: ArtifactVersionRefV1,
    active: bool,
}

impl PinSource {
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
}

pub(super) fn reference_source(
    tx: &Connection,
    key: &str,
) -> Result<Option<PinSource>, AdmissionOperationStoreError> {
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
    let row = protected::raw_checked(tx, key)?.ok_or_else(|| refused("pin disappeared"))?;
    protected::source_reference(tx, key)?;
    let pin: PinRecord = protected::decode(&row.payload)?;
    if row.kind != "command"
        || row.scope != scope_key(&pin.scope)?
        || pin.reference.scope != pin.scope
        || pin.owner.key(&pin.scope)? != key
    {
        return Err(refused("pin source changed its purpose"));
    }
    validate_state(&pin)?;
    Ok(Some(PinSource {
        scope: pin.scope,
        owner: pin.owner,
        reference: pin.reference,
        active: pin.state == PinState::Active,
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
/// The pin row goes through the typed intake; its one reference owner is
/// charged to the tenant account by the existing custody writer.
pub(super) fn retain(
    tx: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    now: u64,
    owner: PinOwner,
    reference: &ArtifactVersionRefV1,
) -> Result<(), AdmissionOperationStoreError> {
    if let Some(intake) = super::intake::AuthenticatedKnowledgeIntakeSource::pin_retain(
        tx, actor, profile, now, &owner, reference,
    )? {
        protected::persist_knowledge_intake(tx, serving_owner, intake)?;
    }
    super::reference_custody::retain_pin_references(tx, serving_owner, &owner.key(actor.scope())?)
}

/// The new pin row of an owner, or none when that exact pin is retained. A
/// retained pin bound to anything else refuses.
pub(super) fn derive_retain(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    owner: &PinOwner,
    reference: &ArtifactVersionRefV1,
) -> Result<Option<DerivedWrite>, AdmissionOperationStoreError> {
    if reference.scope != *scope {
        return Err(refused("pin source changed its scope"));
    }
    let key = owner.key(scope)?;
    if let Some(existing) = load::<PinRecord>(tx, &key)? {
        if self::reference(tx, &key)?.as_ref() != Some(reference)
            || existing.scope != *scope
            || existing.owner != *owner
            || existing.reference != *reference
        {
            return Err(refused("pin owner was rebound"));
        }
        return Ok(None);
    }
    Ok(Some(DerivedWrite {
        payload: protected::encode(&PinRecord {
            schema: PinSchema::V1,
            scope: scope.clone(),
            owner: owner.clone(),
            reference: reference.clone(),
            state: PinState::Active,
            retirement: None,
        })?,
        key,
        scope_key: scope_key(scope)?,
        expected: None,
    }))
}

/// Resolve active custody through the authenticated typed pin reader.
pub(super) fn reference(
    tx: &Connection,
    key: &str,
) -> Result<Option<ArtifactVersionRefV1>, AdmissionOperationStoreError> {
    let pin = reference_source(tx, key)?.ok_or_else(|| refused("unsupported pin source"))?;
    Ok(pin.active.then_some(pin.reference))
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

/// The actor's own exact Active operator pin and its one canonical terminal
/// successor, derived from the current authenticated record. An already
/// retired pin has no pending closure.
pub(super) struct PendingOperatorRetirement {
    pub(super) key: String,
    pub(super) head: protected::ProtectedSourceReference,
    pub(super) successor: Vec<u8>,
}

pub(super) fn pending_operator_retirement(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    evidence: &EvidenceRef,
    now: u64,
) -> Result<Option<PendingOperatorRetirement>, AdmissionOperationStoreError> {
    let owner = PinOwner::Operator {
        principal: actor.principal().clone(),
        evidence: evidence.clone(),
    };
    let key = owner.key(actor.scope())?;
    let head = protected::source_reference(tx, &key)?;
    let row = protected::raw_checked(tx, &key)?.ok_or_else(|| refused("operator pin absent"))?;
    let mut pin: PinRecord = protected::decode(&row.payload)?;
    if head.kind() != "command"
        || head.scope_key() != scope_key(actor.scope())?
        || pin.owner != owner
        || pin.scope != *actor.scope()
        || pin.reference != *reference
        || pin.owner.key(&pin.scope)? != key
    {
        return Err(refused("operator pin retirement changed its exact source"));
    }
    validate_state(&pin)?;
    if pin.state == PinState::Retired {
        return Ok(None);
    }
    pin.state = PinState::Retired;
    pin.retirement = Some(PinRetirement {
        principal: actor.principal().clone(),
        installation_generation: profile.generation,
        policy: profile.policy,
        retired_at: SafeInteger::new(now).map_err(refused)?,
    });
    validate_state(&pin)?;
    Ok(Some(PendingOperatorRetirement {
        key,
        head,
        successor: protected::encode(&pin)?,
    }))
}

/// The caller has authenticated a current KnowledgeAdmin in this same fenced
/// writer. Only its own exact operator pin can enter a terminal state, through
/// the prepared closure. An already retired pin writes and refunds nothing.
pub(super) fn retire_operator(
    tx: &Transaction<'_>,
    serving_owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    reference: &ArtifactVersionRefV1,
    evidence: &EvidenceRef,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    match super::closure::PreparedKnowledgeClosure::operator_pin_retirement(
        tx, actor, profile, reference, evidence, now,
    )? {
        Some(closure) => closure.settle(tx, serving_owner),
        None => Ok(()),
    }
}
