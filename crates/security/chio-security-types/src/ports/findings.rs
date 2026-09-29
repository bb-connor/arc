use super::*;

pub const ATTESTED_FINDING_BATCH_SCHEMA_VERSION: u8 = 1;
pub const MAX_ATTESTED_FINDING_BATCH_SIZE: usize = 4_096;
pub const ATTESTED_FINDING_BATCH_ID_DOMAIN: &[u8] = b"chio.security.attested-finding-batch-id.v1\0";
pub const ATTESTED_FINDING_ACTION_ID_DOMAIN: &[u8] =
    b"chio.security.attested-finding-action-id.v1\0";
pub const ATTESTED_FINDING_RESERVATION_ID_DOMAIN: &[u8] =
    b"chio.security.attested-finding-reservation-id.v1\0";

/// One authoritative finding's durable identity in the response-planning
/// queue. Policy-specific response fields are deliberately absent. The
/// planning policy consumes this identity before it builds an executable
/// response plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchBinding {
    pub tenant_id: TenantId,
    pub evidence_id: OpaqueReceiptRef,
    pub finding_id: RecordId,
    pub finding_hash: Digest32,
    pub action_id: ActionId,
    pub reservation_id: RecordId,
}

pub type AttestedFindingBatchBindings =
    BoundedVec<AttestedFindingBatchBinding, MAX_ATTESTED_FINDING_BATCH_SIZE>;

/// Canonical crash-recovery body for one ordered planning publication.
///
/// `batch_id`, every `action_id`, and every `reservation_id` are derived from the
/// exact ordered authoritative finding identities. This assigns durable work
/// identities without inventing response effects, approval policy, TTL, or
/// operator authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchBody {
    pub schema_version: u8,
    pub batch_id: RecordId,
    pub tenant_id: TenantId,
    pub bindings: AttestedFindingBatchBindings,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchPublication {
    pub body: AttestedFindingBatchBody,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestedFindingBatchKey {
    pub tenant_id: TenantId,
    pub batch_id: RecordId,
}

#[cfg(feature = "std")]
fn attested_finding_derived_id(
    domain: &[u8],
    prefix: &str,
    components: &[&[u8]],
) -> PortResult<String> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        let length = u64::try_from(component.len()).map_err(|_| PortError::invalid_data())?;
        hasher.update(length.to_be_bytes());
        hasher.update(component);
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut suffix = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        suffix.push(char::from(HEX[usize::from(byte >> 4)]));
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(format!("{prefix}-{suffix}"))
}

/// Derive the idempotency key for one exact ordered finding batch.
#[cfg(feature = "std")]
pub fn derive_attested_finding_batch_id(
    ordered_evidence_ids: &[OpaqueReceiptRef],
) -> PortResult<RecordId> {
    if ordered_evidence_ids.is_empty()
        || ordered_evidence_ids.len() > MAX_ATTESTED_FINDING_BATCH_SIZE
    {
        return Err(PortError::invalid_data());
    }
    let mut unique = alloc::collections::BTreeSet::new();
    if ordered_evidence_ids
        .iter()
        .any(|evidence_id| !unique.insert(evidence_id))
    {
        return Err(PortError::invalid_data());
    }
    let components = ordered_evidence_ids
        .iter()
        .map(|evidence_id| evidence_id.as_str().as_bytes())
        .collect::<Vec<_>>();
    RecordId::new(attested_finding_derived_id(
        ATTESTED_FINDING_BATCH_ID_DOMAIN,
        "finding-batch",
        &components,
    )?)
    .map_err(PortError::from)
}

/// Derive the future response plan identity for one authoritative finding.
#[cfg(feature = "std")]
pub fn derive_attested_finding_action_id(
    batch_id: &RecordId,
    ordinal: usize,
    tenant_id: &TenantId,
    evidence_id: &OpaqueReceiptRef,
    finding_id: &RecordId,
    finding_hash: &Digest32,
) -> PortResult<ActionId> {
    let ordinal = u64::try_from(ordinal).map_err(|_| PortError::invalid_data())?;
    ActionId::new(attested_finding_derived_id(
        ATTESTED_FINDING_ACTION_ID_DOMAIN,
        "response-action",
        &[
            batch_id.as_str().as_bytes(),
            &ordinal.to_be_bytes(),
            tenant_id.as_str().as_bytes(),
            evidence_id.as_str().as_bytes(),
            finding_id.as_str().as_bytes(),
            finding_hash.as_bytes(),
        ],
    )?)
    .map_err(PortError::from)
}

/// Derive the planning reservation identity for one future response plan.
#[cfg(feature = "std")]
pub fn derive_attested_finding_reservation_id(
    batch_id: &RecordId,
    action_id: &ActionId,
    evidence_id: &OpaqueReceiptRef,
) -> PortResult<RecordId> {
    RecordId::new(attested_finding_derived_id(
        ATTESTED_FINDING_RESERVATION_ID_DOMAIN,
        "response-reservation",
        &[
            batch_id.as_str().as_bytes(),
            action_id.as_str().as_bytes(),
            evidence_id.as_str().as_bytes(),
        ],
    )?)
    .map_err(PortError::from)
}

/// Validate the exact 1:1 authoritative-finding, action, and reservation shape.
#[cfg(feature = "std")]
pub fn validate_attested_finding_batch_body(body: &AttestedFindingBatchBody) -> PortResult<()> {
    if body.schema_version != ATTESTED_FINDING_BATCH_SCHEMA_VERSION || body.bindings.is_empty() {
        return Err(PortError::invalid_data());
    }
    let ordered_evidence_ids = body
        .bindings
        .as_slice()
        .iter()
        .map(|binding| binding.evidence_id.clone())
        .collect::<Vec<_>>();
    if derive_attested_finding_batch_id(&ordered_evidence_ids)? != body.batch_id {
        return Err(PortError::integrity_failure());
    }
    let mut finding_ids = alloc::collections::BTreeSet::new();
    let mut action_ids = alloc::collections::BTreeSet::new();
    let mut reservation_ids = alloc::collections::BTreeSet::new();
    for (ordinal, binding) in body.bindings.as_slice().iter().enumerate() {
        if binding.tenant_id != body.tenant_id
            || binding.finding_hash == Digest32::new([0_u8; 32])
            || !finding_ids.insert((&binding.tenant_id, &binding.finding_id))
            || !action_ids.insert((&binding.tenant_id, &binding.action_id))
            || !reservation_ids.insert((&binding.tenant_id, &binding.reservation_id))
            || derive_attested_finding_action_id(
                &body.batch_id,
                ordinal,
                &binding.tenant_id,
                &binding.evidence_id,
                &binding.finding_id,
                &binding.finding_hash,
            )? != binding.action_id
            || derive_attested_finding_reservation_id(
                &body.batch_id,
                &binding.action_id,
                &binding.evidence_id,
            )? != binding.reservation_id
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(())
}

/// Crash-atomic publication ledger between authoritative correlation evidence
/// and the policy-specific response planning pipeline.
#[cfg(feature = "std")]
pub trait AttestedFindingBatchStore: Send + Sync {
    fn ensure_attested_finding_batches_ready(&self) -> PortResult<()>;
    fn publish_attested_finding_batch(
        &self,
        publication: &AttestedFindingBatchPublication,
    ) -> PortResult<CreateOutcome>;
    fn load_attested_finding_batch(
        &self,
        key: &AttestedFindingBatchKey,
    ) -> PortResult<Option<AttestedFindingBatchPublication>>;
}
