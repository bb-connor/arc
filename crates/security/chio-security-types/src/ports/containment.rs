use super::identifiers::MAX_ID_BYTES;
# [cfg (feature = "std")]
use super::format;
use super::String;
use super::Deserialize;
use super::Serialize;
use super::Digest32;
use super::BoundedVec;
# [cfg (feature = "std")]
use super::sort_json_object_keys;
use super::EffectRequest;
use super::EffectResult;
use super::EffectResultQuery;
use super::EffectExecutionStatus;
use super::TenantScopedId;
use super::TenantId;
use super::RecordId;
use super::SessionId;
use super::ActionId;
use super::EffectId;
use super::PortError;
use super::PortResult;

pub const CONTAINMENT_TARGET_DOMAIN: &[u8] = b"chio.security.containment-target.v1\0";
pub const CONTAINMENT_OVERLAY_VERSION_DOMAIN: &[u8] = b"chio.response-effect-overlay-state.v1\0";
pub const CONTAINMENT_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-overlay-contribution.v1\0";
pub type OverlayContributions = BoundedVec<OverlayContribution, 256>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayContribution {
    pub effect_id: EffectId,
    pub posture_rank: u32,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentOverlayCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: OverlaySnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayApplyRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub contribution: OverlayContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: ContainmentOverlayCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayRemoveRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: ContainmentOverlayCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySnapshot {
    pub target: TenantScopedId,
    pub generation: u64,
    pub effective_posture_rank: u32,
    pub active_contributions: OverlayContributions,
    pub highest_fencing_token: u64,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContainmentOverlayVersionCommitment<'a> {
    schema_version: u8,
    target: &'a TenantScopedId,
    generation: u64,
    effective_posture_rank: u32,
    active_contributions: &'a OverlayContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContainmentInstalledContributionCommitment<'a> {
    schema_version: u8,
    target: &'a TenantScopedId,
    effect_id: &'a str,
    posture_rank: u32,
    contribution_hash: Digest32,
    expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentTargetKind {
    Session,
    Principal,
    Lineage,
    Capability,
}

impl ContainmentTargetKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Principal => "principal",
            Self::Lineage => "lineage",
            Self::Capability => "capability",
        }
    }
}

#[cfg(feature = "std")]
pub fn containment_target(
    tenant_id: &TenantId,
    kind: ContainmentTargetKind,
    authoritative_id: &str,
) -> PortResult<TenantScopedId> {
    use sha2::{Digest as _, Sha256};

    if authoritative_id.is_empty() || authoritative_id.len() > MAX_ID_BYTES {
        return Err(PortError::invalid_data());
    }
    let mut hasher = Sha256::new();
    hasher.update(CONTAINMENT_TARGET_DOMAIN);
    hasher.update(kind.as_str().as_bytes());
    hasher.update([0_u8]);
    hasher.update(authoritative_id.as_bytes());
    let digest = hasher.finalize();
    let mut target_hex = String::with_capacity(digest.len().saturating_mul(2));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        target_hex.push(char::from(HEX[usize::from(byte >> 4)]));
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        target_hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(TenantScopedId {
        tenant_id: tenant_id.clone(),
        id: RecordId::new(format!("{}-{target_hex}", kind.as_str())).map_err(PortError::from)?,
    })
}

#[cfg(feature = "std")]
pub fn containment_session_target(
    tenant_id: &TenantId,
    session_id: &SessionId,
) -> PortResult<TenantScopedId> {
    containment_target(
        tenant_id,
        ContainmentTargetKind::Session,
        session_id.as_str(),
    )
}

#[cfg(feature = "std")]
pub fn validate_containment_overlay_snapshot(
    snapshot: &OverlaySnapshot,
    expected_target: &TenantScopedId,
) -> PortResult<()> {
    if &snapshot.target != expected_target {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.active_contributions.as_slice();
    if contributions
        .array_windows::<2>()
        .any(|pair| pair[0].effect_id >= pair[1].effect_id)
    {
        return Err(PortError::integrity_failure());
    }
    let recomputed_posture = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let contribution_count =
        u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if recomputed_posture != snapshot.effective_posture_rank
        || (snapshot.effective_posture_rank == 0) != contributions.is_empty()
        || snapshot.generation < contribution_count
        || (!contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn containment_overlay_version_hash(snapshot: &OverlaySnapshot) -> PortResult<Digest32> {
    validate_containment_overlay_snapshot(snapshot, &snapshot.target)?;
    containment_domain_hash(
        CONTAINMENT_OVERLAY_VERSION_DOMAIN,
        &ContainmentOverlayVersionCommitment {
            schema_version: 1,
            target: &snapshot.target,
            generation: snapshot.generation,
            effective_posture_rank: snapshot.effective_posture_rank,
            active_contributions: &snapshot.active_contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn containment_installed_version_hash(
    target: &TenantScopedId,
    contribution: &OverlayContribution,
) -> PortResult<Digest32> {
    containment_domain_hash(
        CONTAINMENT_INSTALLED_CONTRIBUTION_DOMAIN,
        &ContainmentInstalledContributionCommitment {
            schema_version: 1,
            target,
            effect_id: contribution.effect_id.as_str(),
            posture_rank: contribution.posture_rank,
            contribution_hash: contribution.contribution_hash,
            expires_at_unix_ms: contribution.expires_at_unix_ms,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_containment_overlay_apply(
    current: &OverlaySnapshot,
    contribution: &OverlayContribution,
    scheduler_fencing_token: u64,
) -> PortResult<OverlaySnapshot> {
    validate_containment_overlay_snapshot(current, &current.target)?;
    let mut contributions = current.active_contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions
        .iter()
        .find(|entry| entry.effect_id == contribution.effect_id)
    {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let effective_posture_rank = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let snapshot = OverlaySnapshot {
        target: current.target.clone(),
        generation,
        effective_posture_rank,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_containment_overlay_snapshot(&snapshot, &current.target)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_containment_overlay_remove(
    current: &OverlaySnapshot,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<OverlaySnapshot> {
    validate_containment_overlay_snapshot(current, &current.target)?;
    let mut contributions = current.active_contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.effect_id != effect_id);
    let removed = contributions.len() != before;
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let effective_posture_rank = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let snapshot = OverlaySnapshot {
        target: current.target.clone(),
        generation,
        effective_posture_rank,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_containment_overlay_snapshot(&snapshot, &current.target)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
fn containment_domain_hash(domain: &[u8], commitment: &impl Serialize) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let mut value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    sort_json_object_keys(&mut value);
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

#[cfg(feature = "std")]
pub trait ContainmentOverlayStore: Send + Sync {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()>;
    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot>;
    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot>;
    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>>;
    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}
