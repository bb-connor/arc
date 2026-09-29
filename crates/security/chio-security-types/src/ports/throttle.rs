use super::*;

pub const SESSION_THROTTLE_VERSION_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-state.v1\0";
pub const SESSION_THROTTLE_INSTALLED_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-contribution.v1\0";
pub const SESSION_THROTTLE_WINDOW_DOMAIN: &[u8] =
    b"chio.response-effect-session-throttle-window.v1\0";
pub const SESSION_THROTTLE_MAX_WINDOW_MS: u64 = 86_400_000;
pub const SESSION_THROTTLE_MAX_INVOCATIONS: u32 = 1_000_000;
pub type SessionThrottleContributions = BoundedVec<SessionThrottleContribution, 256>;
pub type SessionThrottleWindowUsages = BoundedVec<SessionThrottleWindowUsage, 256>;

/// Closed contribution body for a session throttle effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleLimits {
    pub window_ms: u64,
    pub max_invocations: u32,
}

impl SessionThrottleLimits {
    pub fn validate(self) -> PortResult<()> {
        if self.window_ms == 0
            || self.window_ms > SESSION_THROTTLE_MAX_WINDOW_MS
            || self.max_invocations == 0
            || self.max_invocations > SESSION_THROTTLE_MAX_INVOCATIONS
        {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleKey {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleContribution {
    pub effect_id: EffectId,
    pub limits: SessionThrottleLimits,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleSnapshot {
    pub key: SessionThrottleKey,
    pub generation: u64,
    pub contributions: SessionThrottleContributions,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: SessionThrottleSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleApplyRequest {
    pub key: SessionThrottleKey,
    pub action_id: ActionId,
    pub contribution: SessionThrottleContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: SessionThrottleCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleRemoveRequest {
    pub key: SessionThrottleKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: SessionThrottleCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleConsumeRequest {
    pub key: SessionThrottleKey,
    pub invocation_id: RecordId,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleWindowIdentity {
    pub window_id: RecordId,
    pub window_start_unix_ms: u64,
    pub window_end_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleWindowUsage {
    pub effect_id: EffectId,
    pub identity: SessionThrottleWindowIdentity,
    pub consumed_before: u32,
    pub consumed_after: u32,
    pub max_invocations: u32,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleDecision {
    pub key: SessionThrottleKey,
    pub allowed: bool,
    pub generation: u64,
    pub current_version_hash: Digest32,
    pub windows: SessionThrottleWindowUsages,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleVersionCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    generation: u64,
    contributions: &'a SessionThrottleContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    contribution: &'a SessionThrottleContribution,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleWindowCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    effect_id: &'a str,
    window_ms: u64,
    window_start_unix_ms: u64,
}

#[cfg(feature = "std")]
pub fn empty_session_throttle_snapshot(
    key: SessionThrottleKey,
) -> PortResult<SessionThrottleSnapshot> {
    let snapshot = SessionThrottleSnapshot {
        key,
        generation: 0,
        contributions: SessionThrottleContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    };
    validate_session_throttle_snapshot(&snapshot, &snapshot.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_session_throttle_snapshot(
    snapshot: &SessionThrottleSnapshot,
    expected_key: &SessionThrottleKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key
        || snapshot
            .contributions
            .as_slice()
            .array_windows::<2>()
            .any(|pair| pair[0].effect_id >= pair[1].effect_id)
    {
        return Err(PortError::integrity_failure());
    }
    for contribution in snapshot.contributions.as_slice() {
        contribution
            .limits
            .validate()
            .map_err(|_| PortError::integrity_failure())?;
        if contribution.expires_at_unix_ms == 0
            || contribution
                .contribution_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::integrity_failure());
        }
    }
    let count =
        u64::try_from(snapshot.contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < count
        || (!snapshot.contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn session_throttle_version_hash(snapshot: &SessionThrottleSnapshot) -> PortResult<Digest32> {
    validate_session_throttle_snapshot(snapshot, &snapshot.key)?;
    session_throttle_domain_hash(
        SESSION_THROTTLE_VERSION_DOMAIN,
        &SessionThrottleVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn session_throttle_installed_version_hash(
    key: &SessionThrottleKey,
    contribution: &SessionThrottleContribution,
) -> PortResult<Digest32> {
    contribution.limits.validate()?;
    if contribution.expires_at_unix_ms == 0
        || contribution
            .contribution_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::invalid_data());
    }
    session_throttle_domain_hash(
        SESSION_THROTTLE_INSTALLED_CONTRIBUTION_DOMAIN,
        &SessionThrottleInstalledCommitment {
            schema_version: 1,
            key,
            contribution,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_session_throttle_apply(
    current: &SessionThrottleSnapshot,
    contribution: &SessionThrottleContribution,
    scheduler_fencing_token: u64,
) -> PortResult<SessionThrottleSnapshot> {
    validate_session_throttle_snapshot(current, &current.key)?;
    contribution.limits.validate()?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
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
    let snapshot = SessionThrottleSnapshot {
        key: current.key.clone(),
        generation,
        contributions: SessionThrottleContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_session_throttle_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_session_throttle_remove(
    current: &SessionThrottleSnapshot,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<SessionThrottleSnapshot> {
    validate_session_throttle_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.effect_id != effect_id);
    let removed = before != contributions.len();
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let snapshot = SessionThrottleSnapshot {
        key: current.key.clone(),
        generation,
        contributions: SessionThrottleContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_session_throttle_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn session_throttle_window_identity(
    key: &SessionThrottleKey,
    effect_id: &EffectId,
    limits: SessionThrottleLimits,
    observed_at_unix_ms: u64,
) -> PortResult<SessionThrottleWindowIdentity> {
    limits.validate()?;
    let window_start_unix_ms = observed_at_unix_ms
        .checked_div(limits.window_ms)
        .and_then(|bucket| bucket.checked_mul(limits.window_ms))
        .ok_or_else(PortError::integrity_failure)?;
    let window_end_unix_ms = window_start_unix_ms
        .checked_add(limits.window_ms)
        .ok_or_else(PortError::integrity_failure)?;
    let digest = session_throttle_domain_hash(
        SESSION_THROTTLE_WINDOW_DOMAIN,
        &SessionThrottleWindowCommitment {
            schema_version: 1,
            key,
            effect_id: effect_id.as_str(),
            window_ms: limits.window_ms,
            window_start_unix_ms,
        },
    )?;
    Ok(SessionThrottleWindowIdentity {
        window_id: RecordId::new(format!(
            "session_throttle_window:{}",
            session_throttle_hex(digest.as_bytes())
        ))
        .map_err(PortError::from)?,
        window_start_unix_ms,
        window_end_unix_ms,
    })
}

#[cfg(feature = "std")]
fn session_throttle_domain_hash(
    domain: &[u8],
    commitment: &impl Serialize,
) -> PortResult<Digest32> {
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
fn session_throttle_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        #[allow(clippy::indexing_slicing, reason = "The masked nibble is in 0..16 and HEX has exactly 16 entries.")]
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(feature = "std")]
pub trait SessionThrottleStore: Send + Sync {
    fn ensure_session_throttles_ready(&self) -> PortResult<()>;
    fn apply_session_throttle(
        &self,
        request: &SessionThrottleApplyRequest,
    ) -> PortResult<SessionThrottleSnapshot>;
    fn remove_session_throttle(
        &self,
        request: &SessionThrottleRemoveRequest,
    ) -> PortResult<SessionThrottleSnapshot>;
    fn load_session_throttles(
        &self,
        key: &SessionThrottleKey,
    ) -> PortResult<Option<SessionThrottleSnapshot>>;
    fn consume_session_invocation(
        &self,
        request: &SessionThrottleConsumeRequest,
    ) -> PortResult<SessionThrottleDecision>;
    fn load_session_throttle_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus>;
}
