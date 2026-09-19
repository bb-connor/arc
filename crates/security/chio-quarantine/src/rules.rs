use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{Digest32, RecordId, RuleId};
use chio_security_types::{SecurityEventKind, SecuritySeverity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const RULE_HASH_DOMAIN: &[u8] = b"chio.temporal-rule.v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupingKey {
    AgentId,
    CapabilityId,
    LineageSeed,
    SessionId,
    SubjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleLimits {
    max_stages: usize,
    max_window_ms: u64,
    max_groups: u32,
    max_state_entries: u64,
}

impl RuleLimits {
    pub fn new(
        max_stages: usize,
        max_window_ms: u64,
        max_groups: u32,
        max_state_entries: u64,
    ) -> Result<Self, RuleError> {
        if max_stages == 0 || max_window_ms == 0 || max_groups == 0 || max_state_entries == 0 {
            return Err(RuleError::InvalidLimits);
        }
        Ok(Self {
            max_stages,
            max_window_ms,
            max_groups,
            max_state_entries,
        })
    }
}

impl Default for RuleLimits {
    fn default() -> Self {
        Self {
            max_stages: 32,
            max_window_ms: 86_400_000,
            max_groups: 1_024,
            max_state_entries: 65_536,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TemporalRuleDocument {
    rule_id: RuleId,
    policy_version: RecordId,
    group_by: GroupingKey,
    max_groups: u32,
    max_partial_matches_per_group: u32,
    allow_event_reuse: bool,
    stages: Vec<TemporalStageDocument>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TemporalStageDocument {
    name: RecordId,
    event_kind: SecurityEventKind,
    minimum_severity: SecuritySeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<RecordId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    within_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalStage {
    name: RecordId,
    event_kind: SecurityEventKind,
    minimum_severity: SecuritySeverity,
    predecessor_index: Option<usize>,
    within_ms: Option<u64>,
}

impl TemporalStage {
    #[must_use]
    pub const fn name(&self) -> &RecordId {
        &self.name
    }

    #[must_use]
    pub const fn event_kind(&self) -> SecurityEventKind {
        self.event_kind
    }

    #[must_use]
    pub const fn minimum_severity(&self) -> SecuritySeverity {
        self.minimum_severity
    }

    #[must_use]
    pub const fn predecessor_index(&self) -> Option<usize> {
        self.predecessor_index
    }

    #[must_use]
    pub const fn within_ms(&self) -> Option<u64> {
        self.within_ms
    }

    #[must_use]
    pub fn matches(&self, kind: SecurityEventKind, severity: SecuritySeverity) -> bool {
        self.event_kind == kind && severity >= self.minimum_severity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemporalRule {
    document: TemporalRuleDocument,
    stages: Vec<TemporalStage>,
    version_hash: Digest32,
    maximum_window_ms: u64,
}

impl TemporalRule {
    pub fn parse_json(bytes: &[u8], limits: &RuleLimits) -> Result<Self, RuleError> {
        let document: TemporalRuleDocument =
            serde_json::from_slice(bytes).map_err(RuleError::Parse)?;
        Self::from_document(document, limits)
    }

    fn from_document(
        document: TemporalRuleDocument,
        limits: &RuleLimits,
    ) -> Result<Self, RuleError> {
        if document.stages.is_empty() {
            return Err(RuleError::EmptyStages);
        }
        if document.stages.len() > limits.max_stages {
            return Err(RuleError::TooManyStages);
        }
        if document.max_groups == 0 || document.max_groups > limits.max_groups {
            return Err(RuleError::InvalidGroupBound);
        }
        if document.max_partial_matches_per_group == 0 {
            return Err(RuleError::InvalidPartialBound);
        }
        let stage_count =
            u64::try_from(document.stages.len()).map_err(|_| RuleError::StateEstimateOverflow)?;
        let state_estimate = u64::from(document.max_groups)
            .checked_mul(u64::from(document.max_partial_matches_per_group))
            .and_then(|value| value.checked_mul(stage_count))
            .ok_or(RuleError::StateEstimateOverflow)?;
        if state_estimate > limits.max_state_entries {
            return Err(RuleError::StateEstimateExceeded);
        }

        let mut prior_names = BTreeMap::<String, usize>::new();
        let mut stages = Vec::with_capacity(document.stages.len());
        let mut maximum_window_ms = 0_u64;
        for (index, stage) in document.stages.iter().enumerate() {
            if prior_names.contains_key(stage.name.as_str()) {
                return Err(RuleError::DuplicateStage);
            }
            let (predecessor_index, within_ms) = if index == 0 {
                if stage.after.is_some() || stage.within_ms.is_some() {
                    return Err(RuleError::InvalidFirstStageTiming);
                }
                (None, None)
            } else {
                let after = stage.after.as_ref().ok_or(RuleError::MissingPredecessor)?;
                let predecessor = prior_names
                    .get(after.as_str())
                    .copied()
                    .ok_or(RuleError::InvalidPredecessor)?;
                let window = stage.within_ms.ok_or(RuleError::MissingWindow)?;
                if window == 0 || window > limits.max_window_ms {
                    return Err(RuleError::InvalidWindow);
                }
                maximum_window_ms = maximum_window_ms.max(window);
                (Some(predecessor), Some(window))
            };
            prior_names.insert(stage.name.as_str().to_owned(), index);
            stages.push(TemporalStage {
                name: stage.name.clone(),
                event_kind: stage.event_kind,
                minimum_severity: stage.minimum_severity,
                predecessor_index,
                within_ms,
            });
        }

        let canonical = canonical_json_bytes(&document).map_err(|_| RuleError::Canonicalize)?;
        let mut hash_input = Vec::with_capacity(RULE_HASH_DOMAIN.len() + canonical.len());
        hash_input.extend_from_slice(RULE_HASH_DOMAIN);
        hash_input.extend_from_slice(&canonical);
        let version_hash = Digest32::new(*sha256(&hash_input).as_bytes());
        Ok(Self {
            document,
            stages,
            version_hash,
            maximum_window_ms,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RuleError> {
        canonical_json_bytes(&self.document).map_err(|_| RuleError::Canonicalize)
    }

    #[must_use]
    pub const fn rule_id(&self) -> &RuleId {
        &self.document.rule_id
    }

    #[must_use]
    pub const fn policy_version(&self) -> &RecordId {
        &self.document.policy_version
    }

    #[must_use]
    pub const fn group_by(&self) -> GroupingKey {
        self.document.group_by
    }

    #[must_use]
    pub const fn max_groups(&self) -> u32 {
        self.document.max_groups
    }

    #[must_use]
    pub const fn max_partial_matches_per_group(&self) -> u32 {
        self.document.max_partial_matches_per_group
    }

    #[must_use]
    pub const fn allow_event_reuse(&self) -> bool {
        self.document.allow_event_reuse
    }

    #[must_use]
    pub fn stages(&self) -> &[TemporalStage] {
        self.stages.as_slice()
    }

    #[must_use]
    pub const fn version_hash(&self) -> Digest32 {
        self.version_hash
    }

    #[must_use]
    pub const fn maximum_window_ms(&self) -> u64 {
        self.maximum_window_ms
    }
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("rule canonicalization failed")]
    Canonicalize,
    #[error("rule contains duplicate stage names")]
    DuplicateStage,
    #[error("rule has no stages")]
    EmptyStages,
    #[error("first stage has predecessor timing")]
    InvalidFirstStageTiming,
    #[error("rule grouping bound is invalid")]
    InvalidGroupBound,
    #[error("rule limits are invalid")]
    InvalidLimits,
    #[error("stage predecessor is unknown or not prior")]
    InvalidPredecessor,
    #[error("rule partial-match bound is invalid")]
    InvalidPartialBound,
    #[error("stage window is zero or exceeds the configured bound")]
    InvalidWindow,
    #[error("non-first stage is missing its predecessor")]
    MissingPredecessor,
    #[error("non-first stage is missing its window")]
    MissingWindow,
    #[error("rule JSON is invalid: {0}")]
    Parse(serde_json::Error),
    #[error("rule state estimate exceeds the configured limit")]
    StateEstimateExceeded,
    #[error("rule state estimate overflowed")]
    StateEstimateOverflow,
    #[error("rule exceeds the stage limit")]
    TooManyStages,
}
