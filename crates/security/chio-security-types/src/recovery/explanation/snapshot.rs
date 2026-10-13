use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationFactKind {
    Capability,
    Policy,
    DestinationAcl,
    AuthorityCoverage,
    Transformation,
    Prerequisite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationFactSource {
    NativeAuthority,
    ProcessJournal,
    OperatorRegistry,
    ProviderAcl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationIntegrity {
    NativeOwned,
    OperatorVerified,
    ProviderVerified,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationGap {
    Unavailable,
    NotConsulted,
    Unsupported,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExplanationFactTargetV1 {
    Intent {
        intent: IntentDigest,
    },
    Destination {
        destination: crate::ports::DestinationId,
    },
    Authority {
        scope: AuthorityScopeDigest,
    },
    Template {
        template: TemplateId,
    },
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExplanationFactStateV1 {
    Known {
        version: SafeInteger,
        evidence: EvidenceRef,
        satisfied: bool,
    },
    /// Evidence has an observed validity interval, without a source-owned
    /// version. Workflow revisions must never be substituted for one.
    FreshnessQualified {
        evidence: EvidenceRef,
        satisfied: bool,
    },
    Gap {
        reason: ExplanationGap,
    },
}

/// Each store/provider retains its own version and interval. Even equal
/// versions from different sources do not establish an atomic global snapshot.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryExplanationFactV1 {
    pub id: ObservationId,
    pub scope: RecoveryScopeV1,
    pub object: EvidenceRef,
    pub source: ExplanationFactSource,
    pub fact: ExplanationFactKind,
    pub target: ExplanationFactTargetV1,
    pub integrity: ExplanationIntegrity,
    pub label: InformationLabel,
    pub observed_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
    pub state: ExplanationFactStateV1,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExplanationInfluenceV1 {
    Observed {
        basis: SourceDigest,
        integrity: ExplanationIntegrity,
    },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoverySnapshotSchema {
    #[serde(rename = "chio.recovery.explanation-snapshot.v1")]
    V1,
}

/// Classified input facts. Context classification covers intent, native status,
/// constraints, scope, policy and influence, independently of hidden templates.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySnapshotV1 {
    pub schema: RecoverySnapshotSchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub deployment_digest: DeploymentDigest,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub intent_digest: IntentDigest,
    pub context_label: InformationLabel,
    pub influence: ExplanationInfluenceV1,
    pub observed_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
    pub effect: EffectObservationV1,
    pub observations: BoundedList<RecoveryExplanationFactV1, MAX_EXPLANATION_FACTS>,
}
impl RecoverySnapshotV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at_unix_ms <= self.observed_at_unix_ms
            || self.expires_at_unix_ms.get() - self.observed_at_unix_ms.get()
                > MAX_EXPLANATION_VALIDITY_MS
        {
            return Err(ContractError::InvalidState);
        }
        let mut ids = alloc::collections::BTreeSet::new();
        for fact in self.observations.as_slice() {
            fact.scope.ensure_matches(&self.scope)?;
            if !ids.insert(&fact.id) {
                return Err(ContractError::DuplicateIdentity);
            }
            if fact.observed_at_unix_ms > self.observed_at_unix_ms
                || fact.expires_at_unix_ms <= fact.observed_at_unix_ms
                || matches!(fact.state, ExplanationFactStateV1::Known { version, .. } if version == SafeInteger::ZERO)
            {
                return Err(ContractError::InvalidState);
            }
        }
        Ok(())
    }
    /// Canonical observation order without changing any source's version.
    pub fn normalized(&self) -> Result<Self, ContractError> {
        self.validate()?;
        let mut result = self.clone();
        let mut facts = self.observations.as_slice().to_vec();
        facts.sort_by(|a, b| a.id.cmp(&b.id));
        result.observations = BoundedList::new(facts)?;
        Ok(result)
    }
}
redacted!(
    RecoverySnapshotV1,
    RecoveryExplanationFactV1,
    ExplanationFactStateV1,
    ExplanationInfluenceV1,
    ExplanationFactTargetV1
);
