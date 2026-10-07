use super::*;
use crate::ports::DestinationId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationRemedyKind {
    ExistingDestination,
    ExactApproval,
    Transformation,
    Prerequisite,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationLatencyClass {
    Local,
    Remote,
    Unspecified,
}

/// Estimates retain provenance and never reserve budget or promise completion.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationCostV1 {
    pub approvals: SafeInteger,
    pub irreversible_effects: SafeInteger,
    pub budget_units: SafeInteger,
    pub latency: ExplanationLatencyClass,
    pub evidence: EvidenceRef,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRemedyTemplateV1 {
    pub template_id: TemplateId,
    pub kind: ExplanationRemedyKind,
    pub family: ContractDigest,
    pub authority_scope: AuthorityScopeDigest,
    pub destination: DestinationId,
    pub disclosure_label: InformationLabel,
    pub classification: InformationLabel,
    pub satisfies_task: bool,
    pub requires_integrity: bool,
    pub cost: ExplanationCostV1,
    pub requirements: NonEmptyBoundedList<ObservationId, MAX_EXPLANATION_DEPENDENCIES>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryRemedyRegistrySchema {
    #[serde(rename = "chio.recovery.remedy-registry.v1")]
    V1,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRemedyRegistryV1 {
    pub schema: RecoveryRemedyRegistrySchema,
    pub version: VersionV1,
    pub scope: RecoveryScopeV1,
    pub deployment_digest: DeploymentDigest,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub classification: InformationLabel,
    pub templates: BoundedList<RecoveryRemedyTemplateV1, MAX_EXPLANATION_TEMPLATES>,
}
impl RecoveryRemedyRegistryV1 {
    pub fn validate(&self, snapshot: &RecoverySnapshotV1) -> Result<(), ContractError> {
        self.scope.ensure_matches(&snapshot.scope)?;
        if self.deployment_digest != snapshot.deployment_digest
            || self.policy_digest != snapshot.policy_digest
            || self.contract_digest != snapshot.contract_digest
        {
            return Err(ContractError::BindingMismatch);
        }
        let mut ids = alloc::collections::BTreeSet::new();
        for template in self.templates.as_slice() {
            if !ids.insert(&template.template_id) {
                return Err(ContractError::DuplicateIdentity);
            }
            if template.cost.approvals.get() > 8 || template.cost.irreversible_effects.get() > 8 {
                return Err(ContractError::LimitExceeded);
            }
            let mut dependencies = alloc::collections::BTreeSet::new();
            let mut kinds = alloc::collections::BTreeSet::new();
            for required in template.requirements.as_slice() {
                if !dependencies.insert(required) {
                    return Err(ContractError::DuplicateIdentity);
                }
                let fact = snapshot
                    .observations
                    .as_slice()
                    .iter()
                    .find(|f| &f.id == required)
                    .ok_or(ContractError::MissingDependency)?;
                let matches = match (&fact.fact, &fact.target) {
                    (
                        ExplanationFactKind::Capability | ExplanationFactKind::Policy,
                        ExplanationFactTargetV1::Intent { intent },
                    ) => *intent == snapshot.intent_digest,
                    (
                        ExplanationFactKind::DestinationAcl,
                        ExplanationFactTargetV1::Destination { destination },
                    ) => destination == &template.destination,
                    (
                        ExplanationFactKind::AuthorityCoverage,
                        ExplanationFactTargetV1::Authority { scope },
                    ) => *scope == template.authority_scope,
                    (
                        ExplanationFactKind::Transformation | ExplanationFactKind::Prerequisite,
                        ExplanationFactTargetV1::Template { template: id },
                    ) => id == &template.template_id,
                    _ => false,
                };
                if !matches {
                    return Err(ContractError::BindingMismatch);
                }
                kinds.insert(fact.fact);
            }
            if [
                ExplanationFactKind::Capability,
                ExplanationFactKind::Policy,
                ExplanationFactKind::DestinationAcl,
            ]
            .iter()
            .any(|kind| !kinds.contains(kind))
                || (template.kind == ExplanationRemedyKind::ExactApproval
                    && !kinds.contains(&ExplanationFactKind::AuthorityCoverage))
                || (template.kind == ExplanationRemedyKind::Transformation
                    && !kinds.contains(&ExplanationFactKind::Transformation))
                || (template.kind == ExplanationRemedyKind::Prerequisite
                    && !kinds.contains(&ExplanationFactKind::Prerequisite))
            {
                return Err(ContractError::MissingDependency);
            }
        }
        Ok(())
    }
    pub fn normalized(&self, snapshot: &RecoverySnapshotV1) -> Result<Self, ContractError> {
        self.validate(snapshot)?;
        let mut result = self.clone();
        let mut templates = self.templates.as_slice().to_vec();
        templates.sort_by(|a, b| a.template_id.cmp(&b.template_id));
        for template in &mut templates {
            let mut required = template.requirements.as_slice().to_vec();
            required.sort();
            template.requirements = NonEmptyBoundedList::new(required)?;
        }
        result.templates = BoundedList::new(templates)?;
        Ok(result)
    }
}
redacted!(
    RecoveryRemedyRegistryV1,
    RecoveryRemedyTemplateV1,
    ExplanationCostV1
);
