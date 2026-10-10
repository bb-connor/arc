use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationAssessmentV1 {
    FeasibleUnderSnapshot,
    RequiresExactApproval,
    RequiresTransformation,
    RequiresPrerequisite,
    NeedsFreshEvidence,
    BlockedByCapability,
    UnknownOutcome,
    NoRegisteredRemedy,
    SearchBoundReached,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationCandidateV1 {
    pub template_id: TemplateId,
    pub assessment: ExplanationAssessmentV1,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryExplanationEvaluationV1 {
    pub planner_version: RecoveryPlannerVersion,
    pub assessment: ExplanationAssessmentV1,
    pub complete: bool,
    pub work_used: SafeInteger,
    pub classification: InformationLabel,
    pub candidates: BoundedList<ExplanationCandidateV1, MAX_EXPLANATION_TEMPLATES>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplanationViewSummaryV1 {
    AuthorizedInspectionRequired,
    NoDisclosableAdvice,
    AlternativesUnderSnapshot,
    SearchBoundReached,
}

/// Contains only authorized per-candidate facts. No total count, full-graph
/// status, private digest, membership, signature or transitive commitment.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationProjectionV1 {
    pub summary: ExplanationViewSummaryV1,
    pub candidates: BoundedList<ExplanationCandidateV1, MAX_EXPLANATION_TEMPLATES>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryExplanationViewSchema {
    #[serde(rename = "chio.recovery.explanation-view.v1")]
    V1,
}

/// An opaque reference is host-generated random data bound to this recipient.
/// It is neither a digest of a secret nor a bearer token or execution permit.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryExplanationViewV1 {
    pub schema: RecoveryExplanationViewSchema,
    pub version: VersionV1,
    pub planner_version: RecoveryPlannerVersion,
    pub trust_domain: AuthorityDomainId,
    pub issuer: IssuerId,
    pub recipient: ActorId,
    pub report_ref: ExplanationRef,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
    pub projection: ExplanationProjectionV1,
}
impl RecoveryExplanationViewV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms.get() - self.issued_at_unix_ms.get()
                > MAX_EXPLANATION_VALIDITY_MS
        {
            return Err(ContractError::InvalidState);
        }
        let candidates = self.projection.candidates.as_slice();
        if candidates
            .windows(2)
            .any(|p| p[0].template_id >= p[1].template_id)
            || (matches!(
                self.projection.summary,
                ExplanationViewSummaryV1::AuthorizedInspectionRequired
                    | ExplanationViewSummaryV1::NoDisclosableAdvice
            ) && !candidates.is_empty())
        {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryExplanationReportSchema {
    #[serde(rename = "chio.recovery.explanation-report.v1")]
    V1,
}

/// The entire report and all its commitments are classified. Public views
/// never carry this envelope or pretend to recompute inaccessible evidence.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryExplanationReportV1 {
    pub schema: RecoveryExplanationReportSchema,
    pub version: VersionV1,
    pub planner_version: RecoveryPlannerVersion,
    pub scope: RecoveryScopeV1,
    pub trust_domain: AuthorityDomainId,
    pub issuer: IssuerId,
    pub deployment_digest: DeploymentDigest,
    pub policy_digest: PolicyDigest,
    pub contract_digest: ContractDigest,
    pub snapshot_digest: SnapshotDigest,
    pub registry_digest: RemedyRegistryDigest,
    pub intent_digest: IntentDigest,
    pub evaluation_digest: EvaluationDigest,
    pub projection_digest: ProjectionDigest,
    pub protected_graph_ref: ExplanationRef,
    pub recipient: ActorId,
    pub limits: ExplanationLimitsV1,
    pub issued_at_unix_ms: SafeInteger,
    pub expires_at_unix_ms: SafeInteger,
}
impl RecoveryExplanationReportV1 {
    pub fn validate(&self) -> Result<(), ContractError> {
        self.limits.validate()?;
        if self.limits.work.get() < 2 {
            return Err(ContractError::WorkBudgetExceeded);
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms.get() - self.issued_at_unix_ms.get()
                > MAX_EXPLANATION_VALIDITY_MS
        {
            return Err(ContractError::InvalidState);
        }
        Ok(())
    }
}
redacted!(
    ExplanationCandidateV1,
    RecoveryExplanationEvaluationV1,
    ExplanationProjectionV1,
    RecoveryExplanationViewV1,
    RecoveryExplanationReportV1
);
