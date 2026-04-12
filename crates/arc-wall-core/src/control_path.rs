use std::collections::HashSet;

use serde::{Deserialize, Serialize};

pub const ARC_WALL_CONTROL_PROFILE_SCHEMA: &str = "arc.wall.control_profile.v1";
pub const ARC_WALL_POLICY_SNAPSHOT_SCHEMA: &str = "arc.wall.policy_snapshot.v1";
pub const ARC_WALL_AUTHORIZATION_CONTEXT_SCHEMA: &str = "arc.wall.authorization_context.v1";
pub const ARC_WALL_GUARD_OUTCOME_SCHEMA: &str = "arc.wall.guard_outcome.v1";
pub const ARC_WALL_DENIED_ACCESS_RECORD_SCHEMA: &str = "arc.wall.denied_access_record.v1";
pub const ARC_WALL_BUYER_REVIEW_PACKAGE_SCHEMA: &str = "arc.wall.buyer_review_package.v1";
pub const ARC_WALL_CONTROL_PACKAGE_SCHEMA: &str = "arc.wall.control_package.v1";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ArcWallContractError {
    #[error("invalid ARC-Wall schema `{actual}` (expected `{expected}`)")]
    InvalidSchema {
        expected: &'static str,
        actual: String,
    },
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    #[error("field `{0}` must not be empty")]
    EmptyField(&'static str),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("json error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for ArcWallContractError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArcWallBuyerMotion {
    ControlRoomBarrierReview,
}

impl ArcWallBuyerMotion {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlRoomBarrierReview => "control_room_barrier_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArcWallControlSurface {
    ToolAccessDomainBoundary,
}

impl ArcWallControlSurface {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ToolAccessDomainBoundary => "tool_access_domain_boundary",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArcWallInformationDomain {
    Research,
    Execution,
}

impl ArcWallInformationDomain {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::Execution => "execution",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallControlProfile {
    pub schema: String,
    pub profile_id: String,
    pub workflow_id: String,
    pub buyer_motion: ArcWallBuyerMotion,
    pub control_surface: ArcWallControlSurface,
    pub source_domain: ArcWallInformationDomain,
    pub protected_domain: ArcWallInformationDomain,
    pub retained_artifact_policy: String,
    pub intended_use: String,
    pub fail_closed: bool,
}

impl ArcWallControlProfile {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_CONTROL_PROFILE_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_CONTROL_PROFILE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("control_profile.profile_id", &self.profile_id)?;
        ensure_non_empty("control_profile.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "control_profile.retained_artifact_policy",
            &self.retained_artifact_policy,
        )?;
        ensure_non_empty("control_profile.intended_use", &self.intended_use)?;
        if self.source_domain == self.protected_domain {
            return Err(ArcWallContractError::Validation(
                "control_profile.source_domain and protected_domain must differ".to_string(),
            ));
        }
        ensure_fail_closed("control_profile.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallPolicySnapshot {
    pub schema: String,
    pub policy_id: String,
    pub source_domain: ArcWallInformationDomain,
    pub allowed_tools: Vec<String>,
    pub fail_closed: bool,
    pub note: String,
}

impl ArcWallPolicySnapshot {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_POLICY_SNAPSHOT_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_POLICY_SNAPSHOT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("policy_snapshot.policy_id", &self.policy_id)?;
        ensure_non_empty("policy_snapshot.note", &self.note)?;
        ensure_non_empty_list("policy_snapshot.allowed_tools", &self.allowed_tools)?;
        ensure_unique_strings(
            "policy_snapshot.allowed_tools contains duplicate tool name",
            &self.allowed_tools,
        )?;
        ensure_fail_closed("policy_snapshot.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallAuthorizationContext {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub actor_label: String,
    pub buyer_motion: ArcWallBuyerMotion,
    pub control_surface: ArcWallControlSurface,
    pub source_domain: ArcWallInformationDomain,
    pub requested_domain: ArcWallInformationDomain,
    pub tool_name: String,
    pub policy_reference: String,
}

impl ArcWallAuthorizationContext {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_AUTHORIZATION_CONTEXT_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_AUTHORIZATION_CONTEXT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("authorization_context.request_id", &self.request_id)?;
        ensure_non_empty("authorization_context.workflow_id", &self.workflow_id)?;
        ensure_non_empty("authorization_context.actor_label", &self.actor_label)?;
        ensure_non_empty("authorization_context.tool_name", &self.tool_name)?;
        ensure_non_empty(
            "authorization_context.policy_reference",
            &self.policy_reference,
        )?;
        if self.source_domain == self.requested_domain {
            return Err(ArcWallContractError::Validation(
                "authorization_context.requested_domain must differ from source_domain".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArcWallGuardDecision {
    Allow,
    Deny,
}

impl ArcWallGuardDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallGuardOutcome {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub decision: ArcWallGuardDecision,
    pub guard_name: String,
    pub pipeline_name: String,
    pub matched_policy: String,
    pub evaluated_tool: String,
    pub allowed_tools: Vec<String>,
    pub reason: String,
    pub fail_closed: bool,
}

impl ArcWallGuardOutcome {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_GUARD_OUTCOME_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_GUARD_OUTCOME_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("guard_outcome.request_id", &self.request_id)?;
        ensure_non_empty("guard_outcome.workflow_id", &self.workflow_id)?;
        ensure_non_empty("guard_outcome.guard_name", &self.guard_name)?;
        ensure_non_empty("guard_outcome.pipeline_name", &self.pipeline_name)?;
        ensure_non_empty("guard_outcome.matched_policy", &self.matched_policy)?;
        ensure_non_empty("guard_outcome.evaluated_tool", &self.evaluated_tool)?;
        ensure_non_empty("guard_outcome.reason", &self.reason)?;
        ensure_non_empty_list("guard_outcome.allowed_tools", &self.allowed_tools)?;
        ensure_unique_strings(
            "guard_outcome.allowed_tools contains duplicate tool name",
            &self.allowed_tools,
        )?;
        if self.decision == ArcWallGuardDecision::Deny
            && self
                .allowed_tools
                .iter()
                .any(|tool| tool == &self.evaluated_tool)
        {
            return Err(ArcWallContractError::Validation(
                "guard_outcome cannot deny a tool that is present in allowed_tools".to_string(),
            ));
        }
        ensure_fail_closed("guard_outcome.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallDeniedAccessRecord {
    pub schema: String,
    pub request_id: String,
    pub workflow_id: String,
    pub source_domain: ArcWallInformationDomain,
    pub requested_domain: ArcWallInformationDomain,
    pub tool_name: String,
    pub escalation_owner: String,
    pub support_owner: String,
    pub note: String,
}

impl ArcWallDeniedAccessRecord {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_DENIED_ACCESS_RECORD_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_DENIED_ACCESS_RECORD_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("denied_access_record.request_id", &self.request_id)?;
        ensure_non_empty("denied_access_record.workflow_id", &self.workflow_id)?;
        ensure_non_empty("denied_access_record.tool_name", &self.tool_name)?;
        ensure_non_empty(
            "denied_access_record.escalation_owner",
            &self.escalation_owner,
        )?;
        ensure_non_empty("denied_access_record.support_owner", &self.support_owner)?;
        ensure_non_empty("denied_access_record.note", &self.note)?;
        if self.source_domain == self.requested_domain {
            return Err(ArcWallContractError::Validation(
                "denied_access_record.requested_domain must differ from source_domain".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArcWallArtifactKind {
    ControlProfile,
    PolicySnapshot,
    AuthorizationContext,
    GuardOutcome,
    DeniedAccessRecord,
    BuyerReviewPackage,
    ArcEvidenceExport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallArtifact {
    pub artifact_kind: ArcWallArtifactKind,
    pub relative_path: String,
}

impl ArcWallArtifact {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        ensure_non_empty(
            "control_package.artifacts[].relative_path",
            &self.relative_path,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallBuyerReviewPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub buyer_motion: ArcWallBuyerMotion,
    pub control_surface: ArcWallControlSurface,
    pub control_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub control_package_file: String,
    pub authorization_context_file: String,
    pub policy_snapshot_file: String,
    pub guard_outcome_file: String,
    pub denied_access_record_file: String,
    pub arc_evidence_dir: String,
    pub note: String,
}

impl ArcWallBuyerReviewPackage {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_BUYER_REVIEW_PACKAGE_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_BUYER_REVIEW_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("buyer_review_package.package_id", &self.package_id)?;
        ensure_non_empty("buyer_review_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty("buyer_review_package.control_owner", &self.control_owner)?;
        ensure_non_empty("buyer_review_package.support_owner", &self.support_owner)?;
        ensure_non_empty(
            "buyer_review_package.control_package_file",
            &self.control_package_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.authorization_context_file",
            &self.authorization_context_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.policy_snapshot_file",
            &self.policy_snapshot_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.guard_outcome_file",
            &self.guard_outcome_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.denied_access_record_file",
            &self.denied_access_record_file,
        )?;
        ensure_non_empty(
            "buyer_review_package.arc_evidence_dir",
            &self.arc_evidence_dir,
        )?;
        ensure_non_empty("buyer_review_package.note", &self.note)?;
        ensure_fail_closed("buyer_review_package.fail_closed", self.fail_closed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArcWallControlPackage {
    pub schema: String,
    pub package_id: String,
    pub workflow_id: String,
    pub same_system_boundary: String,
    pub buyer_motion: ArcWallBuyerMotion,
    pub control_surface: ArcWallControlSurface,
    pub control_owner: String,
    pub support_owner: String,
    pub fail_closed: bool,
    pub profile_file: String,
    pub buyer_review_package_file: String,
    pub arc_evidence_dir: String,
    pub artifacts: Vec<ArcWallArtifact>,
}

impl ArcWallControlPackage {
    pub fn validate(&self) -> Result<(), ArcWallContractError> {
        if self.schema != ARC_WALL_CONTROL_PACKAGE_SCHEMA {
            return Err(ArcWallContractError::InvalidSchema {
                expected: ARC_WALL_CONTROL_PACKAGE_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        ensure_non_empty("control_package.package_id", &self.package_id)?;
        ensure_non_empty("control_package.workflow_id", &self.workflow_id)?;
        ensure_non_empty(
            "control_package.same_system_boundary",
            &self.same_system_boundary,
        )?;
        ensure_non_empty("control_package.control_owner", &self.control_owner)?;
        ensure_non_empty("control_package.support_owner", &self.support_owner)?;
        ensure_non_empty("control_package.profile_file", &self.profile_file)?;
        ensure_non_empty(
            "control_package.buyer_review_package_file",
            &self.buyer_review_package_file,
        )?;
        ensure_non_empty("control_package.arc_evidence_dir", &self.arc_evidence_dir)?;
        ensure_fail_closed("control_package.fail_closed", self.fail_closed)?;
        if self.artifacts.is_empty() {
            return Err(ArcWallContractError::MissingField(
                "control_package.artifacts",
            ));
        }
        let mut artifact_kinds = HashSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            if !artifact_kinds.insert(artifact.artifact_kind) {
                return Err(ArcWallContractError::Validation(format!(
                    "control_package.artifacts contains duplicate artifact kind {:?}",
                    artifact.artifact_kind
                )));
            }
        }
        Ok(())
    }
}

fn ensure_non_empty(field: &'static str, value: &str) -> Result<(), ArcWallContractError> {
    if value.trim().is_empty() {
        Err(ArcWallContractError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn ensure_non_empty_list(
    field: &'static str,
    values: &[String],
) -> Result<(), ArcWallContractError> {
    if values.is_empty() {
        return Err(ArcWallContractError::MissingField(field));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ArcWallContractError::Validation(format!(
            "{field} must not contain empty values"
        )));
    }
    Ok(())
}

fn ensure_unique_strings(
    message: &'static str,
    values: &[String],
) -> Result<(), ArcWallContractError> {
    let unique_count = values.iter().collect::<HashSet<_>>().len();
    if unique_count != values.len() {
        return Err(ArcWallContractError::Validation(message.to_string()));
    }
    Ok(())
}

fn ensure_fail_closed(field: &'static str, value: bool) -> Result<(), ArcWallContractError> {
    if !value {
        Err(ArcWallContractError::Validation(format!(
            "{field} must remain true"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> ArcWallControlProfile {
        ArcWallControlProfile {
            schema: ARC_WALL_CONTROL_PROFILE_SCHEMA.to_string(),
            profile_id: "arc-wall-profile".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            buyer_motion: ArcWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ArcWallControlSurface::ToolAccessDomainBoundary,
            source_domain: ArcWallInformationDomain::Research,
            protected_domain: ArcWallInformationDomain::Execution,
            retained_artifact_policy: "retain_authorization_context_and_deny_records".to_string(),
            intended_use: "Barrier review for denied cross-domain tool access.".to_string(),
            fail_closed: true,
        }
    }

    #[test]
    fn control_profile_validates() {
        sample_profile().validate().expect("profile validates");
    }

    #[test]
    fn policy_snapshot_rejects_duplicate_allowed_tools() {
        let snapshot = ArcWallPolicySnapshot {
            schema: ARC_WALL_POLICY_SNAPSHOT_SCHEMA.to_string(),
            policy_id: "arc.wall.policy".to_string(),
            source_domain: ArcWallInformationDomain::Research,
            allowed_tools: vec![
                "research_news.read".to_string(),
                "research_news.read".to_string(),
            ],
            fail_closed: true,
            note: "duplicate tool".to_string(),
        };
        let error = snapshot.validate().expect_err("duplicate tool rejected");
        assert!(error.to_string().contains("duplicate tool name"));
    }

    #[test]
    fn guard_outcome_rejects_denied_tool_in_allowlist() {
        let outcome = ArcWallGuardOutcome {
            schema: ARC_WALL_GUARD_OUTCOME_SCHEMA.to_string(),
            request_id: "req-1".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            decision: ArcWallGuardDecision::Deny,
            guard_name: "mcp-tool".to_string(),
            pipeline_name: "guard-pipeline".to_string(),
            matched_policy: "arc.wall.policy".to_string(),
            evaluated_tool: "execution_oms.submit_order".to_string(),
            allowed_tools: vec![
                "research_news.read".to_string(),
                "execution_oms.submit_order".to_string(),
            ],
            reason: "tool denied".to_string(),
            fail_closed: true,
        };
        let error = outcome.validate().expect_err("invalid denial rejected");
        assert!(error.to_string().contains("cannot deny"));
    }

    #[test]
    fn control_package_rejects_duplicate_artifacts() {
        let package = ArcWallControlPackage {
            schema: ARC_WALL_CONTROL_PACKAGE_SCHEMA.to_string(),
            package_id: "arc-wall-package".to_string(),
            workflow_id: "workflow-information-domain-barrier".to_string(),
            same_system_boundary:
                "Information-domain tool access evidence for one bounded barrier-control workflow."
                    .to_string(),
            buyer_motion: ArcWallBuyerMotion::ControlRoomBarrierReview,
            control_surface: ArcWallControlSurface::ToolAccessDomainBoundary,
            control_owner: "barrier-control-room".to_string(),
            support_owner: "arc-wall-ops".to_string(),
            fail_closed: true,
            profile_file: "control-profile.json".to_string(),
            buyer_review_package_file: "buyer-review-package.json".to_string(),
            arc_evidence_dir: "arc-evidence".to_string(),
            artifacts: vec![
                ArcWallArtifact {
                    artifact_kind: ArcWallArtifactKind::ControlProfile,
                    relative_path: "control-profile.json".to_string(),
                },
                ArcWallArtifact {
                    artifact_kind: ArcWallArtifactKind::ControlProfile,
                    relative_path: "control-profile-copy.json".to_string(),
                },
            ],
        };
        let error = package.validate().expect_err("duplicate artifact rejected");
        assert!(error.to_string().contains("duplicate artifact kind"));
    }
}
