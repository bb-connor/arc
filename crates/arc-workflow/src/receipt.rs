//! Workflow receipts capturing complete execution traces.
//!
//! A `WorkflowReceipt` is a single auditable artifact that captures the
//! entire execution of a skill, including per-step results, timing,
//! cost attribution, and the overall outcome.

use arc_core::capability::MonetaryAmount;
use arc_core::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Schema identifier for workflow receipts.
pub const WORKFLOW_RECEIPT_SCHEMA: &str = "arc.workflow-receipt.v1";

/// A signed receipt for a complete skill/workflow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceipt {
    /// Unique receipt ID.
    pub id: String,
    /// Schema version.
    pub schema: String,
    /// Unix timestamp when the workflow started.
    pub started_at: u64,
    /// Unix timestamp when the workflow completed.
    pub completed_at: u64,
    /// Skill ID from the manifest.
    pub skill_id: String,
    /// Skill version from the manifest.
    pub skill_version: String,
    /// Agent that executed the workflow.
    pub agent_id: String,
    /// Session the workflow ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Capability ID that authorized the workflow.
    pub capability_id: String,
    /// Overall workflow outcome.
    pub outcome: WorkflowOutcome,
    /// Per-step execution records.
    pub steps: Vec<StepRecord>,
    /// Total cost of the workflow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost: Option<MonetaryAmount>,
    /// Total wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Kernel public key.
    pub kernel_key: PublicKey,
    /// Signature over the receipt body.
    pub signature: Signature,
}

/// The body of a workflow receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowReceiptBody {
    pub id: String,
    pub schema: String,
    pub started_at: u64,
    pub completed_at: u64,
    pub skill_id: String,
    pub skill_version: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub capability_id: String,
    pub outcome: WorkflowOutcome,
    pub steps: Vec<StepRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_cost: Option<MonetaryAmount>,
    pub duration_ms: u64,
    pub kernel_key: PublicKey,
}

/// Outcome of a workflow execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WorkflowOutcome {
    /// All steps completed successfully.
    Completed,
    /// The workflow was denied before execution started.
    Denied { reason: String },
    /// A step failed, halting the workflow.
    StepFailed { step_index: usize, reason: String },
    /// The workflow exceeded its budget envelope.
    BudgetExceeded {
        limit_units: u64,
        spent_units: u64,
        currency: String,
    },
    /// The workflow exceeded its time limit.
    TimedOut { limit_secs: u64, elapsed_secs: u64 },
    /// The workflow was cancelled by the agent or operator.
    Cancelled { reason: String },
}

/// Record of a single step's execution within a workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    /// Step index in the manifest.
    pub step_index: usize,
    /// Tool server.
    pub server_id: String,
    /// Tool name.
    pub tool_name: String,
    /// Whether this step was allowed.
    pub allowed: bool,
    /// Receipt ID for the underlying tool call (if it ran).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_receipt_id: Option<String>,
    /// Step outcome.
    pub outcome: StepOutcome,
    /// Step duration in milliseconds.
    pub duration_ms: u64,
    /// Cost attributed to this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<MonetaryAmount>,
    /// SHA-256 hash of the step's output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
}

/// Outcome of a single step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// Step completed successfully.
    Success,
    /// Step was denied by policy.
    Denied,
    /// Step failed during execution.
    Failed,
    /// Step was skipped (e.g. workflow aborted before reaching it).
    Skipped,
}

impl WorkflowReceipt {
    /// Sign a workflow receipt body.
    pub fn sign(body: WorkflowReceiptBody, keypair: &Keypair) -> Result<Self, arc_core::Error> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            schema: body.schema,
            started_at: body.started_at,
            completed_at: body.completed_at,
            skill_id: body.skill_id,
            skill_version: body.skill_version,
            agent_id: body.agent_id,
            session_id: body.session_id,
            capability_id: body.capability_id,
            outcome: body.outcome,
            steps: body.steps,
            total_cost: body.total_cost,
            duration_ms: body.duration_ms,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Verify the receipt signature.
    pub fn verify(&self) -> Result<bool, arc_core::Error> {
        let body = WorkflowReceiptBody {
            id: self.id.clone(),
            schema: self.schema.clone(),
            started_at: self.started_at,
            completed_at: self.completed_at,
            skill_id: self.skill_id.clone(),
            skill_version: self.skill_version.clone(),
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            capability_id: self.capability_id.clone(),
            outcome: self.outcome.clone(),
            steps: self.steps.clone(),
            total_cost: self.total_cost.clone(),
            duration_ms: self.duration_ms,
            kernel_key: self.kernel_key.clone(),
        };
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Count how many steps completed successfully.
    #[must_use]
    pub fn successful_steps(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.outcome == StepOutcome::Success)
            .count()
    }

    /// Check whether the workflow completed successfully.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.outcome == WorkflowOutcome::Completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_step_record(index: usize, outcome: StepOutcome) -> StepRecord {
        StepRecord {
            step_index: index,
            server_id: "srv".to_string(),
            tool_name: format!("tool_{index}"),
            allowed: matches!(outcome, StepOutcome::Success | StepOutcome::Failed),
            tool_receipt_id: Some(format!("rcpt-{index}")),
            outcome,
            duration_ms: 100,
            cost: None,
            output_hash: None,
        }
    }

    #[test]
    fn sign_and_verify_workflow_receipt() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-1".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 2000,
            skill_id: "search-summarize".to_string(),
            skill_version: "1.0.0".to_string(),
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            capability_id: "cap-1".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![
                make_step_record(0, StepOutcome::Success),
                make_step_record(1, StepOutcome::Success),
            ],
            total_cost: Some(MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            }),
            duration_ms: 1000,
            kernel_key: kp.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify().unwrap());
        assert!(receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 2);
    }

    #[test]
    fn tampered_receipt_fails() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-2".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 2000,
            skill_id: "s".to_string(),
            skill_version: "1.0".to_string(),
            agent_id: "a".to_string(),
            session_id: None,
            capability_id: "c".to_string(),
            outcome: WorkflowOutcome::Completed,
            steps: vec![],
            total_cost: None,
            duration_ms: 500,
            kernel_key: kp.public_key(),
        };

        let mut receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        receipt.duration_ms = 999; // tamper
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn partial_failure_stats() {
        let kp = Keypair::generate();
        let body = WorkflowReceiptBody {
            id: "wf-3".to_string(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: 1000,
            completed_at: 1500,
            skill_id: "s".to_string(),
            skill_version: "1.0".to_string(),
            agent_id: "a".to_string(),
            session_id: None,
            capability_id: "c".to_string(),
            outcome: WorkflowOutcome::StepFailed {
                step_index: 1,
                reason: "tool error".to_string(),
            },
            steps: vec![
                make_step_record(0, StepOutcome::Success),
                make_step_record(1, StepOutcome::Failed),
                make_step_record(2, StepOutcome::Skipped),
            ],
            total_cost: None,
            duration_ms: 500,
            kernel_key: kp.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &kp).unwrap();
        assert!(!receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 1);
    }

    #[test]
    fn workflow_outcome_serialization() {
        let outcome = WorkflowOutcome::BudgetExceeded {
            limit_units: 1000,
            spent_units: 1100,
            currency: "USD".to_string(),
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let deserialized: WorkflowOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, outcome);
    }
}
