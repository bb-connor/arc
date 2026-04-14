//! Workflow authority -- validates each step against declared scope and budget.
//!
//! The `WorkflowAuthority` manages the lifecycle of a skill execution:
//! beginning, step validation, step recording, and finalization into a
//! signed `WorkflowReceipt`.

use arc_core::capability::MonetaryAmount;
use arc_core::crypto::Keypair;
use tracing::debug;

use crate::grant::SkillGrant;
use crate::manifest::{SkillManifest, SkillStep};
use crate::receipt::{
    StepOutcome, StepRecord, WorkflowOutcome, WorkflowReceipt, WorkflowReceiptBody,
    WORKFLOW_RECEIPT_SCHEMA,
};

/// Errors from the workflow authority.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// The skill grant does not authorize the requested skill.
    #[error("skill grant does not authorize skill '{skill_id}' version '{version}'")]
    UnauthorizedSkill { skill_id: String, version: String },

    /// A step is not authorized by the skill grant.
    #[error("step {step_index} ({server}:{tool}) is not authorized")]
    UnauthorizedStep {
        step_index: usize,
        server: String,
        tool: String,
    },

    /// A step is out of order (when strict ordering is required).
    #[error("step {step_index} is out of order (expected step {expected})")]
    StepOutOfOrder { step_index: usize, expected: usize },

    /// The workflow budget has been exceeded.
    #[error("budget exceeded: spent {spent_units} of {limit_units} {currency}")]
    BudgetExceeded {
        limit_units: u64,
        spent_units: u64,
        currency: String,
    },

    /// The workflow time limit has been exceeded.
    #[error("time limit exceeded: {elapsed_secs}s of {limit_secs}s allowed")]
    TimeLimitExceeded { elapsed_secs: u64, limit_secs: u64 },

    /// The maximum number of executions has been reached.
    #[error("execution limit reached: {limit} executions")]
    ExecutionLimitReached { limit: u32 },

    /// The workflow is in an invalid state for the requested operation.
    #[error("workflow is in invalid state: {0}")]
    InvalidState(String),

    /// Receipt signing failed.
    #[error("receipt signing failed: {0}")]
    SigningFailed(String),
}

/// A workflow execution in progress.
///
/// Created by `WorkflowAuthority::begin()` and consumed by `finalize()`.
#[derive(Debug)]
pub struct WorkflowExecution {
    /// Unique execution ID (becomes the receipt ID).
    pub id: String,
    /// Skill ID from the manifest.
    pub skill_id: String,
    /// Skill version.
    pub skill_version: String,
    /// Agent performing the execution.
    pub agent_id: String,
    /// Session binding.
    pub session_id: Option<String>,
    /// Capability ID.
    pub capability_id: String,
    /// Unix timestamp when execution started.
    pub started_at: u64,
    /// Steps completed so far.
    pub step_records: Vec<StepRecord>,
    /// Budget spent so far (in policy currency minor units).
    pub budget_spent: u64,
    /// Budget limit from grant or manifest.
    pub budget_limit: Option<MonetaryAmount>,
    /// Time limit in seconds.
    pub time_limit_secs: Option<u64>,
    /// Whether the execution is still active.
    pub active: bool,
}

impl WorkflowExecution {
    /// Return the number of completed steps.
    #[must_use]
    pub fn completed_steps(&self) -> usize {
        self.step_records
            .iter()
            .filter(|s| s.outcome == StepOutcome::Success)
            .count()
    }
}

/// Workflow authority that validates and manages skill executions.
pub struct WorkflowAuthority {
    signing_key: Keypair,
    /// Number of executions completed (for limit tracking).
    execution_count: u32,
}

impl WorkflowAuthority {
    /// Create a new workflow authority with the given signing key.
    pub fn new(signing_key: Keypair) -> Self {
        Self {
            signing_key,
            execution_count: 0,
        }
    }

    /// Begin a new workflow execution.
    ///
    /// Validates the grant against the manifest before starting.
    pub fn begin(
        &self,
        manifest: &SkillManifest,
        grant: &SkillGrant,
        agent_id: String,
        capability_id: String,
        session_id: Option<String>,
    ) -> Result<WorkflowExecution, WorkflowError> {
        // Validate grant matches manifest
        if grant.skill_id != manifest.skill_id || grant.skill_version != manifest.version {
            return Err(WorkflowError::UnauthorizedSkill {
                skill_id: manifest.skill_id.clone(),
                version: manifest.version.clone(),
            });
        }

        // Check execution limit
        if let Some(limit) = grant.max_executions {
            if self.execution_count >= limit {
                return Err(WorkflowError::ExecutionLimitReached { limit });
            }
        }

        // Check all manifest steps are authorized
        for step in &manifest.steps {
            if !grant.authorizes_step(&step.server_id, &step.tool_name) {
                return Err(WorkflowError::UnauthorizedStep {
                    step_index: step.index,
                    server: step.server_id.clone(),
                    tool: step.tool_name.clone(),
                });
            }
        }

        let budget_limit = grant
            .budget_envelope
            .clone()
            .or_else(|| manifest.budget_envelope.clone());

        let time_limit_secs = grant.max_duration_secs.or(manifest.max_duration_secs);

        let now = current_unix_secs();

        debug!(
            skill_id = %manifest.skill_id,
            agent_id = %agent_id,
            "beginning workflow execution"
        );

        Ok(WorkflowExecution {
            id: format!("wf-{}", now),
            skill_id: manifest.skill_id.clone(),
            skill_version: manifest.version.clone(),
            agent_id,
            session_id,
            capability_id,
            started_at: now,
            step_records: Vec::new(),
            budget_spent: 0,
            budget_limit,
            time_limit_secs,
            active: true,
        })
    }

    /// Validate a step before execution.
    ///
    /// Checks authorization, ordering, budget, and time constraints.
    pub fn validate_step(
        &self,
        execution: &WorkflowExecution,
        step: &SkillStep,
        grant: &SkillGrant,
    ) -> Result<(), WorkflowError> {
        if !execution.active {
            return Err(WorkflowError::InvalidState(
                "workflow is no longer active".to_string(),
            ));
        }

        // Check authorization
        if !grant.authorizes_step(&step.server_id, &step.tool_name) {
            return Err(WorkflowError::UnauthorizedStep {
                step_index: step.index,
                server: step.server_id.clone(),
                tool: step.tool_name.clone(),
            });
        }

        // Check ordering
        if !grant.is_step_in_order(step.index, execution.completed_steps()) {
            return Err(WorkflowError::StepOutOfOrder {
                step_index: step.index,
                expected: execution.completed_steps(),
            });
        }

        // Check time limit
        if let Some(limit_secs) = execution.time_limit_secs {
            let elapsed = current_unix_secs().saturating_sub(execution.started_at);
            if elapsed >= limit_secs {
                return Err(WorkflowError::TimeLimitExceeded {
                    elapsed_secs: elapsed,
                    limit_secs,
                });
            }
        }

        Ok(())
    }

    /// Record the result of a step execution.
    #[allow(clippy::too_many_arguments)]
    pub fn record_step(
        &self,
        execution: &mut WorkflowExecution,
        step: &SkillStep,
        outcome: StepOutcome,
        duration_ms: u64,
        cost: Option<MonetaryAmount>,
        tool_receipt_id: Option<String>,
        output_hash: Option<String>,
    ) -> Result<(), WorkflowError> {
        if !execution.active {
            return Err(WorkflowError::InvalidState(
                "workflow is no longer active".to_string(),
            ));
        }

        // Track budget
        if let Some(ref c) = cost {
            execution.budget_spent = execution.budget_spent.saturating_add(c.units);

            // Check budget envelope
            if let Some(ref limit) = execution.budget_limit {
                if execution.budget_spent > limit.units {
                    execution.active = false;
                    return Err(WorkflowError::BudgetExceeded {
                        limit_units: limit.units,
                        spent_units: execution.budget_spent,
                        currency: limit.currency.clone(),
                    });
                }
            }
        }

        let record = StepRecord {
            step_index: step.index,
            server_id: step.server_id.clone(),
            tool_name: step.tool_name.clone(),
            allowed: matches!(outcome, StepOutcome::Success | StepOutcome::Failed),
            tool_receipt_id,
            outcome: outcome.clone(),
            duration_ms,
            cost,
            output_hash,
        };

        execution.step_records.push(record);

        if outcome == StepOutcome::Failed || outcome == StepOutcome::Denied {
            execution.active = false;
        }

        Ok(())
    }

    /// Finalize a workflow execution and produce a signed receipt.
    pub fn finalize(
        &mut self,
        mut execution: WorkflowExecution,
    ) -> Result<WorkflowReceipt, WorkflowError> {
        execution.active = false;

        let completed_at = current_unix_secs();
        let duration_ms = completed_at
            .saturating_sub(execution.started_at)
            .saturating_mul(1000);

        let outcome = determine_outcome(&execution, completed_at);

        let total_cost = if execution.budget_spent > 0 {
            execution.budget_limit.as_ref().map(|limit| MonetaryAmount {
                units: execution.budget_spent,
                currency: limit.currency.clone(),
            })
        } else {
            None
        };

        let body = WorkflowReceiptBody {
            id: execution.id.clone(),
            schema: WORKFLOW_RECEIPT_SCHEMA.to_string(),
            started_at: execution.started_at,
            completed_at,
            skill_id: execution.skill_id,
            skill_version: execution.skill_version,
            agent_id: execution.agent_id,
            session_id: execution.session_id,
            capability_id: execution.capability_id,
            outcome,
            steps: execution.step_records,
            total_cost,
            duration_ms,
            kernel_key: self.signing_key.public_key(),
        };

        let receipt = WorkflowReceipt::sign(body, &self.signing_key)
            .map_err(|e| WorkflowError::SigningFailed(e.to_string()))?;

        self.execution_count = self.execution_count.saturating_add(1);

        debug!(
            receipt_id = %receipt.id,
            skill_id = %receipt.skill_id,
            "workflow receipt signed"
        );

        Ok(receipt)
    }

    /// Return the number of completed executions.
    #[must_use]
    pub fn execution_count(&self) -> u32 {
        self.execution_count
    }
}

fn determine_outcome(execution: &WorkflowExecution, _completed_at: u64) -> WorkflowOutcome {
    // Check for step failures
    for step in &execution.step_records {
        if step.outcome == StepOutcome::Failed {
            return WorkflowOutcome::StepFailed {
                step_index: step.step_index,
                reason: "step execution failed".to_string(),
            };
        }
        if step.outcome == StepOutcome::Denied {
            return WorkflowOutcome::StepFailed {
                step_index: step.step_index,
                reason: "step denied by policy".to_string(),
            };
        }
    }

    // Check budget
    if let Some(ref limit) = execution.budget_limit {
        if execution.budget_spent > limit.units {
            return WorkflowOutcome::BudgetExceeded {
                limit_units: limit.units,
                spent_units: execution.budget_spent,
                currency: limit.currency.clone(),
            };
        }
    }

    WorkflowOutcome::Completed
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{IoContract, SkillStep};

    fn make_manifest() -> SkillManifest {
        SkillManifest::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            "Search and Summarize".to_string(),
            vec![
                SkillStep {
                    index: 0,
                    server_id: "search-srv".to_string(),
                    tool_name: "search".to_string(),
                    label: Some("Search".to_string()),
                    input_contract: None,
                    output_contract: Some(IoContract {
                        required_fields: vec![],
                        produced_fields: vec!["results".to_string()],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    budget_limit: None,
                    retryable: false,
                    max_retries: None,
                },
                SkillStep {
                    index: 1,
                    server_id: "llm-srv".to_string(),
                    tool_name: "summarize".to_string(),
                    label: Some("Summarize".to_string()),
                    input_contract: Some(IoContract {
                        required_fields: vec!["results".to_string()],
                        produced_fields: vec![],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    output_contract: Some(IoContract {
                        required_fields: vec![],
                        produced_fields: vec!["summary".to_string()],
                        optional_fields: vec![],
                        json_schema: None,
                    }),
                    budget_limit: None,
                    retryable: false,
                    max_retries: None,
                },
            ],
        )
    }

    fn make_grant() -> SkillGrant {
        let mut grant = SkillGrant::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            vec![
                "search-srv:search".to_string(),
                "llm-srv:summarize".to_string(),
            ],
        );
        grant.budget_envelope = Some(MonetaryAmount {
            units: 1000,
            currency: "USD".to_string(),
        });
        grant
    }

    #[test]
    fn successful_workflow_execution() {
        let manifest = make_manifest();
        let grant = make_grant();
        let mut authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                Some("sess-1".to_string()),
            )
            .unwrap();

        // Validate and record step 0
        authority
            .validate_step(&execution, &manifest.steps[0], &grant)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepOutcome::Success,
                100,
                Some(MonetaryAmount {
                    units: 50,
                    currency: "USD".to_string(),
                }),
                Some("rcpt-0".to_string()),
                None,
            )
            .unwrap();

        // Validate and record step 1
        authority
            .validate_step(&execution, &manifest.steps[1], &grant)
            .unwrap();
        authority
            .record_step(
                &mut execution,
                &manifest.steps[1],
                StepOutcome::Success,
                200,
                Some(MonetaryAmount {
                    units: 100,
                    currency: "USD".to_string(),
                }),
                Some("rcpt-1".to_string()),
                None,
            )
            .unwrap();

        let receipt = authority.finalize(execution).unwrap();
        assert!(receipt.is_complete());
        assert_eq!(receipt.successful_steps(), 2);
        assert!(receipt.verify().unwrap());
        assert_eq!(authority.execution_count(), 1);
    }

    #[test]
    fn unauthorized_skill_rejected() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.skill_id = "wrong-skill".to_string();

        let authority = WorkflowAuthority::new(Keypair::generate());
        let result = authority.begin(
            &manifest,
            &grant,
            "agent-1".to_string(),
            "cap-1".to_string(),
            None,
        );
        assert!(matches!(
            result,
            Err(WorkflowError::UnauthorizedSkill { .. })
        ));
    }

    #[test]
    fn missing_step_authorization_rejected() {
        let manifest = make_manifest();
        let grant = SkillGrant::new(
            "search-summarize".to_string(),
            "1.0.0".to_string(),
            vec!["search-srv:search".to_string()],
            // Missing llm-srv:summarize
        );

        let authority = WorkflowAuthority::new(Keypair::generate());
        let result = authority.begin(
            &manifest,
            &grant,
            "agent-1".to_string(),
            "cap-1".to_string(),
            None,
        );
        assert!(matches!(
            result,
            Err(WorkflowError::UnauthorizedStep { .. })
        ));
    }

    #[test]
    fn budget_exceeded_during_execution() {
        let manifest = make_manifest();
        let mut grant = make_grant();
        grant.budget_envelope = Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        });

        let authority = WorkflowAuthority::new(Keypair::generate());
        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Step 0 costs 80 out of 100 budget
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepOutcome::Success,
                100,
                Some(MonetaryAmount {
                    units: 80,
                    currency: "USD".to_string(),
                }),
                None,
                None,
            )
            .unwrap();

        // Step 1 costs 50, pushing over budget
        let result = authority.record_step(
            &mut execution,
            &manifest.steps[1],
            StepOutcome::Success,
            100,
            Some(MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            }),
            None,
            None,
        );
        assert!(matches!(result, Err(WorkflowError::BudgetExceeded { .. })));
    }

    #[test]
    fn step_order_enforcement() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Try step 1 before step 0
        let result = authority.validate_step(&execution, &manifest.steps[1], &grant);
        assert!(matches!(result, Err(WorkflowError::StepOutOfOrder { .. })));
    }

    #[test]
    fn step_failure_deactivates_workflow() {
        let manifest = make_manifest();
        let grant = make_grant();
        let authority = WorkflowAuthority::new(Keypair::generate());

        let mut execution = authority
            .begin(
                &manifest,
                &grant,
                "agent-1".to_string(),
                "cap-1".to_string(),
                None,
            )
            .unwrap();

        // Record a failed step
        authority
            .record_step(
                &mut execution,
                &manifest.steps[0],
                StepOutcome::Failed,
                50,
                None,
                None,
                None,
            )
            .unwrap();

        // Workflow should be deactivated
        assert!(!execution.active);

        // Trying to validate next step should fail
        let result = authority.validate_step(&execution, &manifest.steps[1], &grant);
        assert!(matches!(result, Err(WorkflowError::InvalidState(_))));
    }
}
