# Architectural Extensions: Model Routing, Plan Evaluation, Cloud Guardrails

> **Status**: Proposed April 2026
> **Priority**: High -- these three gaps require new ARC primitives in the
> type system and kernel, not just new guards or integration adapters.

These are the gaps that cannot be solved by adding another guard to the
pipeline or writing another SDK wrapper. They require changes to the
core types in `arc-core-types/src/capability.rs` and new evaluation
methods on the kernel.

---

## 1. Model Routing Governance

### 1.1 The Problem

ARC governs which tools an agent calls but not which LLM model processes
the request. In production multi-model deployments (GPT-4 for reasoning,
Claude for code, smaller models for classification), there is no ARC
primitive for "this capability token authorizes tool calls only when
driven by model X at provider Y."

This matters because model choice is a security-relevant decision. A
financial tool call driven by a small uncensored model is categorically
higher risk than the same call driven by a safety-aligned frontier model.
NIST AI RMF and EU AI Act both emphasize knowing which model produced
which output.

### 1.2 Solution: ModelConstraint

Add a new `Constraint` variant and a model metadata field on
`ToolCallRequest`:

```rust
// In arc-core-types/src/capability.rs

pub enum Constraint {
    // ... existing variants ...

    /// Restrict which LLM models may drive tool calls under this grant.
    ModelConstraint {
        /// Allowed model identifiers (e.g., "claude-sonnet-4-6", "gpt-4o").
        /// Glob patterns supported: "claude-*", "gpt-4*".
        allowed_models: Vec<String>,
        /// Allowed provider identifiers (e.g., "anthropic", "openai").
        /// Empty means any provider.
        allowed_providers: Vec<String>,
        /// Minimum model safety tier. Models below this tier are denied.
        /// Tier assignment is operator-configured, not intrinsic.
        min_safety_tier: Option<ModelSafetyTier>,
    },
}

/// Operator-assigned model safety tiers.
/// These are not intrinsic properties of models -- operators classify
/// models into tiers based on their evaluation and risk appetite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSafetyTier {
    /// Unclassified or unknown model.
    Unclassified,
    /// Basic safety alignment (instruction following, refusal training).
    Basic,
    /// Standard safety (RLHF, constitutional AI, red-teaming).
    Standard,
    /// High safety (formal evaluation, external audit, safety cases).
    High,
}
```

### 1.3 Model Metadata on Tool Call Requests

The agent (or the framework wrapping the agent) includes model metadata
in the tool call request:

```rust
// In arc-core-types (or arc-kernel types)

/// Metadata about the LLM model driving this tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Model identifier (e.g., "claude-sonnet-4-6").
    pub model_id: String,
    /// Provider identifier (e.g., "anthropic").
    pub provider: String,
    /// Operator-assigned safety tier for this model.
    pub safety_tier: Option<ModelSafetyTier>,
}

pub struct ToolCallRequest {
    // ... existing fields ...

    /// Optional metadata about the LLM model driving this call.
    /// Used by ModelConstraint evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,
}
```

### 1.4 Kernel Evaluation

The kernel checks `ModelConstraint` during grant matching, alongside
existing constraint checks:

```rust
// In arc-kernel constraint evaluation

fn check_model_constraint(
    constraint: &ModelConstraint,
    model: &Option<ModelMetadata>,
) -> Result<(), KernelError> {
    let model = model.as_ref().ok_or_else(|| {
        KernelError::ConstraintViolation(
            "ModelConstraint requires model_metadata on request".into()
        )
    })?;

    // Check allowed models (glob matching)
    if !constraint.allowed_models.is_empty() {
        let matches = constraint.allowed_models.iter()
            .any(|pattern| glob_match(pattern, &model.model_id));
        if !matches {
            return Err(KernelError::ConstraintViolation(format!(
                "Model '{}' not in allowed list: {:?}",
                model.model_id, constraint.allowed_models,
            )));
        }
    }

    // Check allowed providers
    if !constraint.allowed_providers.is_empty() {
        if !constraint.allowed_providers.contains(&model.provider) {
            return Err(KernelError::ConstraintViolation(format!(
                "Provider '{}' not in allowed list: {:?}",
                model.provider, constraint.allowed_providers,
            )));
        }
    }

    // Check minimum safety tier
    if let Some(min_tier) = constraint.min_safety_tier {
        let actual_tier = model.safety_tier.unwrap_or(ModelSafetyTier::Unclassified);
        if actual_tier < min_tier {
            return Err(KernelError::ConstraintViolation(format!(
                "Model safety tier {:?} is below minimum {:?}",
                actual_tier, min_tier,
            )));
        }
    }

    Ok(())
}
```

### 1.5 Capability Grant Examples

```json
{
  "server_id": "financial-tools",
  "tool_name": "execute_trade",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "model_constraint",
      "value": {
        "allowed_models": ["claude-sonnet-4-6", "claude-opus-4-6", "gpt-4o"],
        "allowed_providers": ["anthropic", "openai"],
        "min_safety_tier": "high"
      }
    },
    { "type": "require_approval_above", "value": { "threshold_units": 100000 } }
  ],
  "max_cost_per_invocation": { "units": 50000, "currency": "USD" }
}
```

This grant says: the `execute_trade` tool can only be invoked when driven
by Claude Sonnet/Opus or GPT-4o, from Anthropic or OpenAI, with a high
safety tier rating. Trades above $1000 require approval.

### 1.6 Receipt Enrichment

Model metadata is captured in the receipt for audit:

```json
{
  "receipt_id": "rcpt_abc123",
  "tool_name": "execute_trade",
  "model_metadata": {
    "model_id": "claude-sonnet-4-6",
    "provider": "anthropic",
    "safety_tier": "high"
  }
}
```

---

## 2. Plan-Level Evaluation

### 2.1 The Problem

Agent frameworks create multi-step execution plans before running them:

- Semantic Kernel planners compose `KernelFunction` sequences
- CrewAI creates task execution plans from crew configurations
- LangGraph compiles state graphs with node sequences
- Custom agents use ReAct loops with planned tool sequences

ARC evaluates per-tool-call. A plan with 5 steps might be denied at step
5 after steps 1-4 already executed. This wastes compute, creates partial
state, and surprises the agent.

### 2.2 Solution: evaluate_plan() Kernel Method

Add a new evaluation method that takes a list of planned tool calls and
checks all of them against the capability scope before any execute:

```rust
// New types in arc-core-types

/// A planned tool call that has not yet been executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedToolCall {
    /// Unique step identifier within the plan.
    pub step_id: String,
    /// The tool to invoke.
    pub tool_name: String,
    /// The server hosting the tool.
    pub server_id: String,
    /// Expected arguments (may be partial or templated).
    pub arguments: serde_json::Value,
    /// Dependencies: step_ids that must complete before this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Optional: estimated cost of this step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost: Option<MonetaryAmount>,
}

/// Request to evaluate an entire plan before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEvaluationRequest {
    /// The capability token authorizing this plan.
    pub capability: CapabilityToken,
    /// The agent submitting the plan.
    pub agent_id: String,
    /// Ordered list of planned tool calls.
    pub steps: Vec<PlannedToolCall>,
    /// Optional: model metadata for model constraint checking.
    pub model_metadata: Option<ModelMetadata>,
}

/// Result of plan evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEvaluationResponse {
    /// Per-step verdicts.
    pub step_verdicts: Vec<StepVerdict>,
    /// Overall plan verdict: Allow only if ALL steps are allowed.
    pub plan_verdict: PlanVerdict,
    /// If the plan has a total estimated cost, check against budget.
    pub budget_check: Option<BudgetCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepVerdict {
    pub step_id: String,
    pub tool_name: String,
    pub verdict: Verdict,
    /// Why this step was denied (if denied).
    pub reason: Option<String>,
    /// Which constraint failed (if denied).
    pub constraint_violation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanVerdict {
    /// All steps are allowed. Safe to execute.
    AllAllowed,
    /// Some steps are denied. Plan should be revised.
    PartiallyDenied,
    /// All steps are denied. Plan is not executable.
    AllDenied,
    /// The plan's total estimated cost exceeds the budget.
    BudgetExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetCheckResult {
    pub estimated_total: MonetaryAmount,
    pub budget_remaining: MonetaryAmount,
    pub within_budget: bool,
}
```

### 2.3 Kernel Method

```rust
impl ArcKernel {
    /// Evaluate a multi-step plan before execution begins.
    ///
    /// Checks every step against the capability scope, constraints,
    /// and guards. Does NOT execute any tool calls or consume budget.
    /// Budget is checked against estimated costs, not actual costs.
    pub fn evaluate_plan(
        &self,
        request: &PlanEvaluationRequest,
    ) -> Result<PlanEvaluationResponse, KernelError> {
        // 1. Verify capability token (signature, time bounds, revocation)
        self.verify_capability(&request.capability)?;

        let scope = &request.capability.scope;
        let mut step_verdicts = Vec::with_capacity(request.steps.len());
        let mut total_estimated_cost: u64 = 0;

        for step in &request.steps {
            // 2. Check if tool is in scope
            let grant_match = self.find_matching_grant(
                scope,
                &step.server_id,
                &step.tool_name,
            );

            let verdict = match grant_match {
                None => StepVerdict {
                    step_id: step.step_id.clone(),
                    tool_name: step.tool_name.clone(),
                    verdict: Verdict::Deny,
                    reason: Some(format!(
                        "Tool {}:{} not in capability scope",
                        step.server_id, step.tool_name,
                    )),
                    constraint_violation: None,
                },
                Some((grant_idx, grant)) => {
                    // 3. Check constraints
                    match self.check_constraints(grant, &step.arguments, &request.model_metadata) {
                        Ok(()) => {
                            // 4. Run guards (dry-run mode: don't record, don't consume budget)
                            let guard_ctx = self.build_plan_guard_context(
                                &request, &step, grant_idx,
                            );
                            match self.evaluate_guards_dry_run(&guard_ctx) {
                                Ok(Verdict::Allow) => StepVerdict {
                                    step_id: step.step_id.clone(),
                                    tool_name: step.tool_name.clone(),
                                    verdict: Verdict::Allow,
                                    reason: None,
                                    constraint_violation: None,
                                },
                                Ok(Verdict::Deny) | Err(_) => StepVerdict {
                                    step_id: step.step_id.clone(),
                                    tool_name: step.tool_name.clone(),
                                    verdict: Verdict::Deny,
                                    reason: Some("Guard denied in dry-run".into()),
                                    constraint_violation: None,
                                },
                            }
                        }
                        Err(e) => StepVerdict {
                            step_id: step.step_id.clone(),
                            tool_name: step.tool_name.clone(),
                            verdict: Verdict::Deny,
                            reason: Some(format!("Constraint violation: {}", e)),
                            constraint_violation: Some(e.to_string()),
                        },
                    }
                }
            };

            if let Some(cost) = &step.estimated_cost {
                total_estimated_cost += cost.units;
            }

            step_verdicts.push(verdict);
        }

        // 5. Determine overall plan verdict
        let all_allowed = step_verdicts.iter().all(|v| v.verdict == Verdict::Allow);
        let all_denied = step_verdicts.iter().all(|v| v.verdict == Verdict::Deny);

        // 6. Check total estimated cost against budget
        let budget_check = if total_estimated_cost > 0 {
            let remaining = self.get_remaining_budget(&request.capability)?;
            Some(BudgetCheckResult {
                estimated_total: MonetaryAmount {
                    units: total_estimated_cost,
                    currency: remaining.currency.clone(),
                },
                budget_remaining: remaining,
                within_budget: total_estimated_cost <= remaining.units,
            })
        } else {
            None
        };

        let budget_exceeded = budget_check.as_ref()
            .map(|b| !b.within_budget)
            .unwrap_or(false);

        let plan_verdict = if budget_exceeded {
            PlanVerdict::BudgetExceeded
        } else if all_allowed {
            PlanVerdict::AllAllowed
        } else if all_denied {
            PlanVerdict::AllDenied
        } else {
            PlanVerdict::PartiallyDenied
        };

        Ok(PlanEvaluationResponse {
            step_verdicts,
            plan_verdict,
            budget_check,
        })
    }
}
```

### 2.4 HTTP API

```
POST /evaluate-plan

Request:
{
  "capability": { ... },
  "agent_id": "agent-42",
  "steps": [
    { "step_id": "1", "tool_name": "search", "server_id": "search-api", "arguments": { "query": "..." } },
    { "step_id": "2", "tool_name": "analyze", "server_id": "analytics", "arguments": { "data": "..." }, "depends_on": ["1"] },
    { "step_id": "3", "tool_name": "send_email", "server_id": "email-api", "arguments": { "to": "...", "body": "..." }, "depends_on": ["2"], "estimated_cost": { "units": 10, "currency": "USD" } }
  ]
}

Response:
{
  "step_verdicts": [
    { "step_id": "1", "tool_name": "search", "verdict": "allow" },
    { "step_id": "2", "tool_name": "analyze", "verdict": "allow" },
    { "step_id": "3", "tool_name": "send_email", "verdict": "deny", "reason": "Tool email-api:send_email not in capability scope" }
  ],
  "plan_verdict": "partially_denied",
  "budget_check": { "estimated_total": { "units": 10, "currency": "USD" }, "budget_remaining": { "units": 5000, "currency": "USD" }, "within_budget": true }
}
```

The agent sees that step 3 will be denied and can revise the plan before
executing steps 1 and 2.

### 2.5 Relationship to arc-workflow

`arc-workflow` provides `SkillManifest` with declared `SkillStep` sequences
and `WorkflowAuthority` that validates each step during execution. Plan
evaluation extends this:

| arc-workflow | Plan evaluation |
|-------------|-----------------|
| Steps declared in manifest at registration | Steps declared in plan at evaluation time |
| Validated per-step during execution | Validated all-at-once before execution |
| Manifest is static (tool author defines it) | Plan is dynamic (agent generates it) |
| WorkflowReceipt captures execution trace | PlanEvaluationResponse prevents wasted execution |

They are complementary. A workflow validates during execution (enforcement).
Plan evaluation validates before execution (planning). Both can be used
together: evaluate the plan, then execute it as a workflow.

---

## 3. Cloud Guardrail Interop

### 3.1 The Problem

Enterprises already run cloud-native content safety layers:

- **AWS Bedrock Guardrails**: content filters, denied topics, word filters,
  sensitive information filters, contextual grounding checks
- **Azure AI Content Safety**: text moderation (hate, violence, sexual,
  self-harm), prompt shield, groundedness detection
- **Google Vertex AI Safety**: content classification, safety filters,
  responsible AI metrics

These are often mandated by enterprise security teams. If ARC cannot
integrate with them, it becomes an either/or choice -- and the cloud
providers win by default.

ARC should not compete with these services. It should consume their
verdicts as guard evidence and record them in ARC receipts.

### 3.2 Architecture

Cloud guardrail adapters are `ExternalGuard` implementations (from doc 12)
wrapped in `AsyncGuardAdapter` with circuit breakers:

```
Agent -> ARC Kernel -> Guard Pipeline:
  1. Built-in guards (path, shell, egress, etc.)
  2. Content safety guards (jailbreak, prompt injection -- from doc 06)
  3. Cloud guardrail adapters (Bedrock, Azure, Vertex)
     |
     +-> AsyncGuardAdapter wraps the API call
     |     - Circuit breaker (don't hammer a failing API)
     |     - Cache (same content -> same verdict)
     |     - Timeout (don't block the pipeline)
     |
     +-> Cloud API returns verdict + categories + scores
     |
     +-> Mapped to ARC Verdict + GuardEvidence
  4. Advisory pipeline (non-blocking)
```

### 3.3 Guard Implementations

```rust
/// AWS Bedrock Guardrails adapter.
pub struct BedrockGuardrailGuard {
    /// Bedrock guardrail identifier.
    guardrail_id: String,
    /// Bedrock guardrail version.
    guardrail_version: String,
    /// AWS region.
    region: String,
    /// HTTP client for Bedrock API.
    http_client: HttpClient,
    /// AWS credentials (resolved from env/role).
    credentials: AwsCredentials,
}

impl ExternalGuard for BedrockGuardrailGuard {
    fn name(&self) -> &str { "bedrock-guardrail" }

    fn cache_key(&self, ctx: &GuardContext) -> Option<String> {
        // Cache by content hash
        let content = extract_content(ctx)?;
        Some(format!("bedrock:{}:{}", self.guardrail_id, sha256_hex(&content)))
    }

    fn check_external(&self, ctx: &GuardContext) -> Result<Verdict, ExternalGuardError> {
        let content = extract_content(ctx)
            .ok_or(ExternalGuardError::NotApplicable)?;

        // Call Bedrock ApplyGuardrail API
        let response = self.http_client.post(
            &format!(
                "https://bedrock-runtime.{}.amazonaws.com/guardrail/{}/version/{}/apply",
                self.region, self.guardrail_id, self.guardrail_version,
            ),
            &ApplyGuardrailRequest {
                source: "INPUT",
                content: vec![ContentBlock { text: content }],
            },
        )?;

        let result: ApplyGuardrailResponse = parse_response(response)?;

        // Map Bedrock action to ARC verdict
        match result.action.as_str() {
            "NONE" => Ok(Verdict::Allow),
            "GUARDRAIL_INTERVENED" => {
                // Record the intervention details as guard evidence
                // (stored in the receipt via GuardContext)
                Ok(Verdict::Deny)
            }
            _ => Ok(Verdict::Allow), // Unknown action: allow (fail-open for external)
        }
    }
}

/// Azure AI Content Safety adapter.
pub struct AzureContentSafetyGuard {
    /// Azure endpoint URL.
    endpoint: String,
    /// API key.
    api_key: String,
    /// Categories to check (hate, violence, sexual, self_harm).
    categories: Vec<String>,
    /// Severity threshold (0-6). Deny if any category exceeds this.
    severity_threshold: u32,
    http_client: HttpClient,
}

impl ExternalGuard for AzureContentSafetyGuard {
    fn name(&self) -> &str { "azure-content-safety" }

    fn cache_key(&self, ctx: &GuardContext) -> Option<String> {
        let content = extract_content(ctx)?;
        Some(format!("azure-cs:{}", sha256_hex(&content)))
    }

    fn check_external(&self, ctx: &GuardContext) -> Result<Verdict, ExternalGuardError> {
        let content = extract_content(ctx)
            .ok_or(ExternalGuardError::NotApplicable)?;

        let response = self.http_client.post(
            &format!("{}/contentsafety/text:analyze?api-version=2024-09-01", self.endpoint),
            &AnalyzeTextRequest {
                text: content,
                categories: self.categories.clone(),
            },
        )?;

        let result: AnalyzeTextResponse = parse_response(response)?;

        // Check if any category exceeds threshold
        for category in &result.categories_analysis {
            if category.severity >= self.severity_threshold {
                return Ok(Verdict::Deny);
            }
        }

        Ok(Verdict::Allow)
    }
}

/// Google Vertex AI Safety adapter.
pub struct VertexSafetyGuard {
    /// GCP project ID.
    project_id: String,
    /// GCP region.
    region: String,
    /// Safety settings (harm categories + thresholds).
    safety_settings: Vec<SafetySetting>,
    http_client: HttpClient,
    credentials: GcpCredentials,
}

impl ExternalGuard for VertexSafetyGuard {
    fn name(&self) -> &str { "vertex-safety" }

    fn cache_key(&self, ctx: &GuardContext) -> Option<String> {
        let content = extract_content(ctx)?;
        Some(format!("vertex:{}", sha256_hex(&content)))
    }

    fn check_external(&self, ctx: &GuardContext) -> Result<Verdict, ExternalGuardError> {
        let content = extract_content(ctx)
            .ok_or(ExternalGuardError::NotApplicable)?;

        // Use Vertex AI's moderate text endpoint
        let response = self.http_client.post(
            &format!(
                "https://{}-aiplatform.googleapis.com/v1/projects/{}/locations/{}/publishers/google/models/text-bison:predict",
                self.region, self.project_id, self.region,
            ),
            &ModerateRequest { content },
        )?;

        let result: ModerateResponse = parse_response(response)?;

        for rating in &result.safety_ratings {
            if rating.blocked {
                return Ok(Verdict::Deny);
            }
        }

        Ok(Verdict::Allow)
    }
}
```

### 3.4 Guard Evidence in Receipts

The cloud provider's verdict, categories, and scores are captured as
`GuardEvidence` in the ARC receipt. This means the signed receipt contains
proof of what the cloud safety API said:

```json
{
  "receipt_id": "rcpt_xyz789",
  "guard_evidence": [
    {
      "guard": "bedrock-guardrail",
      "verdict": "allow",
      "details": {
        "guardrail_id": "gr-abc123",
        "action": "NONE",
        "assessments": []
      }
    },
    {
      "guard": "azure-content-safety",
      "verdict": "allow",
      "details": {
        "categories": {
          "hate": { "severity": 0 },
          "violence": { "severity": 0 },
          "sexual": { "severity": 0 },
          "self_harm": { "severity": 0 }
        }
      }
    }
  ]
}
```

### 3.5 Policy Configuration

```yaml
guards:
  cloud_guardrails:
    bedrock:
      enabled: true
      guardrail_id: "gr-abc123"
      guardrail_version: "1"
      region: "us-east-1"
      timeout_seconds: 5
      cache_ttl_seconds: 300
      circuit_failure_threshold: 5

    azure_content_safety:
      enabled: true
      endpoint: "https://my-resource.cognitiveservices.azure.com"
      api_key: "${AZURE_CONTENT_SAFETY_KEY}"
      severity_threshold: 4
      categories: ["hate", "violence", "sexual", "self_harm"]

    vertex_safety:
      enabled: false
```

### 3.6 Fail-Open vs Fail-Closed

Cloud guardrail adapters default to **fail-open** when the external API
is unavailable (circuit breaker open, timeout, rate limited). This is
different from built-in guards which fail-closed.

Rationale: the built-in content safety guards (jailbreak, prompt injection
from doc 06) provide baseline protection. Cloud guardrails add defense in
depth. If the cloud API is down, the built-in guards still run. Denying
all tool calls because a cloud API is unreachable would make the system
brittle.

This is configurable per-guard via `AsyncGuardConfig::circuit_open_verdict`.

---

## 4. Implementation Priority

| Extension | Effort | Depends on | Priority |
|-----------|--------|------------|----------|
| ModelConstraint | Small | arc-core-types change | P1 |
| Plan evaluation | Medium | Kernel method, HTTP endpoint | P1 |
| Bedrock adapter | Medium | AsyncGuardAdapter (doc 12) | P1 |
| Azure adapter | Medium | AsyncGuardAdapter (doc 12) | P1 |
| Vertex adapter | Medium | AsyncGuardAdapter (doc 12) | P2 |

ModelConstraint and plan evaluation are independent and can be built in
parallel. Cloud guardrail adapters depend on the `AsyncGuardAdapter`
infrastructure from doc 12 section 2.
