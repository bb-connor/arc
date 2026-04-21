# SaaS and Communication Platform Governance

> **Status**: Tier 1 -- proposed April 2026
> **Priority**: Critical -- agent actions on SaaS APIs produce externally
> visible, often irreversible side effects. A Slack message reaches a human
> inbox. A Stripe charge moves real money. A PagerDuty page wakes someone at
> 3am. Content-review guards are mandatory: the kernel must inspect WHAT the
> agent sends, not just WHETHER it can send.

## 1. Threat Model

Traditional tool governance asks a binary question: "does the agent have
permission to call this tool?" SaaS integrations demand a deeper question:
"is the content the agent is about to send appropriate, safe, and within
policy?"

Without content-level governance:

- An agent with `slack:send` scope can post customer SSNs into a public channel.
- An agent with `stripe:charge` scope can charge $50,000 to a customer card.
- An agent with `pagerduty:create_incident` scope can page the entire
  on-call rotation at 3am for a non-critical issue.
- An agent with `github:merge` scope can merge untested code to `main`.

Chio's existing capability model (scoped `ToolGrant`, `Constraint` variants,
guard pipeline) provides the structural foundation. This document extends it
with content-aware governance for external SaaS actions.

## 2. New Type Extensions

### 2.1 ToolAction Variant: ExternalApiCall

The existing `ToolAction` enum in `chio-guards/src/action.rs` categorizes
actions by kind (file access, shell command, network egress). SaaS
interactions need a new variant that carries service identity and visibility
classification.

```rust
/// Visibility level of an external API action.
/// Guards use this to determine the required review depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionVisibility {
    /// Internal-only: dashboards, metrics, project management reads.
    /// Errors are correctable. Lowest review bar.
    Internal,
    /// Externally visible: messages, notifications, ticket updates.
    /// Reaches humans outside the agent's trust boundary.
    External,
    /// Financial: charges, refunds, transfers, subscription changes.
    /// Moves real money. Highest review bar.
    Financial,
}

// In ToolAction enum:
pub enum ToolAction {
    // ... existing variants ...

    /// An API call to an external SaaS service.
    ExternalApiCall {
        /// Service identifier (e.g., "slack", "stripe", "pagerduty").
        service: String,
        /// Action within the service (e.g., "send_message", "create_charge").
        action: String,
        /// Visibility classification -- determines guard strictness.
        visibility: ActionVisibility,
    },
}
```

Extraction logic maps tool names to `ExternalApiCall` using a registry:

```rust
// In extract_action():
if let Some(svc) = SAAS_TOOL_REGISTRY.get(tool.as_str()) {
    return ToolAction::ExternalApiCall {
        service: svc.service.to_string(),
        action: svc.action.to_string(),
        visibility: svc.visibility,
    };
}
```

### 2.2 New Constraint Variants

Two new `Constraint` variants extend the existing enum in
`chio-core-types/src/capability.rs`:

```rust
pub enum Constraint {
    // ... existing variants: PathPrefix, DomainExact, DomainGlob,
    //     RegexMatch, MaxLength, GovernedIntentRequired,
    //     RequireApprovalAbove, SellerExact, MinimumRuntimeAssurance,
    //     MinimumAutonomyTier, Custom ...

    /// Restricts the tool to a set of allowed recipients.
    /// The kernel checks the `to`, `channel`, `recipient`, or `email`
    /// argument against this list before allowing invocation.
    RecipientAllowlist(Vec<String>),

    /// Requires content-review guard evaluation before invocation.
    /// The guard inspects the outbound message body for policy violations.
    /// The String value identifies which review policy to apply.
    ContentReviewRequired(String),
}
```

`RecipientAllowlist` is enforced by the kernel during constraint matching.
`ContentReviewRequired` triggers the content-review guard pipeline described
in section 7.

## 3. Communication Platforms

Slack, Discord, Teams, Email (SendGrid/SES), SMS (Twilio).

### 3.1 Capability Grant Structure

A communication grant scopes three dimensions: which channels/recipients,
what content policies apply, and how fast the agent can send.

```json
{
  "grants": [
    {
      "server_id": "slack-server",
      "tool_name": "send_message",
      "operations": ["invoke"],
      "constraints": [
        {
          "type": "recipient_allowlist",
          "value": ["#ops-alerts", "#deploy-log", "@oncall-bot"]
        },
        {
          "type": "content_review_required",
          "value": "slack-standard"
        },
        {
          "type": "max_length",
          "value": 4000
        }
      ],
      "max_invocations": 100
    }
  ]
}
```

For email, the grant narrows the recipient space and enforces content review:

```json
{
  "server_id": "email-server",
  "tool_name": "send_email",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "recipient_allowlist",
      "value": ["*@internal.example.com"]
    },
    {
      "type": "content_review_required",
      "value": "email-external"
    }
  ]
}
```

### 3.2 Deny Scenarios

**Scenario: PII leak to public channel.**
Agent calls `send_message` with `channel: "#general"` and body containing
a customer SSN (`123-45-6789`).

```
1. Kernel validates ToolGrant       -> ALLOW (channel in allowlist)
2. ContentReviewGuard scans body    -> DENY
   reason: "High-sensitivity pattern 'SSN' detected in outbound content"
   receipt: signed denial with redacted excerpt
```

**Scenario: recipient not in allowlist.**
Agent calls `send_message` with `channel: "#executive-board"`.

```
1. Kernel checks RecipientAllowlist -> DENY
   reason: "Recipient '#executive-board' not in allowlist
            [#ops-alerts, #deploy-log, @oncall-bot]"
```

**Scenario: rate limit exceeded.**
Agent has sent 95 messages in the last hour. VelocityGuard bucket is
configured for 100/hour.

```
1. Kernel validates ToolGrant       -> ALLOW
2. ContentReviewGuard               -> ALLOW
3. VelocityGuard checks bucket      -> ALLOW (95 < 100)
... 6 more sends ...
4. VelocityGuard checks bucket      -> DENY
   reason: "Rate limit exceeded: 101/100 per 3600s window"
```

### 3.3 VelocityGuard Configuration for Communication

The existing `VelocityGuard` (token bucket in `chio-guards/src/velocity.rs`)
applies directly. Communication-specific configuration:

```rust
VelocityGuard::new(VelocityConfig {
    // Per-grant bucket: 50 messages per hour, burst of 10
    capacity_tokens: 10,
    max_per_window: 50,
    window_secs: 3600,
})
```

For SMS (higher cost, higher annoyance), tighter limits:

```rust
VelocityGuard::new(VelocityConfig {
    capacity_tokens: 3,
    max_per_window: 10,
    window_secs: 3600,
})
```

## 4. Payment and Financial APIs

Stripe, Plaid, internal billing systems.

### 4.1 Anti-Self-Dealing: Separate Grants for Charge and Refund

A single capability must never grant both `charge` and `refund` operations.
An agent that can charge and refund can cycle money without oversight. The
kernel enforces this by rejecting `ToolGrant` issuance where both actions
coexist on the same server.

```json
[
  {
    "server_id": "stripe-server",
    "tool_name": "create_charge",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "require_approval_above",
        "value": { "threshold_units": 10000 }
      }
    ],
    "max_cost_per_invocation": { "units": 50000, "currency": "USD" },
    "max_total_cost": { "units": 500000, "currency": "USD" }
  },
  {
    "server_id": "stripe-server",
    "tool_name": "create_refund",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "require_approval_above",
        "value": { "threshold_units": 5000 }
      }
    ],
    "max_cost_per_invocation": { "units": 25000, "currency": "USD" },
    "max_total_cost": { "units": 100000, "currency": "USD" }
  }
]
```

These grants live on **separate capability tokens** issued to different
agent identities or requiring different approval chains.

### 4.2 Approval Thresholds

The existing `RequireApprovalAbove` constraint triggers the kernel's
approval flow. For financial APIs, this is mandatory:

```
Agent requests: create_charge(amount: 15000, currency: "USD")

1. Kernel validates ToolGrant               -> ALLOW
2. Kernel evaluates RequireApprovalAbove    -> amount 15000 >= threshold 10000
   -> PENDING_APPROVAL
3. Kernel creates ApprovalRequest:
   {
     "tool": "create_charge",
     "amount": {"units": 15000, "currency": "USD"},
     "agent": "agent-billing-01",
     "awaiting": "finance-approver"
   }
4. Human approves via dashboard             -> receipt signed with approver key
5. Kernel retries evaluation                -> ALLOW
6. Tool executes, receipt includes approval chain
```

### 4.3 Receipts as Financial Audit Trail

Every financial action produces a receipt that chains into the Merkle log.
The receipt includes:

- The exact charge/refund amount and currency
- The capability token ID that authorized it
- The approval chain (if RequireApprovalAbove triggered)
- The tool server's response (transaction ID, status)
- Timestamp, agent identity, kernel signature

```json
{
  "receipt_id": "rcpt_7f3a...",
  "tool": "create_charge",
  "arguments_hash": "sha256:ab12...",
  "result_hash": "sha256:cd34...",
  "capability_id": "cap_9e8d...",
  "approval_chain": ["approver_key_5f6a..."],
  "amount": {"units": 15000, "currency": "USD"},
  "timestamp": 1713200000,
  "kernel_signature": "sig_..."
}
```

This receipt is admissible as an audit record: it proves who authorized what,
when, and under which capability.

### 4.4 Deny Scenarios

**Scenario: charge exceeds per-invocation cap.**

```
Agent requests: create_charge(amount: 75000, currency: "USD")

1. Kernel checks max_cost_per_invocation    -> 75000 > 50000
   -> DENY: "Amount 75000 USD exceeds per-invocation cap of 50000 USD"
```

**Scenario: aggregate spend exhausted.**

```
Agent has charged 480000 USD across prior invocations.
Agent requests: create_charge(amount: 25000, currency: "USD")

1. Kernel checks max_total_cost             -> 480000 + 25000 = 505000 > 500000
   -> DENY: "Aggregate cost 505000 USD would exceed total cap of 500000 USD"
```

**Scenario: agent attempts charge + refund cycle.**

```
Agent holds capability with grants for both create_charge and create_refund.

1. Capability Authority rejects issuance    -> DENY at token creation time
   reason: "Anti-self-dealing: charge and refund grants must not coexist
            on the same capability token"
```

## 5. Monitoring and Incident Platforms

PagerDuty, OpsGenie, Datadog, Sentry.

### 5.1 Severity-Level Caps

Agents should be able to create low-severity incidents autonomously but
require approval for high-severity pages that wake humans.

```json
{
  "server_id": "pagerduty-server",
  "tool_name": "create_incident",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "custom",
      "value": ["max_severity", "P3"]
    },
    {
      "type": "content_review_required",
      "value": "incident-validation"
    }
  ]
}
```

A separate, higher-privilege capability with approval:

```json
{
  "server_id": "pagerduty-server",
  "tool_name": "create_incident",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "custom",
      "value": ["max_severity", "P1"]
    },
    {
      "type": "require_approval_above",
      "value": { "threshold_units": 0 }
    },
    {
      "type": "content_review_required",
      "value": "incident-validation"
    }
  ]
}
```

The `threshold_units: 0` means every P1/P2 incident requires human approval
regardless of any monetary dimension.

### 5.2 Service-Scoped Capabilities

Monitoring capabilities are scoped to specific services to prevent an agent
responsible for service A from creating incidents for service B:

```json
{
  "server_id": "pagerduty-server",
  "tool_name": "create_incident",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "custom",
      "value": ["service_id", "PSVC_payment_api"]
    },
    {
      "type": "custom",
      "value": ["max_severity", "P3"]
    }
  ]
}
```

### 5.3 Content Validation for Incidents

The content-review guard for incident platforms validates that page content
is consistent with actual system state. The `incident-validation` review
policy:

- Requires a `source_metric` or `source_alert_id` field linking the
  incident to an observable signal
- Rejects pages where the description contains no structured evidence
- Flags pages where severity does not match the linked metric's threshold

```
Agent requests: create_incident(
  service: "payment_api",
  severity: "P2",
  title: "Payment API latency spike",
  description: "Latency is high",      // no evidence
  source_metric: null                   // no link
)

1. ContentReviewGuard (incident-validation) -> DENY
   reason: "Incident must include source_metric or source_alert_id.
            Description lacks structured evidence."
```

### 5.4 Deny Scenarios

**Scenario: severity exceeds cap.**

```
Agent holds P3-capped capability.
Agent requests: create_incident(severity: "P1", ...)

1. SeverityCapGuard checks max_severity     -> P1 > P3
   -> DENY: "Severity P1 exceeds cap P3 for this capability"
```

**Scenario: wrong service scope.**

```
Agent holds capability scoped to service "payment_api".
Agent requests: create_incident(service: "auth_service", ...)

1. Kernel checks Custom("service_id") constraint -> "auth_service" != "PSVC_payment_api"
   -> DENY: "Service 'auth_service' not covered by this capability"
```

## 6. Project Management Platforms

Jira, Linear, GitHub API, Notion.

### 6.1 Read vs Write Scoping

Project management grants use the existing `Operation` enum to separate
read-only access from write operations:

```json
[
  {
    "server_id": "jira-server",
    "tool_name": "search_issues",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "custom",
        "value": ["project_key", "ENG"]
      }
    ]
  },
  {
    "server_id": "jira-server",
    "tool_name": "create_issue",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "custom",
        "value": ["project_key", "ENG"]
      },
      {
        "type": "content_review_required",
        "value": "jira-content"
      }
    ],
    "max_invocations": 20
  }
]
```

### 6.2 Transition Guards

Agents should not be able to move tickets to terminal states (Done, Closed)
without meeting defined criteria. A transition guard inspects the
`transition` argument:

```json
{
  "server_id": "jira-server",
  "tool_name": "transition_issue",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "custom",
      "value": ["blocked_transitions", "Done,Closed,Released"]
    },
    {
      "type": "custom",
      "value": ["project_key", "ENG"]
    }
  ]
}
```

An agent with this grant can move issues through In Progress, In Review,
and QA -- but cannot close them.

A higher-privilege grant allows terminal transitions with approval:

```json
{
  "server_id": "jira-server",
  "tool_name": "transition_issue",
  "operations": ["invoke"],
  "constraints": [
    {
      "type": "require_approval_above",
      "value": { "threshold_units": 0 }
    }
  ]
}
```

### 6.3 GitHub: PR Creation vs Merge Restrictions

An agent can create pull requests autonomously but must not merge to
protected branches:

```json
[
  {
    "server_id": "github-server",
    "tool_name": "create_pull_request",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "custom",
        "value": ["repo", "backbay/platform"]
      },
      {
        "type": "content_review_required",
        "value": "github-pr-description"
      }
    ]
  },
  {
    "server_id": "github-server",
    "tool_name": "merge_pull_request",
    "operations": ["invoke"],
    "constraints": [
      {
        "type": "custom",
        "value": ["repo", "backbay/platform"]
      },
      {
        "type": "custom",
        "value": ["protected_branch_block", "main,release/*"]
      },
      {
        "type": "require_approval_above",
        "value": { "threshold_units": 0 }
      }
    ]
  }
]
```

### 6.4 Deny Scenarios

**Scenario: merge to protected branch.**

```
Agent requests: merge_pull_request(repo: "backbay/platform", base: "main", pr: 1234)

1. Kernel checks Custom("protected_branch_block") -> "main" in blocked list
2. RequireApprovalAbove(0)                         -> requires approval
   -> PENDING_APPROVAL
3. Human reviewer approves (or denies)
```

**Scenario: create issue in wrong project.**

```
Agent requests: create_issue(project: "FINANCE", ...)

1. Kernel checks Custom("project_key")     -> "FINANCE" != "ENG"
   -> DENY: "Project 'FINANCE' not covered by this capability"
```

## 7. Content-Review Guard

The content-review guard is a new pre-invocation guard type. It inspects
tool call arguments for outbound content and evaluates it against
configurable policies. It reuses PII detection patterns from the existing
`ResponseSanitizationGuard` in `chio-guards/src/response_sanitization.rs`
but applies them to **inputs** (outbound content) rather than outputs
(inbound responses).

### 7.1 Architecture

```
ToolCallRequest arrives at Kernel
        |
        v
  ToolGrant validation (scope, constraints, time bounds)
        |
        v
  ContentReviewGuard (pre-invocation)
    1. Extract outbound content from arguments
    2. Look up review policy by ContentReviewRequired constraint value
    3. Run policy checks: PII scan, tone check, confidentiality markers
    4. Return Verdict::Allow, Verdict::Deny, or Verdict::Escalate
        |
        v
  VelocityGuard (rate limiting)
        |
        v
  Tool execution (if all guards allow)
        |
        v
  PostInvocationHook (response sanitization, receipt signing)
```

### 7.2 Review Policies

A review policy is a named configuration that specifies which checks to run
and at what sensitivity:

```rust
/// A named content-review policy applied before tool invocation.
#[derive(Debug, Clone)]
pub struct ContentReviewPolicy {
    /// Policy identifier (matches ContentReviewRequired constraint value).
    pub name: String,
    /// Which argument fields contain outbound content to inspect.
    pub content_fields: Vec<String>,
    /// PII detection settings.
    pub pii_config: PiiReviewConfig,
    /// Tone and profanity detection settings.
    pub tone_config: ToneReviewConfig,
    /// Confidentiality marker detection.
    pub confidentiality_config: ConfidentialityConfig,
    /// Minimum ActionVisibility level that triggers this policy.
    /// Policies can be scoped to only apply above a visibility threshold.
    pub minimum_visibility: ActionVisibility,
}

/// PII detection configuration for content review.
#[derive(Debug, Clone)]
pub struct PiiReviewConfig {
    /// Reuse patterns from ResponseSanitizationGuard.
    pub patterns: Vec<SensitivePattern>,
    /// Action on detection: block the entire request or redact and allow.
    pub action: SanitizationAction,
    /// Minimum sensitivity level to trigger (Low, Medium, High).
    pub minimum_level: SensitivityLevel,
}
```

### 7.3 Content Field Extraction

The guard extracts outbound content from tool arguments by field name.
For `send_message`, the content lives in `body` or `text`. For
`send_email`, it spans `subject`, `body`, and `html_body`.

```rust
impl ContentReviewGuard {
    fn extract_content(
        &self,
        policy: &ContentReviewPolicy,
        arguments: &serde_json::Value,
    ) -> Vec<(String, String)> {
        let mut fields = Vec::new();
        for field_name in &policy.content_fields {
            if let Some(value) = arguments.get(field_name) {
                if let Some(text) = value.as_str() {
                    fields.push((field_name.clone(), text.to_string()));
                }
            }
        }
        fields
    }
}
```

### 7.4 PII Detection (reuse from response_sanitization)

The content-review guard reuses the same `SensitivePattern` definitions
from `chio-guards/src/response_sanitization.rs`: SSN, email, phone, credit
card, and medical record patterns. The difference is directionality:

- `ResponseSanitizationGuard`: post-invocation, scans tool **output**
  before delivery to the agent.
- `ContentReviewGuard`: pre-invocation, scans tool **input** before the
  agent's message reaches the external world.

```rust
fn check_pii(
    content: &str,
    config: &PiiReviewConfig,
) -> Vec<ContentViolation> {
    let mut violations = Vec::new();
    for pattern in &config.patterns {
        if pattern.level >= config.minimum_level {
            if pattern.regex.is_match(content) {
                violations.push(ContentViolation {
                    check: "pii",
                    pattern_name: pattern.name.clone(),
                    level: pattern.level,
                    // Never include the matched text in the violation --
                    // that would leak the PII into the receipt log.
                    excerpt: "[match redacted]".to_string(),
                });
            }
        }
    }
    violations
}
```

### 7.5 Tone and Profanity Detection

Basic pattern matching for inappropriate tone. This is not a sentiment
analysis model -- it is a blocklist of patterns that should never appear
in agent-generated external communications.

```rust
#[derive(Debug, Clone)]
pub struct ToneReviewConfig {
    /// Blocked word/phrase patterns (case-insensitive regex).
    pub blocked_patterns: Vec<Regex>,
    /// Whether to block or just flag (advisory mode).
    pub enforcement: ToneEnforcement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToneEnforcement {
    /// Block the request on match.
    Block,
    /// Allow but attach an advisory signal to the receipt.
    Advisory,
}
```

### 7.6 Visibility-Keyed Guard Strictness

The `ActionVisibility` level on the `ExternalApiCall` variant determines
which review policies activate and at what strictness:

| Visibility | PII Check | Tone Check | Approval |
|------------|-----------|------------|----------|
| Internal | Medium+ sensitivity | Advisory | No |
| External | Low+ sensitivity | Block | Per policy |
| Financial | Low+ sensitivity | Block | RequireApprovalAbove |

Guards that see `ActionVisibility::Financial` always escalate to the
strictest review path. Guards that see `ActionVisibility::Internal` run
checks in advisory mode -- violations are logged in the receipt but do
not block execution.

### 7.7 Guard Implementation Sketch

```rust
impl Guard for ContentReviewGuard {
    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        // 1. Check if this tool call has a ContentReviewRequired constraint
        let policy_name = match ctx.active_constraint::<ContentReviewRequired>() {
            Some(name) => name,
            None => return Ok(Verdict::Allow),
        };

        // 2. Look up the policy
        let policy = self.policies.get(&policy_name)
            .ok_or_else(|| KernelError::GuardError(
                format!("Unknown content review policy: {policy_name}")
            ))?;

        // 3. Extract content fields from arguments
        let fields = self.extract_content(policy, &ctx.arguments);
        if fields.is_empty() {
            // No content fields found -- fail closed
            return Ok(Verdict::Deny {
                reason: "ContentReviewRequired but no content fields found \
                         in arguments".to_string(),
            });
        }

        // 4. Run PII check
        let mut all_violations = Vec::new();
        for (field_name, content) in &fields {
            let pii_hits = check_pii(content, &policy.pii_config);
            for v in pii_hits {
                all_violations.push(v.with_field(field_name));
            }
        }

        // 5. Run tone check
        for (field_name, content) in &fields {
            let tone_hits = check_tone(content, &policy.tone_config);
            for v in tone_hits {
                all_violations.push(v.with_field(field_name));
            }
        }

        // 6. Decide verdict
        if all_violations.iter().any(|v| v.blocks()) {
            return Ok(Verdict::Deny {
                reason: format!(
                    "Content review failed: {}",
                    all_violations.iter()
                        .filter(|v| v.blocks())
                        .map(|v| v.summary())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            });
        }

        // Non-blocking violations become advisory signals on the receipt
        if !all_violations.is_empty() {
            return Ok(Verdict::AllowWithAdvisory {
                signals: all_violations.into_iter()
                    .map(|v| v.to_advisory_signal())
                    .collect(),
            });
        }

        Ok(Verdict::Allow)
    }
}
```

## 8. SDK Patterns (Python)

### 8.1 Decorators for Content-Reviewed Tools

The Python SDK provides decorators that register tools with content-review
policies and recipient constraints:

```python
from chio_sdk import tool, content_review, recipient_allowlist, velocity_limit

@tool(server="slack-server")
@content_review(policy="slack-standard", fields=["text", "blocks"])
@recipient_allowlist(["#ops-alerts", "#deploy-log", "@oncall-bot"])
@velocity_limit(max_per_window=50, window_secs=3600)
async def send_slack_message(
    channel: str,
    text: str,
    blocks: dict | None = None,
) -> dict:
    """Send a message to a Slack channel."""
    return await slack_client.chat_postMessage(
        channel=channel,
        text=text,
        blocks=blocks,
    )
```

The decorators produce a `ToolGrant` with the corresponding constraints:

```python
# The above decorators generate:
ToolGrant(
    server_id="slack-server",
    tool_name="send_slack_message",
    operations=[Operation.INVOKE],
    constraints=[
        Constraint.RecipientAllowlist(["#ops-alerts", "#deploy-log", "@oncall-bot"]),
        Constraint.ContentReviewRequired("slack-standard"),
        Constraint.MaxLength(4000),
    ],
)
```

### 8.2 Financial Tool Decorators

```python
from chio_sdk import tool, require_approval_above, max_cost

@tool(server="stripe-server")
@require_approval_above(threshold_cents=10000)
@max_cost(per_invocation_cents=50000, total_cents=500000, currency="USD")
async def create_charge(
    amount: int,
    currency: str,
    customer_id: str,
    description: str,
) -> dict:
    """Create a Stripe charge."""
    return await stripe.Charge.create(
        amount=amount,
        currency=currency,
        customer=customer_id,
        description=description,
    )
```

### 8.3 Incident Platform Decorators

```python
from chio_sdk import tool, content_review, severity_cap

@tool(server="pagerduty-server")
@content_review(policy="incident-validation", fields=["title", "description"])
@severity_cap(max_severity="P3")
async def create_incident(
    service: str,
    severity: str,
    title: str,
    description: str,
    source_metric: str | None = None,
) -> dict:
    """Create a PagerDuty incident."""
    return await pagerduty_client.create_incident(
        service=service,
        severity=severity,
        title=title,
        body=description,
    )
```

### 8.4 GitHub Decorators

```python
from chio_sdk import tool, content_review, protected_branches

@tool(server="github-server")
@content_review(policy="github-pr-description", fields=["title", "body"])
async def create_pull_request(
    repo: str,
    head: str,
    base: str,
    title: str,
    body: str,
) -> dict:
    """Create a GitHub pull request."""
    return await github_client.pulls.create(
        owner=repo.split("/")[0],
        repo=repo.split("/")[1],
        head=head,
        base=base,
        title=title,
        body=body,
    )


@tool(server="github-server")
@protected_branches(blocked=["main", "release/*"])
@require_approval_above(threshold_cents=0)
async def merge_pull_request(
    repo: str,
    pr_number: int,
) -> dict:
    """Merge a GitHub pull request."""
    return await github_client.pulls.merge(
        owner=repo.split("/")[0],
        repo=repo.split("/")[1],
        pull_number=pr_number,
    )
```

## 9. Guard Pipeline Composition

A production deployment targeting SaaS integrations composes guards in a
specific order. The pipeline runs fail-closed: if any guard denies, the
request is denied.

```python
from chio_guards import (
    GuardPipeline,
    ContentReviewGuard,
    VelocityGuard,
    AgentVelocityGuard,
)

pipeline = GuardPipeline([
    # 1. Content review first -- cheapest to reject early
    ContentReviewGuard(policies={
        "slack-standard": slack_policy,
        "email-external": email_policy,
        "incident-validation": incident_policy,
        "jira-content": jira_policy,
        "github-pr-description": github_policy,
    }),
    # 2. Per-grant velocity (token bucket)
    VelocityGuard(default_config=velocity_config),
    # 3. Per-agent velocity (cross-grant)
    AgentVelocityGuard(config=agent_velocity_config),
])

kernel.add_guard(pipeline)
```

## 10. Receipt Log Integration

Every SaaS interaction -- allowed or denied -- produces a receipt in the
Merkle-committed log. Receipts for external API calls carry additional
metadata:

```json
{
  "receipt_id": "rcpt_a1b2...",
  "verdict": "allow",
  "tool": "send_message",
  "action_visibility": "external",
  "service": "slack",
  "content_review": {
    "policy": "slack-standard",
    "pii_detected": false,
    "tone_flags": [],
    "advisory_signals": []
  },
  "recipient": "#ops-alerts",
  "capability_id": "cap_c3d4...",
  "timestamp": 1713200000,
  "kernel_signature": "sig_..."
}
```

For denied requests, the receipt includes the denial reason and the guard
that denied, but never includes the raw content (to avoid leaking sensitive
data into the audit log).

## 11. Open Questions

1. **LLM-based content review.** Pattern matching catches known PII formats
   but misses semantic leaks ("the patient in room 302 has diabetes"). Should
   the content-review guard support an optional LLM evaluation step for
   `External` and `Financial` visibility levels? What are the latency and
   cost implications?

2. **Approval UX for high-frequency tools.** If an agent sends 50 Slack
   messages per hour and each requires human approval, the human becomes the
   bottleneck. Should there be a "batch approval" mode where a human approves
   a content policy rather than individual messages?

3. **Cross-service correlation.** An agent that reads from a database and
   then sends the result via Slack may leak data even if both individual
   actions are allowed. Should the `BehavioralSequenceGuard` track
   cross-service data flow patterns?

4. **Webhook-triggered revocation.** If Slack reports a message was flagged
   by its own content policies, should that trigger automatic revocation of
   the agent's communication capability?

5. **Multi-tenant content policies.** In a multi-tenant deployment, each
   tenant may have different PII sensitivity thresholds and tone policies.
   How should per-tenant policy configuration integrate with the guard
   pipeline?
