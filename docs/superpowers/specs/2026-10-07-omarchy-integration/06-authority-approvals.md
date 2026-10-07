# Authority, threat model and exact approvals

Status: Proposed. Confidence: high on the required boundary; implementation
availability varies by native prerequisite. Dependencies: [source readiness](research/chio-readiness.md),
[host contracts](07-host-provider-adapters.md), [Linux](08-linux-confinement.md).
The canonical Chio protocol remains [spec/PROTOCOL.md](../../../../spec/PROTOCOL.md).
This document defines an application profile, not a competing signature format.

## Protected assets and principals

Assets: operator credentials; kernel signing/capability authority; native outcome
and budget journals; original project bytes; scoped resource generations; model
context; private receipts; approval decisions; and the ability to stop new work.
Principals: desktop operator, installed desktop plugins, controller, trusted host
parent, confined guest, native authority, resource owner and model provider.

The default profile trusts the logged-in desktop user, installed shell plugins,
kernel and qualified native owners. It distrusts agent-generated content, model
outputs, project instructions, resource inputs, provider replies and imported
artifacts until independently verified. A compromised same-UID desktop plugin is
outside the initial isolation claim. Socket modes/peer UID checks are user-level
access controls, not isolation among those plugins.

| Threat | Required barrier | Residual boundary |
| --- | --- | --- |
| Agent reads operator/provider keys | Guest mount, descriptor, environment and network closure | Trusted parent and OS remain in TCB |
| Agent bypasses tools through shell/network/desktop sockets | Qualified whole-guest confinement and fixed tool inventory | Resource server also needs its own bounded effect surface |
| Prompt injection requests broader authority | Policy/grants selected outside model, denied widening | Helpful task completion still depends on model behavior |
| Fake model success or forged output | Native bound receipt verification and resource observation | Receipt attests its stated claim, not arbitrary truth |
| UI stale approval or substituted arguments | Exact proposal digest, native decision verifier and atomic consume | Trusted desktop user interaction assumed |
| Restart repeats an effect | Durable original operation and native recovery fencing | Unknown external outcome can require manual reconciliation |
| Concurrent cancellation/approval | Native admission linearization and exact operation binding | Already committed effects cannot be recalled |
| Arbitrary desktop plugin accesses same-user files | No protection claimed in default profile | Stronger principal separation is a separate future profile |

## Authority lifecycle

An operator chooses a named, publisher-reviewed profile. A qualified provisioning
owner issues bounded authority and returns an opaque reference plus signed public
bindings. The controller stores references and public bindings; it never issues a
capability merely because a QML control is clicked. The guest receives only the
ephemeral or delegated transport authority its existing host contract permits.

The binding includes authority identity, subject/process, resource owner and
generation, tool inventory digest, provider/model profile, governance selection,
limits identity and expiry. Any resume rechecks these exact bindings, current
revocation and original native outcome. Disagreement is refusal; no automatic
new session or grant restores availability.

Files, tools, context disclosure, provider requests, execution limits and child
delegation are separate capability dimensions. A grant to read a resource is not
permission to publish its contents to a model or clipboard. The execution-only
profile discloses its limited coverage; required information-flow governance
remains unavailable until its native services qualify.

## Exact proposal and review

The native owner creates a proposal bound to the original operation. Required
semantic fields, using native canonical formats, are: proposal identity,
authority/session/process binding, native operation ID, tool/resource identity,
argument digest, input generation, destination digest, policy version, budget
reservation, not-before/expiry and one-time decision binding. Some operations
have no publication destination; that absence is explicit and signed.

The controller verifies native authenticity and projects a bounded review view.
It does not invent a proposal from a model's explanation. The reviewer retrieves
the authoritative native proposal through the trusted operator path and verifies
the same digest before collecting a choice. The panel's `review.open` requests
that review; it cannot authorize by passing `approved: true`.

`approval.submit` carries an opaque decision handle produced by the qualified
reviewer/native operator. A handle is not a bearer that grants arbitrary future
actions. The native authority validates exact requested decision, proposal,
subject, operation, arguments, expiry and current revocation before retaining or
consuming it. A mismatched approved token returned for a requested denial must
be rejected before any approval is retained. The present candidate's refusal of
`approval-decide` is a required P3 blocker, not a UI feature to work around.

Review text must distinguish original content, escaped untrusted explanation,
exact action summary and independently verified bindings. Render plain text,
not executable HTML or terminal escape sequences. A hidden/redacted secret
parameter must be represented by an operator-verified description and its bound
digest; if the operator cannot meaningfully review the action, the profile does
not offer approval. UI trimming must disclose omitted content and require full
trusted review before a consequential decision.

## Approval state machine

Native proposal states: `pending`, `approved`, `denied`, `expired`, `invalidated`,
`consumed`. They are distinct from task states. Pending review does not dispatch
the resource. An approved proposal does not mean executed. Consumption joins the
native admission and original operation; crashes recover that original.

Only the native owner decides transitions. It serializes competing decisions,
requires current policy and revocation, and invalidates changed resource/argument
bindings. A late click after expiry or task cancellation cannot restore authority.
On an untrusted clock anomaly, stop new admission and revalidate expiry with the
native authority. Restart must not extend proposal lifetime.

The first profile requires one explicit operator decision per exact proposal.
No approve-all, remembered broad approval or model-driven automatic approval.
This is a profile choice, not a limitation imposed on the general Chio protocol.
Lock-screen notifications contain no task details and never offer an approve
action. Loss of trusted review availability leaves the native proposal pending
or expired; it never defaults to permission.

## Cancellation and emergency stop

The stop action first requests native refusal of new admissions and records its
linearization result, then requests provider abort and guest/resource process
termination through their actual lifecycle owners. UI distinguishes:
`admissions_stopped`, `guest_exit_observed`, `provider_abort_requested` and
`outcome_reconciliation_required`. A PID signal alone does not establish any
native outcome. Previously admitted effects may finish. No stop operation
rewrites receipts or classifies an unknown effect as absent.

On failed cancellation transport, display unconfirmed stop and keep the task
visible. A local emergency process kill can contain further guest activity, but
its receipt must not claim native capability revocation. Re-enablement requires
native reconciliation, not a new guest profile.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-AUT-001 | The declared trust profile MUST match actual principal and same-UID boundaries. | AT-AUT-001 |
| OM-AUT-002 | Authority MUST be provisioned by the selected native owner and bound to the exact task/resource/profile. | AT-AUT-002 |
| OM-AUT-003 | All consequential guest paths MUST be mediated or independently confined. | AT-AUT-003 |
| OM-AUT-004 | A proposal MUST bind the exact original operation, arguments, resource generation, policy, limits and validity. | AT-AUT-004 |
| OM-AUT-005 | Native decision validation MUST precede retention, rejecting a decision different from the operator's choice. | AT-AUT-005 |
| OM-AUT-006 | Approval consumption MUST be one-time and recover by original operation under concurrent/replayed requests. | AT-AUT-006 |
| OM-AUT-007 | Stale, expired, revoked or cancelled proposals MUST refuse without authority widening. | AT-AUT-007 |
| OM-AUT-008 | Reviewer presentation MUST separate verified bindings from untrusted content and disclose truncation. | AT-AUT-008 |
| OM-AUT-009 | Stop controls MUST report admission, process and effect outcomes independently. | AT-AUT-009 |
| OM-AUT-010 | Execution-only and required disclosure governance MUST remain explicitly distinguishable. | AT-AUT-010 |

## Proposed acceptance

### AT-AUT-001: Threat-profile claim audit
Trigger: compare release claims against process users, mounts and channels.
Expected: no same-user plugin isolation claim; guest exclusion demonstrated.
Oracle: independent threat review and hostile guest. Artifact: `trust-profile.json`.

### AT-AUT-002: Binding substitution
Trigger: resume with changed signer, resource, provider, limits or authority.
Expected: refusal before provider/native effect. Oracle: independent counters
and retained unchanged bindings. Artifact: `authority-substitution.json`.

### AT-AUT-003: Complete guest action inventory
Trigger: file, shell, direct network, compositor, extension, delegation and
background probes alongside allowed work. Expected: no unmediated effect.
Oracle: outside sentinel files, listeners and process observer. Artifact:
`guest-action-inventory.json` with individual pass/fail, no silent skips.

### AT-AUT-004: Exact proposal tampering
Trigger: independently mutate each bound field and one nested argument byte.
Expected: rejection before execution. Oracle: authority verifier and resource
dispatch observer. Artifact: `proposal-binding-negatives.json`.

### AT-AUT-005: Requested deny cannot retain approve
Trigger: native bridge returns signed approval when operator requested denial,
and the inverse case. Expected: reject before retention, no reusable token.
Oracle: separately read native decision store and effect log. Artifact:
`decision-before-retention.json`.

### AT-AUT-006: One-time consume and crash recovery
Trigger: concurrent consumes and crash after resource effect before UI reply.
Expected: one original effect or retained unknown, never second dispatch.
Oracle: native ledger plus resource effect counter. Artifact: `approval-consume.json`.

### AT-AUT-007: Invalidated review races
Trigger: expiry, ancestor revocation, changed generation and task cancel between
review open and decision. Expected: no effect, explicit invalidation. Oracle:
native admission record and unchanged resource sentinel. Artifact: `late-decision.json`.

### AT-AUT-008: Hostile review text
Trigger: injected markup, control sequences, bidi spoofing, oversized diff and
hidden secret fields. Expected: escaped bounded display and full-review gate;
no misleading action binding. Oracle: UI capture and digest comparison with
native proposal. Artifact: `review-presentation.json`.

### AT-AUT-009: Honest emergency stop
Trigger: stop before admission, during provider request and after resource
commit; also lose cancellation reply. Expected: independently classified states
and retained uncertainty. Oracle: native ledger, process watcher and resource
counter. Artifact: `stop-cutpoints.json`.

### AT-AUT-010: Disclosure governance availability
Trigger: choose required governance without native release service, then use
execution-only. Expected: required refuses before credentials/egress; alternate
profile has explicit narrower claim. Oracle: provider listener and UI capture.
Artifact: `governance-selection.json`.
