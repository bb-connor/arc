# What Chio should replicate, and make better

The [second pass on current security/process code](security-branch-second-pass.md) implements a local flow prototype and refines operation identity: a remedy that changes an already frozen, terminally denied request needs an explicitly linked continuation. Pending approvals retain their native lifecycle, and uncertain effects retain their original identity.

This is a proposed design, not an implemented API or a release claim. It builds on the verified public source and separately identified development foundations in [the technical review](technical-review.md). Confidence: high in the product priorities; moderate in the implementation decomposition until a vertical slice exercises the actual host path.

**Build recoverable authority into Chio's modern Rust kernel for agentic operating systems.** An agent should be able to ask what legal action would accomplish its task, receive an exact bounded option, and execute that option through the same kernel that owns permission, budget, durable operation state, output mediation, and receipts.

The success criterion is observable: fewer unauthorized effects, more legitimate tasks completed, and less application code supervising capabilities, approvals, retries, and recovery. A larger list of security mechanisms is not an acceptance criterion.

## 1. Adoption decision

| Option | Benefit | Cost or unresolved issue | Recommendation |
|---|---|---|---|
| Embed OpenAPPA runtime as a mandatory dependency | Fast access to its complete semantics and recovery model | Two stores/lifecycles for offers, dispatch, effects, and approvals; different label algebra; preview compatibility; mediation still belongs to the host | Do not select yet |
| Use OpenAPPA only as an external decision service | Easy initial sidecar experiment | Allow/dispatch state gap; operation and grant ownership still need integration; a decision is not an execution permit | Useful only as a bounded lab comparator |
| Adapt the product ideas onto Chio primitives | One operation and authority lifecycle; preserves Chio semantics | We must build and test the recovery layer ourselves | Preferred direction |
| Share fixtures or a deliberately limited contract format | Makes comparisons and migration easier without a second enforcement authority | Needs explicit unsupported cases; cannot pretend the two lattices are identical | Pursue after the first slice |

The MIT license permits substantial reuse subject to its notice requirements. That makes source reuse possible; it does not make runtime adoption automatically cheaper. No production OpenAPPA code was imported in this research. [License](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/LICENSE.md).

A dependency decision can change if a small integration experiment demonstrates that embedding removes meaningful code while preserving one atomic admission/dispatch lifecycle and all relevant Chio restrictions. Require that evidence rather than choosing by aesthetic preference.

## 2. P0: actionable denials and exact remedy offers

### Replicate

OpenAPPA returns typed plans derived from actual policy mandates. Chio should attach comparable legal next actions to structured denial reasons. Start with a small, explicit remedy vocabulary:

| Remedy | Purpose | Authority boundary |
|---|---|---|
| Request exact disclosure approval | Permit these bytes to this tool/destination for this purpose | Existing owner authority and single-use declassification grant |
| Select a compatible destination | Complete the work through an already permitted internal sink | Normal sink/capability checks; no permission expansion |
| Apply a reviewed input transformation | Generate a new candidate that omits or transforms restricted data | Transformation identity, provenance, reclassification, then fresh admission |
| Obtain a prerequisite | Acquire a legitimate prior effect or required proof | The prerequisite is a new checked operation, not an implicitly authorized tool |
| Reconcile the original operation | Resolve an outcome-unknown dispatch safely | Exact operation identity and endpoint evidence; no generic retry |

Isolation and constrained returns come later. The initial planner should not become a general-purpose workflow generator, search arbitrary tool sequences, or promise every conceivable solution. An empty result means there is no remedy in its registered subset at this state, not that the task is metaphysically impossible.

### Improve

The remedy must join Chio's existing capture and execution lifecycle. The recovery service can inspect and propose; the kernel must revalidate and consume the resulting authority at the actual operation boundary. Do not make a previously returned `allow` value sufficient to dispatch later.

An offer should bind at least the following, using existing canonical identities where possible:

```text
proposed RemedyOfferV1
  offer identity and schema version
  original denial and logical operation identity
  tenant, principal, session, isolation epoch
  capability and relevant lineage
  canonical tool, arguments hash, payload/content hash
  source label and flow generation
  destination identity and purpose
  policy digest and semantic-contract digest
  authority or transformation identity
  expiration and relevant revocation/version basis
  required budget and execution-state preconditions
  typed remedy steps
  evidence references safe for the receiving audience
```

This is a design checklist, not a proposal to duplicate every kernel field into a parallel database. Store references and binding digests to existing records. The authority statement should cover the full exact operation identity, while fresh state checks remain the kernel's responsibility. An offer to approve a disclosure is also not itself an approval.

Recommendations and consumable offers must be different types. “Use the internal sink” may be sound advice even though that sink currently requires another capability. “Take this exact approval offer” has a concrete state-bound execution path. A transport timeout or missing classifier should produce an operational refusal with diagnostic next steps, not be converted into a policy denial or permission relaxation.

Retain accumulated taint after an approved send. A grant authorizes one crossing, not a new global source classification. Retry after a crash must resolve the same logical operation and consumption state; minting a new operation to get another use is not recovery.

### First slice and acceptance

Use **a private support ticket that must become a public issue**. The agent first proposes a disallowed public disclosure. Chio explains the source restriction and offers one exact owner-authorized disclosure or a compatible private destination. After approval, one public issue is created, with a receipt tying together the source, payload, recipient, grant, and operation.

Required acceptance cases:

1. Authorized private work succeeds without asking for unnecessary permission.
2. The unapproved public write produces no external effect.
3. Approval permits exactly the bound content and destination once.
4. Reuse, changed bytes, changed destination, expired authority, stale policy, revoked capability, exhausted budget, and changed flow generation are refused before dispatch.
5. Restart between grant issuance and consumption preserves the offer and grant lifecycle.
6. Restart after a possibly successful external dispatch returns an unknown/reconciliation state rather than blindly creating another issue.
7. A later public disclosure remains denied unless separately authorized.
8. Diagnostic text, transformation errors, receipts, and model-visible acknowledgements do not disclose the restricted source through a side channel outside the declared audience.

Record which assertions run through actual host dispatch and which are pure/kernel-level tests. A fake issue sink can prove the kernel path locally; a real provider run is a separate integration claim.

## 3. P0: policy examples that developers can run

### Replicate

OpenAPPA makes policy behavior reviewable through configuration checks and readable trajectories. Chio already has receipt replay and signature verification. Extend that surface with approachable authored scenarios and typed assertions rather than implementing a competing replay engine.

A proposed fixture should express source reads, operation proposals, expected allow/deny/refusal, expected remedies, authority consumption, output classification, and actual effect counts. It should be readable enough for a connector maintainer to understand why a policy change failed.

### Improve

Replay should exercise the real admission, grant consumption, operation, and result paths. Preserve distinctions between:

- a policy decision with stubbed data;
- a transformation contract checked with a fake sanitizer;
- a real transformation whose output has independently checked assertions;
- a signed retained operation/receipt being reconstructed;
- a host integration that physically blocked an effect.

This matters because OpenAPPA's convenient replay auto-approves an authority and can stand in for a sanitizer with unchanged bytes. That is useful for algebra testing; it does not prove a production redactor works.

Add mutation cases that break the claimed property: remove the second permission check, reuse a consumed grant, change a content hash, lose a restart record, admit raw child output, or clear a reservation on unknown outcome. The test must fail for the relevant mutation rather than merely reproduce the implementation's happy path.

Keep a benign counterpart beside each attack. A fixture that passes by rejecting every action should fail utility acceptance. Policy differences should report changed permissible effects and authority usage, not only changed strings or exit codes.

Any new CLI spelling remains a proposal until implemented. The existing public `chio replay` is the integration point; this report is not an instruction to run a nonexistent `chio policy test` command.

## 4. P1: semantic connector packs

### Replicate

Borrow OpenAPPA's battery concept: ship source and sink semantics for real tool sets, plus deterministic contract rules, membership lookups, approved transformation bindings, and tests. A connector should answer: who wrote this result, which readers may receive it, what trust does the operation require, where do its effects go, and which authority can permit an exception?

### Improve

Build this on Chio's manifests/policy registry and authority model. A package supplies assertions and executable integration code; the operator supplies the deployment's trusted bindings. Package identity and signatures prove which package was used, not that its claims about a provider ACL are correct.

Require:

- Canonical tool and argument schemas with explicit source/sink/output contracts.
- Contract versions and content digests bound into operation evidence.
- Operator-controlled meanings for principals, organizations, compartments, and provider groups.
- Membership evidence with scope, freshness, audience, and outage behavior.
- Explicit tool coverage: declared, bounded dynamic annotation, or refused.
- Root overrides shown in a resolved-policy explanation, with tests proving their intended precedence.
- Migration and rollback behavior for retained policy and operation records.

Prefer deterministic contracts for familiar structured provider operations. Keep dynamic annotators an explicit exceptional route with bounded mandates, pinned output, and no permissive fallback when they cannot answer. Do not equate a classifier's confidence with a proof of an opaque shell's real information flow.

Start with two connector families needed by the first workflows, such as support/ticket data and issue creation. These are candidate choices, not assertions that production provider integrations were tested here. Acceptance should include exact ACL queries and denied/allowed recipients under provider-native permissions.

## 5. P1: isolated readers and constrained return channels

### Replicate

A parent that needs a public fact should be able to delegate a sensitive read into a separate context and receive only an authorized, constrained result. OpenAPPA's recovery and return declarations make this much easier to understand than a raw “subagent isolation” capability.

### Improve

Connect the return contract to Chio's execution and flow evidence. In the inspected development implementation, principal, lineage, session, and isolation epoch all matter. A fresh session name must not erase information retained by a contaminated principal or inherited lineage. If a new isolated reader is required, its identity and epoch must be created through the existing isolation/authority rules, not through an arbitrary reset operation.

Check the entire parent/child exchange: spawn parameters, inherited context, provider requests where mediated, child tool outputs, success and error return bodies, logs, diagnostics, cancellation, and persisted checkpoints. A guarded final message does not help if raw content crossed earlier through another callback.

Use closed bounded types when possible and bind the return to its producing operation and policy. A boolean still conveys a bit; a schema is not a confidentiality proof or a semantic truth guarantee. Where the return intentionally discloses information beyond the child's label, the operator must authorize that projection or transformation and its output scope.

Acceptance needs both confidentiality and utility: the parent must complete a legitimate decision from the bounded return while an attempted instruction-bearing or unauthorized return is withheld. Include restart, forced child termination, malformed return, sanitizer failure, and hidden extra-channel tests. Target two actual host frameworks before claiming portability.

## 6. P1: durable artifact labels and provenance

### Replicate

Keep OpenAPPA's distinction between value output and file content output, including copy/move propagation and failure-body classification. Track version identity, content digest, source dependencies, producer operation, and label.

### Improve

The demonstrated gap is durability, not a different serialization format. Artifact provenance should survive runtime restart, reader restart, copy, checkpoint restore, and archive/recovery. Missing or corrupt label evidence must lead to restrictive unknown handling, not adoption as public simply because bytes exist on disk.

A durable database alone is insufficient: filesystem mutation and label publication need a recoverable protocol. At minimum, reserve the exact version/basis, stage bytes, retain mutation intent and label evidence, publish under a fenced writer, commit the observed version, and reconcile interruptions before exposing the artifact. Define the sequence precisely for the chosen storage backend; do not claim the filesystem and database magically share a transaction.

External writers require an explicit model: exclude them with enforceable ownership, detect digest/generation changes and refuse, or integrate their writes through the same authority path. Source inspection of a single-writer algorithm is not proof of safe concurrent mutation.

Acceptance cases should include private write → restart → public copy denial; inherited restrictions through rename and transfer; failed writes and informative stderr; changed content between check and use; links and descriptor substitution; database/bytes disagreement; restore of an older checkpoint; and a crash at every transition between staged bytes and published metadata.

Reuse Chio's existing operation capture, result publication, store fences, and recovery records where they fit. Durable principal-flow tables do not already prove durable per-artifact version semantics; inspect and test that boundary independently.

## 7. P1: evaluate useful authority, not just denials

Replicate the best part of OpenAPPA's evaluation approach: measure the work done, effects actually produced, and attacks that actually cross a boundary. Keep proposed harmful tool calls separate from dispatched harmful effects.

Build a small shared corpus around the first two workflows. For each task, retain a legitimate version, an adversarial version, and crash/retry variants. Candidate comparisons are an unguarded or ordinary-policy baseline, OpenAPPA with explicit matched policy, and Chio with equivalent authority and source/sink intent. Match actor model, prompts, tools, memberships, task budget, trial identities, and retry limits. Publish supported semantic differences rather than forcing a lossy policy translation.

Measure:

| Axis | Evidence |
|---|---|
| Unauthorized effects | Authority-side changed resources, recipients, and writes |
| Legitimate completion | Deterministic task/resource assertions where possible |
| Recovery usefulness | Which remedy was offered, selected, and successfully consumed |
| Authority scope | Grants used, approvals asked, refusals, and unnecessary escalations |
| Runtime failures | Missing evidence, dead runtime, lost response, unknown outcome, restart |
| Cost | Model tokens, external consults, latency, and kernel cost measured separately |
| Integration burden | Host supervisory code removed and behavior transferred to the kernel |
| Evidence quality | Exact source/policy/artifact versions and accessible traces |

Use repeated runs when making comparative performance or completion claims. Single-run tables are exploratory observations. Keep evaluator uncertainty and operational failures visible. Publish sanitized raw trace/effect evidence where possible, not only a large aggregate with an inaccessible archive.

A stronger Chio result would be: two unrelated workflows, two hosts, useful completion retained, no unauthorized effects in the stated corpus, and concrete host supervision deleted. It would still be corpus-bounded evidence, not a universal security theorem.

No paid agent evaluation was necessary to complete this research proposal, and none was run. The deterministic probe and 1,502 local upstream tests establish an initial baseline only.

## 8. P2: evidence-driven policy maintenance and observability

Replicate the feedback loop: an agent can report a confusing denial with a bounded explanation and correlation ID. A separate maintenance process can propose a policy diff, attach benign and adversarial replay cases, and submit it for normal operator review.

Improve it by tying the proposal to retained policy versions, authority evidence, rollout state, and rollback. A complaint must never function as a grant. A remote-service outage should be fixed as an operational fault rather than “solved” by broadening disclosure policy.

Export safe decision categories and bounded timing/cardinality metrics by default. Treat raw payloads, arguments, diagnostic bundles, and classified receipts as audience-governed data. Best-effort telemetry is useful for investigation; it cannot substitute for durable operation ownership or authenticated evidence.

## 9. Features and shortcuts to reject

- A second global enforcement engine whose approvals race Chio's actual dispatch.
- A naive `top`-to-`Top` label mapping or loss of owner/compartment restrictions.
- A new empty session, fork, or checkpoint used as a taint reset.
- Post-output redaction used to justify a pre-dispatch permission requirement.
- Shell syntax classification presented as filesystem/network confinement.
- Schema compliance presented as proof of truth or zero information leakage.
- Unknown outcomes presented as safe retries or generic exactly-once execution.
- A “zero attacks” headline without matched utility, effect evidence, and stated corpus.
- Preview-style incompatible changes to retained Chio operation and receipt schemas without migration planning.
- Automatic policy relaxation by the agent whose work was denied.

## 10. Implementation order and release boundary

1. **Choose the first host and workflow from current adoption work.** Inventory existing grant, flow, capture, replay, and host-dispatch paths; identify the one place that actually controls the effect.
2. **Implement the smallest remedy schema and exact disclosure path.** Include generation/expiry checks and one-time consumption from the outset. Keep unrelated planner kinds out of this first slice.
3. **Add authored trajectories to existing replay.** Prove benign completion, changed-content refusal, consumed-grant refusal, and interrupted-operation recovery with effect assertions.
4. **Package the connector semantics used by that workflow.** Make configuration and tool coverage understandable to a developer trying Chio.
5. **Add the second workflow and host.** Establish reusable contracts and meaningful deletion of application supervision.
6. **Then extend constrained isolation and durable artifact mediation.** Each needs independent physical-boundary and crash qualification.
7. **Run matched comparative evaluations and prepare public evidence.** Only then choose the dependency/compatibility strategy or claim a measured advantage.

The existing combined qualification work remains a prerequisite for production claims about its newer flow and Linux execution foundations. This proposal does not promote an incomplete acceptance record into a release. Public source, installation availability, supported host behavior, local checks, Linux qualification, and actual deployed behavior must each be stated at their own verified level.

The immediate architectural decision is clear: build the recovery experience around Chio's kernel contract. The comparative product claim remains open until that contract completes useful work through a real host.
