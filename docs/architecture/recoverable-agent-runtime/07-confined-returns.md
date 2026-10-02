# Confined readers and constrained child returns

## Two distinct forms of delegation

Ordinary child processes retain current capability attenuation, ancestry, aggregate budgets and inherited flow/influence semantics. They are not a way to obtain a clean context after the parent has read restricted material.

A confined reader is an explicitly authorized separate observation domain. It receives only admitted seed input, a scoped read capability, a declared return contract and an operator-selected execution profile. It may observe sensitive data without exposing raw data to the parent. The parent receives only a separately authorized return or status projection.

This requires a new trusted `IsolationBoundaryV1`, not a caller-chosen session string. It binds parent/process ancestry, child principal and confined lineage, fresh host-issued epoch, capability attenuation, admitted seed artifacts, provider context identity, execution image/configuration, confinement evidence, return contract and aggregate resource limits.

The economic/delegation ancestry remains connected to the parent. The observation lineage can branch only through this verified boundary. Current `ProcessSecurityProfile` and its root-based context derivation must be extended by an explicit validated boundary type; no general setter may reset lineage state. Parent data passed as seed remains labeled and contributes to child restrictions.

All parent-influenced child inputs are releases from the parent's current knowledge context: prompt text, seed selection, resource names, arguments, requested tools, filenames, environment, callback routing and observable launch metadata. Merely passing an artifact with a public label does not make a tainted parent's chosen message public. These channels retain the applicable parent confidentiality/influence join unless exact scoped projection/endorsement authority permits narrower input. Host-fixed templates may be treated separately only when their lack of parent influence is established. A new lineage or provider conversation is never itself a declassification operation.

## Launch and execution

Proposed lifecycle: `Reserved` -> `LaunchPrepared` -> `EnforcedRunning` -> `ReturnStaged` -> `ReturnAdmitted` -> `Closed`, with `Failed`, `Cancelled` and `Quarantined` dispositions retaining evidence. The host reserves deterministic child identity and limits before launch. Replays recover the same child/boundary; duplicate spawn commands cannot create a second fresh context.

Before accepting sensitive input, the host verifies the selected cage/broker execution identity and enforcement evidence. The exact profile covers filesystem, network, credentials, tool invocation and model-provider egress. A declaration of isolation or separate process ID is insufficient. If the platform cannot demonstrate the required profile, the confined remedy is unavailable; the system may offer an ordinary restricted child as a differently named operation only if policy permits it.

Use new provider conversation/context identity or a verified empty context under the profile. Do not reuse a contaminated provider-side cache and call the child clean. A process restart restores the same boundary and retained knowledge. A replacement launch needs a new measured execution epoch bound to the existing logical child; it does not reset observations or authorize another unresolved tool effect.

## Return contracts

`ReturnContractV1` binds child and parent recipient, schema and byte/cardinality limits, confidentiality target and acceptable influence/evidence requirements, projection/transform identity, permitted status channel, success/error behavior, stream policy, expiry and authority policy. The parent selects only from operator-registered contracts. A freeform “please return a safe summary” prompt is not a return contract.

The child stages an immutable return artifact and producer evidence. The host verifies exact child/boundary identity, active parent authority, schema/size, source join, transform evidence and any required declassification/endorsement. It then commits return admission and the parent's appropriate knowledge transition before bytes become visible. A retained `ReturnAdmissionV1` binds both sides and exact artifact/version; duplicate delivery recovers the same admitted return without a second disclosure grant consumption.

The child retains its full observed source restrictions. The parent retains its existing knowledge and joins the restrictions of the exact admitted return and its visible metadata. It need not inherit a source it never observed when verified projection/release authority establishes the return's narrower label. Without that evidence the return retains the full source join. Integrity follows the independently verified endorsement contract, never confidentiality authority alone. Redelivery rechecks the same recipient context and current read authority; a different parent, lineage or provider context is a new release requiring its own admission.

A schema constrains structure. It does not prove a statement true or authorize disclosure. A boolean can disclose a private predicate; a deterministic projection can reveal restricted data. The policy must explicitly authorize the exact projection or class of release and its recipients. Integrity assertions require evidence beyond valid JSON. Unknown provenance or unavailable transform evidence means withheld return.

## All channels

| Channel | Required treatment |
|---|---|
| Child tool values and errors | Retain within child; mediate every parent-visible projection |
| stdout/stderr/logging/tracing | Child-scoped classified sink, no direct parent forwarding |
| Progress and completion status | Contract-approved bounded status projection |
| Model prompts/responses/cache | Provider sink contract and same child context binding |
| Files, attachments, screenshots, generated artifacts | Immutable governed artifact references |
| Mailboxes and callbacks | Recipient-bound return admission before delivery |
| Crash reports and cancellation reasons | Classified diagnostics; generic safe parent status |
| Streaming tokens/chunks | Withhold by default; enable only under a qualified per-chunk release contract |

Termination after observing a secret does not make its error body public. A failed schema/transform cannot return the original bytes for debugging. Cancellation after an external child effect retains the original operation for reconciliation. Closing a child revokes future admission authority without claiming its already sent data or effects vanished.

## Budget, authority and restart

Child count, depth, model calls, tool calls, bytes, approval prompts and wall-clock deadlines consume explicit parent-tree limits. Recovery cannot evade them by repeatedly allocating new epochs or children. A denied child invocation still follows existing logical-call accounting.

The parent's authority to receive a return is rechecked at delivery. Parent cancellation/revocation withholds future returns and retains outcome evidence for an independently authorized operator. Expired return approval does not justify recomputing the child under a new identity to get a fresh opportunity. The caller requests a new workflow only through ordinary authority and resource accounting.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| ISO-01 | Ordinary child creation MUST preserve inherited knowledge and authority attenuation. | `isolation::ordinary_fork_cannot_clear_taint` | P5 |
| ISO-02 | A confined lineage/epoch MUST require host-issued boundary authority and admitted seed provenance. | `isolation::forged_boundary_and_seed_substitution` | P5 |
| ISO-03 | Sensitive observation MUST wait for verified enforcement and provider-context identity. | `isolation::unconfined_or_reused_provider_context` | P5 |
| ISO-04 | Return release MUST bind exact artifact, child, parent, boundary, policy and scoped authority. | `returns::cross_parent_and_cross_epoch_substitution` | P5 |
| ISO-05 | Parent knowledge MUST be committed before return bytes are delivered. | `returns::crash_before_and_after_parent_join` | P5 |
| ISO-06 | Success, failure, logs, progress, files and streams MUST share the declared release boundary. | `returns::alternate_channel_canary_campaign` | P5 |
| ISO-07 | Schema compliance MUST NOT substitute for disclosure or integrity authority. | `returns::well_typed_unauthorized_predicate` | P5 |
| ISO-08 | Restart, cancellation and duplicate spawn/return MUST preserve logical identity and consumed resources. | `isolation::restart_duplicate_and_cancel_cutpoints` | P5 |
| ISO-09 | The parent tree's budgets and limits MUST include confined work and its recovery. | `isolation::epoch_churn_cannot_escape_limits` | P5 |
| ISO-10 | Confined launch MUST mediate every parent-influenced seed, control and metadata channel using the parent's current knowledge. | `isolation::tainted_parent_control_channel_laundering` | P5 |
