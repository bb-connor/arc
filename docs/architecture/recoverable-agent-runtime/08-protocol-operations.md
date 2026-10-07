# Protocol, deployment, migration and policy maintenance

## Shared host protocol

Rust owns authoritative decisions. Python/TypeScript/other SDKs carry generated closed wire types, authenticate the caller, expose typed decisions and preserve idempotency keys. They must not reimplement grant validation, label arithmetic, effect classification or a second retry coordinator.

Proposed commands are `CreateWorkflow`, `InspectWorkflow`, `ExplainIntent`, `SelectOffer`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow` and `ReportDecision`. Each command has a closed versioned body binding its authenticated actor, tenant/domain, command ID and applicable workflow revision. `CreateWorkflow` binds a creation idempotency key and expected absence, then returns the host-assigned workflow ID; it does not require a null placeholder for an identity not yet allocated. Other mutations bind their existing workflow ID and expected revision. Some commands are host/operator-only. Workers never select their own tenant, isolation profile, serving epoch or authority roots.

| Command | Authority and behavior |
|---|---|
| Create/inspect | Process-scoped recovery capability; explicit intent idempotency and audience-checked views |
| Explain | Read/consult authority for required facts; pure result with no effect ownership |
| Select | Process-scoped selection capability; exact retained offer and expected revision |
| Submit approval | Authenticated reviewer/issuer route; independently verified data-owner scope |
| Resume | Drives the retained continuation or reconciliation; never means resend blindly |
| Cancel | Stops future admissible work where possible; retains captured/unknown operation ownership |
| Report | Writes bounded classified feedback; cannot grant, mutate policy or execute a remedy |

An adapter sees `WaitingForApproval`, `WaitingForOutcome`, `ReconciliationRequired`, `Completed`, `CompletedWithEffects`, `Withheld`, `Refused` or `Quarantined`, with authorized references. A partially applied operation can be settled without successful task completion. Transport-level `202`, cancellation or timeout does not replace this semantic state. Delivery cursors are replayable projections over a bounded event stream. They neither allocate operations nor expose protected raw event bodies.

`CancelWorkflow` durably records cancellation intent with the workflow revision before acknowledging it. Selection and native capture check that intent inside their authoritative mutation. If capture wins the race, cancellation retains the operation for reconciliation; if cancellation wins, no later capture is authorized. `ResumeWorkflow` may recover an already captured result but never clears cancellation or silently chooses another step. Starting new work after cancellation requires an explicitly created workflow under normal authority and accounting.

CLI spellings such as `chio recovery inspect`, `chio recovery explain` and `chio recovery resume` are proposed product surfaces. Implement them over this protocol; do not create a CLI-only execution path. A resume command states whether it recovered a result, advanced a pre-effect step or remained uncertain. Avoid a generic force-retry command.

HTTP endpoints are service bases, including an optional mount path. Clients append the fixed relative `v1/recovery/...` routes below that path, treat slashless and slash-terminated bases as directories, and preserve encoded path segments. A root-only service base produces the existing `/v1/recovery/...` routes. The existing TLS, deadline, redirect and response-limit requirements apply to each resolved endpoint.

### Command replay order

1. Enforce envelope/resource bounds and authenticate the current actor. Derive tenant/domain and stable authorization context from that verified identity.
2. Derive the idempotency key from the stable actor scope, command kind and caller command ID. Keep a separate canonical semantic-body digest, including the original expected revision; rotating access tokens and transport nonces are not command identity.
3. Read the command ledger under the owning authority. Same key with different semantic content conflicts. A matching committed command is found before checking whether its original expected revision is now stale, otherwise a lost successful response would become an erroneous conflict.
4. For a new command, verify current mutation authority and expected revision in the authoritative transaction, then commit the transition and retained result reference together. `CommitUnknown` permits only exact readback/replay until resolved.
5. For every response, including command replay and notification redelivery, verify current read/audience authority and generate an authorized projection of the retained result. Do not cache and replay protected raw response bytes. Revoked callers may be refused even though their earlier command remains committed; no refund or reversal follows from that refusal.

Replaying a committed command does not reapply its mutation, increment quota or renew consent. An expected-revision check and a fresh authorization check have different roles and cannot be ordered interchangeably. Avoid revealing whether another audience's command key exists.

## Wire and signature discipline

All signed schemas live in the existing authoritative wire schema/code-generation system. Add bodies/envelopes for offers, action intents, grant v2, authority coverage, recovery events, explanations, semantic deployment bindings, artifact provenance, labeled checkpoints, isolation boundaries and return admission. Generate Rust/TypeScript/Python bindings and shared positive/negative vectors from the same sources.

Use closed tagged variants, explicit schema/domain version, canonical signed JSON and exact byte/hash verification. Unknown fields/versions/modes, null required bindings, unsafe integers, duplicates, unbounded arrays and noncanonical encodings refuse. Preserve the existing canonical parser rather than round-tripping through generic floating-point JSON. Identifiers are opaque bounded values; no arbitrary path/URL is authority.

The foundation decode profile bounds authoritative JSON to 65,536 UTF-8 bytes, depth 16, 4,096 nodes, 256 entries per container and 32,768 aggregate encoded string bytes. These limits apply together with each field's decoded UTF-8 bound and collection ceiling. A collection's maximum cardinality does not promise that every set of maximum-size members fits the enclosing allocation budget. Structural schema validation is not a substitute for these raw-wire, duplicate-member and canonical-encoding checks. SDKs must report their structural and native-profile checks separately rather than suggesting a parsed JavaScript number retains an integer token's original spelling.

The mediated `DecisionReportViewV1` and `PolicyMaintenanceViewV1` response profile permits at most 262,144 UTF-8 bytes and depth 64, so finite native audience labels that fit the protected product record remain transportable. For these two product views, the enclosing byte ceiling bounds node and string allocations; the foundation profile's separate 4,096-node, 32,768 aggregate encoded-string-byte and generic 256-entry-container ceilings do not apply. Generated closed field, decoded UTF-8 and collection bounds still apply. This profile rejects duplicate members, invalid Unicode, trailing data and recovery number tokens that are not canonical unsigned safe integers; it has no opaque-result exception. Other authoritative responses retain their foundation allocation profile.

The Chio schema profile requires `x-maxUtf8Bytes` to enforce a string's decoded UTF-8 byte ceiling. Each declaration must be a positive safe integer. Validators claiming this profile enforce the facet through local references and object property names, preserve valid Unicode and refuse strings that cannot be encoded as UTF-8. A generic JSON Schema validator that ignores this extension does not establish conformance to the byte profile.

Typed recovery counters require unsigned interoperable integer tokens. The owning receipt's arbitrary `metadata` and `action.parameters` fields use canonical signed I-JSON numbers, including safe signed integers and finite fractions. Their encoded bytes and structure remain charged to the foundation allocation profile.

`RecoveryCommandResultV1.original_response.result` is an opaque, mediated tool value, not signed recovery authority. Its number tokens may exceed JavaScript's safe-integer range. The complete command response is bounded to 262,144 UTF-8 bytes and depth 64 and rejects duplicate members, invalid Unicode and trailing data. The foundation profile still applies to its signed status and receipt metadata after replacing only the existing opaque result with `null` for validation. This projection must not insert a missing field, discard unknown metadata or derive an effect decision from the opaque result.

The TypeScript client's public `RecoveryCommandResult` carries `LosslessJsonValue` and an SDK-only `original_response.result_json` containing the exact original JSON value. Ordinary numeric tokens that survive a JavaScript JSON round trip stay numbers; other tokens use immutable `LosslessJsonNumber` values with an exact `source`. Integer literals support explicit `toBigInt()`, and `toNumber()` refuses decimal-value loss. Lossless wrappers reject ordinary JSON serialization; forward `result_json` when byte preservation matters. Go decoders retain opaque numbers as `json.Number`. Python retains arbitrary-size integer literals within the interpreter's digit-conversion limit and exposes immutable `LosslessJsonNumber` values for larger integers and fractional, exponent and negative-zero tokens, with exact `source`, `to_decimal()`, integer-literal `to_int()` and explicit `to_float()` that refuses precision loss. Python JSON and Pydantic serializers refuse implicit token conversion. None of these representations establishes execution or release authority, and they do not relax signed metadata's safe-integer rules.

Recovery profile negotiation is operator-selected and bound into deployment, capability/admission requirements and native participant evidence. A client cannot negotiate away a required recovery/artifact/isolation/integrity check. An old host that cannot enforce a required participant refuses the operation. It must not strip an extension and fall back to the legacy path.

## Deployment and protected setup

An enforced deployment profile binds protocol versions, authority/store identity, trust roots, policy/semantic package digests, coverage inventory, native capture support, required cage/broker evidence, clock policy, quotas, provider sink contracts and artifact backend. Startup validates the complete dependency closure before accepting work.

Guided setup resolves packages and identities, validates credentials through bounded checks, shows actual uncovered paths, runs a model-free benign/denied/restart self-test, and produces an authenticated deployment report. “Configuration parsed” is not successful protected setup. A protected launch fails visibly when its mediator/broker is unavailable; it does not silently start an unmediated conversation. Existing provider sessions require an explicit supported import/restore path or a new context.

Observational deployments may collect classified diagnostics and simulation reports, but advertise their weaker coverage explicitly and never mint live recovery grants that claim enforced mediation. Only qualified features are enabled in the profile. For example, ordinary recovery can precede confined readers; a contract requiring an unavailable confined return must refuse.

## Time, keys and policy changes

The initial proposed human-review window is at most 15 minutes, configurable downward. The offer/approval-intent validity deadline is explicit. An issuer signs a short-lived grant after consent and fresh basis checks; initial grant lifetime is at most 60 seconds, further capped by capability/authority/policy deadlines. These are design defaults to validate with user completion data, not measured usability results. Native preparation uses the existing short capture deadline and samples trusted time again at commit.

Expired review is a new explicit review operation, not silent renewal. Clock rollback, unavailable trusted time or incompatible time epochs refuse capture. Persisted deadlines use the selected trusted wall-time contract; process-local monotonic timers only bound waits. Restart cannot reset a grant's age.

Key rotation retains historical verification roots under the existing keyring policy while requiring currently authorized keys/scopes for new capture. Emergency revocation invalidates pending approvals and stops future captures. It does not rewrite captured outcomes. Retained grant/offer tombstones prevent identity reuse after key retirement. Policy rollback creates a new authenticated selection/version; it does not rewind the store or resurrect old offers.

### Settlement authority after expiry or cancellation

Historical verification and current execution authorization are different checks. The host's ordinary invoke API is not a universal recovery entry point: the process can be cancelled and its original capability can expire while native settlement remains necessary. Extend the kernel's existing fenced startup/reconciliation owner with a narrow, operator-authorized recovery scope over retained operation identities. It may verify historical participant evidence, reconcile owned reservations, retain outcome facts and repair projections. It cannot mint a continuation, refresh the caller's capability, clear cancellation or expose a dispatch handle.

External status lookup still requires current broker/connector authority for that exact provider/account and operation, a declared read-only effect contract and separately bounded recovery resources. Reserve that operational capacity independently of the initiating agent's spendable budget. Historical capture does not grant an unlimited provider credential or unlimited lookup budget. If lookup authority is revoked or unavailable, retain uncertainty until an operator restores an authorized observation path. Internal custody does not prove external outcome.

Distinguish four boundaries explicitly:

| Boundary | Required authority |
|---|---|
| New selection, preflight or capture | Current caller/capability, exact action and required live participants; cancellation forbids progress |
| Internal historical settlement | Current serving fence and narrow recovery scope; original authenticated capture/participant evidence, without demanding a newly live initiating grant |
| External status observation | Current scoped observation credential and recovery budget; original lookup identity and no effectful replay |
| Result or artifact release | Current recipient/read authority plus the applicable existing-return or separately admitted release contract |

An expired initiating grant neither invalidates the fact of an earlier authorized capture nor authorizes a new crossing now. Evidence invalidated by a compromised key needs the owning quarantine/repair policy, not blind acceptance because it is old. Removing a host profile must preserve a qualified historical settlement path or quarantine those operations. A revoked caller may receive no result even when the internal recovery service successfully settles the operation. Reconciliation progress cannot be implemented by replaying a fresh tool call with a maintenance credential.

## Migration and compatibility

Use explicit schema-version transitions under serving ownership. Before migration, stop new admissions, fence old writers and retain a verified backup/checkpoint. Inventory pending/unknown operations, historical grants, unclassified state and supported decoder versions. Migration must be restartable and byte-preserving for immutable historical requests and receipts. Verify the new protected participant/table inventory and rollback anchors before reopening.

Existing v1 grants remain interpretable only under their declared legacy profile. They cannot satisfy a new recovery-v2 requirement. A recovery operation cannot be downgraded by a proxy, older SDK or old server. Preserve old process request derivation and original signed request bytes; new reservation/binding tables reference them without rewriting history. An existing unknown operation is reconciled under its original version/profile, or quarantined if that verifier is unavailable.

Unlabeled legacy artifacts require the quarantine/adoption path in the memory spec. Existing worker/read-companion APIs must not bypass the new enforced profile. If a binary rollback cannot understand new retained records, it must refuse serving that store. Operational rollback can disable new work while the capable recovery binary drains retained operations; it cannot delete new ownership rows to let an older binary start.

## Policy feedback and maintenance

`DecisionReportV1` contains a decision/workflow reference, bounded reporter text, declared desired outcome and classified attachments. Reports are untrusted input to a separately authorized maintenance process. That process can propose a policy diff with base/target digests, rationale, affected contracts, benign and adversarial trajectories, expected effect changes and rollback plan.

An operator reviews and signs the deployment change. The agent blocked by a policy cannot approve its relaxation. Provider outages, missing evidence or mediation bugs are repaired in their owning component rather than translated into broader authority. Changes are evaluated against both the reported failure and related negative cases; passing by denying every operation fails utility acceptance.

## Observability and backpressure

Export bounded reason categories, phase durations, state ages, queue sizes, closure/reconciliation counts, grant reuse refusals and resource consumption. Use low-cardinality labels; tenant/resource/workflow IDs stay in authorized traces or exemplars. Raw prompts, arguments, owner sets, approval payloads and diagnostic bundles remain classified artifacts.

Each tenant has bounded queues for planning, consults, approval delivery, reconciliation and policy reports. Reconciliation capacity is reserved so new planning cannot starve already captured work. Retries use stable command identities, bounded attempts/backoff and the operation's owning recovery rules. An unavailable notification sink cannot trigger tool execution or authority refund. Audit events are durable; best-effort metrics are not authoritative state.

P1 admission also bounds active workflows, retained offers/approvals, unresolved operations, pinned bytes and verification work per tenant and authority. An attacker cannot evade the single-workflow bound by creating unlimited workflows. Reserve write/queue headroom for settling already owned work; stop new intake before exhausting it. Quota exhaustion never removes unknown operations or tombstones. Implementation must specify exhaustion and recovery behavior for disk-full/WAL growth and bounded blocking executors. P6 qualifies scale and tuning, not the first existence of these controls.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| OPS-01 | All SDK/CLI paths MUST share Rust-owned recovery semantics and stable command identity. | `protocol::cross_sdk_replay_and_conflict` | P1 |
| OPS-02 | Required enforcement features MUST be bound to the deployment/admission profile and resist downgrade. | `protocol::old_host_and_stripped_extension` | P0 |
| OPS-03 | Shared generated wire vectors MUST reject malformed or unknown signed bindings. | `wire::shared_negative_recovery_vectors` | P0 |
| OPS-04 | Protected setup MUST prove required mediation/self-test coverage before accepting protected work. | `deployment::missing_broker_or_uncovered_path` | P6 |
| OPS-05 | Time and key changes MUST refuse stale authority without corrupting historical recovery. | `operations::clock_rollback_rotation_and_revocation` | P1 |
| OPS-06 | Store upgrades/rollbacks MUST preserve original identities and reject incompatible serving binaries. | `migration::interrupted_upgrade_and_old_binary` | P1 |
| OPS-07 | Policy feedback MUST remain a classified proposal with separate deployment authority. | `policy::report_cannot_relax_or_approve` | P6 |
| OPS-08 | Telemetry MUST be audience-safe and never substitute for durable ownership/audit state. | `observability::telemetry_loss_and_secret_canaries` | P1 |
| OPS-09 | Reconciliation MUST retain bounded reserved capacity under overload. | `operations::planner_flood_does_not_starve_recovery` | P6 |
| OPS-10 | Cancellation and notification failures MUST not create new effect attempts. | `operations::cancel_and_delivery_replay` | P1 |
| OPS-11 | Command replay MUST resolve committed identity before stale-revision rejection and freshly authorize every returned projection without reapplying mutations. | `protocol::lost_ack_stale_revision_and_revoked_replay` | P1 |
| OPS-12 | New recovery intake MUST obey durable per-tenant/authority quotas while preserving headroom and ownership for existing unresolved work. | `operations::workflow_flood_and_disk_headroom` | P1 |
| OPS-13 | Historical settlement MUST use scoped current recovery authority independently of expired initiating authority, without creating execution rights or bypassing current release checks. | `operations::revoked_caller_settlement_and_lookup_authority` | P1 |
