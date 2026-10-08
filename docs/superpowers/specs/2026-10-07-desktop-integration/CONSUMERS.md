# External consumer and application acceptance

Status: accepted planning direction; implementation and installed acceptance open.
This contract defines consumer outcomes and evidence, not new endpoints or wire
operations. [HOST-CONTRACT](HOST-CONTRACT.md) owns the systems boundary;
[PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md) owns source/owner reconciliation;
[QUALIFICATION](QUALIFICATION.md) owns applicable Q01-Q31 native and systems acceptance cases.
[Product grounding](research/product-grounding.md) records the public documentation,
Megastart source and packaged Herdr compatibility used in this design.
[CAPABILITIES](CAPABILITIES.md) maps the wider passport, delegation, swarm,
verifiable-work, resource and competitive-research decisions to their owners.

## Consumer boundary

[FIRST-CLASS-INTEGRATIONS](FIRST-CLASS-INTEGRATIONS.md) requires Claude Code,
Codex, Pi and Hermes through their existing integration owners, and Herdr through
its workspace plugin. Every named integration needs its own installed platform
evidence. One selected harness in C01 is an incremental proof, not completion of
that support commitment. Mini-swe is an optional reference/test workload only.

An external agent harness and an application coordinator must be able to use the
selected Chio capabilities with every Chio graphical frontend absent. A client
may present review/approval or monitoring, but its closure, replacement or upgrade
cannot erase authority, retained work, reservations, resource fences or evidence.
Selected approval policy still applies to headless callers. A missing approval
mechanism makes that operation unavailable, not automatically approved.

The application and harness must be independently implemented consumers. A CLI
and a UI wrapping the same application adapter cannot establish reusable host
infrastructure by themselves. Reuse their owner bindings, while keeping each
consumer's planning and application state independent.

Use existing supported SDK/protocol/owner bindings selected by source
reconciliation. Native L0, process L1, work L2 and recovery L3 are different
surfaces. Historical process/example protocols and proposed layered contracts are
not assumed ABI-compatible. W1 planned handles/queries do not exist merely because
a sample has a mission ID. Do not invent a common control endpoint to hide an
unimplemented owner.

The external harness keeps planning, model/session state and its own workflow.
The application keeps assignment strategy and business completion criteria.
Trusted application components that actually hold signing keys, state or dispatch
custody are included in the relevant owner TCB. Herdr and other presentation
clients receive projections and supported actions, without opening a second
runtime against an owner's store.

## Exact implementation handoffs

Aliases F, W, R, K and T below are the pinned sources in PROGRAM-MAP. A path at F
may be absent from the platform worktree; consume the named owner revision after
its gates pass rather than fabricating that file or port locally.

| Responsibility | Existing source or owner register | Required handoff |
| --- | --- | --- |
| Agent identity, workers and lifecycle | F:`crates/kernel/chio-process/src/registry.rs`, `src/lib.rs`, `WORKER_PROTOCOL.md`; F:`crates/products/chio-cli/PROCESS_HOST.md` | Process owner supplies exact supported bootstrap/invoke/observe/control and stop semantics; reconcile historical ABI versions. Preserve host lock, attempts, credentials and original logical operations. Live control is owner work where the current CLI requires a stopped host. |
| Authenticated native clients | F:`crates/security/chio-secure-ipc/src/lib.rs`; HOST-CONTRACT native-port inventory | IPC owner ports and qualifies actual OS peer/service identity and bounded connection handling. A token-only sample loopback API is not Darwin/Linux native-control qualification. |
| Harness integration and model custody | [FIRST-CLASS-INTEGRATIONS](FIRST-CLASS-INTEGRATIONS.md) names the Claude Code, Codex, Pi and Hermes plugin/launcher owners; F:`docs/strategy/chio-direction/19-priority-agent-integrations.md`; F:`crates/security/chio-secret-broker/README.md` | Each harness owner routes its supported effects/model calls and supplies provenance; secret/native owners retain credentials and confinement. Qualify its actual runtime and transport, not mini-swe as a substitute. Each advertised protected host separately passes I01-I08. |
| Resource mutation and capacity | `crates/kernel/chio-kernel/src/budget_store.rs`; `crates/platform/chio-store-sqlite/src/budget_store.rs`; PROGRAM-MAP's kernel/store/foundation gates | Resource and budget owners bind trusted caller, assignment/fence, exact request, reservation and result in their own transaction. Platform adapters supply missing OS ports, not a second allowance ledger. |
| Work commitments and acceptance | W:`docs/superpowers/specs/2026-10-03-work-runtime-design.md`, W1.0-W1.6 in PROGRAM-MAP | Work owner lands preparation/command/query/acceptance and exact original lookup. Application exit, queue completion or a sample mission cannot synthesize accepted W1 work. |
| Recovery and result release | R:`crates/security/chio-security-types/src/recovery/commands.rs`; R:`crates/platform/chio-control-plane/src/recovery/{transport,runtime}.rs`; R:`crates/kernel/chio-kernel/src/knowledge.rs` | Recovery/knowledge owners reconcile actual revision, recipient, retry disposition, endorsement and disclosure semantics. Use their non-persisting observation and original-operation recovery; retain planned versus implemented release-port differences. |
| Independent operators | `crates/trust/chio-federation/src/{trust_establishment,treaty}.rs`; `crates/trust/chio-federation/src/bilateral_verifier.rs`; `crates/kernel/chio-kernel/src/federation_artifact_store.rs` | Federation/runtime owners pin the accepted implementation and test peer/issuer trust, treaty evidence, local refusal, revocation freshness and durable bilateral artifacts. Existing file presence is not an accepted composed host. |
| Identity/passports | F:`crates/trust/chio-credentials/src/{passport,presentation,challenge}.rs`; F:`crates/kernel/chio-kernel-core/src/passport_verify.rs` | Credential/native admission owners bind current subject, issuer policy, challenge, audience, validity and selected revocation requirements. Portable verification is a narrower primitive; a passport never becomes an automatic grant. |
| Recursive delegation | F:`crates/core/chio-core-types/src/capability/attenuation.rs`; K:S1 delegation-parent custody and S4 closure | Authority/process owners qualify supported depth, reduce-only scope, expiry, constraints and applicable allocation rules. Preserve original lineage and revoke descendants through current native admission; client assignment cannot impersonate delegation. |
| Swarm authority and extension | W:`crates/kernel/chio-swarm-authority/src/{types,verifier,evolution}.rs`; W:`crates/kernel/chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs` | Swarm/W1 owners retain protected graph head, issuance, witness/route/allocation/epoch bindings and runtime replay. Graph extension requires atomic owner commit; offline bundle verification and signed joins do not establish accepted dependency outcomes. |
| Existing application/Herdr consumer | `chio-world:public/examples/megastart/src/{authority,mission,operator}.rs`, `src/agents/service.rs`, `herdr/{CONTRACT.md,src/client.rs}` | Application owner preserves the packaged v1 API and adds an adapter to newly qualified owner bindings if needed. Herdr consumes the app API; it does not become the kernel/control/resource authority. |

Public process/resource examples provide acceptance patterns, not alternative
owner implementations to copy into platform code. In particular,
`chio-world:public/examples/agent-processes/languages/rust/resource/src/lib.rs`
shows atomic caller/assignment/version/deduplication, while
`public/examples/agentic-os/source/worker-fleet/src/jobs.rs` shows retained claim
and unknown-outcome states. Freeze their own source identities if reused as test
workloads. PROGRAM-MAP must supply the target owner pins independently.

## Consumer acceptance cases

C01-C11 below are acceptance labels, not wire vocabulary. Every case names an
installed tuple, supported owner calls and a useful positive control. Negatives
must inspect the actual resource, dispatch counter, private-byte canary, ledger
or native process census independently of client status and signed claims.
A denial-only system cannot pass by refusing the positive work.

| Case | Useful positive and required failure stimulus | Independent result and owner handoff |
| --- | --- | --- |
| C01 External harness, no frontend | With browser/workbench/menu/QML components absent, attach one selected external harness through its supported binding. Give it a durable scoped task and obtain a useful artifact. Attempt a registered operation outside its authority and, for a protected profile, an alternate native file/network path. | Artifact bytes and their bound original receipt verify; denied operation produces no resource mutation. Protected alternate paths produce no canary read/write/egress. Harness/process/IPC/security owners supply I01-I08 and applicable Q02/Q04/Q10-Q14/Q22. MCP mediation alone makes no claim about the harness's unmediated session or direct tools. |
| C02 Work continuity across replacement | Persist a checkpoint and original operation, stop the worker, then resume through another authorized worker/client. Also lose a reply after effect dispatch, race exact duplicates, and submit changed arguments under the original ID. | Retained actor, remaining allowance and exact request survive. Known replay returns original outcome/receipt without another resource effect; changed intent conflicts; unknown effect stays unresolved until owner reconciliation. Independent mutation count and resource bytes distinguish replay from repeated dispatch. Process/recovery/resource owners supply Q02/Q03/Q19. |
| C03 Shared work with current resource ownership | Two scoped consumers share a bounded mailbox/queue. Let A's claim expire, let B acquire delivery and current resource assignment, and let B publish. A rereads the latest version and attempts a fresh mutation. Repeat A's previously completed exact operation. | Old claim cannot complete the new delivery; stale owner cannot change the resource despite fresh version data. Exact historical replay returns its retained result without a new mutation. Inspect assignment/fence, document version, mutation history and retained operation separately. Resource/process owners qualify their transaction and Q02/Q14; a mailbox refusal alone is insufficient. |
| C04 Shared capacity survives concurrency/restart | Two independent consumers perform permitted work under one declared owner-enforced capacity family. Synchronize requests at the remaining bound; saturate new admission; lose a reply and reconnect/restart. | Independent owner reservations/consumption plus downstream effect counts stay within that contract. In-flight obligations count under owner rules. Reopening clients does not replenish allowance; original lookup remains available under saturation; unavailable capacity is not unlimited. Budget/storage/recovery owners supply Q02/Q15/Q21. Money, invocations and CPU/memory/storage ceilings remain separate dimensions. |
| C05 Client removal and reconnect | Complete part of a job, close and remove its presentation component, continue using a second authorized headless client, then reconnect/reinstall the original client. Introduce stale cursor, reordered/duplicate events, unauthorized scope and server replacement. | Owner state and capacity remain; no startup/reconnect dispatch or duplicate effect occurs. Client re-reads authentic state and displays uncertainty/disconnection truthfully. Native process census proves declared host continuity; resource counters prove no replay. Presentation/IPC/observation owners supply Q04/Q09/Q10/Q16/Q17/Q21. Service-host continuity must pass independently of user-session hosting. |
| C06 Three independent owners cooperate | Customer discloses bounded diagnostics; specialist returns a proposal; provider locally approves one exact repair. Use separate authority, policy, resource state and credentials. Provider first refuses an overbroad/stale proposal, then accepts a narrowed one. Substitute peer/issuer, audience, request/configuration binding, stale revocation state and evidence. | Rejected exchanges leak no protected diagnostic/credential bytes and cause no provider effect. An admitted exact proposal changes only the provider-owned resource. Customer health observation independently accepts or leaves the incident unresolved; a successful repair receipt alone does not close it. Federation/resource/approval/disclosure owners provide current trust/treaty/freshness and applicable Q02/Q04-Q06/Q10/Q13/Q14. |
| C07 Bilateral interruption and relationship change | Drop a reply after provider mutation or before remote co-sign persistence; restart each owner independently. Rotate/revoke the relevant relationship using its supported procedure; repeat old/fresh requests under explicit freshness rules. | Original operation remains known or unknown according to retained owner evidence. A missing co-sign is not a missing effect; old signed history remains inspectable without authorizing new work. Independent resource and artifact-store observations show no duplicate effect or invented bilateral success. Federation/recovery/storage owners supply original lookup, signer transport, artifact retention and revocation evidence. |
| C08 Exact application acceptance and release | A coding or report app produces a candidate, tests/reviews its exact digest, and asks the owner to publish. Change candidate after approval; substitute output/receipt; race an existing destination; make execution succeed while acceptance or delivery fails. | Only the approved unchanged candidate publishes. Independent destination content and publication count show no overwrite/duplicate release. Execution, acceptance, result, recovery, settlement and bilateral delivery remain separate wherever the selected W1 profile exposes them. App/work/approval/knowledge owners provide applicable Q01-Q06/Q14/Q18. |
| C09 Portable identity with local admission | Present a valid credential bundle for the intended subject through the selected authenticated workload/challenge path. The receiver explicitly issues a bounded grant under its own policy. Substitute subject, workload, issuer, audience or challenge; replay an old presentation; exercise expiry and required revocation freshness. Present a valid passport without a resource grant. | The positive obtains only locally approved scope. Each negative leaves the protected resource and disclosure canaries unchanged, including the otherwise valid passport without authority. Inspect receiver policy/grant and effect counters independently of a displayed score. Credential/identity/kernel owners qualify the actual presentation/admission path; a portable verification test alone does not close this case. |
| C10 Recursive scoped delegation | On a profile advertising recursion, let a coordinator delegate to a child that delegates a narrower task to a grandchild. Complete useful descendant work; widen a tool/resource/constraint, extend expiry, change delegator or exceed the supported allocation rule. Revoke an ancestor, then attempt new descendant work. | Exact signed lineage and current admission support only narrowed work. Independent child/grandchild effects and resource counters show no forbidden operation after widening or effective ancestor revocation. Unknown outcomes of already dispatched work retain their identity. Authority/process/budget/closure owners qualify supported depth and conservation; the Megastart one-hop aggregate profile must still refuse unsupported multi-hop aggregate delegation. |
| C11 Connected swarm authority and accepted dependencies | Configure the actual runtime evidence/replay owner. Execute a useful fan-out/fan-in with pinned graph, witness, continuation, route, allocation and revocation context. Substitute each binding, duplicate a single-use continuation across clients/restart, and, if extension is exposed, race additive extensions against one graph head. Offer a signed join whose required parent result is not accepted. | Runtime refuses invalid or consumed authority before another protected effect. Owner graph-head/allocation records plus independent effects establish no forked issuance or duplicated allocation. A signed join alone cannot satisfy the selected work acceptance predicate. Swarm/W1/runtime owners qualify protected head, durable replay and exact accepted-parent evidence; pure offline verification and client DAG rendering do not qualify this path. |

C06-C07 cannot claim organizational independence from three IDs or processes under
one administrator. A local fixture may qualify the named protocol branch only.
The organizational acceptance record names separate operators, keys, stores,
resource owners, trust enrollment and disclosure policy. Each owner can refuse
without another owner overriding its policy. Do not share signing keys/databases
or infer a global atomic allowance from local C04. Each organization's budget and
any settlement/distributed accounting contract require their own owner evidence.

C09 is mandatory when passport or portable-identity participation is advertised;
C10 when recursive authority is exposed; C11 when runtime swarm admission,
extension or accepted-dependency behavior is exposed. Record an unavailable
capability explicitly while its owner gates remain open. A passing lower-level
cryptographic check cannot replace these consumer/native cases.

## Preserve Megastart and Herdr compatibility

The packaged `herdr/CONTRACT.md` v1 is an application API. Its three existing
routes and tagged actions remain owned by Megastart. Nothing here renames them,
requires a breaking change, or turns them into a universal host contract.

An application adapter can map a new owner binding into the existing projection,
but must preserve operation identity, approval/candidate binding, authority and
capacity provenance, disconnection semantics and no automatic mutation retry.
Keep host keys and state in their declared owners. A changed adapter must pass
existing client conformance and C02/C04/C05/C08 against the exact installed tuple;
optional direct clients also qualify their chosen native binding.

For the current packaged consumer, C05 checks the documented behavior: closing a
Herdr pane or unlinking registration leaves the detached host and retained mission
state; reopening inspects the actual process and authentic descriptor; an event
gap refreshes state instead of replaying an action. Plugin removal must not delete
mission storage. This is compatibility acceptance to execute, not a claim that the
new native host program has already inherited the old example's results.

Retain the documented current limits: one-hop aggregate-family delegation,
single-authority durable family accounting, explicit uncertainty outside the
captured crash point, and no qualified interactive native PTY. A coordinator's
assignment is not another delegated authority hop. Migrating to a stronger owner
contract requires independent evidence for the additional behavior.

## Source, target and evidence manifest

Each implementation packet supplies a strict owner-format manifest with:

1. Immutable public Chio revision that can actually be fetched, target owner
   revisions from PROGRAM-MAP, application source revision/archive hash, both
   Megastart and Herdr Cargo lock hashes when that consumer is selected, and all
   built/installed component hashes. A mutable docs URL alone is insufficient.
2. Host and plugin versions, native launcher and executable identity, OS build and
   architecture, backend/profile, configuration and policy digests, credential
   context, trust enrollment, supported ABI and exact client adapter.
3. Existing source behavior versus target behavior for each exposed capability,
   including unsupported/unavailable cases and explicit owner delivery gates.
   Source compilation, model proof, example capture and installed execution remain
   separate evidence dimensions.
4. Actual test command, bound input, positive control, adversarial stimulus, raw
   output, independent effect/private-byte/capacity observations, expected result
   and reviewer decision for every selected C case and applicable Q case.
5. Public source/artifact availability, local tests, hosted checks, installed
   platform qualification and independently operated federation as separate
   statuses. A package rebuild or changed tuple invalidates artifact-specific
   acceptance until its selected cases pass again.

The recorded current Megastart public dependency is
`6753edbc365f5ea820224b96a59940feedbfca94`; its archive and lockfile hashes are in
product-grounding. Those values identify inspected public bytes, not a release
instruction to combine that historical kernel with proposed native owner APIs.
A migration freezes its own available public tuple and records any changed API
or behavior explicitly.

For an existing supported external host, neither a consumer scenario, a prior
Megastart recording nor a passing owner unit test inherits I01-I08. Claude Code,
Codex, Cursor, Hermes, Pi and OpenClaw retain separate installation, useful work,
bypass, dependency, authority, evidence, recovery and delivery gates. Only selected
qualified hosts are advertised. One qualified host does not imply six-host
completion.

## Promotion and implementation order

First reconcile source and native owners, then implement one external harness and
one application consumer against the installed headless profile. C01-C05 establish
local useful systems behavior; C08 is added for exposed acceptance/publication.
Apply all selected native Q gates even when no UI exists. C06-C07 additionally gate
an advertised cross-organization capability. A local release can ship with that
capability explicitly unavailable while its owner work continues.
Add C09-C11 for the exact identity, recursive-delegation and swarm capabilities
selected in CAPABILITIES and PROGRAM-MAP; do not collapse the full kernel into the
features exercised by the first application.

User-session and service-host profiles qualify independently. Test headless service
operation without a human login only where its separately enrolled principal,
credential custody, startup and restart contract exist. Detached processes and
GUI-free startup do not qualify unattended authority.

Herdr is a required supported workspace/plugin integration, with optional
installation and use. It qualifies its presentation and action bindings against
the same owner state and the required harness matrix in FIRST-CLASS-INTEGRATIONS.
Workbench, menu bar and QML are optional additional consumers. None can be a
prerequisite for direct owner clients. Each native profile promotes on its own selected
predecessor and installed gates in QUALIFICATION; a prior sealed-coding release
is not required. Consumer acceptance waives no applicable native obligation.
