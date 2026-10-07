# Delegation, worker ownership, and cross-host custody

Status: proposed normative design. Confidence: high in the single-authority and attenuation requirements, moderate in the proposed integration boundaries, unknown for installed Mac or cross-host qualification.

Delegation lets a Mac task assign bounded work to additional workers without handing them the user's credentials or creating competing authority. One Chio authority retains parentage, exact admission, hierarchical resource reservations, stop state and original-operation history. Worker location can change only under that authority's qualified ownership and recovery contract.

M7 depends on M3 project workers, M4 resource/publication boundaries, M6 recovery and [host adapters](15-host-adapters.md). Local VM children and remote workers need separate [qualification tuples](17-qualification.md). A remote worker does not imply that the remote machine supplies Mac-native tools. Optional stopped-authority relocation is a separately gated capability; live authority migration and disconnected cached-permit execution are unavailable in the initial design.

## Existing source versus required delivery

At MAC-BASE, `crates/core/chio-core-types/src/capability/attenuation.rs` contains signed attenuation types and `crates/kernel/chio-kernel/src/kernel/delegation.rs` contains delegated-dispatch revocation checks. Those components are useful foundations; their presence is not evidence that the consolidated north-star process host, sealed tree ledger, current stop crossing or Mac worker lease is implemented and qualified.

The inspected north-star at `8dffff3da53dfb56da8e60019af5e3ae896f7f5b` is a documentation baseline. Its crossing and durable-stop contracts govern the intended implementation, including the distinction between intent committed before stop and later output release. Missing runtime contracts are owned prerequisites in [the kernel plan](../../plans/2026-10-07-macos-integration/00-kernel-prerequisites.md), not permission to invent a desktop ledger.

The pinned public Pi [child facade](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/delegation.ts) requires a native child port and rejects request-supplied launch selectors. Its submitted-ID set is process-local. The [native prerequisites](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/NATIVE-PREREQUISITES.md) state that bundled bridge attenuation is unsupported and distinguish narrower retained-session transport credentials from child capability issuance. These sources establish composition boundaries and gaps, not installed child authority.

The Omarchy delegation precedent, `docs/superpowers/specs/2026-10-07-omarchy-integration/13-delegation-multihost.md` in the separately pinned Omarchy specification worktree, informs the design. Its Linux launch, candidate runtime references and proposed lease numbers are not copied as Mac implementation or qualification. See the shared [source pins](research/source-pins.json) for its inspected checkout.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-DEL-001 | Child execution MUST remain unavailable until native child admission, sealed tree ledger, ownership, output custody and selected confinement contracts are implemented and qualified together. | AT-MAC-DEL-001 |
| MAC-DEL-002 | Every child MUST have a verified parent-bound attenuation chain preserving issuer, tenant, budget family, resource constraints, validity and ancestor revocation; no hop may enlarge authority. | AT-MAC-DEL-002 |
| MAC-DEL-003 | Child admission MUST atomically retain original request, parent, exact input/template/target binding, signer custody and reservations before launch; equal replay MUST reconcile and changed replay MUST conflict. | AT-MAC-DEL-003 |
| MAC-DEL-004 | Workers MUST launch only operator-installed immutable templates bound to an exact host/profile tuple; guest input MUST NOT select executables, environment, arbitrary sockets, credentials or packages. | AT-MAC-DEL-004 |
| MAC-DEL-005 | All child and descendant allocations MUST remain within the sealed hierarchical ledger's root and ancestor ceilings; cancellation, restart and partition MUST NOT mint or implicitly refund budget. | AT-MAC-DEL-005 |
| MAC-DEL-006 | Each live worker and serving writer MUST have one authenticated owner generation and qualified lease/fence; PID, heartbeat or elapsed timeout alone MUST NOT transfer custody. | AT-MAC-DEL-006 |
| MAC-DEL-007 | Lease issuance and renewal MUST recheck current authority, policy, installation, parent validity and stop generation at the serving writer; stale or partitioned workers MUST NOT begin new crossings. | AT-MAC-DEL-007 |
| MAC-DEL-008 | Subtree stop and ancestor revocation MUST fence new crossings monotonically while retaining precommitted effects, progress-only return records, withheld output and actual process termination as distinct states. | AT-MAC-DEL-008 |
| MAC-DEL-009 | Cross-host context and commands MUST authenticate authority, host, worker and owner generation, disclose only admitted exact content, and exclude ambient parent transcripts, secrets and host-control interfaces. | AT-MAC-DEL-009 |
| MAC-DEL-010 | Each effect MUST retain its original native operation and request binding across retries, worker replacement and host changes; uncertain effects MUST NOT be redispatched with a fresh identity. | AT-MAC-DEL-010 |
| MAC-DEL-011 | Child results MUST pass native receipt, result, recipient and disclosure verification before parent ingestion, output release or ACK; signed origin MUST NOT erase input influence. | AT-MAC-DEL-011 |
| MAC-DEL-012 | Dependency waits MUST be acyclic and bounded; root success MUST require declared required child outcomes and artifacts plus explicit resolution of every outstanding effect. | AT-MAC-DEL-012 |
| MAC-DEL-013 | Stopped-authority relocation MUST transfer or explicitly retain all original custody under a qualified native protocol, fence the source before serving at destination and reconcile interrupted transfer under the same identity. | AT-MAC-DEL-013 |
| MAC-DEL-014 | Remote effect settlement MUST use the selected resource owner's actual reconciliation contract; disconnection, cancellation, provider idempotency keys or worker death MUST NOT imply exactly-once completion or rollback. | AT-MAC-DEL-014 |
| MAC-DEL-015 | Task views and evidence MUST separately report authority admission, worker connectivity, restriction convergence, process liveness, effect state and result delivery; external sensor IDs MUST NOT replace native crossing order. | AT-MAC-DEL-015 |
| MAC-DEL-016 | Local children, remote workers, stopped relocation and every changed host/runtime/provider tuple MUST pass separate applicable qualification with independent observers and explicit unavailable gates. | AT-MAC-DEL-016 |

## Authority and launch transaction

The child request is a proposed native contract, not a new desktop RPC or a current public API. It binds the retained root/parent, original submission identity, canonical input digest, exact installed template, destination host/installation, worker architecture/profile, capability lineage, policy/contracts, intended resource set, disclosure disposition, ledger allocation and absolute expiry. The native owner derives authenticated parent and issuer identity; guest-supplied fields cannot choose an issuer or signer. [The operator protocol](06-operator-protocol.md) carries only the defined request and opaque native references.

The native admission transaction validates the chain, captures child signer custody, seals the allocation and records one child/launch identity. Publication authority is not inherited from ability to produce an artifact. A child needing publication must possess the appropriate attenuated scope and obtain the kernel-owned exact endorsement for that action. UI child approval, an MCP consent callback and an external detector response cannot substitute.

Launch is a later, independently observed event. A crash after durable admission but before launch recovers that launch identity. A crash after possible launch requires ownership reconciliation before replacement. Duplicate equal requests return the original retained admission; different template, bytes, parent or allocation under the same identity conflict. A local cache can improve duplicate detection but cannot be the durable oracle.

Templates contain fixed installed executable/runtime hashes, permitted arguments, sanitized environment, image digest, mounts, transport routes, resource inventory and host version. Workers receive no root capability, signing key, provider login cache, SSH agent, container socket, XPC operator endpoint or unrestricted network route. Parameters supply bounded job data, never deployment selectors. Mac-specific effects such as Xcode or signing require separately qualified native brokers; a Linux guest's presence proves neither.

## Ledger, ownership, leases and partitions

The native sealed hierarchical ledger is the single authority for tree allocations. It accounts for each configured dimension separately: processes, depth, active concurrency, logical calls, model reservations, bytes, time and money where actually enforceable. Parent limits bound every child allocation and aggregate descendants. In-flight reservations and unknown effects retain their allocations until the native settlement rule releases them. A desktop counter, Clawdstrike restriction TTL or provider usage estimate cannot refund or issue authority.

The initial implementation plan uses finite fixture ceilings to exercise these rules, not universal product defaults. Real launch requires an explicit bounded policy. An unsupported hard provider limit is unavailable, not represented as zero or silently omitted. Resource holds and process slots are distinct; terminating a process does not prove an external monetary or publication obligation settled.

Ownership names the authority/store, child/launch, destination host and boot identity, installed runtime/profile digest, process incarnation where applicable, owner generation and validity. An authenticated native operation changes ownership. PID alone is insufficient on macOS, and process identity must survive neither reboot nor reuse by inference. Positive OS termination evidence is distinct from native revocation and still does not resolve an external effect.

Lease renewal is a crossing at the authoritative writer, with current parent validity, policy, integrity, ledger allocation, stop and revocation checks. An activity heartbeat cannot renew a lease. The exact validity interval, renewal margin and clock-uncertainty bound belong to the qualified tuple and must be finite. If the selected native implementation cannot enforce those fields under suspend/resume and clock changes, remote execution remains unavailable.

A worker under partition stops initiating new crossings when valid authority cannot be established. It may report/retain already-admitted results through the progress path when connectivity returns, but may not release those results under a stale grant. The serving writer fences stale generations. A partition or expired lease does not prove the old process stopped; overlapping replacement work stays fenced until the native recovery rule establishes safe takeover. Disconnected offline execution is excluded, so a cached local restriction allow cannot become an independent grant.

## Stop, recovery and output custody

The serving writer's crossing order determines whether an intent committed before subtree stop. Such work may still cause an effect. The return record remains progress-only where the kernel contract permits it; later output release rechecks current stop, revocation, closure and integrity. This preserves evidence while withholding delivery. Closing the VM or signaling a process is an additional containment operation, not a substitute for the authority fence.

Every effect retains original authority/store identity, operation/request IDs, canonical request digest, resource owner and contract, capability lineage, admission history, result/receipt commitments, delivery custody and owner generation. Worker IDs and transport request IDs cannot replace these. After lost response, replacement asks the original owner to reconcile. It cannot turn an uncertain effect into a new request because a provider supplied a retry hint.

Child output enters parent context only through the admitted native release. Verify the authority and issuer chain, original operation, exact result/artifact, recipient parent, content/disclosure binding, current generation and receipt integrity. Join child-derived influence before parent consumption. A worker checkpoint, queue message or signed success statement is not proof that required tests passed or the artifact matches. Delivery ACK remains with the native owner after exact consumer receipt; detached UI/adapter observers cannot discard pending ACK custody.

Dependencies name admitted children, not arbitrary foreign tasks. Cycles and undeclared waits refuse. A required child test failure prevents root success. An optional child's known failure can be represented according to the task policy, but its unknown effect cannot disappear as skipped work. Connectivity, execution, cancellation, output withholding and completed delivery remain independently inspectable.

## Optional stopped-authority relocation

Moving a worker while the original authority remains reachable is not moving the authority. The initial remote profile keeps the original writer and ledger at their established host. A separate stopped-relocation feature may later move durable authority state only through the implemented native transfer protocol.

Relocation must inventory authority keys and seals, stop/revocation history, ledger/holds, original-operation journal, process lineage, retained results, resource-owner mappings, model reservations, knowledge/artifact provenance, gateway ownership, private ACK records and installation compatibility. Each item either moves under the sealed protocol or remains at a reachable authenticated original owner under an explicitly qualified contract. Copying receipts, a VM snapshot, a gateway directory, PID files or a live socket is insufficient.

The source becomes durably retired/fenced before the destination can serve. Missing state, divergent generations, corrupt content or failed destination verification keeps both sides from new admission until native reconciliation establishes a single owner. Transfer retry retains the original relocation identity. Rollback cannot resurrect source authority or reset budgets. Live dual writers, cross-authority lineage migration and ambient-key reissuance are unavailable.

## Acceptance procedures

### AT-MAC-DEL-001: Native prerequisite closure

Request a child with only a Pi callback facade, missing sealed ledger, incompatible native ABI, absent output custody and an unqualified guest. Native credential/launch counters remain zero and each missing prerequisite is explicit. A complete real implementation is required for the positive case; fake ports can test refusal shape only.

### AT-MAC-DEL-002: Attenuation and revoked ancestor

Admit one read-only child; attempt broader path/destination, changed issuer/tenant, longer expiry, foreign budget family, omitted hop, sibling parent and revoked ancestor. An independent signed-chain verifier and protected resource canaries confirm only the narrowed valid request works. Repeat after parent revocation while child remains alive.

### AT-MAC-DEL-003: Admission crash and duplicate race

Concurrently submit equal requests, then lose the response at each transaction/launch cutpoint and replay changed input/template/share. Native records retain one child, signer and sealed allocation; one launch owner is admitted, while changed replay conflicts. Observe the worker launch externally, independent of the request handler's reported success.

### AT-MAC-DEL-004: Immutable launch template

Inject executable/argv/env/socket/package selectors into nested and top-level input, mutate the installed image/runtime hash and probe parent secrets. Independent process/image/mount inventory matches only the selected template; all selector attempts refuse without launch or credential exposure. A Linux guest cannot claim successful native Mac compilation without its separately admitted broker.

### AT-MAC-DEL-005: Tree ledger conservation

Race sibling and grandchild admissions across finite process, depth, concurrency, call and model ceilings. Crash, cancel and restart a child with an unresolved hold. Independently query the native ledger and effect/provider counters: sealed allocations plus retained obligations never exceed ancestors, and no allocation is automatically reclaimed from an unknown outcome.

### AT-MAC-DEL-006: One owner across PID reuse

Pause a launch owner, recycle its numeric PID, reboot its worker host and attempt concurrent replacement. Native owner generations and independent host process observations show that stale identity never acquires custody or signals the replacement process. If the platform cannot make the termination claim race-safe, that termination capability remains unavailable.

### AT-MAC-DEL-007: Renewal under partition and sleep

Use the tuple's declared lease and clock bounds; partition renewal, sleep through expiry, move the wall clock and change policy/stop before renewal. Record both hosts' monotonic observations and the authority's commits. No stale generation obtains new crossing authority; already-in-flight obligations stay retained. A heartbeat-only reconnect cannot renew.

### AT-MAC-DEL-008: Stop/effect/release race

Pause one child before intent, one after committed intent and one before output release. Stop their ancestor. Native crossing order proves new intent refusal, retained precommitted effects, accepted progress-only returns and current release withholding. Separately observe VM/process termination and retained settlement obligations.

### AT-MAC-DEL-009: Authenticated minimal disclosure

Connect a wrong host, worker, tenant or owner generation; replay a command; request the parent's full transcript and a raw host-control socket. Independent destination capture shows zero prohibited bytes/effects. A valid child receives only the exact admitted content and routes, with no provider credentials.

### AT-MAC-DEL-010: Original identity after replacement

Kill the worker before dispatch, after a provider-observed effect and after retained return before ACK. Resume on the original host and then an independently qualified second host. Original request/operation and content bindings persist; the effect counter stays one where the owner proves completion, and uncertainty cannot cause redispatch.

### AT-MAC-DEL-011: Child output receipt and influence

Return changed result bytes, foreign signer, wrong parent, stale generation, prohibited disclosure and a malicious instruction in a validly signed artifact. Invalid bytes do not enter parent context or receive ACK. Valid bytes retain their influence and need their own later action authority. Verify native delivery and parent context commitments independently.

### AT-MAC-DEL-012: Bounded dependency settlement

Construct a dependency cycle, foreign wait, hung required child, failed required test and optional child with unknown effect. Native graph checks reject invalid waits; bounded waits expose unfinished work. The root cannot report clean success while required work fails or any effect remains unknown. Use independently checked artifact/test results rather than child prose.

### AT-MAC-DEL-013: Complete stopped relocation

Attempt export with a live worker, omit model/ACK custody, corrupt a retained file, interrupt import and start source/destination concurrently. Native transfer seals and observers on both hosts prove refusal or single-owner recovery under the same identity. The valid stopped transfer retains all counters, original operations, revocations and output custody; old source cannot serve.

### AT-MAC-DEL-014: Unknown remote effect

Let an independent provider effect occur, lose the reply and disable authoritative lookup. Cancellation and a repeated idempotency key do not resolve it. Inject forged completion, then valid original resource-owner evidence. The native state stays unresolved until that evidence satisfies the selected contract; no broad exactly-once or rollback claim appears.

### AT-MAC-DEL-015: Independent state projection

Feed out-of-order sensor events, duplicated hints, a lost subscription and a disconnected live worker. Compare UI projection against native commits, external process observer and actual effect state. Sensor IDs remain separate, gaps are visible, and no heartbeat or exit overwrites authority/delivery truth.

### AT-MAC-DEL-016: Per-profile and two-host qualification

Pass local VM child tests, then select a new remote OS/architecture, host runtime, provider or relocation feature without its artifacts. Admission remains unavailable. A remote release requires simultaneous independent observations from both exact installations plus all applicable failure cases; component tests and another platform's cage evidence cannot qualify it.
