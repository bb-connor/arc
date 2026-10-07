# Host and provider adapters

Status: Proposed.

Confidence: high for the inspected Pi behavior and identified gaps; moderate for this adapter contract until a compatible native binary and real Omarchy x64 run exist. Basis: the [readiness source crosswalk](research/chio-readiness.md), pinned public Pi source and explicit native prerequisite refusals.

Scope: a Pi-first protected host adapter, provider relay, capability negotiation, lifecycle and original-result delivery. Dependencies: the architecture, operator protocol, task lifecycle, authority/policy, confinement and recovery specifications in this package. P2 enables one confined project task. P3 separately enables exact approval and publication. Delegated workers require P6 and [the delegation contract](13-delegation-multihost.md).

## Decision and alternatives

Use Pi's restricted SDK/print surface as the first host. The desktop controller invokes an installed, versioned adapter that connects Pi to the existing native authority and protected resource owner. It must not launch the user's ordinary Pi profile. Native task, operation and approval authority remains in Chio. An adapter cannot translate a successful precheck into local filesystem, shell or network execution.

A general interactive terminal wrapper is deferred: the inspected protected candidate does not qualify Pi's interactive TUI, arbitrary extensions, user slash commands, local shell tools or project discovery. A generic host plugin alone would leave those effect paths uncontrolled. Host-native providers and additional hosts can be introduced only through their own capability manifests and acceptance records; a common UI does not establish equivalent enforcement.

The initial supported feature set is an immutable declared registry, sequential native execution, fixed provider route/account/model, parent-owned credentials, bounded model requests and native result delivery. Pi's current typed tools and legacy `chio_execute` wrapper are distinct registry modes; switching modes changes the registry digest and cannot occur during resume.

## Proposed adapter boundary

These method names describe a proposed trusted in-process or local adapter API. They are not claims of existing public Chio routes and do not replace the package's versioned operator protocol.

| Method | Input and responsibility | Output |
| --- | --- | --- |
| `describeInstalledHost()` | Read a pinned installation, without credentials or provider traffic | Exact host/adapter/runtime identities, supported protocol versions, available entry modes and diagnostic capability claims |
| `prepareHost(binding, selection)` | Freeze operator-selected task, authority, profile, registry, provider, disclosure mode, bounds and private session target; validate native prerequisites | Opaque parent-owned prepared handle, or typed refusal before provider credentials |
| `startHost(prepared, privateInput)` | Consume bounded private prompt/context input; launch only the qualified guest; native owners admit effects | Event stream carrying observations and original-operation references, never a new receipt signer |
| `inspectHost(binding)` | Ask the trusted original owner for retained status and verify referenced evidence as required | Status with evidence class, freshness and exact immutable identities |
| `cancelHost(binding)` | Request native admission cancellation and separately terminate the confined host through its owner | Cancellation acknowledgement plus unresolved operation references; no promise of effect rollback |
| `resumeHost(binding, original)` | Resume the same authority/session/registry/profile after native recovery eligibility is established | Original lookup/delivery or explicitly permitted continuation; no implicit fresh effect |

The closed installation descriptor must include `adapterProtocol`, package/archive and installed-file hashes, Pi exact version and consumer-lock digest, Node and architecture, native compatibility-manifest digest, confinement profile digest, registry digest/mode, provider profile identity, governance mode and per-feature qualification references. A feature has one of `unavailable`, `source_supported_unqualified`, or `qualified_for_profile`. The last requires a matching independent qualification artifact. This descriptor is an observation, not execution authority. Unknown fields, incompatible major versions and unsupported required features refuse preparation.

The frozen binding includes task UUID, native authority/store identity, retained caller/session/capability, resource owner, trust roots, installation generation, registry digest, profile identity, provider API/route/model/account binding, credential generation reference, original absolute deadline and limits identity. Credentials themselves never appear in this descriptor. A native operation ID is not the desktop UUID: retain its original native format and map it durably without truncation, normalization or regeneration.

Initial proposed desktop limits are one active effect-bearing call per retained session, one selected provider profile per task, 256 KiB of explicit initial prompt/context input, and a 10-second prerequisite timeout. These are policy defaults for implementation review, not measured production values. Oversized input is refused before launch; it is not silently truncated. The versioned operator protocol may impose stricter bounds.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| OM-HST-001 | The first adapter MUST use the exact qualified Pi SDK/print entry mode and negotiate a closed installation descriptor before creating a task host; interactive or unsupported hosts MUST refuse. | AT-HST-001 |
| OM-HST-002 | The adapter MUST disable implicit discovery and freeze one exact tool registry, including aliases, schemas and canonical argument binding; reload and replacement sessions MUST retain these restrictions. | AT-HST-002 |
| OM-HST-003 | Preparation MUST pin all host/native/runtime/account/registry identities and validate required prerequisites before credential access or provider traffic; mismatch MUST refuse without fallback. | AT-HST-003 |
| OM-HST-004 | Protected effects MUST dispatch through their native owner and admission path; the guest MUST lack direct access to operator control, protected resources and alternative tool transports. | AT-HST-004 |
| OM-HST-005 | Provider and native credentials MUST remain in the trusted owner; guests receive only scoped transport access, and task input/credentials MUST use private non-argv transport. | AT-HST-005 |
| OM-HST-006 | Governance mode MUST be immutable and explicitly visible as `execution-only` or `required`; unavailable native committed model release MUST refuse `required` before credentials or egress. | AT-HST-006 |
| OM-HST-007 | Every model release MUST bind the exact selected provider route/model/account, permitted prompt/context, tool schemas and history; remote references, hosted tools and undeclared disclosure paths MUST refuse. | AT-HST-007 |
| OM-HST-008 | Limits MUST report enforceable, observed and unavailable dimensions separately; durable reservations/deadlines MUST survive failure/resume and no unsupported hard token or spending ceiling may be claimed. | AT-HST-008 |
| OM-HST-009 | Tool calls MUST execute sequentially, and a new effect MUST remain fenced while an earlier original lacks native delivery acknowledgement or retains uncertainty. | AT-HST-009 |
| OM-HST-010 | Completed-result ACK MUST require verified exact native history delivery and original receipt/result/authority binding; UI display, export, a denial or a tool callback alone MUST NOT ACK. | AT-HST-010 |
| OM-HST-011 | Native approval submission, decision and resume MUST remain separate operations; the known unavailable decision utility MUST refuse, and no desktop control may manufacture approval authority. | AT-HST-011 |
| OM-HST-012 | Lifecycle replacement, import, compaction, model changes and shutdown MUST preserve the frozen security binding and durable owner custody; unsupported transformations MUST refuse. | AT-HST-012 |
| OM-HST-013 | Cancellation and termination MUST report native admission/effect state independently from guest exit, preserve unresolved originals and observe actual process-group exit before releasing launch custody. | AT-HST-013 |
| OM-HST-014 | Errors MUST carry an exact safe binding and dispatch/evidence classification; unknown or mismatched outcomes MUST never become successful task completion or automatic retries. | AT-HST-014 |
| OM-HST-015 | Recovery MUST act on original native identities, current valid authority and independently verified retained results, with explicit refusal for missing/corrupt/foreign state and stale ownership. | AT-HST-015 |
| OM-HST-016 | Additional provider/host support MUST be gated by exact profile-specific acceptance, including negative boundaries, package provenance and current native compatibility. | AT-HST-016 |

## Host discovery and callable surfaces

Initial Pi settings use no default local tools, packages, extensions, skills, prompt templates, themes, context files or telemetry discovery. The selected inline Chio extension is explicit. The protected profile ignores the user's ordinary Pi profile and project configuration. Host-native shell, MCP, delegation, background work, attachments and unreviewed installation are unavailable unless a later profile independently admits them.

`createToolRegistry` freezes the inventory and maps typed aliases to native tools. `createRestrictedSession` checks Pi `VERSION === "1.0.2"`, sets `toolExecution = "sequential"`, compares native arguments to the model's original canonical JSON before dispatch, and checks callable names/declarations against the registry. Desktop preparation must retain that behavior. A numerical path coerced into a string, an injected undeclared property or altered alias is a binding failure, not a convenient normalization.

After public `session.reload()`, runtime replacement or resume, revalidate exact declarations and reinstall applicable lifecycle restrictions before work can continue. A successful extension load followed by changed callable tools is an unavailable host. Preserve native records while diagnosing it.

## Provider selection and credentials

The candidate's existing provider profiles are the following source-supported choices. Neither is asserted qualified for Omarchy by this specification.

| Candidate profile | Fixed destination and authority | Bound dimensions | Unavailable claims |
| --- | --- | --- | --- |
| `openai/gpt-4.1-mini` | OpenAI Responses route, parent-held API credential; account/project identity must be independently resolvable when account-specific policy requires it | Requests, request timeout, response bytes, absolute wall duration; supported output ceiling conservatively reserved before submission | Exact spend or total input/output consumption from stream bytes alone |
| `openai-codex/gpt-5.5` | Native Codex subscription route, parent-read login cache and exact ChatGPT account binding | Requests, request timeout, response bytes, absolute wall duration | Hard output-token ceiling and remaining hard output-token budget are `null` |

Existing candidate defaults are 32 model requests, 120,000 ms per-request timeout, 8,388,608 response bytes, 1,800,000 ms absolute wall duration and 1,000 ms graceful termination interval. The API profile additionally defaults to 4,096 reserved output tokens per request and 131,072 across a run. These are existing candidate policy values, not observed latency or billing guarantees. Desktop profiles may lower them through the frozen operator configuration. Raising limits creates a newly admitted profile, not a mutation of a retained run.

Credential acquisition happens only after compatibility, confinement, authority and governance preflight. This first stage verifies operator-selected account requirements from the frozen binding; checking the actual credential's account occurs privately after acquisition and before any provider egress. No test should claim to know an unread credential's account. API secrets may enter a private owner credential facility; the desktop shim and guest must not inherit an API key environment variable. Codex credentials remain in their native private cache under the trusted owner; cache refresh belongs to the selected credential owner. Missing login, expiry, wrong account, unknown account where policy requires a known account, or refresh failure produces a typed refusal. There is no fallback to another credential, account, provider, model, raw network route or unconstrained Pi execution.

A credential rotation for the same admitted account needs an explicit native-supported generation transition. It must preserve original operation identities and authority checks. A changed account, route, policy or installation is a new admission requirement; a stale prepared handle cannot adopt it. Never put bearer credentials, prompts or context in process arguments, environment, status projections or ordinary logs. The candidate's `--prompt` interface is a known private-input gap; the proposed desktop adapter must qualify bounded stdin/FD transport or trusted SDK embedding without weakening confinement.

## Governance and disclosure

`execution-only` means protected tool effects remain native-mediated, while the fixed parent relay sends permitted prompt, history and tool-result bytes to the selected provider without native knowledge/disclosure governance. Show that scope before admission. P2 must select an explicit project/context boundary and exclude unknown classification or prohibited disclosure; this does not claim label-aware native governance.

`required` needs a qualified native model port whose `releaseFrozenRequest` owns final knowledge joining, retained original release intent, commit acknowledgement and provider submission. It must not return a permission bit and ask the adapter to call `fetch`. Native custody, installation generation, policy/contracts, provider profile, limits identity, credential generation and final serialized JSON must all match. The opaque parent-created relay reference proves object ownership only; the native service still verifies authority and freshness at release. Current CLI required governance remains unavailable.

Both modes restrict request envelopes to bounded inline history and the frozen function-tool inventory. Reject alternate tools, hosted web/computer tools, external item references, attachment fetches, unexpected proxy headers, route overrides and alternate model identities. A provider refusal is a provider event; it does not become a Chio authorization denial or prove that a preceding tool had no effect.

## Delivery, lifecycle and errors

Two model-emitted tool calls in one response do not permit two concurrent effects. The first call may complete, but the second remains refused/fenced until the first exact result has reached native history and the native owner has acknowledged it. `parallel_tool_calls=false` is defense in depth, not the enforcement mechanism.

The history observer accepts verified completed results only after checking their retained original. It delegates ACK to the native owner, including verified tool-error results when delivery is valid. Signed denials use their own exact verification and keep their fence; they do not use a fabricated completion ACK. Lost ACK responses cause original lookup and reconciliation, never effect repetition. An operator may separately export and receive the original result and invoke the native delivery protocol; listing or exporting alone does not establish receipt by the selected consumer.

Pi Durable, when selected, registers tools as `replay: "unsafe"` and sequential. Persistent call mappings and native owner custody survive observer detachment. Closing the adapter must allow `Session.close()` to cancel active work, yet retain exclusive custody until active callbacks, pending writes and ACK observers have actually settled. A new owner cannot attach during that interval.

Proposed error records contain a stable code, stage (`preflight`, `model_release`, `tool_admission`, `tool_dispatch`, `history_delivery`, `recovery`), task/native-operation references, immutable binding digest, safe message, evidence class, observed native state, and permitted next action. They never include raw provider response bodies, credential material or unredacted private input. `dispatch_status` is `proven_undispatched`, `committed`, or `unknown`; only the native owner supplies that classification. An adapter timeout ordinarily means `unknown` unless authoritative evidence proves otherwise.

| Host observation | Task projection and permitted response |
| --- | --- |
| Preflight version/account/runtime mismatch, no native admission | `failed` with unavailable prerequisite; reprepare only after a deliberate compatible selection |
| Exact native pending approval | `waiting_approval`; decision remains disabled until P3 prerequisite is met |
| Native unresolved/pending dispatch, corrupted result or missing retained evidence | `blocked_unknown`; preserve original and offer inspect/reconcile |
| Guest stopped while effects are settled and native cancel is confirmed | `cancelled`; retain completed effects and cancellation scope |
| Guest stopped while original effect remains uncertain | `cancelling` during reconciliation, then `blocked_unknown` if unresolved; guest exit does not prove task cancellation complete |
| Provider 401/429/5xx, malformed envelope, timeout or stream overflow | `failed` only when no unresolved native operation remains; otherwise `blocked_unknown`; no automatic provider/tool retry |
| Host prints `completed` or exits zero | Insufficient for success; require intended workflow checks, verified artifact and settled original outcomes |
| Host `completed_with_tool_errors`, `incomplete` or failed required recipe | `failed` with retained tool evidence; never `succeeded` because the model wrote a reassuring summary |

Connectivity `offline` or `stale` is separate from these task states. Native terminal observations have precedence over model prose. Unknown original effects have precedence over apparent cancellation or success.

## Proposed acceptance cases

Every case records the complete compatibility manifest, selected profile, exact arguments digest, timestamps, native original IDs and independent observations. The named evidence files are proposed artifacts. A fixture-only run must label that boundary; P2/P3 release gates also require actual native execution where specified.

### AT-HST-001: Entry mode and negotiation refusal

Trigger: prepare the pinned Pi print/SDK profile, then substitute a different Pi version, protocol major, missing feature and interactive entry mode. Observable outcome: only the exact supported profile prepares; refused variants create no session or provider request. Independent oracle: installed package/file hashes and a provider listener outside the adapter. Evidence artifact: `AT-HST-001-host-negotiation.json` with both accepted and refused descriptors.

### AT-HST-002: Immutable inventory under hostile discovery

Trigger: add project/global extension, skill, context and MCP files; attempt an undeclared local tool, schema coercion and registry mutation before and after `session.reload()`. Observable outcome: discovered content is absent, registry digest stays fixed and invalid calls produce zero protected dispatch. Independent oracle: native callable inventory and separate resource dispatch log plus unchanged filesystem canaries. Evidence artifact: `AT-HST-002-inventory-and-reload.json`.

### AT-HST-003: Preflight binds the complete installation

Trigger: change one of host archive, consumer lock, Node/runtime hash, native signer, store identity, account, policy generation or session target after initial selection; also hold prerequisite lookup beyond the proposed 10-second limit. Observable outcome: preparation refuses before credential access and before provider or resource traffic; no alternate route is tried. Independent oracle: instrumented credential file-open observer and separate network/resource counters. Evidence artifact: `AT-HST-003-preflight-bindings.json` with the one-field mutation matrix.

### AT-HST-004: No alternative effect path

Trigger: execute the useful project fixture, then request direct protected files, shell, raw compositor/session bus, SSH/container sockets, operator socket and direct kernel endpoint from the confined guest. Observable outcome: declared useful tools succeed through native receipts; all undeclared paths refuse. Independent oracle: resource owner audit, filesystem canaries and external socket listeners, each with an outside-boundary positive control. Evidence artifact: `AT-HST-004-native-effect-boundary.json` on actual x64 Omarchy.

### AT-HST-005: Private input and credential custody

Trigger: launch/resume with unique synthetic secrets in provider credentials, prompt and context; sample every related process argv/env and ordinary logs, then inject malformed credential/config JSON. Observable outcome: no canary appears there or in QML status; only the permitted provider receives the selected prompt through its private route; malformed input yields a sanitized refusal. Independent oracle: supervisor-side process sampling, isolated provider capture and guest mount inspection. Evidence artifact: `AT-HST-005-private-input.json`, retaining digests and boolean canary findings rather than secret bytes.

### AT-HST-006: Governance profile cannot silently weaken

Trigger: request `required` with absent, incomplete, expired and callback-only native services, then attempt to resume a retained run as `execution-only`. Observable outcome: each unsupported profile refuses with no provider credential access/egress, and governance binding is unchanged. After a native profile is delivered, separately test a real committed release and its interrupted commit. Independent oracle: native writer/release journal and independently counted provider requests. Evidence artifact: `AT-HST-006-governance-boundary.json`; absent native evidence keeps required mode unavailable.

### AT-HST-007: Exact model request and disclosure

Trigger: submit permitted inline context, then alter account/model/route, add hosted tools, remote references or an undeclared attachment, and mutate frozen bytes during release. Observable outcome: only the admitted envelope reaches the chosen provider; source binding changes refuse. Independent oracle: exact provider-observed request digest and, in required mode, native release record bound to that digest. Evidence artifact: `AT-HST-007-request-disclosure.json`, excluding raw private context from ordinary reports.

### AT-HST-008: Honest limits across restart

Trigger: reserve the final request/token allowance, interrupt before response, restart with the same profile, exhaust wall time and inject accounting-write failure. Test both candidate provider profiles. Observable outcome: no reservation or deadline resets; storage failure fences submission; Codex hard-token fields remain `null`; API reservations equal the final normalized submitted ceiling. Independent oracle: provider request counts, retained parent accounting and request envelopes. Evidence artifact: `AT-HST-008-provider-limits.json`; stream byte counts are never reported as total provider spend.

### AT-HST-009: Sibling calls remain fenced

Trigger: make the host receive two tool calls in one provider response while holding the first history ACK, including a provider response that ignores `parallel_tool_calls=false`. Observable outcome: at most the first effect dispatches; the second cannot execute until original delivery is settled through the permitted flow. Independent oracle: separate resource counter and native admission/delivery records. Evidence artifact: `AT-HST-009-sequential-delivery.json` with actual host execution and explicitly identified injected provider fixture.

### AT-HST-010: Native history is the ACK prerequisite

Trigger: substitute result bytes, signer, caller, receipt/request ID or arguments; export a correct result without delivering it; then deliver the exact retained completed result and a verified tool-error result. Observable outcome: substituted/export-only cases never ACK; exact completed native history does; verified error remains an error; denied history never fabricates completion ACK. Independent oracle: owner delivery latch and native session history read independently. Evidence artifact: `AT-HST-010-history-ack.json`.

### AT-HST-011: Approval decisions remain gated

Trigger: invoke desktop approval submission and both approve/deny decisions against the current frozen utility; after replacement qualification, return an approved token for a denied decision, wrong approval ID, expired token and changed arguments. Observable outcome: current decision actions refuse before admin traffic; replacement mismatches refuse before credential retention and cause zero effect. Independent oracle: approval store, private credential directory and resource audit. Evidence artifact: `AT-HST-011-decision-binding.json`; fixture success alone does not close P3 native acceptance.

### AT-HST-012: Lifecycle and Durable custody races

Trigger: reload, fork, switch/import, compact/summarize, change model, close with active work, then close while an ACK observer is paused and attempt a second owner attachment. Observable outcome: unsupported boundary changes refuse; allowed transitions keep their exact bindings; the second owner cannot mutate provenance until active work, private writes and ACK observer settle. Independent oracle: backend/session close state, native owner lock and original mapping digests. Evidence artifact: `AT-HST-012-lifecycle-custody.json` covering stock Pi and optional Durable separately.

### AT-HST-013: Cancellation does not erase effects

Trigger: cancel before admission, during a held native dispatch and after independently observed effect but before result delivery; kill the guest wrapper and parent at separate cutpoints. Observable outcome: new admissions stop where native cancellation linearizes, observed effects remain recorded, unresolved originals stay fenced, and custody is not released while a guest group survives. Independent oracle: resource effect counter, native journal, `/proc` process-group observer and provider request counter. Evidence artifact: `AT-HST-013-interruption.json` with final task and connectivity states separately recorded.

### AT-HST-014: Error binding and truthful task outcomes

Trigger: inject provider refusal/401/429/5xx, timeout, malformed tool output, failed recipe and unknown post-effect result while the host later prints a success message or exits zero. Observable outcome: typed errors retain the original safe binding and correct evidence class; unresolved effects project `blocked_unknown`; failed required checks never project `succeeded`. Independent oracle: native operation query and workflow artifact verifier outside model output. Evidence artifact: `AT-HST-014-error-classification.json`.

### AT-HST-015: Recover only the original

Trigger: lose a result or ACK response, restart the desktop and host, then present a forged owner result, absent journal, foreign live owner and finally the exact retained original. Observable outcome: invalid/missing state refuses without new identity or dispatch; valid native reconciliation restores original delivery and preserves counters. Independent oracle: native operation IDs, effect count, signature verification and authority-store identity before/after. Evidence artifact: `AT-HST-015-original-recovery.json`; diagnostic success is not a receipt.

### AT-HST-016: Additional host or provider cannot inherit qualification

Trigger: register an additional host/provider with plausible descriptor fields but no exact compatible evidence, then change one qualified archive/hash or provider API contract. Observable outcome: feature remains unavailable or source-supported-unqualified; required-profile admission refuses until its own positive and negative matrix passes. Independent oracle: public artifact provenance plus independent verifier matching every manifest field. Evidence artifact: `AT-HST-016-profile-qualification.json` with explicit skipped/open cases.

## Risks and prerequisite owners

The Pi maintainer owns SDK/print compatibility, immutable discovery restrictions, private prompt transport and native history delivery. The runtime/bridge maintainer owns actual authority, ACK/import semantics and the replacement approval utility. The Linux confinement maintainer owns the real x64 profile and process termination behavior. The provider adapter maintainer owns account binding, current route behavior and truthful limits. The release verifier owns exact compatibility and clean installation evidence.

Open prerequisites are listed as named artifacts in [readiness](research/chio-readiness.md). In particular, stock-host tests do not close native coding, provider or Linux x64 gates; source facade interfaces do not close required disclosure or child-process gates. P1 may show these capabilities as unavailable. P2 cannot expose an action whose required artifact is missing.

Source anchors: pinned [Pi session API](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/session.ts), [history observer](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/host-delivery.ts), [terminal classification](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/terminal.ts), [native compatibility contract](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/NATIVE-COMPATIBILITY.md), [provider limits](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/docs/RUN-LIMITS-LINUX.md) and [Durable adapter](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/durable.ts).
