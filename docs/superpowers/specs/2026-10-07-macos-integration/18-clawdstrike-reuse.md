# Selective Clawdstrike reuse and coexistence

Status: proposed normative design. Confidence: high in the reverified pinned source findings; moderate in the proposed reuse architecture; unknown for installed Chio Mac enforcement and coexistence.

Clawdstrike contributes useful endpoint observations, restrictive provider mechanisms, policy tooling and response patterns. Chio remains the authority for agent work: its kernel owns admission, exact approval, sealed allocations, durable stop, integrity and release receipts. Reuse should reduce platform implementation work while preserving that ownership.

Primary evidence and exact raw-file hashes are in [the source review](research/clawdstrike.md). Public main was reverified at `b9515321f4a20bd676dfef88bdf3ba4d015bc6e9`. Eleven selected local files at checkout HEAD `c493ad843e1a587168aa818cd8296baeb5ee77b7` match those public files byte-for-byte. No installed provider or Mac task profile was qualified by this review.

Dependencies: [authority](04-authority-integrity.md), [host architecture](05-host-architecture.md), [Endpoint Security](08-endpoint-security.md), [Network Extension](09-network-extension.md), [recovery](11-state-recovery.md), [distribution](12-distribution.md), [privacy/performance](13-privacy-performance.md), [operations](14-operations.md), and [qualification](17-qualification.md).

## Reuse decisions

| Component | Selected reuse | Boundary and required new work |
| --- | --- | --- |
| HushSpec frontend and corpus | Reuse portable syntax cases, explicit validation stages, semantic conformance fixtures and selected algorithms where license/provenance permits | Dialect projection must be closed and monotone; Chio native compiler and authenticated approver directory retain their authority. |
| Endpoint observation models | Reuse audit-token conversion, event metadata, gap/health vocabulary and pure detection input types | Bind to Mac host/user/boot/process incarnation and Chio run through qualified attribution; sensor sequence is not crossing order. |
| ES runtime plumbing | Reuse bounded AUTH_OPEN response and deadline/caching test patterns | The inspected observer default allows and its runtime subscribes to AUTH_OPEN only. Broader mediation and macOS 27 descendant APIs need new explicit implementation and qualification. |
| NE provider plumbing | Reuse content-filter lifecycle, real allow/drop path, policy reload and health patterns | Existing decision input is host/port plus TTL, not run/lease or semantic export authority. Add scoped attribution, generation convergence, existing-flow tests and unrelated-traffic behavior. |
| Pure detectors | Reuse selected observation-to-finding logic and fixtures | Findings are evidence. Any response becomes a request to the proper Chio owner or an independently administered external restriction. |
| Process response mechanics | Reuse protected-target and error-handling lessons | Inspected validation does not check the live PID incarnation before PID signaling. Do not adopt its docstring as a stop guarantee; qualify incarnation and check-to-signal races. |
| Health UI patterns | Reuse installation, user approval, activation, synchronization, degradation and last-success concepts | Represent each separately with source/freshness. An aggregate healthy state is not proof of task protection. |
| Approval queue and remediation UI | Reuse presentation and typed action mechanics selectively | Do not import independent approval credentials, task budget, execution ledger or semantic decision engine. |
| Installer/updater/dogfood patterns | Reuse provenance checks and joined same-host proof structure | A prebuilt signed extension needs source-to-binary evidence and clean-host activation. Existing app CI cannot qualify the system extension or Chio task. |

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-CLW-001 | Every reused component MUST record immutable upstream commit, exact file/artifact hash, license obligations, local changes and evidence class; public availability MUST be reverified before release claims. | AT-MAC-CLW-001 |
| MAC-CLW-002 | Reused mechanisms MUST remain observations or restrictions under the Chio crossing owner; they MUST NOT issue independent positive Chio authority, approvals, budgets or stop generations. | AT-MAC-CLW-002 |
| MAC-CLW-003 | HushSpec import/export MUST declare source and target dialects, compiler versions and supported semantic subset; unrepresentable, unresolved or weakening projections MUST refuse. | AT-MAC-CLW-003 |
| MAC-CLW-004 | Every policy load MUST perform parsing, semantic validation, pinned inheritance resolution and target compilation validation; lower-level compilation or lossy decompilation MUST NOT bypass those gates. | AT-MAC-CLW-004 |
| MAC-CLW-005 | Native exact approval, integrity and authenticated approver-directory requirements MUST survive policy projection; external policy approval or allow results MUST NOT become independent Chio endorsement. | AT-MAC-CLW-005 |
| MAC-CLW-006 | Reused ES code MUST declare its actual subscribed events, handler configuration and enforcement limits, and MUST NOT claim AUTH_EXEC, descendant confinement or installed coverage from AUTH_OPEN observer tests. | AT-MAC-CLW-006 |
| MAC-CLW-007 | Reused NE code MUST identify the actual host/port restriction scope and unknown attribution, and MUST NOT grant semantic, per-task or existing-flow guarantees without their own implementation and proof. | AT-MAC-CLW-007 |
| MAC-CLW-008 | Native process responses MUST validate live process incarnation and qualified targeting immediately around execution; unresolved reuse/race behavior MUST refuse the response or leave the capability unavailable. | AT-MAC-CLW-008 |
| MAC-CLW-009 | Detection findings and provider observations MUST carry provenance, clock/sequence and gap information separately from authoritative receipts; automatic remediation MUST traverse the owning native action contract. | AT-MAC-CLW-009 |
| MAC-CLW-010 | Restriction synchronization, stale policy, provider failure and removal MUST follow the selected profile's fail-closed task semantics without silently imposing an accidental whole-host policy. | AT-MAC-CLW-010 |
| MAC-CLW-011 | Distribution MUST prove reviewed-source-to-signed-extension provenance, required entitlements, activation and actual block/restore on the same qualified host; packaging or component CI alone MUST NOT qualify enforcement. | AT-MAC-CLW-011 |
| MAC-CLW-012 | Coexistence MUST keep product identities, policy stores, signers, approvals and operation histories distinct, with effective permission constrained by all applicable restrictions and no shared-transaction claim. | AT-MAC-CLW-012 |
| MAC-CLW-013 | Coexistence failures, updates, rollback, uninstall and independent external restrictions MUST preserve truthful Chio task/custody state, and MUST NOT remove another product's policy or bypass its enforcement. | AT-MAC-CLW-013 |
| MAC-CLW-014 | Reuse and upstream changes MUST pass exact component conformance plus applicable installed profile regressions before activation; policy or provider version mismatch MUST remain unavailable. | AT-MAC-CLW-014 |
| MAC-CLW-015 | Telemetry and evidence exchange MUST be scoped, bounded and redacted with explicit disclosure authority; neither product's raw events or secrets may be silently copied into the other's model context. | AT-MAC-CLW-015 |

## HushSpec dialect and semantic projection

Both products use HushSpec vocabulary; that is not sufficient to establish byte-for-byte or semantic interchange. At MAC-BASE, Chio has its own closed schema and native compiler in `crates/guards/chio-policy/src/{models.rs,compiler.rs,validate.rs,resolve.rs}`. Its `compile_policy_with_approver_directory` resolves threshold approvers through an authenticated directory. At CLW-PUBLIC, `compile_hushspec` validates both HushSpec and the resulting native policy, while lower-level `compile` has a different validation contract. `decompile` drops engine-only fields and rejects some unrepresentable semantics. A successful parse or roundtrip cannot certify preserved protection.

The proposed projection record carries source dialect/version, source content and dependency digests, target dialect/version, compiler build, supported feature manifest, target commitment and per-feature semantic disposition. Dispositions are `preserved`, `more_restrictive`, or `unsupported`; unsupported security semantics refuse activation. A UI may preview a lossy export for explanation only if visibly non-authoritative, but it cannot replace the installed policy.

The initial shared subset is chosen by conformance evidence, not by accepting every field with the same name. Corpus cases must include allow/deny precedence, defaults, inheritance/merge, glob/path normalization, port/host matching, expiry, disabled rules, thresholds, posture/origin conditions, output rules and unknown extensions. Path behavior must be checked under the actual platform's filesystem and case/symlink semantics. Remote inheritance is pinned and bounded under the Chio resolver contract; a URL or package name is not a stable policy identity.

The no-weakening obligation is semantic: for every admitted action in the declared domain, target evaluation and all native Chio constraints must permit no action forbidden by the source. A finite fixture suite provides bounded evidence for its declared subset, not a general mathematical proof. If subset checking cannot decide a feature, projection refuses it. Chio capability, integrity, exact endorsement, ledger, stop and output-release checks remain mandatory regardless of a portable policy allow.

An external Clawdstrike approval may authorize that product's own administrator action. It does not endorse a Chio publication, declassify task input or satisfy Chio's threshold approver policy. There is no adapter-created approval signer. Trusted UI surfaces submit native approval requests through [the existing operator boundary](06-operator-protocol.md), preserving the native issuer and generation.

## Native process and provider gaps

Clawdstrike's reviewed ES converter includes PID version in process identity, but the inspected process signal validator does not compare that version against the live target. Its signal-zero check proves neither identity continuity nor race-free delivery of a later signal. The Mac implementation needs a qualified process-incarnation source, target binding and evidence that a stale target cannot signal a replacement between check and action. If the available API cannot satisfy the required claim, restrict response to a separately qualified supervisor-owned worker mechanism or leave that action unavailable. Do not replace unknown targeting with process-name matching.

The inspected ES runtime's AUTH_OPEN subscription, default allow observer, uncached response and deadline fallback have different scopes. Reusing its event adapter does not imply that native execution, inherited handles, mapped files, process descendants, XPC helpers or existing descriptors are fully mediated. [The ES specification](08-endpoint-security.md) owns those experiments and the macOS 27 beta/final SDK gate.

The NE code has real allow/drop decisions. Its target conversion and policy compare host/port restrictions with expiration; the current decision input does not carry Chio run, lease or generation. Action/execution IDs in a restriction are Clawdstrike response identifiers, not proof of Chio authority. The source path does not establish closure of keep-alive, multiplexed HTTP/2, UDP/QUIC or already-released bytes on revocation. A network destination is also insufficient to authorize an HTTP account, recipient, upload body or signing request.

For Chio-managed tasks, scope restrictions to qualified attribution and route custody. Unknown attribution becomes an explicit unavailable task boundary or a separately chosen administrator policy, not accidental attribution to whichever agent recently ran. The selected profile must state how unrelated apps and users behave when policy is stale. A host-wide managed-endpoint installation may impose broader restrictions only under that independently selected deployment contract.

## Coexistence contract

Two modes are possible and independently qualified:

1. **Component reuse:** reviewed code or libraries are incorporated into Chio-owned provider components under Chio bundle identities, build provenance and lifecycle. The reused code contributes no external daemon authority.
2. **Co-installed products:** Clawdstrike retains its own administrator policy and service identity. Chio may consume scoped authenticated observations or encounter independent restrictions. There is no shared approval queue, signer, database transaction or implicit atomic stop.

In the second mode, a Chio-admitted operation may still be denied by external policy. Chio records a real refusal or unresolved effect based on its resource contract; it cannot loosen or disable the external product to make the task succeed. A Clawdstrike allow does not enlarge a Chio grant. Unknown external policy is reported as external/unknown rather than projected as current Chio authority.

A coexistence installation descriptor records both product build/signing identities, enabled provider kinds, lifecycle owner, policy schema/generation observations, supported observation channel and known OS extension conflicts. Do not assume filter evaluation order. Qualify duplicate providers, opposing restrictions, global-versus-per-user scoping, Fast User Switching, sleep/resume and independent update/remove. Provider operation IDs are namespaced; any correlation with a Chio task is an evidence relation, not an assertion of one transaction.

A response rollback removes only the exact restriction owned by its original issuer under that issuer's contract. It does not reverse a Chio effect, release ledger holds, delete another product's rules or imply restoration of every network flow. Uninstall or update keeps unresolved original Chio operations inspectable and does not relabel them cancelled. The [operations](14-operations.md) and [distribution](12-distribution.md) contracts own user-facing recovery.

## Acceptance procedures

### AT-MAC-CLW-001: Source and binary provenance

Fetch each immutable upstream blob, recompute the source-review hashes, compare the exact reused patch and license inventory, then substitute an unpinned or altered bundle. The independent provenance checker refuses missing/mismatched source-to-binary records. A matching source hash permits only a source claim until separate installed evidence exists.

### AT-MAC-CLW-002: Restriction cannot grant authority

Supply external allow, signed external approval and fresh restriction-cache state to a task lacking native authority or under stop. Native dispatch and output counters stay zero. A further external deny can block an admitted task, with separate provenance. No new native approval, budget, generation or receipt signer appears.

### AT-MAC-CLW-003: Projection refuses weakening

Project a finite declared shared corpus, then policies with unsupported extensions, defaults, origin conditions, threshold semantics and lossy export fields. Compare independently evaluated actions across both dialects and native constraints. Only preserved/more-restrictive declared cases activate; unknown or weaker behavior refuses with the exact feature path.

### AT-MAC-CLW-004: Full validation chain

Feed malformed YAML, schema-valid but semantically invalid policy, cyclic/unpinned inheritance and a native policy invalid after compilation. Exercise lower-level compiler entry points through the adapter. None can activate invalid policy; native installed digest stays unchanged. The successful case records every validation stage and pinned dependency.

### AT-MAC-CLW-005: Approval and integrity preservation

Import policy requiring threshold approvals and integrity constraints; attempt an unsigned directory, substituted approver, external approval token and omitted output rule. Independent native receipt/approval verification rejects each bypass before effect or release. A real native exact endorsement remains bound to the unchanged action and current influence.

### AT-MAC-CLW-006: Honest ES coverage

Inspect measured subscription and handler configuration, exercise AUTH_OPEN allow/deny, then attempt exec, pre-opened FD and delegated helper behavior under the proposed profile. Independent OS/effect observation determines coverage. Observer/component evidence cannot mark descendant-native or managed-endpoint qualified; missing coverage keeps that capability unavailable.

### AT-MAC-CLW-007: NE scope and existing flows

Run two tasks and an unrelated app against the same host/port, include unresolved attribution, IP/hostname differences and a held HTTP/2 or UDP flow, then revoke a task. Independent endpoint byte/effect observations show exactly which traffic is restricted. Host/port component success cannot satisfy semantic disclosure or per-task release gates.

### AT-MAC-CLW-008: Process incarnation race

Bind a target, terminate it, reuse its PID and pause between identity check and signal. Independently observe the replacement process. It must never receive the stale response; unavailable targeting refuses explicitly. Include boot change and same executable/name cases so neither process name nor PID equality passes as incarnation proof.

### AT-MAC-CLW-009: Sensor and authority separation

Inject duplicated/out-of-order findings, missing sequences, stale health and a forged response request. Native history retains separate sensor provenance/gaps and admits remediation only under its own current contract. An independent verifier cannot mistake a detector signature or external event ID for a native crossing receipt.

### AT-MAC-CLW-010: Failure scope

With an admitted managed task and unrelated app, make policy stale, remove synchronization, crash the provider and withdraw activation. Record actual task and unrelated-app behavior for the selected profile. Unsafe new task effects stop or the profile becomes unavailable as designed; an accidental whole-host block is a failed per-task test, not a security success.

### AT-MAC-CLW-011: Signed installed block and restore

On a clean qualified Mac, bind app/provider source and binary digests, signing identities, entitlements, approval/activation, policy generation and same host/user/run. Demonstrate permitted baseline, actual blocked target, unchanged unrelated traffic, explicit restriction removal and restored reachability with endpoint observations. Reject development exceptions, mismatched runs, dropped verdicts and packaging-only evidence.

### AT-MAC-CLW-012: Independent co-installation authority

Install both exact products under the intended deployment; apply Chio allow/external deny, Chio deny/external allow and independent approvals. Effects obey all restrictions. Receipts retain separate signers and identifiers; no external allow satisfies a missing Chio grant and no filter-order assumption enters the result.

### AT-MAC-CLW-013: Update/remove without lost custody

Hold an original effect, independently update or uninstall one provider/product, and roll back one owned external restriction while another stays active. Independent product stores and native journal prove no foreign rule deletion, authority resurrection or automatic refund. Unresolved effects remain visible after UI or provider removal.

### AT-MAC-CLW-014: Upstream drift gate

Change upstream compiler/provider code, policy schema or prebuilt extension while keeping the display version. Source/binary hashes and conformance detect the change; activation refuses until the exact updated tuple passes applicable component and installed tests. A version string alone cannot retain qualification.

### AT-MAC-CLW-015: Bounded evidence exchange

Send oversize, secret-bearing, foreign-user and untrusted raw endpoint events through the proposed observation channel. Independent capture shows only authorized bounded redacted fields reach the receiver, none automatically enters model context, and dropped/gapped evidence remains explicit. Export requires the resource/disclosure contract and retains provenance commitments.
