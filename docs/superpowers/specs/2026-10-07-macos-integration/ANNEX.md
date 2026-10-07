# macOS platform annex for the desktop operator program

Status: accepted platform direction; implementation and installed-runtime qualification unavailable. Date: 2026-10-07. Confidence: high in the ownership boundaries and cited source observations; moderate in platform choices and initial budgets; unknown in delivered macOS behavior.

This annex implements [ADR-0038](../../../adr/ADR-0038-desktop-operator-program.md) and the [shared desktop program](../2026-10-07-desktop-integration/README.md). The [program map](../../../architecture/PROGRAM-MAP.md), [operator projection](../2026-10-07-desktop-integration/OPERATOR.md), and [shared qualification](../2026-10-07-desktop-integration/QUALIFICATION.md) own cross-platform semantics. This document owns Mac integration, permission presentation, platform experiments, and distribution evidence. It creates no new task, recovery, credential, event, approval, or stop contract.

The previous numbered macOS specifications, plans, protocol schemas, and fixture catalog are superseded. Historical research remains source evidence only. In particular, `native-descendant-v1` is **retired**, not relaxed or renamed to Seatbelt. It cannot be selected, migrated into another profile, or advertised as qualified. Any future descendant-ES proposal needs a new decision and independent qualification including its original ES/NE and network-containment concerns.

## Product and boundary

Chio is a modern Rust kernel for agentic operating systems. On a Mac, the desktop makes the kernel's work, authority, receipts, recovery, and acceptance visible. The first execution product is a sealed, single-owner, unpaid W1 work commitment with a fixed recipe and review artifact. It reuses `chio-mini-swe`, the Pi restricted session and coding resource, and the workbench. A menu bar app and CLI lead native entry, with Finder Services secondary. The browser workbench is the first full operator and review client.

Isolation denies; Chio grants. The OS adapter restricts ambient access. Kernel-owned tools, gateway-routed calls, model relay, broker, approvals, work, and recovery retain their native owners. An isolation backend cannot grant Chio authority, and a successful gateway request does not prove that direct routes or descendants were confined.

| Profile or surface | `boundary_class` | `planning_status` | Mac-specific gate and honest presentation |
| --- | --- | --- | --- |
| Observe hook-mode sessions | `detect_only` | `ready_after_adr` | Show source and gaps. Hook absence, crash, or timeout can miss activity; observation does not protect the session. |
| Workbench, CLI, menu bar status/review display | `advisory_only` | `ready_after_adr` | Render owner data and freshness. The client cannot grant authority. |
| Approve and stop for protected/sealed work | `prevent` at the owning pre-effect gate | `ready_after_adr` | Approval requires S28 roster, production passkey verification, exact intent binding and repaired installed Pi approval utility. Independently, per-task stop requires S4/live process-host control and Kernel stop requires S8 phase 1 with its native route authorization. Missing approval prerequisites do not disable a qualified stop scope. |
| Sealed W1 work | `prevent` for kernel-owned tool calls; `cannot_see` for shell effects inside a granted execution | `ready_after_adr` | W1, recovery fixes, qualified runner and selected S7 backend, independent artifact/acceptance oracle. No per-write receipt claim. |
| Protected interactive, native shell removed | `prevent` for mediated tools | `ready_after_adr` | Each host independently passes doc 19 I01-I08, including alternate-tool and direct-route denial. |
| Boundary interactive with native shell | `prevent` for gateway-routed requests and adapter-routed MCP calls authorized before dispatch; `cannot_see` for internal workspace activity | `deferred` | S7 backend evidence, direct-egress denial and descendant confinement. A permitted native write has no Chio decision or per-write receipt. |
| Managed endpoint ES/NE | `detect_only` for observations; `cannot_see` for unmediated local effects | `deferred` | Administrator restrictions may deny OS activity, but are not Chio grants or receipts. Separate enterprise entitlement and deployment program. |
| Retired `native-descendant-v1` | `cannot_see` (no available desktop profile) | `hard_skip` | Never admitted. Its former ES/NE gates are not satisfied by Seatbelt or a VM. |

Every active row has `runtime_evidence: unavailable` for this desktop deliverable. Historical component evidence does not change that status. `ready_after_adr` records planning direction under ADR-0011, not delivery readiness.

All six doc 19 hosts remain in scope: Claude Code, Codex, Cursor, Hermes, Pi, and OpenClaw. Pi goes first because it has the furthest prior restricted-session evidence; neither that evidence nor a public version increment qualifies the current installed tuple. The contract and UI must be host-generic. A host cannot inherit another host's I01-I08 results. Hook-mode Claude Code and Codex remain `detect_only`; injection-safety claims additionally require their owning S11 work and are absent here.

## Runtime composition and ownership

The shared controller is an S1 C-layer process outside the TCB. It runs separately from the gateway, authority services, and agent hosts. The menu bar, CLI, and workbench are thin clients. A controller restart may lose cached presentation state; it must not lose native task ownership, restart an unknown operation, or create authority from a cache.

| Responsibility | Existing owner consumed on Mac | Platform delta |
| --- | --- | --- |
| Work identity and status | W1 `WorkHandleV1`, `WorkViewV1`, `WorkClient` and `WorkTransport` | Display execution, acceptance, result, recovery, settlement, and delivery separately. Do not invent `WorkPhase`. |
| Recovery and retry | Original-operation recovery; `InspectWorkflow`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`; S9 M20 | Lost reply is unknown until the owner resolves the original identity. Reusable/Retained/Terminal semantics come from S9. |
| Events | S5 Part A fixes and Part B stable subscriptions | Mac is another consumer of hints. Re-read authoritative views on gaps; no desktop-private event log or routine `InspectWorkflow` polling. |
| IPC | `chio-secure-ipc` | Add Darwin peer credentials to the existing crate; retain custody, framing, permission, replacement and lifecycle checks. |
| Process/child custody | `chio-process`, `ProcessRegistry` | Integrate Darwin launch and termination evidence, including descendants and live cancel/revoke. Never use a numeric PID as durable task identity. |
| Secrets and model release | `chio-secret-broker`, `chio-keyring`, existing Pi model relay | Per-user Mac credential storage and session behavior. No controller-owned credential proxy. |
| Approvals | S8 S28 roster and native approval owners | Production integration/qualification of the existing passkey verifier and exact visible-intent binding. Touch ID unlock or OS consent alone is not an approval. |
| Stop | S4 per-task closure; S8 phase 1 and S30 result kinds | Show fence acceptance, observed process death, outstanding effects and closure separately. `EmergencyControl` is not task stop. |
| Confinement | S7 evidence and backend adapters | Proposed `Seatbelt` and Mac VM kinds must be added at S7 before use. Until then render “not confined by Chio”. |
| Artifact/review | `chio-mini-swe` coding resource and workbench | Extend source intake/export and acceptance there, without a new Mac runner or acceptance ledger. |

The source baseline for this Mac branch does not contain every predecessor. [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md) is the retrieval and ownership reference. Implementation first integrates its dependency closures and verifies actual APIs. Do not rebuild missing owners in `integrations/macos/`. NK-01 to NK-03, W2-W4, M11, and witness topology are not blanket desktop prerequisites. S3 phase 1 supplies receipts for non-durable calls; S10 check-only reads in `SideEffecting` mode avoid imposing durable admission on every observation. Durability remains mandatory where the owning effect contract requires it.

### Darwin IPC and per-user lifecycle

Transport selection is an M1 work packet in `chio-secure-ipc`. Evaluate authenticated AF_UNIX first: on the connected descriptor, initialize `socklen_t token_len = sizeof(audit_token_t)` and call `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &token_len)`, requiring success and the exact returned size. Preserve the kernel-returned token; derive user, process, audit-session and PID-version facts through the SDK accessors. Pass its exact bytes as `CFData` under `kSecGuestAttributeAudit` to `SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code)`, then require `SecCodeCheckValidity` against the locally pinned designated requirement for the intended peer. A peer-supplied requirement or mere signature validity is insufficient. [Apple code lookup](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)), [dynamic requirement validation](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:)).

The inspected macOS 26.5 SDK exposes these APIs, but this is source evidence only. The pinned [Apple XNU implementation](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/uipc_usrreq.c#L900-L934) obtains the token through the peer socket's `last_pid`, `proc_find` and `TASK_AUDIT_TOKEN`; acquisition is not thereby proved safe against every PID-reuse or descriptor-handoff race. Security's audit-token path retains PID-version checking, which must not be reduced to a PID-only lookup. M1 must establish the complete custody path on each selected OS/SDK tuple, including peer exit/exec/reuse, inherited or transferred descriptors, reconnect/endpoint replacement, and current-session binding. An audit session ID alone does not prove the current unlocked operator session. The [source and SDK record](research/apple-platform.md#darwin-local-peer-token-candidate-2026-10-07) records the distinction; no installed qualification has run.

Retain XPC, integrated into this crate's custody abstraction, as the alternative if AF_UNIX cannot establish the required facts and custody. [Apple's archived `getpeereid` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html) supplies user/group facts only. Never fabricate UID/PID or incarnation facts, accept request-supplied identities as kernel evidence, or fall back to weaker admission when token, code-identity, session or lifecycle validation is unavailable.

Use per-user private service state and explicit native operator enrollment. Socket possession, loopback origin, UID equality, app signature, and an unlocked desktop are separate facts; none alone is approval authority. Authenticate browser access through the shared controller and enforce its origin/session protections. Deep links and Finder selection are untrusted requests for navigation/intake, never shell commands or grants. The secondary Finder Services handler validates the supplied pasteboard selection and submits only a proposal through authenticated owner intake; rejected or pending intake cannot capture a resource or issue authority. Its clean installed signed-app handoff is a release gate.

Native peer admission also binds authenticated dynamic code identity and applicable executable/library closure to the currently accepted release inventory/generation. A stable team/bundle designated requirement alone admits too many correctly signed builds. Fresh connections from old or alternate builds, exec/replacement and descriptor handoff must fail unless their exact tuple is accepted; unavailable identity or release custody keeps protected reads, events and commands closed. The native owner supplies both the release decision and process-derived evidence; UI version claims supply neither.

Register the per-user controller through `SMAppService`; registration/authorization, running state, authenticated reachability, owner health, and qualified execution are separate indicators. A refused login-item approval yields a clear unavailable state. A global ES/NE provider is installed only for the independently selected managed-endpoint track. [Apple SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

Lock, fast user switching, logout, sleep/wake, service death, and reboot invalidate sensitive cached views and require fresh owner/session checks. New affected actions stay unavailable while that reconciliation runs. An already-dispatched remote effect can remain unresolved; a cleared UI cannot prove its cancellation. The controller requests the owners' closure/reconciliation behavior instead of defining a new resume or stop state machine.

## Isolation adapters and runtime evaluation

### Lower-assurance native Seatbelt adapter

The restricted launchers already use `sandbox-exec`; the current public Pi source builds a deny-default Seatbelt policy with bounded runtime paths and gateway/model loopback destinations, and denies process fork and file links. That is concrete implementation evidence and must not be dismissed because App Sandbox serves a different packaged-app use case. It is not a promise of supported arbitrary sandbox APIs or a qualified desktop release. The current policy's fork denial also means a native-shell boundary profile needs different, independently measured descendant behavior. [Pinned Pi sandbox source](https://github.com/backbay-labs/chio-pi-plugin/blob/4214a5a8ddec776a5ff9ec78007442683fd8df03/src/sandbox.ts).

Keep Seatbelt as a thin, lower-assurance Mac backend under the accepted layer decision. Pin the exact executable, libraries, host/plugin versions, policy bytes, OS build, allowed paths, inherited descriptors, and permitted endpoints. Fail if the selected policy cannot load or an expected denial fails; never retry unsandboxed. Adding `Seatbelt` to S7 is a prerequisite, not retrospective qualification.

Qualify outside-workspace reads/writes, path replacement and symlink races, process execution and descendants, credential files, IPC endpoints, inherited files/sockets, IPv4/IPv6/UDP/direct DNS/loopback routes, host restart, revocation, and exact allowed useful work. Restricted sessions that deny descendants must prove fork/exec denial. Boundary sessions that allow descendants must prove the same restrictions follow them, including reparented workers and delegated services. Differences in those policies produce different qualification tuples.

### Higher-assurance VM candidates

Evaluate existing runtimes before authoring a bespoke Virtualization.framework supervisor. The decision criterion is a measured fit for the W1 workload and Chio authority boundary, not a vendor label. A VM is a candidate for stronger host isolation; no VM candidate has desktop runtime evidence here.

| Candidate | Current source-supported fact | Required selection evidence |
| --- | --- | --- |
| Apple Containerization | Swift package on Virtualization.framework; one lightweight VM per Linux container. Current upstream requires Apple silicon, macOS 26 and Xcode 26. | Pinned API and guest image; deny direct egress and host shares; preserve native ownership; usable runner, stop, import/export, lifecycle and resource limits. |
| OpenShell MicroVM | Official source documents explicit `vm` selection, Apple Hypervisor support, no guest NIC, and traffic through the host supervisor. | Actual Mac boot, process and bridge identity, supervisor failure behavior, Chio-only grant route, model/broker integration, no competing approval grants, and pinned middleware compatibility. |
| Existing `chio-mini-swe` Docker path | Reusable networkless coding workspace and mediated `sandbox/execute` owner. | Exact Mac container-runtime/guest tuple and safe broker routes. `ProcessContainer` evidence does not automatically establish a dedicated per-task VM boundary. |
| Bespoke VZ adapter | Apple's virtualization primitives can supply guest configuration, sockets, sharing and lifecycle control. | Consider only after documented fit gaps in the existing candidates justify a separately approved narrow adapter. No default guest/supervisor rewrite. |

Source pins and primary links are in [Apple platform research](research/apple-platform.md). Apple Containerization's macOS 26 requirement does not raise the menu bar experiment's minimum by implication. It makes that backend unavailable on earlier release rows. ARM64 and x86_64/Rosetta evidence are distinct. Linux x86_64 cage qualification cannot cover an ARM64 guest or a Node agent host.

The VM experiment admits only explicit owner-controlled service routes. Prefer zero direct network devices; if an existing runtime differs, prove equivalent direct-egress denial instead of treating NAT as policy. No host-directory share outside explicit captured input, including read-only shares, host credential mount, runtime management socket, signing key, arbitrary device passthrough, or unbounded guest output. Inventory every mount/channel and prove outside-input read and write sentinels remain inaccessible; a read-only share can still disclose host data. Before selecting a VM, bound stdout/stderr retention, ingress byte rate, bridge frame size and queue depth; test useful output plus malicious output/bridge floods. Excess yields explicit bounded truncation of display payload or owner-directed stop, while authoritative messages are never truncated into valid results and unresolved custody remains retained. Imports are captured snapshots; exports are bounded untrusted artifacts. A vsock endpoint identifies a transport, not a Chio principal; bind it to the owning VM and launch generation. VM request-stop, observed termination, bridge closure, authority closure, and remote outcome are different facts.

## Sealed work, approvals, and safe artifacts

The entry flow is: select a project and fixed recipe in the workbench/CLI, capture input through the existing coding-resource owner, create W1 single-owner work, run the pinned restricted host, review the resulting artifact, display evaluator-derived acceptance recorded by the W1 owner under the configured acceptance contract, and explicitly export or apply the reviewed result. Task submission cannot install an arbitrary host, substitute a runtime, add an ambient credential, or change its acceptance oracle.

Reuse the workbench's worktree-per-task model. Capture source identity, dependencies, declared task inputs, recipe, budget, acceptance criteria and oracle identity. The acceptance oracle runs outside the agent's writable workspace and checks the produced artifact independently. Agent-written tests are useful output, not the independent acceptance verdict. Human patch-apply or export approval authorizes only that exact effect; it cannot set an acceptance boolean, replace the configured evaluator, or turn a rejected artifact into accepted W1 work. Useful-work qualification includes a known-good patch and a plausible but incorrect patch which must be rejected.

Show `WorkViewV1` observations separately. A stopped worker may have produced an artifact, a completed execution may fail acceptance, accepted work may remain undelivered, and an unknown external outcome may prevent safe retry. Neither a green build nor a signed authorization receipt proves acceptance or delivery.

An attributable approval requires the S28 roster, an integrated and qualified production approval path using the existing `PasskeyCapabilityVerifier`, and the installed repaired Pi `approval-decide` utility. The verifier is exported source; its presence does not establish production approval-path integration or installed qualification. The utility must compare both requested decision and approval ID before retaining a credential; deny and mismatched-ID responses must retain none. A wrapper guard alone does not close that gate. The human reviews exact native intent, resource/result digest, destination, requested decision, authority scope and relevant current generations; owner verification consumes the bound approval. UI changes or stale/superseded intent invalidate the review. No app-held signing key or generic Touch ID success substitutes for this chain.

Safe artifact handling extends existing mini-swe/workbench owners:

- Resolve approved inputs without following attacker-replaced symlinks outside the captured scope. Reject special files, traversal, symlink/hardlink escapes, excessive entry counts, expansion size, and control-character filenames. Normalize Unicode/case collision checks for the actual target filesystem.
- Render code, diff text and filenames as untrusted text with bounded previews. Do not execute project scripts, HTML, Markdown resources, or shell escapes merely to display a review.
- Scan the complete bounded artifact for bidirectional and invisible formatting controls before truncating its preview; visibly escape/annotate them in rendered and accessible review content. Show omitted ranges and control counts, preserve the original bytes/digest, and label the safe view as a derivative. Copy behavior must expose controls explicitly; essential unreviewable scope/content blocks approval. Ordinary Unicode/RTL text remains usable. Evaluator acceptance cannot replace safe human review.
- Verify captured base and reviewed artifact digests before apply/export. A changed target, unexpected existing file, stale base, altered artifact or changed destination invalidates the operation. Expected-absent publication requires an atomic no-replace operation at the native owner; a regular file created at the same path after review must survive unchanged. Overwrite requires a separately bound native intent and current target revalidation. Retain the original native operation identity across lost replies.
- Separate local evidence export from effectful patch application or external delivery. Explicitly selected files and destination are required; overwrite needs the owner's exact operation binding. Creating a support archive never publishes code or sends a message.
- Qualify effectful patch application at its native owner separately from export, including multi-file interruption, target changes, partial-state custody, conflict-preserving recovery and lost acknowledgements. Export-only delivery may ship while apply remains unavailable; export qualification never enables apply implicitly.
- Redacted receipt derivatives identify omissions; preserve original signed bytes or verified commitments separately. An edited payload cannot retain the original signature claim.

## Installation, signing, upgrade, and removal

The initial application-build experiment targets Apple silicon arm64 with `MACOSX_DEPLOYMENT_TARGET=15.0`; this is a product experiment, not an announced support matrix or a claim about runtime API minima. Release only exact OS/CPU/runtime rows that pass. Intel, Rosetta, older OS versions and each new OS update remain unavailable until separately qualified.

Direct distribution starts with a Developer ID signed and notarized `Chio.app`; a signed disk image is the first packaging candidate and managed installer packages are separate release artifacts. Include reviewed controller/helper binaries in the bundle and bind every executable, native library, runtime artifact and policy to release provenance. Sign nested code with its reviewed identity and minimal entitlements, enable required hardened runtime settings, notarize with the supported toolchain, inspect notary output, and staple/validate the ticket. Notarization and Gatekeeper success are distribution checks, not runtime protection. [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

Permission presentation names the selected feature, needed permission, scope, and refused-permission behavior. Read-only viewing and sealed/VM work cannot require host-wide ES/NE access by default. Project access, model release, browser connection, login service authorization, passkey enrollment and enterprise provider activation are distinct actions. No request to disable SIP, bypass Gatekeeper, or weaken host security appears in normal installation.

A release inventory binds source/lockfiles, unsigned build closure, final signed bytes, team/bundle identities, entitlements, notarization record, runtime image/policy hashes, active provider generations, protocol compatibility, and exact qualification reports. Reproducibility claims specify whether they cover unsigned build output, package contents, or final signed bytes.

Updates stage and verify the complete signed set, fence affected new admission through native owners, reconcile active work, activate compatible components, and check effective installed generations before reopening. Incompatible store/protocol versions, failed migrations, old active extensions, denied replacement, stale runtime images, or failed health checks leave affected profiles unavailable. Rolling back app bytes, app state and per-user Keychain/credential fixtures cannot roll back authority history or revive a spent/revoked approval; restoring both custody domains while newer native authority or freshness access is unavailable must keep affected effects fenced. Never delete unresolved custody to make an upgrade pass.

The native release-generation floor must survive supported restoration independently of the restored app/package/state snapshots. If that custody or its current freshness cannot be established, package activation and affected profile admission stay unavailable. After each supported restoration, rerun signed older-package rejection through every shipped installer/updater and reject restored old peers at startup; credential rollback evidence alone does not qualify downgrade prevention.

Removal first requests native closure, preserves/exportably inventories unresolved work, unregisters the per-user service, and removes only application-owned artifacts selected for removal. Enterprise extension removal follows OS/MDM lifecycle and remains visible until externally confirmed. Credentials are removed/rotated through their owner; user projects, unrelated VMs, other users' state, and exported artifacts remain separate custody. A denied extension removal or unresolved external operation yields a precise remaining-state report, not “fully removed”.

## Managed endpoint and Clawdstrike reuse

ES and NE form an independent managed-endpoint track. Entitlement eligibility, provisioning, installation, user/administrator approval, effective provider activation, task attribution, and actual denial are separate gates. Content-filter deployment follows Apple's provider-specific system-extension rules; global lifetime needs explicit multi-user isolation. An MDM policy is deployment configuration, not proof that a flow was blocked. [Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

Reuse Clawdstrike event conversion, bounded callback patterns, NE plumbing, selected detector fixtures and source-to-bundle evidence methods where the [pinned source review](research/clawdstrike.md) supports them. Its default-allow ES observer is not full process confinement. Its NE allow/drop code is real but does not prove deployed Chio task attribution or existing-flow revocation. Its PID-only signal path is not incarnation-safe termination. Neither its approval queue nor its policy compiler becomes the Chio authority owner.

Before any enterprise claim, obtain actual team entitlements and provisioning, final SDK/OS identity, clean signed activation, scoped denial and restoration, and tests for callback deadline, queue overflow, provider death, policy change, open descriptors/flows, coexisting filters, wrong/missing audit tokens, fast user switching, and removal. Missing identity makes task-specific enforcement unavailable. Apple descendant/deadline documentation remains research relevant to this track; it does not reopen retired `native-descendant-v1`.

## Privacy, resources, and performance budgets

Default collection excludes whole-home scans, clipboard polling, screen recording, background code indexing, remote analytics and crash upload. Project read authority is distinct from model/support disclosure. Model payloads, source, paths, raw errors, credentials and bearer references stay out of diagnostics before persistence. OSLog privacy annotations are additional protection; Chio cannot erase OS-managed logs, backups or provider copies by purging its cache.

Initial retention and bounds are product targets implemented at the existing data owners: task payloads seven days after resolved completion; resolved receipt view 90 days; diagnostics seven days/20 MiB; optional sensor ring 24 hours/50 MiB; aggregate samples 30 days/10 MiB. These presentation/payload defaults are subordinate to each native owner's retention, proof-dependency and numeric-domain rules. The first applicable time or size bound wins. Unresolved authority and proof dependencies are never silently pruned. A support export is explicit, local, previewed, bounded to 10 MiB and a selected 15-minute default window; it excludes credentials, raw databases/WAL, unsafe archive members and unauthorized payloads. When necessary custody exceeds storage capacity, stop affected admission and report the retained obligation.

Support-export preview binds an immutable native-owner selection with fixed absolute time window, audience/scope, record revisions/digests, redaction policy and output manifest. Publication uses exactly those still-authorized bytes; changed binding requires a new preview, and rerunning a rolling query cannot silently add records. The evidence-export owner separately qualifies atomic no-replace destination publication, parent/symlink/regular-file races, exact-target overwrite authorization and original-operation recovery. Mini-swe artifact export cannot stand in for this owner's support-export evidence.

These are initial experience budgets, not measurements. Fix them in a pre-run report before testing; revision requires prospective rationale and a new run. Safety failures close the profile irrespective of good latency.

| Measurement | Proposed release budget | Required distinction |
| --- | --- | --- |
| Cached 200-work list first usable frame | p95 <= 200 ms | Independent rendered UI timing |
| Read-only local IPC | p95 <= 100 ms | Includes parsed reply; no repeated chargeable recovery polling |
| Owner durable work acknowledgement | p95 <= 500 ms | Input capture, model time and final result reported separately |
| Commit hint to visible projection | p95 <= 250 ms | Hints never stand in for the authoritative read |
| Idle shell plus controller, no VM | Mean <= 1% of one CPU core; combined RSS <= 200 MiB | Report browser/VM/provider costs separately and total system cost |
| Idle diagnostic writes | <= 1 MiB/hour | Separate authority writes and measurement overhead |
| Deterministic broker incremental overhead | p95 <= 10 ms above identical direct stub | Same payload/durability/concurrency; full provider latency also reported |
| S8 fence acknowledgement | p95 <= 500 ms when host schedulable | Not process death or external-effect closure |
| Owned worker termination | <= 10 seconds when host schedulable | Otherwise unresolved closure and escalation, never false success |
| Idle/useful-work energy increment | <= 5% / <= 15% versus paired equivalent baseline | Inconclusive if instrument resolution is insufficient |

Measure five warmups and 30 latency samples at loads 1, 8 and 32; report p50, p95, maximum, errors and raw samples. Idle CPU/RSS uses ten minutes after five minutes settling. Energy uses at least five randomized paired 60-minute trials with fixed hardware, OS, display, power mode, battery/thermal range, network fixture, completion artifact, and calibrated units. Record all observer overhead. Coalesce subscriptions and stop idle collection; power savings never defer safety callbacks or authority fencing.

## Failure modes and qualification handoff

The [shared qualification owner](../2026-10-07-desktop-integration/QUALIFICATION.md) defines the evidence envelope. Mac adds the exact machine/OS/SDK tuple, signing/permission state, backend and guest identities, installed and active generations, filesystem characteristics, power conditions, and clean-host reproduction. Independent observers record actual file effects, network deliveries, process incarnations and rendered behavior. Synthetic fixtures or source inspection do not become installed proof.

Every artifact used in a release decision needs authenticated provenance and current trust/freshness at that shared owner, either directly signed or included by identity/digest in its signed manifest. Consistent hashes alone cannot authenticate a report. Missing, unauthorized, invalid, expired or revoked endorsements and unavailable freshness block the affected decision. Raw logs may be bound manifest members; there is no Mac-only signer or qualification authority.

| Condition | Required result | Platform oracle |
| --- | --- | --- |
| Owner/IPC/backend missing, bad signature, wrong peer | Refuse affected action and show reason; no unconfined fallback | No child launch, secret release or external effect |
| Dropped subscription hints or controller restart | Refresh owner's bounded views using stable cursor semantics | Native work identities unchanged; gaps visible; no duplicate work |
| Lost approval/create/export reply | Resolve original operation under owner retry rules | Independent effect count remains correct |
| Lock/logout/user switch | Clear sensitive display, reject stale authority/session and reconcile | Second user and lock-screen captures disclose no task data |
| Worker escape/direct egress/descendant bypass | Deny and mark backend qualification failed | Outside sentinel unchanged, external sink receives no payload |
| Stop accepted but child/remote effect survives | Separate fence from incomplete closure/unknown outcome | Process and network observer agree with reported uncertainty |
| Disk full, queue saturation, clock/freshness unavailable | Bounded diagnostic gaps; affected authorization refuses | No effect after failed required persistence |
| Update crash/mixed versions/backup restore | Reconcile native owner; keep affected admission closed | No replayed spent grant or duplicated effect |
| Wrong artifact/base/destination or malicious archive | Refuse apply/export; keep original custody | Independent destination inventory unchanged |
| ES/NE entitlement denied or provider exits | Managed profile unavailable with explicit remaining state | Effective OS/provider inventory, flow and file probes |

The [implementation plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md) maps these cases to dependency-gated packets. Delivery requires useful work plus negative probes, installation/upgrade/removal, privacy and performance on the same exact candidate. This annex supplies planning direction only; no Mac desktop profile, runtime candidate, signed application or enterprise provider was built or qualified in this consolidation.
