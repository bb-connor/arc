# Native host acceptance and release evidence

Status: specification only. `planning_status: ready_after_adr` under ADR-0038.
Every proposed execution profile is unavailable until its exact tuple passes.
Document checks, mock data and historical host runs cannot satisfy runtime gates.

## Evidence identity and authority

[RELEASE](RELEASE.md) assigns the native-profile schema, trusted verifier and
activation enforcement to shared packet 2a in `chio-release-evidence` plus the
actual native lifecycle consumers. The existing tool verifies artifact hashes
and a self-signed internal manifest; it does not enforce Q-case completeness or
profile readiness. O7/M10 cannot close until packet 2a supplies that executable
gate and their installed tests exercise its actual activation call sites.


A qualification record binds the owner source commit, public release revision,
host/plugin versions, controller/client builds, OS version and architecture,
backend and policy digest, artifact hashes, test commands, raw outputs, expected
outcomes and reviewer decision. Dependency eligibility is separate from runtime
readiness. A prerequisite's green test does not qualify a different installed
artifact. Public instructions may reference only revisions actually available
in the public repository.

Maintain the authoritative evidence with the owner being tested. The native host
release manifest references those records; it does not duplicate their status
or reinterpret them. A test record must include a positive control, the actual
adversarial stimulus, observed native result, and proof that no forbidden effect
occurred. Omitted cases, zero evaluated profiles, skipped commands, stale logs,
unknown evidence kinds and missing signatures cannot yield a ready state.

The existing release owner must reject raw ambiguous, noncanonical or over-limit
manifests under its selected format before they contribute evidence or profile
state. Exercise duplicate/escaped member aliases, invalid numeric/Unicode forms
and byte/depth/count limits using payloads authenticated by an authorized fixture
signer so signature rejection cannot mask a decoding defect. Signature checking
and semantic consumption share the exact accepted bytes and one unambiguous
decode; normalization must not turn rejected input into a different accepted
tuple. Pair each negative with the owner-format canonical positive control.

All profile checks use ADR-0011 `boundary_class` and `planning_status` separately.
Hook activity is `detect_only`; local effects outside mediation are `cannot_see`;
UI guidance is `advisory_only`; only a proven pre-effect gate is `prevent`.

## Required acceptance matrix

The following are test obligations, not claims that these tests exist or pass.
Put each executable test in the named owner when implementing the dependency.
The delivery plan covers native bindings and consumer tests after those contracts land.

| ID | Owner and stimulus | Required result |
| --- | --- | --- |
| Q01 | Work owner: finish process, reject acceptance, withhold settlement or delivery independently | When W1 is exposed, WorkViewV1 preserves all six observations; consumers invent no composite success |
| Q02 | Each exposed effecting mutation owner: lose a response after admission; restart; barrier-synchronize exact duplicate and same-ID changed-intent submissions at native lookup/admission/commit | Original command/preparation/operation lookup; atomic full-intent arbitration yields one original operation/outcome or retained uncertainty, no new identity or duplicate protected dispatch/downstream effects; changed intent conflicts before retention/effect |
| Q03 | S9 M20: retry reusable, retained and terminal failures | Owner classification and original identity control retry; UI never promotes unknown to safe replay |
| Q04 | Selected native binding or optional projection: substitute response method, parameters, pagination, session, work, scope revision or request intent | Reject substituted response including error/retry replies; never render another request's evidence |
| Q05 | Native approval: request deny but receive an approved token; substitute approval ID or bound scope | Reject before retention/use; no credential persisted, no resume or external effect |
| Q06 | S28/verifier: missing roster, stale/revoked identity, test-only verifier, sidecar-signed approval | Attributable approval unavailable; SharedCredential shown truthfully; no approval UI bypass |
| Q07 | S4/process owner: stop while children/grandchildren run, then restart services | Closure evidence includes the real process/resource boundary; pending/failed/unknown distinct from stopped |
| Q08 | S8: stop before restart and exercise operator route authorization | Durable kernel stop survives; tenant/recovery scopes remain unavailable before their owner phases |
| Q09 | Selected S5 Part B stream: disconnect, duplicate/reorder hints, overflow retention, stale cursor, unauthorized stream | Bounded resync against the non-persisting owner read; no invented authoritative event or paid inspect polling |
| Q10 | IPC/browser session owners: wrong UID/PID/session, reused PID, stale socket, spoofed server, duplicate controller; malicious-origin HTTP and cross-site WebSocket requests to the genuine controller with a live ambient-cookie session | Native peer/session policy rejects; one authoritative owner per declared custody scope, distinct enrolled clients, and no weaker transport fallback; the optional projection enforces its own single-controller rule; exact browser origin plus non-ambient owner proof precede protected reads/subscriptions/mutations, with zero unauthorized bytes/effects; genuine authenticated requests succeed, no weaker fallback |
| Q11 | Host owner/doc 19: crash/omit/timeout hooks, enable alternate native tool/shell, change host version | Hook mode stays detect_only; protected mode fails closed and requires I01-I08 for that host tuple |
| Q12 | S7/backend: unknown kind, stale policy/hash, launcher bypass, inherited FD, direct IP/DNS/IPv6 egress, child escape, admitted lifetime across suspend and realtime changes | No confinement claim without native evidence; fail launch or restrict; no unconfined fallback |
| Q13 | Secret broker/relay: malicious host tries environment/file/process-list/log access or alternate provider route | Raw credentials absent from agent/client; every permitted model route bound to enrolled scope |
| Q14 | Applicable artifact/evidence export owner: symlink/hardlink replacement or alias, path traversal, descriptor race, oversized/archive/device artifact, changed base, unauthorized staging reads, repository-controlled capture execution/fetch/object indirection | Bounded audience-private staging and descriptor-based export reject unsafe input; result hash/base/review identity bind applicable acceptance and publication, and unrelated alias contents/identity/access policy remain unchanged |
| Q15 | Budget owner: zero, max, overflow, fraction, missing/unknown units, duplicate dimensions, unavailable observations | Exact typed bounds and unique dimensions; unavailable never interpreted as unlimited; native enforcement independently proven |
| Q16 | Native owner/profile health (and projection when selected): no evaluated profiles, stale session, expired evidence, missing backend | Feature unavailable with a reason; no empty healthy/ready response |
| Q17 | Each exposed helper owner, plus UI/workbench only when selected: forged artifact text, injected commands/links, notification click, out-of-order response; leading-dash operands, option aliases and Git pathspec magic/globs | Inert presentation and qualified literal operand semantics; no unintended file reads, execution, egress or authority transition; useful ordinary operands and keyboard/screen-reader state remain correct |
| Q18 | Release: swap one artifact/tuple field, remove required evidence or submit authenticated ambiguous/noncanonical/over-limit manifest bytes | Positive baseline passes; each mutation fails its intended gate before evidence admission or profile state changes; signature and semantic consumption use one strict bounded owner decode |
| Q19 | Process backend: timeout and descendants, spawn/exec/reparent during closure, unrelated exited child, unkillable/pending child | Bounded cleanup and complete custody evidence; do not reap another task's status or report false completion |
| Q20 | Install/update: unsigned/tampered/wrong-arch artifact, downgrade across installation users, competing update/removal, concurrent exact and changed-intent duplicate lifecycle submissions, unauthorized/replayed privileged caller, mid-update crash, reboot/uninstall | Reject invalid package/caller; native atomic original-identity arbitration, single-writer custody and installation-scoped floor guard shared mutations; no duplicate downstream effects or lost uncertainty, preserve recoverable state and revalidate before enablement; explicit cleanup |
| Q21 | Observation/S5 owners, plus recovery when exposed: subscriber idle for long periods and sustained event traffic | No observation path spends recovery-command quota or drains settlement reserve; configured buffer and resource limits enforced; exposed recovery additionally passes native saturation/finality controls |
| Q22 | Isolation profile: attempt an in-workspace write through the host's native shell, outside an explicitly granted runner operation | Boundary interactive labels a permitted write cannot_see with no per-write receipt; protected/sealed profiles reject the alternate native-shell route. An expressly granted sealed recipe's internal shell is a separate bounded execution and cannot qualify this negative. |

## Native effects and sealed-work safety without blanket keystone dependencies

Not requiring the complete S9/S10/S11 redesign before every host capability does
not waive admission, crossing or ABI safety. Each selected effect owner must prove
current-authority admission before dispatch, exact request/scope and source
binding, atomic reservation and transition behavior for its effect class,
required persistence before acknowledgement, post-effect receipt/uncertainty
handling, authenticated closed native dispatch and guarded artifact release.
These properties are exercised through W1, recovery, foundation and the required
S3/S4/S5/S8/M20 deltas, using the owning S10 read/effect distinction and S1
placement rules. A selected path missing any of those properties stays
unavailable until its owner implements and qualifies it. A native binding or optional client may not
substitute a weaker path merely because the whole pure-machine/crossing/census
redesign is not a blanket milestone gate.

Sealed qualification includes the configured evaluator whenever it executes
candidate imports/builds/tests. Apply Q12/Q19 confinement, resource and closure
probes to that execution separately from the agent/recipe. A known-good artifact
must produce a bound valid result; hostile candidate hooks must fail outside
file/credential access, direct egress, inherited-descriptor and unrelated-process
effects under independent observers, and must not forge the trusted acceptance
channel. Failed/unknown evaluation cannot become accepted W1 work. Existing
unconfined workbench checks and immutable oracle files are insufficient evidence.

Execution lifetime qualification uses the actual native process/backend owner's
boot/incarnation-bound elapsed deadline and authority-issued absolute expiry.
The selected elapsed timebase must include host suspend; a guest timer or UI
refresh cannot establish the host lifetime bound. On each backend, admit useful
work with a short finite bound, suspend past it, and independently probe native
dispatch, local continuation/effects and descendant custody after wake. The owner
must fence expired new authority and prevent untrusted continuation beyond its
qualified bound, retain closure/unknown outcomes truthfully, and never replenish
a lifetime on restart. Expire the elapsed deadline and authority-issued absolute expiry in separate
trials while the other bound remains valid, so one check cannot mask a missing
second check. Test realtime jumps backward/forward separately and
combined with suspend, missing clock/freshness and boot changes: rollback cannot
revive an expired operation, and uncertainty cannot authorize continuation. Keep
already-dispatched external outcomes distinct from forbidden new dispatch; no
clock check claims to undo them. Record actual owner time APIs, boot identity,
expiry semantics and declared closure latency with independent observers and an
unexpired useful positive control. Q12/Q19 and platform installed acceptance
consume these cases only for selected execution profiles; basic Observe retains
its own read-authority/freshness gates without a task-lifetime dependency.

## Native approval defect handoff

The Pi wrapper refuses `approval-decide` before native invocation. The audited
bundled bridge still exposes its native utility, so wrapper refusal is not a
fix for that utility. The platform research records the source/archive pin.
Any profile that ships or exposes this utility must repair exact decision and
approval-ID matching, replace the packaged dependency, and run Q05 against the
installed binary including direct invocation. Until that evidence exists, that
profile's affected approvals and publication remain disabled. A separate
approval route with no affected utility in its reachable installed closure still
requires Q05/Q06 against its actual native owner and production verifier; it does
not require installing Pi. A source-level fix alone is insufficient.

Other owner defects remain explicit dependencies: durable stop and mounted
authorized routes, safe observation without reserve consumption, live process
cancel/revoke, roster attribution and a production endorsement verifier. This
package records the handoff; it does not claim those defects are fixed.

The following tracking issues were verified live as **OPEN** on 2026-10-07 with
`gh issue view`. An open issue is a recorded handoff, not a repair or acceptance
record. These internal qualification references are not public checkout or
release instructions.

| Tracking issue | Unresolved owner obligation and qualification effect |
| --- | --- |
| [Native approval decision/ID binding](https://github.com/backbay-labs/chio-bridge/issues/3) | Repair the utility, publish/replace its packaged archive and pass installed Q05 controls. Pi wrapper refusal does not fix direct utility invocation; affected approval/publication remains unavailable. |
| [Emergency stop custody, routing and authorization](https://github.com/bb-connor/arc/issues/1180) | Constant-time token comparison, an explicit route-mounting decision with mounted-route tests where applicable, and S8 phase-1 restart/cross-process durability. Q08 remains unaccepted. |
| [Recovery observation and settlement reserve](https://github.com/bb-connor/arc/issues/1181) | Current remediation still needs source-bound re-review and saturation/finality acceptance; Q09/Q21 must use non-persisting observation without consuming settlement reserve. The historical review's count does not establish current unresolved totals or resolution. |
| [Host-plugin and tool-server boundary claims](https://github.com/bb-connor/arc/issues/1182) | Complete the owner README/AGENTS/plugin wording cross-check against ADR-0011. The issue remains open; this package's corrected wording alone cannot close its broader acceptance scope or qualify a host. |

Live process control, roster attribution and production endorsement verification
retain their separate owner gates in the program map; these four issues are not
a complete inventory of every predecessor obligation.

## Profile coverage

| Profile | Mandatory acceptance | Runtime gate |
| --- | --- | --- |
| Observe | Q04, Q10-Q11, Q16-Q17, Q21; Q09 for exposed streams; Q15 projection cases for an exposed budget view; Q02 for every exposed effecting mutation, including support export/lifecycle; applicable Q01/Q03 for exposed W1 views or recovery capability | Authenticated bounded non-persisting selected owner reads, trust-control GETs and truthful hook source attribution; S5 A/B gate selected unified stream sources, not non-streaming reads; W1/M20 are not basic receipt/hook observation gates |
| Approve | Q02-Q06, Q09-Q10, Q16-Q17 | Qualified native approval owner, S28 identity, production verifier and exact installed approval-route binding (including the utility when present); no stop capability implied |
| Per-task stop | Q02-Q04, Q07, Q09-Q10, Q16-Q17, Q19 | Qualified S4/process closure and its native route authorization; Q05/Q06 are not prerequisites when approval is absent |
| Kernel stop | Q02-Q04, Q08-Q10, Q16-Q17; Q19 additionally for any claimed process cleanup | Qualified S8 phase-1 scope, durability and native route authorization; no S28 approval or per-task closure prerequisite and no implied process termination |
| Sealed work | Q01-Q22 applicable to its concrete backend, with exclusions justified by owner; Q22's alternate native-shell negative is mandatory | W1, recovery, restricted host, runner, S7 and installed release tuple |
| Protected interactive | Q02-Q13, Q15-Q22 plus doc 19 I01-I08 | Each selected host tuple individually qualified; native-shell removal and Q22 alternate-access rejection enforced; all-six program completion is separate from selected-host promotion |
| Boundary interactive | Q02-Q13, Q15-Q22 as applicable; no mediated-local-effect claim | Deferred; independent backend evidence required |
| Managed endpoint | Platform annex's ES/NE matrix plus Q16-Q20 and Q02 for every exposed effecting mutation | Deferred; consent/entitlements and restrictive-only authority model |

Q09 stream-specific stimuli apply only where subscriptions are exposed in any
row. Non-streaming reads still require bounded audience-safe native reads,
request correlation, truthful freshness and Q21 resource/idle controls. Optional
UI-only stimuli likewise require an explicit absent-surface exclusion, never an
omission of equivalent native authority or effect tests.

Every row expands to an explicit executable case manifest at implementation
time. "Applicable" must not let a release omit a gate silently: the manifest
names the owner-approved exclusion and its reason; an unclassified case fails
qualification. A profile may fail while another independently qualifies.

The Q identifiers are not an exhaustive replacement for the consumed owner
contracts. Each platform's source reconciliation must map every applicable
HOST-CONTRACT, CAPABILITIES and CONSUMERS obligation; consumers selecting the
optional projection also map every OPERATOR normative and protocol-freeze row, as well as
each Q-row stimulus and annex requirement, to its owner, implementation packet,
actual test command, positive control and independent negative observation.
Include negotiation/reconnect, raw decoding, pagination consistency, review
invalidation and hook-to-receipt attribution whenever those surfaces are exposed.
Release qualification removes each required case individually from a passing
manifest and proves the affected surface cannot be promoted; omitted, skipped
or unclassified cases cannot disappear behind a broader passing Q label.

For every browser-delivered profile, Q10 covers the genuine controller as well
as endpoint impersonation. Enroll a legitimate browser session, retain its live
ambient cookies, then issue malicious-origin form/fetch requests and cross-site
WebSocket handshakes/subscriptions against the real controller. Exercise missing,
null and substituted origins and absent/invalid/replayed request/session proof.
Independent owner dispatch/effect counters and read/stream canaries must show no
protected bytes or native effects. Pair these with legitimate protected reads,
subscriptions and each exposed mutation using the owner-approved non-ambient
proof and exact origin, including reconnect. Browser read/subscription authority
is mandatory for Observe; mutation probes apply only to mutations it exposes.
Cookie flags, a CORS rejection or a permitted Origin alone cannot satisfy Q10.

Q17 inventories each native helper invocation reachable by the selected profile,
including open/navigation, capture/import, export/publication and lifecycle
helpers where exposed. Record its actual executable/API, trusted options and
operand parser. Test leading-dash input, option aliases and Git pathspec magic/
globs with outside-file, process and network canaries; rejection or literal-data
handling must cause no unintended reads, execution or egress. A verified `--` is
valid only where that tool supports it; Git additionally requires literal
pathspec semantics. Descriptor/stdin/typed APIs must prove the same data boundary.
Pair every negative with a useful ordinary operand through that exact helper;
blanket helper refusal or an argv-construction assertion is not acceptance.

Q02 applies per entry in an explicit selected-profile mutation inventory, not
just to work creation and approval. Include every exposed effecting owner/action,
its full intent binding and retained identity: offer selection, resume/cancel,
support export, publication/artifact release, task closure, emergency restrict/resume and
installation/update/removal or other lifecycle actions as applicable. In each
owner's actual tests, synchronize competing requests at native lookup, admission
and commit for exact duplicates and for each changed semantic field under the
same ID. Count native operations and downstream effects independently: one
original operation/outcome or retained uncertainty, with no duplicate downstream
effects. Competitors join that original or conflict before changed intent is
retained or dispatched. Repeat with lost replies, restart, stale expected revision
and full new-admission capacity to prove original lookup remains available
without a new identity or repeated effects. Q20 consumes these cases for exposed
lifecycle mutations. An observation profile that exposes support export or
lifecycle actions must qualify their own Q02 cases without acquiring unrelated
W1/M20 dependencies. Pure read-only Observe has no mutation-owner dependency;
mark absent capabilities unavailable.

For basic Observe, Q04 binds the actual receipt/hook/read request parameters;
it does not require a nonexistent work handle. Q09/Q21 prove bounded idle/active
observation and no recovery-command polling or settlement-reserve consumption;
the recovery-specific saturation case becomes mandatory when that source is
exposed. Q11 checks truthful hook omission/crash/timeout behavior; the protected
host cases remain gates for protected profiles. A build with W1 views or recovery
capability adds applicable Q01/Q03 cases; Q02 independently gates every exposed
effecting mutation through its own owner, including support export/lifecycle
without W1/M20. Record owner-justified applicability per case.
Absent optional work/recovery/approval/stop capabilities remain explicitly
unavailable and cannot be exercised through Observe. Packet 2's operator lane
continues to gate selected mutations independently of a read-only candidate.

An exposed read-only budget view adds Q15 projection checks for duplicate
dimensions, exact numeric domains/units, zero and unavailable/measured-only
states, owner/scope/revision binding and truthful rendering. Missing projection
evidence keeps that view unavailable. These checks do not require execution
budget enforcement or an S7 backend; the UI cannot claim enforcement from a
read response, and native enforcement qualification remains a separate gate for
profiles that actually exercise it.

## Performance, privacy and operations

Use the S10 owner's call classes and measurement conventions. Check-only reads
in SideEffecting mode need the appropriate S3 receipt semantics, not a desktop
rule demanding durable admission on every invocation. Mediate tool/egress
policy boundaries; do not create a paid kernel call for every HTTP fragment.
Publish measured cold/warm latency, steady-state idle CPU/memory, stream buffer
limits, restart recovery time and stop acknowledgement versus completed closure
separately. An unmeasured target is not an achieved result.

The platform plans must set numeric resource limits from those experiments
before beta. Exceeding a bound must degrade observation or refuse a new task
explicitly, never weaken the native authority or isolation policy. Logs and
support bundles redact secrets, prompts, private paths and artifact contents by
default; export is previewed and consented. Tokens never enter UI URLs, argv,
notifications or support bundles. Deleting UI caches does not erase owner
receipts or cancel work; explain both retention and active custody to the user.

## Release sequence

1. Freeze the source tuple and obtain each predecessor's native acceptance.
2. Freeze each selected owner binding only after its real schemas/queries exist.
   Run independent consumer conformance against installed owners. Freeze the
   optional projection separately only when selected.
3. Build signed qualification candidates and publish the installation inputs
   needed by a clean host through an explicitly labeled candidate channel.
4. Install on clean supported machines; run positive and negative controls,
   failure/restart/update/uninstall exercises, plus accessibility checks for
   selected graphical/interactive clients.
5. Verify public artifact/revision availability and checksums, then promote the
   exact candidate tuple. A newly rebuilt artifact restarts the artifact gates.
6. Record local tests, hosted CI, bot review, release publication and native
   qualification as separate statuses. This docs PR satisfies none of the
   executable release gates by itself.

Native capability promotion is independent of optional presentation and unrelated
workloads. A protected host requires its own foundation, I01-I08, native boundary,
resource, release and installed evidence; it does not require an earlier sealed
coding release. Test an otherwise passing selected native profile with no
workbench/projection/QML/menu bundle and no unrelated coding profile, and require
promotion only for its exact supported capabilities. Remove each selected owner
or required case in turn and require refusal. A passing sealed cell cannot qualify
another host, resource, deployment principal or platform. Broad product-completion
claims additionally require the coordination/resource/cooperation cases below.

## Systems-layer acceptance added by the product-direction amendment

Q23-Q31 supplement, rather than replace, Q01-Q22. Qualification is per advertised
capability and deployment profile. Pure Observe still has no effect, passport,
recursive-work or cross-organization dependency unless it exposes that feature.
A selected GUI applies every graphical/browser case; a headless exclusion must
name the absent UI surface and retain all equivalent native read/effect cases.

| ID | Owner and stimulus | Required result |
| --- | --- | --- |
| Q23 | Native host and independent consumers: remove all Chio UI/projection components; run useful installed harness and application operations; kill/restart/replace clients and lose responses; apply FIRST-CLASS-INTEGRATIONS H01-H08 to the required Claude Code/Codex/Pi/Hermes and separate Herdr coverage | Native functions remain usable within the selected profile; current owner state, original IDs and resources survive; no implicit replay or cancellation. User-session and service-principal evidence remain distinct. CONSUMERS C01/C02/C05 and W3's independent applications retain their exact scope. |
| Q24 | Credential/current-admission owner: valid passport plus selected holder challenge; substitute subject, issuer, audience, challenge or workload; expire/revoke under the relying-party policy; present a valid passport without a grant | Useful approved scope succeeds; no invalid credential or missing grant yields effects/private bytes. Require configured fresh lifecycle when the profile claims current passport status. Bare portable verification is never promoted to current native admission. C09 supplies independent resource/disclosure controls. |
| Q25 | Delegation/current-admission and budget owners: useful child/grandchild within supported form; widen scopes/constraints, extend expiry, change delegator, exceed allocation; revoke an ancestor; retry after restart | Effective authority only narrows; unsupported forms reject; current descendant work refuses after revocation becomes effective under the qualified contract. Original uncertain effects remain retained. One-hop aggregate examples cannot qualify recursive aggregate conservation. C10 observes actual effects and native accounting. |
| Q26 | Swarm/runtime/W1 owners: fan-out/fan-in; corrupt graph/witness/route/epoch/allocation/continuation binding; race replay and additive extensions; present correctly signed join with unaccepted/wrong/duplicate parents | Qualified runtime admission plus protected graph head and durable issuance/replay prevent duplicated/forked authority. Exact required parent acceptance, producer/task/artifact/evaluator/contract identity gates the successor. Pure bundle verification or fixture minting cannot supply that fact. C11 observes graph/allocation records and downstream effects. |
| Q27 | Actual budget and mutable-resource owners: race consumers at finite capacity, restart, stale assignment with fresh version, copied store, exact replay under new resource holder | No double spending, renewed allowance, stale-owner mutation or duplicate effect. Owner fence/version/ID checks participate atomically in actual mutation; missing telemetry is not unlimited. OS CPU/memory limits, cumulative allowance and money remain separately qualified dimensions. C03/C04 provide independent state/counter evidence. |
| Q28 | Federation/W2/recovery owners: enrolled separately controlled peers do useful unpaid work; either refuses; substitute peer/treaty/audience/current authority; lose responses/evidence delivery and revoke present release access | Independent local refusal and audience protection; original-ID reconciliation without duplicate rights/effects; historical obligations remain separate from current disclosure. Local multi-process runs do not prove independent organizational administration. C06/C07 require actual counterpart custody and evidence. Funding adds its own gates only if selected. |
| Q29 | Native profile/credential/lifecycle owners: user-session lock/logout versus separately enrolled service principal; boot, expiry, credential lock/replacement, cross-context request and removal | No session-to-service privilege conversion; no root/linger/launch registration/detach authorization shortcut. Correct principal, credential/store audience and independent expiry survive restart; unknown authority refuses. Native platform oracles verify credentials and effects before any frontend starts. |
| Q30 | Architecture/release owner: inspect linked/loaded trusted components and stores, remove optional projection; select runtime adapter with mismatched or missing evidence; drop a required consumer/native test | Declared custody/fact-source TCB and owner dependency closure match actual artifact; no hidden application signer or ledger and no new universal daemon requirement. Native feature remains frontend-independent but cannot promote without its exact owner/backend/case evidence. Record useful controls and actual measured resource bounds. |
| Q31 | Every native owner consuming time-bounded authority or qualification evidence: useful current read/grant/approval/service lease; expire it, roll realtime backward; independently test forward jumps, stale/missing clock/freshness, suspend, restart/boot changes | An expired or unprovably current credential, grant, lease, read authority or release record cannot revive or authorize protected bytes/effects. Observe and approval-only profiles test their actual owners without acquiring task execution dependencies. Bind effective time/expiry and retained state to the qualified owner context; Q12/Q19 add execution deadline and custody cases only when execution is selected. |

For a release claiming the full product ambition, Q23 plus the selected
coordination (Q25/Q26 and W1 acceptance), shared resources (Q27), and independent
cooperation (Q28) must pass in addition to every native profile obligation.
Passports (Q24) are mandatory when advertised or selected by peer policy, not an
unrelated prerequisite for every local operation. The completion record names
actual capability coverage, independent applications, external harness tuples
and separately administered owners; unavailable dimensions remain open. No
marketing shorthand merges these dimensions into one green status.


## Expiring authority on every native profile

Q31 is mandatory wherever a selected read, approval, resource, service, credential
or release path consumes time-bounded authority. It is not limited to task
execution. Packet 1 records each actual owner clock/freshness interface, absolute
expiry and any boot-bound elapsed/freshness state. The owner must define and
qualify how it establishes current validity after realtime corrections, suspend
and restart without trusting a replayed client timestamp or renewing expiry.
Missing trustworthy time/freshness refuses the affected protected operation.
This requirement adds no new clock protocol or frontend-owned time authority.

Start with a useful valid operation through the installed native path. Let its
authority expire, move realtime backward into its former validity window and
retry both the original read/operation and a new request under the old authority.
Native protected-byte canaries, approval/credential retention and dispatch/effect
counters must show no new release or effect. Repeat forward jumps, unavailable
clock/freshness, boot changes and retained-state restart; compose suspend with
clock change where that context can suspend. Include long-lived established
connections/cached decisions as well as new connections. Recover valid current
authority through the supported owner path and repeat the useful control.
Historical reconciliation can report only what its independently authorized
contract permits; it cannot reuse an old expiry to disclose newly protected
bytes or dispatch work. Execution profiles additionally prove both independent
deadline/absolute-expiry and descendant-custody cases described above. A read-only
profile qualifies Q31 through its read owner, without needing a task runner.

## Superseded-review trace

Prior review repairs are retained semantically: typed exact bounds and unique
dimensions (Q15), full request and error bindings (Q04), honest retries (Q02-Q03),
nonempty fresh readiness (Q16), masked-test prevention and artifact crosswalks
(Q18), bounded Linux child custody (Q19), public plugin installation order
(Q20/release sequence), and native approval binding (Q05). Deleting the old
platform schemas does not waive these owner obligations. Their old synthetic
fixture counts are intentionally not reported as acceptance of this program.
