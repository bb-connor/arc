# Desktop acceptance and release evidence

Status: specification only. `planning_status: ready_after_adr` under ADR-0038.
Every proposed execution profile is unavailable until its exact tuple passes.
Document checks, mock data and historical host runs cannot satisfy runtime gates.

## Evidence identity and authority

A qualification record binds the owner source commit, public release revision,
host/plugin versions, controller/client builds, OS version and architecture,
backend and policy digest, artifact hashes, test commands, raw outputs, expected
outcomes and reviewer decision. Dependency eligibility is separate from runtime
readiness. A prerequisite's green test does not qualify a different installed
artifact. Public instructions may reference only revisions actually available
in the public repository.

Maintain the authoritative evidence with the owner being tested. The desktop
release manifest references those records; it does not duplicate their status
or reinterpret them. A test record must include a positive control, the actual
adversarial stimulus, observed native result, and proof that no forbidden effect
occurred. Omitted cases, zero evaluated profiles, skipped commands, stale logs,
unknown evidence kinds and missing signatures cannot yield a ready state.

All profile checks use ADR-0011 `boundary_class` and `planning_status` separately.
Hook activity is `detect_only`; local effects outside mediation are `cannot_see`;
UI guidance is `advisory_only`; only a proven pre-effect gate is `prevent`.

## Required acceptance matrix

The following are test obligations, not claims that these tests exist or pass.
Put each executable test in the named owner when implementing the dependency.
The delivery plan covers the handoff and desktop tests after those contracts land.

| ID | Owner and stimulus | Required result |
| --- | --- | --- |
| Q01 | Work owner: finish process, reject acceptance, withhold settlement or delivery independently | WorkViewV1 preserves all six observations; desktop invents no composite success |
| Q02 | Recovery/work owner: lose a response after durable admission; restart controller | Lookup original command/preparation/work identity; no fresh dispatch or idempotency key |
| Q03 | S9 M20: retry reusable, retained and terminal failures | Owner classification and original identity control retry; UI never promotes unknown to safe replay |
| Q04 | Projection: substitute response method, parameters, pagination, session, work, scope revision or request intent | Reject substituted response including error/retry replies; never render another request's evidence |
| Q05 | Native approval: request deny but receive an approved token; substitute approval ID or bound scope | Reject before retention/use; no credential persisted, no resume or external effect |
| Q06 | S28/verifier: missing roster, stale/revoked identity, test-only verifier, sidecar-signed approval | Attributable approval unavailable; SharedCredential shown truthfully; no approval UI bypass |
| Q07 | S4/process owner: stop while children/grandchildren run, then restart services | Closure evidence includes the real process/resource boundary; pending/failed/unknown distinct from stopped |
| Q08 | S8: stop before restart and exercise operator route authorization | Durable kernel stop survives; tenant/recovery scopes remain unavailable before their owner phases |
| Q09 | S5 Part B: disconnect, duplicate/reorder hints, overflow retention, stale cursor, unauthorized stream | Bounded resync against the non-persisting owner read; no invented authoritative event or paid inspect polling |
| Q10 | IPC owner: wrong UID/PID/session, reused PID, stale socket, spoofed server, duplicate controller | Native peer/session policy rejects; one controller per scoped session, no TCP fallback |
| Q11 | Host owner/doc 19: crash/omit/timeout hooks, enable alternate native tool/shell, change host version | Hook mode stays detect_only; protected mode fails closed and requires I01-I08 for that host tuple |
| Q12 | S7/backend: unknown kind, stale policy/hash, launcher bypass, inherited FD, direct IP/DNS/IPv6 egress, child escape | No confinement claim without native evidence; fail launch or restrict; no unconfined fallback |
| Q13 | Secret broker/relay: malicious host tries environment/file/process-list/log access or alternate provider route | Raw credentials absent from agent/client; every permitted model route bound to enrolled scope |
| Q14 | Work resource/mini-swe: symlink replacement, path traversal, descriptor race, oversized/archive/device artifact, changed base | Bounded descriptor-based export rejects unsafe input; result hash/base/review identity bind acceptance and publication |
| Q15 | Budget owner: zero, max, overflow, fraction, missing/unknown units, duplicate dimensions, unavailable observations | Exact typed bounds and unique dimensions; unavailable never interpreted as unlimited; native enforcement independently proven |
| Q16 | Controller health: no evaluated profiles, stale session, expired evidence, missing backend | Feature unavailable with a reason; no empty healthy/ready response |
| Q17 | UI/workbench: forged artifact text, injected commands/links, notification click, out-of-order response | Treat content as untrusted; no automatic execution or authority transition; keyboard/screen-reader state remains accurate |
| Q18 | Release: swap one artifact/tuple field or remove required evidence | Positive baseline passes; each one-field mutation independently fails the intended gate |
| Q19 | Process backend: timeout and descendants, unrelated exited child, unkillable/pending child | Bounded cleanup and complete custody evidence; do not reap another task's status or report false completion |
| Q20 | Install/update: unsigned/tampered/wrong-arch artifact, downgrade, mid-update crash, reboot/uninstall | Reject invalid package, preserve recoverable state, revalidate profile before enablement; explicit custody cleanup |
| Q21 | Observation/S5 owners, plus recovery when exposed: subscriber idle for long periods and sustained event traffic | No observation path spends recovery-command quota or drains settlement reserve; configured buffer and resource limits enforced; exposed recovery additionally passes native saturation/finality controls |
| Q22 | Isolation profile: attempt an in-workspace write through the host's native shell, outside an explicitly granted runner operation | Boundary interactive labels a permitted write cannot_see with no per-write receipt; protected/sealed profiles reject the alternate native-shell route. An expressly granted sealed recipe's internal shell is a separate bounded execution and cannot qualify this negative. |

## Sealed-work safety without blanket keystone dependencies

Removing NK-01 through NK-03 as complete redesign prerequisites does not waive
admission, crossing or ABI safety for sealed work. Its owner must still prove
current-authority admission before dispatch, exact request/scope and source
binding, atomic reservation and transition behavior for its effect class,
required persistence before acknowledgement, post-effect receipt/uncertainty
handling, authenticated closed native dispatch and guarded artifact release.
These properties are exercised through W1, recovery, foundation and the required
S3/S4/S5/S8/M20 deltas, using the owning S10 read/effect distinction and S1
placement rules. A selected path missing any of those properties stays
unavailable until its owner implements and qualifies it. The desktop may not
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

## Native approval defect handoff

The Pi wrapper refuses `approval-decide` before native invocation. The audited
bundled bridge still exposes its native utility, so wrapper refusal is not a
fix for that utility. The platform research records the source/archive pin.
The native owner must repair exact decision and approval-ID matching, replace
the packaged dependency, and run Q05 against the installed binary including
direct invocation. Until that evidence exists, attributable approvals and any
publication requiring them are disabled. A source-level fix alone is insufficient.

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
| Observe | Q04, Q09-Q11, Q16-Q17, Q21; Q15 projection cases when a budget view is exposed; add Q01-Q03 only if the build exposes W1 views or recovery capability | S5 A/B, authenticated bounded non-persisting reads, selected trust-control GETs and truthful hook source attribution; W1/M20 are not basic receipt/hook observation gates |
| Approve | Q02-Q06, Q09-Q10, Q16-Q17 | Qualified native approval owner, S28 identity, production verifier and installed utility binding; no stop capability implied |
| Per-task stop | Q02-Q04, Q07, Q09-Q10, Q16-Q17, Q19 | Qualified S4/process closure and its native route authorization; Q05/Q06 are not prerequisites when approval is absent |
| Kernel stop | Q02-Q04, Q08-Q10, Q16-Q17; Q19 additionally for any claimed process cleanup | Qualified S8 phase-1 scope, durability and native route authorization; no S28 approval or per-task closure prerequisite and no implied process termination |
| Sealed work | Q01-Q22 applicable to its concrete backend, with exclusions justified by owner; Q22's alternate native-shell negative is mandatory | W1, recovery, restricted host, runner, S7 and installed release tuple |
| Protected interactive | Q02-Q13, Q15-Q22 plus doc 19 I01-I08 | Each of six hosts individually qualified; native-shell removal and Q22 alternate-access rejection enforced |
| Boundary interactive | Q02-Q13, Q15-Q22 as applicable; no mediated-local-effect claim | Deferred; independent backend evidence required |
| Managed endpoint | Platform annex's ES/NE matrix plus Q16-Q20 | Deferred; consent/entitlements and restrictive-only authority model |

Every row expands to an explicit executable case manifest at implementation
time. "Applicable" must not let a release omit a gate silently: the manifest
names the owner-approved exclusion and its reason; an unclassified case fails
qualification. A profile may fail while another independently qualifies.

The Q identifiers are not an exhaustive replacement for the consumed operator
contract. Each platform's source reconciliation must map every applicable
OPERATOR normative obligation and protocol-freeze acceptance row, as well as
each Q-row stimulus and annex requirement, to its owner, implementation packet,
actual test command, positive control and independent negative observation.
Include negotiation/reconnect, raw decoding, pagination consistency, review
invalidation and hook-to-receipt attribution whenever those surfaces are exposed.
Release qualification removes each required case individually from a passing
manifest and proves the affected surface cannot be promoted; omitted, skipped
or unclassified cases cannot disappear behind a broader passing Q label.

For basic Observe, Q04 binds the actual receipt/hook/read request parameters;
it does not require a nonexistent work handle. Q09/Q21 prove bounded idle/active
observation and no recovery-command polling or settlement-reserve consumption;
the recovery-specific saturation case becomes mandatory when that source is
exposed. Q11 checks truthful hook omission/crash/timeout behavior; the protected
host cases remain gates for protected profiles. A build with W1 views or recovery
capability adds Q01-Q03 with owner-justified applicability recorded per case.
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
2. Freeze the shared protocol only after its owner schemas/queries exist. Run
   cross-client conformance against the installed owner service, not mocks.
3. Build signed qualification candidates and publish the installation inputs
   needed by a clean host through an explicitly labeled candidate channel.
4. Install on clean supported machines; run positive and negative controls,
   failure/restart/update/uninstall exercises and accessibility checks.
5. Verify public artifact/revision availability and checksums, then promote the
   exact candidate tuple. A newly rebuilt artifact restarts the artifact gates.
6. Record local tests, hosted CI, bot review, release publication and native
   qualification as separate statuses. This docs PR satisfies none of the
   executable release gates by itself.

Enforce the ADR's sealed-first product order at release promotion, independently
of candidate construction. A platform's protected-interactive production entry
requires a recorded earlier qualified sealed-W1 release for that platform.
Promote the sealed cell using its own complete owner/installed evidence, then
consider the protected cell; neither candidate assembly nor protected promotion
is a prerequisite for that first sealed release. Test rejection of an otherwise
passing protected cell when the sealed release is missing, failed or unpromoted,
and acceptance only with the authenticated prior release plus its own current
qualification. Observe, approval and qualified stop remain independent. This
order requires one qualified first sealed tuple, not six-of-six host completion.

## Superseded-review trace

Prior review repairs are retained semantically: typed exact bounds and unique
dimensions (Q15), full request and error bindings (Q04), honest retries (Q02-Q03),
nonempty fresh readiness (Q16), masked-test prevention and artifact crosswalks
(Q18), bounded Linux child custody (Q19), public plugin installation order
(Q20/release sequence), and native approval binding (Q05). Deleting the old
platform schemas does not waive these owner obligations. Their old synthetic
fixture counts are intentionally not reported as acceptance of this program.
