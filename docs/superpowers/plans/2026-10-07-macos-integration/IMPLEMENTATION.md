# macOS Native Host Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Chio's HOST-M1 services on macOS (headless `chio trust serve`
and the door behind `chio api protect`, Keychain key custody, Touch ID passkey
approval, signed arm64 packaging) so a Mac can be either organization in a
HOST-M1 run and the requesting organization in HOST-M3. macOS HOST-M2 is
deferred until after the success test.

**Architecture:** Existing shared owners provide the services; macOS adds launchd
packaging, Keychain backend selection behind #1160's `signing_custody`, and
release wiring. Optional review clients sit outside the TCB. Isolation denies;
Chio grants.

**Spec:** [macOS annex](../../specs/2026-10-07-macos-integration/ANNEX.md),
[NORTH-STAR-FLOWS](../../specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md),
[ADR-0038](../../../adr/ADR-0038-native-host-program.md),
[CASES](../../specs/2026-10-07-desktop-integration/CASES.md),
[STATUS-GLOSSARY](../../specs/2026-10-07-desktop-integration/STATUS-GLOSSARY.md),
[HOST-CONTRACT](../../specs/2026-10-07-desktop-integration/HOST-CONTRACT.md),
[RELEASE](../../specs/2026-10-07-desktop-integration/RELEASE.md),
[shared delivery plan](../2026-10-07-desktop-integration.md) and
[PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md).

**Identifiers.** Packets keep their IDs M0 to M11; they are macOS plan packets,
not flows. Flows are HOST-M1 to HOST-M3 (unified roadmap section 12). Case IDs
are defined once in CASES; this plan names them and does not restate them.

**Global constraints**

- `runtime_evidence: unavailable` applies to every packet. Writing a step does
  not run it. Status terms follow STATUS-GLOSSARY.
- Fail closed. Custody unavailable, a wrong peer, an unaccepted build or
  uncertain time refuses; there is no plaintext, unsandboxed, weaker-profile or
  cross-context fallback.
- HOST-M1 is server-first (roadmap COOP-1). Native review window, menu bar and
  notifications are optional follow-ons (roadmap COOP-1) and never gate a native
  capability; when delivered they keep all their own tests.
- User-session host and service host are separate, separately qualified
  deployment profiles. A GUI-free user service cannot claim login independence.
- No new recovery, work, credential, approval, event or stop contract. A missing
  owner API blocks the dependent step; no mock substitutes for qualification.
- Hook-mode sessions are `detect_only`. `native-descendant-v1` stays retired.
- macOS HOST-M2 packets carry `planning_status: deferred` and point to unified
  roadmap section 11; none is scheduled before G5.
- For a change to a landed owner: add the failing regression in its existing
  suite, retain the failure, implement the minimum owner-approved delta, retain
  the pass, then review and commit.
- No em dashes; public copy links only public Chio sources.

**Review focus (HOST-M1)**

- A locked, logged-out or wrong-code caller must not obtain a signature from
  the Keychain-backed key, and a custody failure must not fall back to a seed
  file (M2).
- A Touch ID unlock or a mismatched approval ID must not become an issuance
  approval (M3).
- A correctly signed older or alternate build must not install, activate or roll
  back authority (M9).
- Expired or clock-rolled-back authority must not revive (M8).

## HOST-M1 packets

`planning_status: ready_after_adr`. These packets deliver the Mac half of
[NORTH-STAR-FLOWS section 3](../../specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md#3-flow-m1-cooperate-0)
and the G1 macOS install. Cases: C09, Q05, Q06, Q24, Q28, Q29, plus platform
cases Q10, Q16, Q18, Q20 and Q31.

### M2: Deliver HOST-M1 services and Keychain key custody

**Fields:** `boundary_class: prevent` at the door (`chio api protect`) and at
custody release; `advisory_only` for service status; `planning_status:
ready_after_adr`; `runtime_evidence: unavailable`.

**Depends on:** M0; #1160 `signing_custody` on main; the shared owner changes
"custody provider behind `SigningBackend`" and "native service packaging for
`chio trust serve` and `chio api protect`" (NORTH-STAR-FLOWS section 9). No UI.

**Files:** Extend the signing-custody owner in its existing crate and suite with a
macOS Keychain backend. Add `integrations/macos/packaging/` (service bundle or
package, user-agent plist, optional machine-daemon plist, entitlement inventory)
and `integrations/macos/tests/{native-service-cases,service-principal-cases,credential-custody-cases}.md`.
A minimal Swift/C ServiceManagement bridge may use `integrations/macos/Package.swift`
without linking any menu app. Record actual test commands in M0 before
implementation.

**Interfaces:** Consume `chio trust serve`, `chio api protect`, the passport and
evidence CLI and `signing_custody` as they exist on main once #1160 lands (F). Produce installed
service identities, authenticated reachability and a Keychain key reference
accepted by every signing command. No new authority or recovery API.

- [ ] **User-session services.** Build a GUI-less composition of
  `chio trust serve --advertise-url` and, for a door, the governed tool behind
  `chio api protect` with `CHIO_TRUSTED_ISSUER_KEY` set to the local
  trust-control authority key. Register it as a per-user LaunchAgent through
  `SMAppService`. Record executable, label, plist, signing, entitlements,
  principal, state paths and listener scope. Observe registration,
  running process, authenticated reachability and owner health separately.
  Denied or revoked background authorization yields unavailable routes, never
  an unsupervised fallback. No menu app, browser, workbench or Herdr may be
  needed to start or keep the services alive.
- [ ] **Door behaviour.** Through the installed services, run NORTH-STAR-FLOWS
  steps 2 to 6 as org B against a Linux org A: allowlist A's DID, issue a
  challenge, approve (M3), federated-issue a B-local capability, then call the
  governed tool with `X-Chio-Capability`. Require an allow receipt for an
  in-scope call and a signed deny receipt for an out-of-scope call, a capability
  from an untrusted issuer, a request beyond A's delegation ceiling and a
  replayed or stale challenge (C09, Q24, Q28). A valid passport without a grant
  is refused.
- [ ] **Keychain custody (user session).** Implement the macOS backend behind
  `signing_custody`: per-user data-protection Keychain
  (`kSecUseDataProtectionKeychain`), synchronization disabled, narrowest
  qualified device-local accessibility, exact service, account, access group and
  audience. The product labels the key OS-protected software (Ed25519 cannot
  live in the Secure Enclave). First run creates the organization key in custody
  or imports it there; seed paths remain a labelled development profile.
  Failing cases, each refusing before a signature is produced: locked session,
  logged-out user, switched or cross-user caller, wrong code identity or access
  group, unavailable class or store, a planted matching legacy or synchronizable
  item, attempted file or environment fallback, migration and reinstall.
  Valid enrolled unlocked signing is the positive control. Inspect the installed
  item's actual attributes and caller access, not the creation request
  ([Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)).
- [ ] **Rotation and revocation races.** Barrier-synchronize signing requests
  immediately before and after lookup, cache fill and signature release, with
  an already cached key, reconnect and service restart, while rotation or
  revocation commits through the owner. When rotation wins the owner's ordering,
  no new signature uses the stale key; committed history is preserved.
- [ ] **Rollback.** In a dedicated synthetic test-user account, snapshot app
  state and the Keychain fixture, spend or revoke authority, then restore both,
  each alone, and with freshness removed. Newer authority or unavailable
  freshness fences every stale attempt; issuance and effect counters do not
  increase. Restore no real user Keychain; Keychain storage is not an
  anti-rollback witness.
- [ ] **Service host (optional, enrolled principal only).** Package a
  system-domain LaunchDaemon with a least-privileged service identity, explicit
  machine enrollment and its own credential backend (reviewed system or
  file-based Keychain policy, or remote custody). A failed user lookup never
  triggers it. Test with every graphical user logged out, cold boot after
  protected storage is available, wrong service, user or code, denied store,
  revocation between lookup and use, and unavailable freshness. A machine
  service cannot synthesize a human passkey endorsement. Missing backend support
  leaves only this profile unavailable (Q29).
- [ ] **Session lifecycle.** With no Chio UI, lock, switch users, log out, sleep
  and reboot; sensitive reads and signing require fresh owner and session checks
  and stay unavailable while reconciliation runs. Closing a client never stops
  native custody (Q29).
- [ ] **Listener pressure.** Confirm the shared owners' pre-authentication and
  per-principal bounds hold for the installed listeners (Q10, Q21). macOS adds
  no listener of its own. A missing or ineffective bound in a shared owner makes
  the affected door profile unavailable until that owner fixes it; it is never
  shipped as a known gap.
- [ ] **Optional review clients (roadmap COOP-1).** Only if a native review window,
  menu-bar item or notifications ship: notification clicks open a neutral view
  that re-reads owner state and can never approve, issue or retry; sensitive
  content clears on lock, switch and reboot; keyboard and VoiceOver access work;
  exact-intent rendering follows M3. Finder Services and browser clients are not
  HOST-M1 scope. The pre-restructure optional client subpackets at `620c703d8`
  are the detailed case list when a client is selected (Q17).
- [ ] Run the changed owner suites and the installed cases above, then review
  and commit.

**Acceptance:** An external harness and the CLI use the installed services with
every Chio frontend absent. Keys live in OS custody, custody failure refuses,
and the user-session and service-host profiles report their own results.

### M3: Attribute HOST-M1 operator approval

**Fields:** `boundary_class: prevent` at native approval retention;
`planning_status: ready_after_adr` for issuance approval; `runtime_evidence:
unavailable`. The stop items of this packet are deferred with HOST-M2.

**Depends on:** M2; the existing `PasskeyCapabilityVerifier` and
`chio-custody-hw`; the S28 roster for attributable records (owner gap; until it
lands the record is labelled `SharedCredential`). No optional client.

**Files:** Native owners `crates/kernel/chio-kernel/src/{approval,custody}.rs`
and their tests; the issuance approval step that federated issue consumes (an
approval route arrives with the roadmap COOP-1 issuance inbox and does not exist
on main yet); optional client review code only when a client ships.

**Interfaces:** Consume the delivered approval and roster types through
supported bindings. Any human-endorsement client presents and binds the exact
native intent; the CLI is sufficient.

- [ ] Require a real passkey verification through Touch ID against the enrolled
  operator. Generic Touch ID success, OS consent or an unlocked desktop fails as
  an approval input.
- [ ] Compare the requested decision and approval ID before retaining any
  credential, at every approval intake including any harness utility used.
  Deny, mismatched ID, mismatched decision, stale or expired response, changed
  intent after presentation and replaced scope, TTL or ceiling must retain
  nothing; a valid matching approval is the positive control (Q05).
- [ ] Missing roster, stale or revoked operator, test-only verifier and
  sidecar-signed approval refuse attributable approval; the record stays
  `SharedCredential` until S28 (Q06). Race roster revocation against retention:
  when revocation wins, no new usable retention or issuance occurs.
- [ ] Barrier-race two identical approvals and a same-ID approval with changed
  intent; exactly one retention for the identical pair, a conflict for the
  changed one (Q02 for this owner). Drop the reply at each durable boundary and
  resolve only through the original operation.
- [ ] When a client renders the review, escape bidi, invisible and terminal
  control characters, keep the canonical intent digest, and refuse endorsement
  of content that cannot be inspected (Q17). Optional clients only.
- [ ] Run the approval owner suites and installed cases; review and commit.

**Acceptance:** Issuance approval is bound to the exact reviewed request and to
the enrolled operator, labelled `SharedCredential` until S28.

### M8: Close lifecycle, privacy and expiry for delivered profiles

**Fields:** `boundary_class: prevent` at owner-controlled release;
`advisory_only` for diagnostics; `planning_status: ready_after_adr`;
`runtime_evidence: unavailable`.

**Depends on:** M2 for each delivered profile; M3 only for approval cases. Applies
to every delivered profile with no task-execution prerequisite.

**Files:** Native service, custody and diagnostics owner suites; proposed
`integrations/macos/tests/{session-lifecycle-cases,default-collection-cases}.md`;
evidence export owners `crates/kernel/chio-kernel/src/evidence_export.rs` and
`crates/platform/chio-store-sqlite/src/evidence_export.rs` only when support
export ships.

- [ ] **Expiry under clock change (Q31).** At every owner of exposed
  time-bounded authority (passport and capability validity, challenges, sessions,
  service leases, release results), using the owner's test clock or an isolated
  machine: cross expiry, roll wall time back before issuance, jump forward 24
  hours and back, sleep, wake and reboot, before protected-byte release and on
  an open connection. Expired authority never revives or renews; unknown or
  inconsistent time fences protected bytes and new admission until the owner
  reconciles. A fresh bounded read is the positive control. A displayed
  timestamp is not qualification.
- [ ] **Diagnostics before persistence.** Seed synthetic canaries in
  credentials, prompts, paths, URLs, errors and identifiers. Instrument each
  logging call boundary before any OSLog, logger or persistence sink; canaries
  must already be removed. A harmless marker proves the observer sees the sink.
  OSLog privacy rendering does not substitute.
- [ ] **No ambient collection.** On a clean synthetic account, run the signed
  candidate idle and through every configured schedule, restart and sleep/wake.
  Independent observers with liveness probes show no whole-home scans,
  clipboard polling, screen, microphone, camera or global keyboard access,
  background indexing, analytics or crash upload. An unobservable surface is
  reported unqualified.
- [ ] **Stale views.** Restore clients with stale request or approval references
  after lock, logout, switch, reboot and owner death; protected bytes stay
  fenced and stale submissions produce no approval or issuance.
- [ ] **Failure after effect.** Inject output, signing and persistence failures
  after an independently marked effect; keep the original operation identity and
  uncertainty and reconcile through original-ID lookup before retry. A missing
  receipt is not evidence that no effect occurred.
- [ ] **Support export (only if shipped).** Explicit, local, previewed, bound to
  an immutable selection and the current audience, 10 MiB encoded ceiling plus
  owner-frozen expanded, allocated and member-count caps, private staging and
  atomic no-replace publication (Q14). The pre-restructure M8 checklist at
  `620c703d8` is the detailed case list.
- [ ] Run changed owner suites; review and commit.

**Acceptance:** Privacy holds before persistence, time-bounded authority never
revives, and lifecycle uncertainty neither discloses data nor manufactures
closure.

### M9: Assemble and evaluate the signed distribution candidate

**Fields:** `boundary_class: advisory_only` for distribution checks; `prevent` at
native admission during transitions; `planning_status: ready_after_adr`;
`runtime_evidence: unavailable`.

**Depends on:** M2 source completion for the HOST-M1 profiles; M3 when approval
ships; 2a-shared (`chio-release-evidence` native-profile verifier) and 2a-macos
activation wiring before installed activation acceptance, independent of
2a-linux. Unqualified profiles stay disabled outside the controlled harness.
macOS HOST-M2 components join later candidates only.

**Files:** `integrations/macos/packaging/{README.md,component-inventory.md,release-checks.sh}`
and `integrations/macos/tests/{distribution-cases,package-admission-cases,credential-rollback-cases,receipt-rollback-cases,performance-cases}.md`
at the native lifecycle owners. Results go into the shared qualification
envelope, not a Mac schema.

**Interfaces:** Consume implemented component bytes and the packet 2a typed,
authenticated eligibility result. Produce immutable signed and notarized
candidate bytes, a candidate inventory and installed evidence. No production
allowlist (that is M10).

- [ ] Freeze the inventory, payload closure, entitlement review and thresholds.
  Record each OS/CPU row (arm64, `MACOSX_DEPLOYMENT_TARGET=15.0` first) and
  every excluded row. Set unqualified profiles disabled.
- [ ] Sign nested components with reviewed identities and minimal
  entitlements, notarize, inspect the notary log and staple. Retain:

  ```bash
  codesign --verify --deep --strict --verbose=2 "$CHIO_SERVICE_BUNDLE"
  codesign --display --entitlements :- "$CHIO_SERVICE_BUNDLE"
  spctl --assess --type execute --verbose=4 "$CHIO_SERVICE_BUNDLE"
  xcrun stapler validate "$CHIO_SERVICE_BUNDLE"
  ```

  Inspect each nested component separately. Submission credentials stay in the
  release owner's custody.
- [ ] Run `cargo test --locked -p chio-release-evidence` plus the native-profile
  suite and installed activation tests recorded in M0. Remove each required case
  or observation, substitute staged versus active bytes, principal or catalog,
  supply untrusted issuers, expired results and unauthorized exclusions; each
  refuses before activation. Malformed, duplicate-key or noncanonical manifest
  bytes refuse before evidence admission (Q18).
- [ ] **Timed outsider install (G1).** Install the downloaded candidate on a
  clean standard-user Mac with SIP and Gatekeeper on, timed, by someone outside
  the core team following the published steps through to connecting an agent and
  seeing a signed deny receipt (C01). Separately refuse every
  permission, registration and enrollment; verify truthful unavailable states
  and no ES/NE request.
- [ ] **Container ingestion bounds (Q20).** Inventory every DMG, archive,
  installer-package and update-container ingestion path before validated staging
  exists, with its owner, parser or extractor, privilege and any script seam.
  Freeze finite compressed, expanded, allocated, entry-count, depth, CPU, time and
  memory bounds at the actual processing boundary. Malformed or truncated
  containers, traversal and absolute paths, escaping links, colliding names,
  special files, sparse files and compression bombs refuse within those bounds
  before any write outside private staging, privileged change, script execution
  or activation; partial staging is cleaned up boundedly or kept unavailable.
  Missing bounded handling disables that ingestion path. A valid container is the
  positive control.
- [ ] **Package admission (Q20).** One change per fixture through the shipped
  installer and updater: tampered resource without re-signing, removed
  signature, correctly signed wrong-architecture build (never silently run under
  Rosetta), signed older generation, non-enrolled publisher, mixed
  current and old inventory, and a correctly signed same-publisher build whose
  digests are absent from the authenticated inventory. Each is refused with no
  registration, replacement or activation; the valid package is the positive
  control.
- [ ] **Races.** Pause after validation and before activation and substitute
  the staged bundle, a nested helper or its parent; substitute the installed
  destination; add hard-link aliases and mounted subtrees before and after
  validation. Each refuses without touching outside bytes, identity, access
  policy or mount state, and interrupted runs keep the original operation.
- [ ] **Caller and writer.** Every elevated entrypoint, including direct helper
  invocation, authenticates the caller for the exact installation and action.
  Two valid updates, or an update and a removal, from one or two users, are
  serialized by the native owner; the loser refuses before writes (Q02).
- [ ] **Update.** Interrupt before and after fencing, replacement, migration and
  reactivation; hold old components alive. Established IPC, subscription and
  browser sessions are closed or revalidated against the accepted tuple at each
  fence before further protected bytes or dispatch. Incompatible stores, failed
  migrations or health checks keep affected profiles closed.
- [ ] **Rollback and floor.** The release-generation floor is scoped to the
  installation, survives restoration of app bytes, state and credential
  fixtures, and blocks an older signed package from a second user. Receipt and
  checkpoint continuity is checked against authenticated history outside the
  restored snapshot; restored old stores keep receipt-backed admission
  unavailable until reconciled.
- [ ] **Removal.** Per-user unenrollment versus shared deletion with a populated
  two-user install; unresolved work and receipt history retained or transferred;
  late, renamed-in, hard-linked and mounted entries preserved; retained
  processes and open connections fenced. Report precise remaining state.
- [ ] Run the annex performance targets applicable to the delivered profiles
  with a pre-run report; safety failures close a profile regardless of latency.
- [ ] Recheck report hashes and tuple bindings; hand the candidate to M10.

**Acceptance:** A signed, notarized arm64 candidate installs, updates, rolls
back and uninstalls under the cases above on a clean Mac, with a timed outsider
install recorded for G1.

## HOST-M2 packets (after the success test)

`planning_status: deferred` for every packet in this section. macOS HOST-M2
comes after the success test (unified roadmap section 11; Lane SHARE "After the
test": Darwin process runner, Keychain and XPC broker, `LOCAL_PEERTOKEN` IPC).
None is scheduled before G5. Until then a macOS-only organization takes part in
HOST-M3 as the requesting organization and the executing organization runs
Linux. The pre-restructure packet text at `620c703d8` is the starting point
when these packets resume; its fail-closed obligations remain attached to the
case IDs named here.

### M1: Darwin transport custody in `chio-secure-ipc`

`planning_status: deferred` (unified roadmap section 11). Scope: AF_UNIX
`LOCAL_PEERTOKEN` with `SecCodeCopyGuestWithAttributes` and `SecCodeCheckValidity`
against a pinned designated requirement and the accepted release generation;
XPC compared in the same crate if needed; stale, forged, replaced and
transferred peers refuse; pre- and post-authentication pressure bounds; raw-byte
parser corpus. Depends on M0 and the Darwin peer-identity owner change
(NORTH-STAR-FLOWS section 9). Cases: Q04, Q10, Q16.

### M2 (HOST-M2 scope): native process, resource and harness services

`planning_status: deferred` (unified roadmap section 11). Scope: Darwin process
runner in `chio-process`, Keychain/XPC broker in `chio-secret-broker`, live
cancel and revoke, and the no-frontend external harness and application
workloads (Q23, Q25 to Q27, C01 to C05, C10, C11). Depends on M1 and the Darwin
runner and broker owner changes.

### M3 (stop scope): per-task closure and kernel stop

`planning_status: deferred` (unified roadmap section 11). Scope: S4 per-task
closure with fork, exec and reparent races; S8 phase 1 kernel stop across
restart; fence, death, outstanding effects and closure reported separately.
Cases: Q07, Q08, Q19.

### M4: Lower-assurance Seatbelt adapter

`planning_status: deferred` (unified roadmap section 11). Scope: S7 `Seatbelt`
kind first; pinned launcher, policy and OS identity; fork-denied restricted
sessions; Mach/XPC, Automation, Accessibility, pasteboard, capture and Input
Monitoring channels under real consent attribution; hard-link aliases; fresh
task-private state; per-session and aggregate CPU, memory, storage, I/O rate,
descriptor, IPC-object and accelerator bounds; authenticated loopback services;
no unsandboxed retry. Depends on M1, process and broker integration. Cases: Q12,
Q13, Q22.

### M5: Select an existing higher-assurance VM runtime

`planning_status: deferred` (unified roadmap section 11). Scope: evaluate Apple
Containerization, OpenShell MicroVM and Docker Desktop on one fixed workload
before any bespoke Virtualization.framework adapter; no host shares outside the
captured import, detached capture, zero direct egress, output and bridge bounds,
numeric per-VM and aggregate resource, I/O-rate and host IPC-object ceilings,
fresh per-work state, crash and sleep behaviour. Depends on the S7 Mac VM kind,
M0 and M1. Cases: Q12, Q22, Q27.

### M7: Qualify required harnesses and Herdr

`planning_status: deferred` (unified roadmap section 11). Scope: one scoped
protected Mac profile each for Claude Code, Codex, Pi and Hermes (H01 to H05,
H06a, H08a, I01 to I08), H06b composition, Herdr H07/H08b for all four
selections, and Megastart as coordinator after its allowance moves onto kernel
holds. Hook observation stays `detect_only`. Depends on M3 stop scope, M4 or M5
and M9. Cases: H01 to H08, Q11, C01.

## HOST-M3 packets

Before macOS HOST-M2, the Mac is the requesting organization only. That role
uses HOST-M1 packets (M2 services and custody, M3 passkey approval for
co-signing) and the shared W1/W2 owners: its own agent (Claude Code or Codex in
MCP mode) proposes work, the operator co-signs through the W2 remote co-signer,
and `chio evidence verify` checks the executing organization's receipts and
acceptance offline against the pinned partner card (C06, C07). macOS adds no
new owner for this role, but qualifies it on an installed Mac:

- [ ] **Mac as requester.** With the Mac as organization A and a Linux
  executing organization B: the Mac's agent proposes bounded unpaid work; the
  operator reviews the exact predicate (treaty reference, action class, digest)
  and co-signs through the W2 remote co-signer with an M3 passkey approval, where
  deny or a changed predicate retains nothing (Q05); the Mac then verifies B's
  evidence package, including B's door receipts, offline against B's pinned
  partner card and refuses a package whose receipts or co-signature fail
  verification (C06, C07, Q28). Depends on the shared W1 facade and W2
  co-signer.

### M6: Optional sealed W1 coding-resource profile (executing owner)

`planning_status: deferred` (unified roadmap section 11): a Mac executes HOST-M3
work only after macOS HOST-M2. Scope: W1 single-owner work through a selected
harness and backend; repository capture that disables repository-controlled
execution, lazy fetch and external objects and bounds object parsing, special
entries, mounts, sizes and whole-generation coherence before dispatch; an
independent evaluator in its own bounded boundary that cannot be forged by
candidate output; safe review rendering; export with atomic no-replace
publication; apply qualified separately; duplicate create races. Depends on W1,
recovery fixes, M3 and M4 or M5. Cases: Q01, Q02, Q14, C08.

## Platform packets

### M0: Reconcile dependencies and freeze the execution tuple

**Fields:** `boundary_class: advisory_only`; `planning_status: ready_after_adr`;
`runtime_evidence: unavailable`.

**Depends on:** ADR-0038 and PROGRAM-MAP. Source and plan reconciliation only; it
enables no effects.

**Files:** Create `docs/superpowers/specs/2026-10-07-macos-integration/evidence/dependency-reconciliation.md`
only after the inspection. Update this plan with actual source locations.

- [ ] Record the implementation revision and inspect tracked source without
  assuming an open proposal is merged:

  ```bash
  git rev-parse HEAD
  git status --short
  rg -n 'signing_custody|SigningBackend|PasskeyCapabilityVerifier|CHIO_TRUSTED_ISSUER_KEY' crates
  ```

- [ ] For HOST-M1, record the actual symbols, entrypoints and test commands for
  `signing_custody`, the passport and federated-issue CLI, `chio api protect`,
  evidence export and verify, the approval and roster owners, and the release,
  install and floor owner (packet 2a-shared and 2a-macos). Absent support blocks
  the dependent step, not the whole packet.
- [ ] Map each HOST-M1 and platform case (C01, C09, Q02, Q05, Q06, Q10, Q14,
  Q16, Q17, Q18, Q20, Q24, Q28, Q29, Q30, Q31) to its owner, packet, test command, positive control and
  independent negative observation. An absent test is an open obligation, never
  an implied pass. M10 rejects each missing mandatory case.
- [ ] Inventory every helper invocation that consumes untrusted filenames, URLs
  or labels in install, export and removal paths; operands stay literal
  (verified option terminator, literal mode or a typed API).
- [ ] For each exposed filesystem owner (install destination, removal, support
  export), map the approved root and mount identity; unknown mount semantics
  leave the route unavailable.
- [ ] Record the HOST-M2 owner inventory (Darwin runner, broker, peer identity,
  S7 kinds, harness repositories) as deferred, without expanding it.

**Acceptance:** A reviewer can find every consumed symbol at the recorded
revision and distinguish shipped source, accepted design and missing runtime
evidence.

### M10: Join qualification evidence and promote exact passing profiles

**Fields:** `boundary_class: advisory_only` for evidence review; `prevent` at
native profile admission; `planning_status: ready_after_adr`; `runtime_evidence:
unavailable`.

**Depends on:** M9's immutable candidate; 2a-shared and 2a-macos; M8 for every
delivered profile; M2 and M3 evidence for the profiles they deliver.

**Files:** [RELEASE](../../specs/2026-10-07-desktop-integration/RELEASE.md), the
packet 2a extension in `crates/tooling/chio-release-evidence`, and M9's
inventory and checks.

- [ ] Join source, final signed bytes, installed and active generations,
  OS/CPU identities and profile configuration across all evidence. Reject
  stale, skipped, mismatched or missing artifacts.
- [ ] Reconcile M0's requirement-to-test map; remove each required case,
  positive control and independent observation in turn and require refusal of
  only the affected capability (Q18, Q30).
- [ ] Derive the allowlist solely from passing exact cells. Unqualified and
  deferred profiles (all macOS HOST-M2 rows, ES/NE, `native-descendant-v1`)
  stay disabled outside the controlled harness.
- [ ] If enabling the allowlist changes signed bytes, configuration or authority
  generation, issue a new candidate and rerun affected checks.
- [ ] Verify ordinary startup admits only reviewed cells and repeat one useful
  operation and one forbidden-effect probe on the promoted tuple.
- [ ] Publish only exact supported claims; candidate availability, promotion and
  production behaviour are reported separately.

**Acceptance:** Promotion follows candidate qualification without a dependency
cycle. Nothing is enabled because it was bundled or signed.

### M11: Keep managed endpoint work independently gated

`planning_status: deferred`. `boundary_class: detect_only` for sensor evidence,
`cannot_see` for unmediated effects. Depends on a separately opened decision,
actual team entitlements, final SDK and OS support and scoped administrator
policy; not a prerequisite for any HOST-M1 profile. ES/NE plumbing from the
earlier Clawdstrike project is prior art and source material absorbed into
Chio's own adapters
([source review](../../specs/2026-10-07-macos-integration/research/clawdstrike.md));
it is never an integration target or owner. Before enabling: signed activation
and removal, actual file and flow denial and restoration, wrong or missing
audit-token attribution, callback deadlines, queue overflow and provider death.

### Execution exit checks

- [ ] Every annex section maps to a packet; every active packet has a recorded
  source revision, owner contract, failing and passing tests and installed
  acceptance for its claim.
- [ ] Every macOS HOST-M2 packet still reads `planning_status: deferred` with its
  pointer to unified roadmap section 11.
- [ ] `planning_status` is never read as runtime availability; unexecuted,
  skipped, stale or wrong-architecture cells stay unavailable.
- [ ] The retired profile and superseded protocol names are rejected by
  configuration rather than mapped to a weaker backend.
- [ ] Public copy contains only supported exact-tuple claims and public links.
