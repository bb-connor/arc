# macOS native host annex

Status: approved platform direction, restructured 2026-10-09 around the
[north-star flows](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md).
Implementation and installed-runtime qualification are unavailable.
`planning_status: ready_after_adr` for HOST-M1 on macOS;
`planning_status: deferred` for macOS HOST-M2 and the managed-endpoint track.
`boundary_class` is stated per operation below and follows ADR-0011. Status
terms follow [STATUS-GLOSSARY](../2026-10-07-desktop-integration/STATUS-GLOSSARY.md);
acceptance cases are defined once in [CASES](../2026-10-07-desktop-integration/CASES.md).

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

On macOS, Chio is a userspace authority and work-state kernel hosted by the OS,
not an XNU replacement or a kernel extension. Isolation denies; Chio grants.
This annex implements [ADR-0038](../../../adr/ADR-0038-native-host-program.md)
and NORTH-STAR-FLOWS for Darwin. It owns Darwin ports, launchd service
deployment, Keychain custody selection, permission handling and distribution
evidence. It creates no new task, recovery, credential, event, approval or stop
contract. [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md) pins the owners;
F means `main` after the #1160 merge commit (experimental; broker Linux-only).
[HOST-CONTRACT](../2026-10-07-desktop-integration/HOST-CONTRACT.md) owns the
shared deployment profiles.

Flow IDs use the `HOST-` prefix (unified roadmap section 12). M0 to M11 are
packet IDs in the [macOS plan](../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md),
not flows. The previous numbered macOS specifications and private protocol are
superseded. `native-descendant-v1` is retired: it cannot be selected, migrated
or renamed Seatbelt.

| Operation or profile | `boundary_class` | `planning_status` |
| --- | --- | --- |
| HOST-M1 door: `chio api protect` admission of a presented, federated capability | `prevent` at B's door only | `ready_after_adr` |
| HOST-M1 evidence check at the requesting organization | `detect_only`; imported reputation `advisory_only` | `ready_after_adr` |
| Optional review window, menu bar, notifications | `advisory_only` | `ready_after_adr`, optional |
| Hook-mode harness sessions | `detect_only` | `ready_after_adr` |
| Protected harness execution (Seatbelt or VM backend) | `prevent` for mediated tools; `cannot_see` inside a granted native shell | `deferred` (macOS HOST-M2) |
| Managed endpoint ES/NE | `detect_only` for observations; `cannot_see` for unmediated effects | `deferred` |
| Retired `native-descendant-v1` | `cannot_see` | `hard_skip` |

Every row has `runtime_evidence: unavailable`. Historical component evidence
does not change that.

## HOST-M1 on macOS

HOST-M1 is cut server-first (unified roadmap COOP-1): headless services, OS key
custody and the door come first; desktop review moments are optional follow-ons
(COOP-1.12). A Mac can play either organization in
[NORTH-STAR-FLOWS section 3](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md#3-flow-m1-cooperate-0).
HOST-M1 cases: C09, Q05, Q06, Q24, Q28, Q29, with platform cases Q18, Q20 and
Q31 for the delivered install and its time-bounded authority.

**Services.** The Mac runs `chio trust serve --advertise-url` and, when it is
the door (org B), the governed tool behind `chio api protect` with
`CHIO_TRUSTED_ISSUER_KEY` set to B's trust-control authority key. Both are
existing shared owners; macOS adds packaging and custody, not a listener,
protocol or authority of its own. Their HTTP listeners keep the shared owners'
pre-authentication and per-principal pressure bounds (Q10, Q16).

| Context | Design direction | Mandatory boundary |
| --- | --- | --- |
| User-session host (default) | Per-user LaunchAgent registered through `SMAppService`, headless, no Chio frontend required | Session lock, logout, credential and freshness fences stay effective. GUI-free operation does not imply login independence. |
| Service host (optional) | System-domain LaunchDaemon only for a separately enrolled service principal, least-privileged service identity | Explicit machine enrollment, its own credential backend, boot and recovery behaviour. No root impersonation and no copied human login context. |

A user-session release cannot be described as login-independent. A service host
starts only after the OS and its protected storage are available; FileVault
unlock, recoveryOS and unattended boot are distinct conditions. User-only
credentials and human endorsements never transfer into a service principal
(Q29).

**Key custody.** Every signing command takes a key reference through #1160's
`signing_custody` (NORTH-STAR-FLOWS section 2 owner change, "custody provider
behind `SigningBackend`"). On the user-session host the organization and domain
keys live in a device-only, non-synchronizing data-protection Keychain item.
Ed25519 cannot live in the Secure Enclave, so this is an OS-protected software
key and the product says so. The service host selects its own backend (a
reviewed system or file-based Keychain policy, or remote custody); it is never
a fallback from a failed user store. Fail-closed rules:

- Custody unavailable, locked or wrong user/code: the signing operation refuses.
  There is no plaintext, legacy or weaker-accessibility fallback, and no
  silent switch between user and service backends.
- Plaintext seed files remain a labelled development profile only; a HOST-M1
  run uses none (NORTH-STAR-FLOWS section 8).
- Installed item class, access group, synchronization flag, accessibility,
  audience and caller access are inspected on the installed tuple, not
  inferred from the creation request.
- Rotation or revocation that wins the owner's ordering before release stops
  a stale cached key from signing. Earlier committed history is preserved.
- Restoring app state or Keychain fixtures cannot revive spent or revoked
  authority; freshness unavailable keeps affected signing fenced.

**Operator approval.** B's operator approves federated issue (flow step 4).
A passkey through Touch ID uses `chio-custody-hw` and the existing
`PasskeyCapabilityVerifier`; Touch ID unlock or OS consent alone is not an
approval. Until the S28 roster lands the approval record is labelled
`SharedCredential` (NORTH-STAR-FLOWS section 3). Every approval intake
compares the requested decision and approval ID before retaining a credential;
deny and mismatched-ID responses retain nothing (Q05). Roster or verifier gaps
keep attributable approval unavailable (Q06). The approval can be taken from
the CLI; a review window is optional.

**Optional desktop moments.** A notification that opens a native review window
and a menu-bar item showing identity and the pending-review count are optional
follow-ons (COOP-1.12), not HOST-M1 gates. When delivered they render owner
data as `advisory_only`, clear sensitive content on lock or user switch, route
notification clicks only to a neutral view that re-reads owner state, and keep
their accessibility, privacy and exact-intent rendering obligations (Q17).
Their absence never disables a native capability.

**Distribution before the test.** Signed and notarized Apple silicon arm64
binaries and a timed outsider install on macOS are required for G1 (unified
roadmap sections 4 and 5). Packaging rules are in
[Packaging and lifecycle](#packaging-and-lifecycle).

**Exit.** The Mac side of a HOST-M1 run meets NORTH-STAR-FLOWS section 8:
native user-session units, no plaintext seed file, a positive in-scope call with
a receipt at the door, each listed negative refused before dispatch, and offline
verification of the counterpart's evidence. Two people control the two
machines.

## HOST-M2 on macOS (after the success test)

`planning_status: deferred`. macOS HOST-M2 starts after the success test
(unified roadmap section 11; Lane SHARE "After the test": a Darwin process
runner, a Keychain and XPC broker, and `LOCAL_PEERTOKEN` IPC). Until then a
macOS-only organization takes part in HOST-M3 as the requesting (counterparty)
organization, and the executing organization runs Linux
(NORTH-STAR-FLOWS section 5, platform note). The detailed pre-restructure
design of this annex at commit `620c703d8` is the starting point when this
work resumes; nothing below is scheduled before G5.

Scope when resumed (NORTH-STAR-FLOWS sections 4 and 9; cases C02 to C05, C10,
C11, Q03, Q07, Q08, Q11 to Q13, Q15, Q19, Q22, Q23, Q25 to Q27, H01 to H08):

- **Darwin process runner** in `chio-process`. Logical process identity stays
  distinct from PID. The SDK lacks kqueue `NOTE_TRACK`/`NOTE_CHILD`, and
  launchd process-group cleanup is not descendant custody, so closure needs
  incarnation-safe tracking of fork, exec and reparent races or a qualified
  backend (Q07, Q19). Live cancel and revoke are owner changes.
- **Keychain and XPC broker** in `chio-secret-broker`, with separately
  qualified user-session and service-principal custody and no controller-owned
  credential proxy (Q13).
- **Local peer identity** through `LOCAL_PEERTOKEN` and code-signing checks
  (see [Services, custody and IPC](#services-custody-and-ipc)).
- **Resource backend selection** among existing runtimes before any bespoke
  Virtualization.framework supervisor: Apple Containerization (Apple silicon,
  macOS 26, Xcode 26), OpenShell MicroVM (explicit `vm` selection, no guest
  NIC) and Docker Desktop, with optional `chio-mini-swe` reference
  comparisons. Selection requires the same fixed workload and the complete
  matrix: zero direct egress, no host-directory share outside the captured
  import, detached or immutable capture, fresh per-task writable state,
  bounded output and bridge queues, and numeric per-VM and aggregate ceilings
  for CPU, memory, disk, processes, storage I/O rates and host IPC objects with
  native stop headroom (Q12, Q22, Q27). A vsock endpoint identifies a
  transport, not a principal.
- **Seatbelt launchers** as a thin, lower-assurance backend. The public Pi
  launcher already uses a deny-default `sandbox-exec` policy with fork denied.
  S7 must admit a `Seatbelt` kind first; until then the UI says "not confined
  by Chio". Qualification covers Mach/XPC, Automation, Accessibility,
  pasteboard, capture and Input Monitoring channels under real consent
  attribution, hard-link aliases to outside canaries, fresh task-private
  state, per-session and aggregate resource and object bounds, accelerator
  routes and authentication of permitted loopback services. A policy that
  fails to load or an expected denial that fails refuses; it never retries
  unsandboxed (Q12, Q22).
- **Required harness cells.** Claude Code, Codex, Pi and Hermes each need one
  scoped protected Mac profile (H01 to H05, H06a, H08a), plus H06b composition
  and the Herdr H07/H08b matrix, under
  [FIRST-CLASS-INTEGRATIONS](../2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md).
  None is available before macOS HOST-M2.
- **Megastart** coordinates on the Mac only after its aggregate allowance moves
  onto kernel holds (ADR-0038 amendment item 5).
- **Kernel stop and per-task closure** (S8 phase 1, S4) stay separate gates;
  fence acceptance, observed process death, outstanding effects and closure
  are shown separately (Q07, Q08).

## HOST-M3 on macOS

Before macOS HOST-M2, a Mac takes part in
[HOST-M3](../2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md#5-flow-m3-work-that-crosses-an-organization-boundary-and-comes-back-verified)
only as the requesting organization:

- Its own agent proposes the work. Claude Code or Codex in MCP mode is enough;
  hooks remain `detect_only` coverage, never enforcement.
- Its operator co-signs the agreement with a passkey through the W2 remote
  co-signer. No party holds both co-signer keys.
- It verifies the executing organization's receipts, the co-signed agreement
  and the evaluator's acceptance offline (`chio evidence verify` against the
  pinned partner card) and may disclose a subset to a third party.

These steps use HOST-M1 services and the shared W1/W2 owners; macOS adds no
packet for them.

### Optional sealed coding work, approvals, and safe artifacts

The Mac becomes an executing owner (work inside its own HOST-M2 tree, an
evaluator, artifact capture, review and apply or export) only after macOS
HOST-M2. That executing role, including the optional sealed W1 coding resource
profile, is `planning_status: deferred` with HOST-M2 (cases C06 to C08, Q01,
Q02, Q14). When it resumes, its obligations are unchanged from the
pre-restructure design at `620c703d8`: repository capture refuses
repository-controlled execution, lazy fetching and external objects and bounds
object parsing, special entries, mounts, sizes and whole-generation coherence
before any dispatch; the evaluator runs in its own bounded boundary and
candidate output cannot forge acceptance; review renders untrusted bytes inertly
with bidi and terminal controls escaped; export publishes atomically without
replacing an unexpected file; apply is qualified separately from export.
Acceptance comes only from the configured evaluator, never from a human click.

## Services, custody and IPC

Native hosting composes existing owners; it requires no new universal daemon.
A consumer or optional controller restart may lose cached presentation state.
It must not lose native custody, restart an unknown operation, replenish
capacity or create authority from a cache.

| Responsibility | Owner and status | macOS delta | Flow |
| --- | --- | --- | --- |
| Passports, challenge, federated issue | `chio passport`, `chio trust` (shipped) | Packaging and custody only | HOST-M1 |
| Door admission | `chio api protect` evaluator (shipped) | Packaging and trusted-issuer configuration | HOST-M1 |
| Signing keys | #1160 `signing_custody` (main, experimental) | Keychain backend selection per deployment context | HOST-M1 |
| Evidence export and verify | `chio evidence` (shipped) | None | HOST-M1, HOST-M3 |
| Approvals | `PasskeyCapabilityVerifier` (exported source); S28 roster (owner gap) | Touch ID passkey; `SharedCredential` label until S28 | HOST-M1, HOST-M3 |
| Work identity and status | Planned W1 owner: `WorkHandleV1`, `WorkViewV1`, `WorkClient` and `WorkTransport` are design-only (PROGRAM-MAP) | Show execution, acceptance, result, recovery, settlement and delivery separately; no invented `WorkPhase` | HOST-M3 |
| Recovery and retry | Original-operation recovery; S9 M20 (R not qualified) | A lost reply stays unknown until the owner resolves the original identity | HOST-M3 |
| Events | S5 Part A and Part B | Re-read authoritative views on gaps; no Mac event log | Platform |
| Local IPC | `chio-secure-ipc` (main, experimental) | Darwin peer identity (owner change) | HOST-M2, deferred |
| Process custody | `chio-process` (main, experimental) | Darwin runner (owner change) | HOST-M2, deferred |
| Secrets and model release | `chio-secret-broker` (main, experimental; Linux-only) | Keychain/XPC broker (owner change) | HOST-M2, deferred |
| Confinement | S7 evidence kinds | `Seatbelt` and Mac VM kinds added at S7 first | HOST-M2, deferred |

**IPC.** HOST-M1 needs only the shared HTTP services above; local operator IPC
is not on its path. Darwin peer identity in `chio-secure-ipc` is a HOST-M2
owner change (deferred). The candidate design, recorded in
[Apple platform research](research/apple-platform.md#darwin-local-peer-token-candidate-2026-10-07):
on the connected AF_UNIX descriptor call
`getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, ...)`, require success and the exact
`audit_token_t` size, pass the kernel-returned token under
`kSecGuestAttributeAudit` to `SecCodeCopyGuestWithAttributes`, and require
`SecCodeCheckValidity` against a locally pinned designated requirement and the
accepted release generation. Token acquisition is not proved race-free against
PID reuse or descriptor handoff, so exit, exec, reuse, transferred descriptors,
endpoint replacement and current-session binding are qualification cases. XPC
is compared inside the same crate if AF_UNIX cannot establish these facts.
`getpeereid` alone never fabricates process identity, and missing facts refuse
rather than fall back (Q10).

**Custody.** The HOST-M1 custody rules above apply to every delivered profile.
The service-host backend is tested with every graphical user logged out, for
wrong service, user or code, denied storage, revocation, freshness and restore
behaviour. On macOS 26.4 and later, file-based keychains may depend on
protected entropy beyond one copied file; attribute names and partial backup
fixtures do not establish lock, restore or anti-rollback guarantees
([native service research](research/native-host-services.md),
[distribution research](research/distribution.md)).

**Time.** Every exposed time-bounded authority (passport and capability
validity, challenges, sessions, service leases, release results) is qualified
against backward and forward wall-clock changes, sleep and boot. Expired
authority never revives or renews; uncertain time refuses protected bytes and
new effects until the owner reconciles (Q31). This applies to HOST-M1 with no
task-execution prerequisite.

**Privacy and diagnostics.** Default collection excludes whole-home scans,
clipboard polling, screen recording, microphone, camera, global keyboard
monitoring, background indexing, remote analytics and crash upload, across every
configured schedule, restart and wake. Credentials, prompts, source, paths and
bearer references are removed before any log or persistence sink receives
them; OSLog privacy annotations are additional protection only. Observers prove
liveness with an authorized probe; an unobservable surface is reported
unqualified, not passed. Support export, when shipped, is explicit, local,
previewed, scoped to the current audience and bounded at the export owner
(Q14).

## Packaging and lifecycle

**Artifacts.** Direct distribution starts with a Developer ID signed and
notarized GUI-less service bundle or installer package. It carries the native
service entrypoints, the required `chio` CLI and launchd plists. A disk image
and any menu app are optional. Nested code is signed with reviewed identities
and minimal entitlements under the hardened runtime; the notary log is inspected
and the ticket stapled. Notarization and Gatekeeper success are distribution
checks, not runtime protection. The first build experiment targets Apple
silicon arm64 with `MACOSX_DEPLOYMENT_TARGET=15.0`; Intel, Rosetta and older OS
rows stay unavailable until qualified. Normal installation never asks to
disable SIP or Gatekeeper.

**Registration.** The user-session service registers through `SMAppService`
(bundled `BundleProgram`). A managed signed package with launchd plists uses
`Program`/`ProgramArguments` and has one installation owner. Registration,
running state, authenticated reachability, owner health and qualified effects
are separate results. Refused or revoked background authorization leaves the
affected routes unavailable
([registration semantics](https://developer.apple.com/documentation/servicemanagement/smappservice/register()),
[GUI-less service package](https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api)).

**Release evidence.** A release inventory binds source and lockfiles, final
signed bytes, team and bundle identities, entitlements, notarization record and
qualification reports. The shared [RELEASE](../2026-10-07-desktop-integration/RELEASE.md)
extension (packet 2a-shared in `crates/tooling/chio-release-evidence`, with
2a-macos wiring, independent of 2a-linux) rejects ambiguous or noncanonical
manifest bytes before admission (Q18). Its current self-signed manifest check
is not readiness evidence.

**Install and update** (Q20, Q02):

- Admission requires the exact final package and component digests in the
  release owner's authenticated inventory. A correctly signed alternate or older
  build from the same publisher is refused before replacement or activation.
- Validation-to-activation substitution of staged bundles, helpers or parents,
  destination substitution, pre-existing or raced hard-link aliases and mounted
  subtrees refuse without touching outside bytes.
- Each elevated entrypoint authenticates and authorizes its caller for the exact
  installation and action. One native owner serializes every mutating installer,
  updater and remover for an installation, across users.
- Updates stage and verify the full set, fence new admission, reconcile active
  work, activate, verify effective generations and reopen. Established IPC,
  subscription and browser sessions are closed or revalidated against the
  accepted tuple at each fence. Incompatible stores, failed migrations or health
  checks keep affected profiles closed.
- The release-generation floor is scoped to the installation and survives
  restoration of app bytes, state and credential fixtures. Receipt and
  checkpoint continuity is checked against authenticated history outside the
  restored snapshot; a valid old signature is not proof of no lost history.

**Lifecycle.** Lock, fast user switching, logout, sleep, service death and
reboot invalidate sensitive user-session views and require fresh owner checks,
with or without a graphical client. Closing a frontend does not stop native
custody; deleting a presentation component is separate from unenrolling a
service.

**Removal** distinguishes per-user unenrollment from shared-installation
deletion. Shared deletion refuses while another enrollment remains, unless an
authorized machine-wide removal reconciles every affected user and service.
Unresolved work and receipt history are inventoried and retained or transferred
before artifacts are removed. Removal unlinks only reviewed entries, preserves
late or renamed-in entries, refuses mounted-subtree traversal and hard-link
mutation, and fences retained processes and open connections. A denied removal
yields a precise remaining-state report, not "fully removed".

**Budgets.** The pre-restructure performance budgets at `620c703d8` (idle native
services at or under 1% of one core and 200 MiB RSS; read-only local IPC p95 at
or under 100 ms; diagnostics at or under 1 MiB per hour) are initial targets
fixed in a pre-run report before testing. Safety failures close a profile
regardless of latency.

**Failure rules.** Fail closed. A missing owner, bad signature or wrong peer
refuses before admission with no unconfined fallback. A lost reply resolves the
original operation. Failures after dispatch keep the original identity and its
uncertainty; a missing receipt is not evidence that no effect occurred. Disk
full or unavailable freshness before admission refuses new work and preserves
existing custody.

## Managed endpoint (ES/NE)

`planning_status: deferred`. HOST-M1 does not need it. Endpoint Security and
Network Extension form a separately qualified, optional managed-endpoint track.
Entitlement eligibility, provisioning, installation, user or administrator
approval, provider activation, task attribution and actual denial are separate
gates. An MDM policy is configuration, not proof that a flow was blocked
([Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)).
Observations are `detect_only`; administrator restrictions may deny OS activity
but are not Chio grants or receipts. Read-only use and sealed or VM work never
require host-wide ES/NE access.

Clawdstrike is an earlier project. Its ES event conversion, bounded callback
patterns, NE plumbing and detector fixtures are prior art and source material
that Chio absorbs into its own host adapters, as recorded in the
[source review](research/clawdstrike.md). Clawdstrike is never an integration
target, a boundary, an owner or a peer. The reviewed observer is default-allow,
its NE allow/drop path does not prove Chio task attribution, and its PID-only
signal path is not incarnation-safe termination; none of those limits is
inherited as a Chio claim.

Before any enterprise claim: actual team entitlements, final SDK and OS
identity, clean signed activation, scoped denial and restoration, callback
deadlines, queue overflow, provider death, wrong or missing audit tokens, fast
user switching and removal. Apple descendant documentation does not reopen
`native-descendant-v1`.
