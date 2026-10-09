# Linux Native Host and Optional Omarchy Implementation Plan

**Goal:** Deliver installed Linux services, custody, IPC, isolation evidence and packaging for the approved [north-star flows](../../specs/2026-10-07-desktop-integration/NORTH-STAR-FLOWS.md): HOST-M1 Cooperate-0, HOST-M2 one root grant across Claude Code, Codex, Pi and Hermes, and HOST-M3 as the executing owner. Linux is the executing platform before the success test. Every advertised capability works with all Chio graphical clients absent; Omarchy QML, notifications, Walker entries and the workbench are optional consumers, and mini-swe is an optional reference workload only.

**Architecture:** Follow [HOST-CONTRACT](../../specs/2026-10-07-desktop-integration/HOST-CONTRACT.md) and the [Linux annex](../../specs/2026-10-07-omarchy-integration/ANNEX.md). Reuse the actual kernel, process, work, recovery, secure IPC, broker, relay and resource owners. Linux adds service lifecycle, identity, isolation, resource and I/O ports. The proposed `chio.operator.v1` projection is optional, outside the TCB and not the kernel ABI.

**Tech stack:** Existing Rust owners and SDK/protocol bindings, Linux peer and process identity, systemd units, qualified bubblewrap and container backends, Arch devtools and pacman for the first candidate, and shared qualification tooling. Omarchy QML, Quickshell and browser tooling apply only to selected add-ons.

Status: dependency-gated planning under [ADR-0038](../../../adr/ADR-0038-native-host-program.md), reorganized on 2026-10-08 by flow. No packet is implemented. Status words follow the [status glossary](../../specs/2026-10-07-desktop-integration/STATUS-GLOSSARY.md); acceptance cases are rows in [CASES](../../specs/2026-10-07-desktop-integration/CASES.md) and are referenced, not restated. The shared [delivery plan](../2026-10-07-desktop-integration.md) owns cross-platform packets (1, 2, 2a, 3, 4, 4a, 5, 6).

### Execution rules

`planning_status` follows ADR-0011. Each packet's `execution_gate` names the actual owner artifacts it needs. Missing source blocks only dependent functions; no stub reports native success. Resolve real owner files, APIs and tests before writing adapters.

All new paths are planned until O0 confirms them. Put reusable platform work under `integrations/linux`, `packaging/linux` and `tests/integration/linux`, extending existing owner crates and SDKs first. Keep genuine shell logic under `integrations/omarchy` and `tests/integration/omarchy`; the first Arch recipe may live under `packaging/linux/arch`. Optional operator work remains in its shared owner. These paths do not authorize a new universal host service, launcher, journal, peer-auth stack or protocol. HOST-M1 unit names and placement follow the [M1 plan](../2026-10-08-m1-cooperate-0.md) as re-cut by COOP-1.0.

| Packet | Flow | Depends on | Output |
| --- | --- | --- | --- |
| O0: source and native profile handoff | Platform | Accepted ADR-0038 and HOST-CONTRACT | Exact source, API, test and owner map; profile gates; Linux baseline. |
| O1: native Linux hosts and UI-independent consumers | HOST-M1 | O0; IPC, identity, service and binding owners | Server-first services and units, custody, sessions, transport bounds, CLI and basic Observe. |
| O4: approval and stop | HOST-M1 (approval), HOST-M2 (stop) | O1 plus each action's owner gates | Attributable approvals and scoped stop without a named GUI. |
| O2: optional Omarchy presentation | HOST-M1, optional | O1; selected projection and read owners | Thin status, review and navigation consumer. |
| O3: coordination and shared resources | HOST-M2; organizational slice HOST-M3 | O1 and each work, process, resource, recovery and S7 owner gate | Native coordination, resource bounds, capture, custody; separately gated cross-organization execution. |
| O5: required harness bindings | HOST-M2 | O1, harness owners; O6 candidate for installed I01-I08 | Separate records for Claude Code, Codex, Pi and Hermes. |
| O6: packages and candidates | Platform | O1 and implemented components of selected profiles | Signed, publicly retrievable, explicitly unqualified candidates. |
| O7: installed qualification | Platform | O6, shared 2a-shared and 2a-linux, selected gates | Independent installed acceptance and per-profile promotion. |

Candidate publication precedes installed qualification. Each capability and host promotes on its own evidence: no all-six, frontend or sealed-coding release blocks an independently qualified profile. Individual harness promotion uses its own H01-H05, H06a and H08a; a Herdr and harness tuple uses H07 and H08b; H06b and the four-selection Herdr matrix gate aggregate completion only. Linux first-class completion needs all four harness records with at least one scoped protected profile each, plus the Herdr matrix; partial releases name what is missing. Cursor and OpenClaw keep their broader doc 19 obligations. Boundary-interactive stays deferred; compositor tools and configuration repair stay removed; cross-host custody transfer and live migration stay deferred owner extensions.

## HOST-M1 packets

### Packet O1: Deploy native Linux hosts and UI-independent consumers

`boundary_class: prevent` for authenticated owner routing and door admission; `advisory_only` for diagnostics.
`planning_status: ready_after_adr`
`execution_gate: selected native binding, service, IPC and enrollment owners. Optional projection adds its controller, ABI and S5 gates; direct bindings never depend on it.`

**Files:** Extend actual owner crates and SDKs from O0 and the `chio` CLI. Create adapters under `integrations/linux/`, units under `packaging/linux/`, and `tests/integration/linux/test_session_lifecycle.py`, `test_service_profile.py`, `test_native_transport.py` and `test_native_consumers.py`. Do not invent unit or binary names before handoff.

- [ ] Package `chio trust serve --advertise-url` and the governed tool behind `chio api protect` (with `CHIO_TRUSTED_ISSUER_KEY` set to the local authority key) as inert systemd units: user-session units, and a separately enrolled system service for an always-on principal. Activation follows profile enrollment. Never enable linger, import the full user environment or create a root controller during user-session onboarding.
- [ ] Route every signing command through key references on #1160's `signing_custody`: Secret Service on desktops, `systemd-creds` `credential:` references (TPM2-sealed where present) on headless hosts. Label plaintext seed files development-only. A missing key, locked keyring or unavailable credential refuses without plaintext, personal-login or other-principal fallback. Verify both custody paths on the target host.
- [ ] Write failing real-Linux tests for wrong UID, stale socket, unavailable endpoint, protocol mismatch, a guest reaching the operator socket and a disconnected client with an unresolved command. Authenticate peers through `chio-secure-ipc`; transport modes and JSON fields never assert identity (Q10).
- [ ] At every exposed listener, freeze finite per-peer and aggregate pre-authentication limits on connections, backlog, accepted descriptors, authentication workers, cost and rate, queues and buffered bytes, plus absolute handshake and partial-frame deadlines that trickled bytes cannot renew. Aggregate bounds hold with unavailable identity, many same-UID processes and reconnects. Flood with wrong peers, idle or partial handshakes and costly authentication, separately and together; independently measure descriptors, workers, CPU, queues and bytes. Reserve native control capacity so an established client and a freshly enrolled client both complete useful reads within declared bounds while stop and reconciliation stay responsive. A universally rejecting listener is not a pass (Q09, Q10, Q21).
- [ ] Separately bound authenticated pressure per principal and in aggregate: request cost and rate, concurrent operations, queues, subscriptions, response and event buffers and slow-reader lifetimes, including downstream fan-out. Reconnects and caller-chosen IDs cannot reset accounting. Event loss produces explicit gaps and resynchronization; dispatched effects keep original uncertainty. Pre-authentication limits do not qualify authenticated clients.
- [ ] Deploy the selected native services without a GUI or mandatory projection daemon, preserving each owner's trust boundary, codecs, reads, resynchronization and retry classes. Read-only reconnect cannot dispatch work; command reconnect performs original-command lookup and never replays under a fresh identity.
- [ ] Implement installed CLI and binding commands from their owners. Helpers use literal package-owned argv, private stdin or descriptor payloads, minimal environment and bounded output. Qualify operand handling at each helper (verified `--`, typed operands, literal Git pathspecs) with leading-dash, option-alias and pathspec negatives and useful ordinary input (Q17). Add leakage canaries for argv, environment, process titles and journals.
- [ ] User-session profile: implement single-enrolled-session policy through the shared IPC and session owner. Persist only UID, boot and logind session identity and host/client incarnation, derived from authenticated peer facts, never `XDG_SESSION_ID`, environment, UID equality or socket possession. Refuse a second concurrent session for the same UID. On logout, lock or lost liveness, fence affected reads and actions and close only original references bound to that session; never issue an implicit user-wide or `Kernel` stop.
- [ ] Run two real graphical sessions A and B for one UID with distinct enrollment and outside effect sentinels: B's enrollment, spoofed environment and copied references disclose nothing of A and dispatch nothing for A. Lock and log out A while B stays active, with pre-existing linger, dropped logind notifications and a host restart. A headless single-session fixture cannot qualify this (Q29).
- [ ] Service-host profile, only after O0 locates its owners: qualify cold boot without login or an unlocked keyring, credential provisioning, rotation and revocation, wrong principal, lease expiry, process/UID/unit/endpoint replacement, duplicate instance, interrupted enrollment, boot change and reconciliation failure. No fresh effect without valid service authority, no renewed budget or expiry and no takeover of session work. Absent owners leave login-independent operation unavailable (Q29).
- [ ] Implement each selected read, freshness and service-authority owner's Q31 contract: useful unexpired access succeeds; expiry followed by realtime rollback, forward jumps, real suspend, restart or boot change, and missing freshness refuse and never revive the old authority. Probe protected bytes, downstream effects and credential reuse independently. These cases need no execution owner.
- [ ] Qualify installed API, CLI and SDK clients and baseline receipt and hook Observe with W1, recovery and execution owners absent: useful reads, authenticated provenance, bounded resynchronization, cross-client agreement and no attempted optional owner query (Q04, Q09, Q11, Q16, Q21, Q23). Unknown optional views stay unavailable.
- [ ] Exercise HOST-M1 end to end with the M1 plan: passport, challenge, federated issue, an in-scope call allowed at `chio api protect` with a receipt, out-of-scope and stale-challenge denials with signed deny receipts, door receipts exported, and offline `chio evidence verify` on the other host (C09, Q24, Q28).
- [ ] Keep a per-role effective-protection table for native service, launcher, relay, guest, resource and any projection controller. Verify namespaces, cgroup controllers and Node thread behavior; missing protection refuses rather than running unrestricted.

```bash
python3 -m unittest discover -s tests/integration/linux -p test_native_transport.py -v
python3 -m unittest discover -s tests/integration/linux -p test_session_lifecycle.py -v
python3 -m unittest discover -s tests/integration/linux -p test_service_profile.py -v
python3 -m unittest discover -s tests/integration/linux -p test_native_consumers.py -v
```

These are planned commands. Cases report an unavailable real host distinctly from a pass; unit-file syntax checks are not lifecycle acceptance.

**Acceptance:** Selected services and bindings work without a Chio GUI, with authenticated clients, scoped authority, OS key custody and retained original custody. Session loss follows the session profile even under linger; service-host operation has its own enrollment evidence or stays unavailable.

### Packet O4: Expose attributable approval and accurate stop controls

`boundary_class: prevent`
`planning_status: ready_after_adr`
`execution_gate: O1 plus the action's gates: approvals need S28 phase 3, a production passkey verifier and qualified native approval routes, including the repaired Pi bridge utility for any profile that ships or exposes it; per-task stop needs S4 phases 1-2; Kernel stop needs S8 phase 1 and S30. Optional graphical controls add O2.`

**Files:** Existing approval, bridge, CLI and binding owners and tests; `tests/integration/linux/test_approval_stop.py`. No QML signer, desktop approval token or substitute authority file.

- [ ] Map every exposed approval route to its native utility and direct-binary cases. For any profile shipping or exposing the affected Pi binary, track the existing defect (backbay-labs/chio-bridge#3) with the bridge owner; wrapper refusal does not repair the directly callable `chio-gateway-operator`. A distinct route without that component needs its own Q05/Q06 evidence and no Pi installation.
- [ ] Run each installed approval utility directly: a requested denial receiving an approved credential, wrong approval ID, wrong request digest, subject, authority or expiry, replay and stale original. Every negative retains no credential and dispatches no effect, checked through credential storage and an external effect counter (Q05).
- [ ] Connect production S28 identity and passkey verification. Unknown or revoked operator, missing roster, shared sidecar credential, mismatched challenge and absent verifier render `SharedCredential` or unavailable; UI authentication alone never claims attribution (Q06).
- [ ] Apply Q31 to each approval and challenge capability: expiry, rollback, forward jumps, suspend, restart and missing freshness never revive an approval or yield an accepted credential or effect.
- [ ] Render exact approval bindings: operation, resource, arguments or digest, recipient and validity window. Lock, stale binding, changed artifact or destination, expired service authority or unknown result disables the action until revalidation. A click or notification never synthesizes acceptance.
- [ ] Execute Q02 for every exposed O4 mutation (approval, denial, publication, per-task closure, selected emergency restrict and resume): barrier-synchronized exact duplicates and same-ID changed intent at each lookup, admission and commit boundary resolve to one original outcome or retained uncertainty with no duplicate effect.
- [ ] Wire per-task stop to S4 closure and emergency action only to implemented S8 scopes (`Kernel` in phase 1; `Tenant` and `Recovery` after phases 4 and 5). Render S30 result kinds. A stop receipt never claims an admitted external effect was undone (Q07, Q08).

```bash
python3 -m unittest discover -s tests/integration/linux -p test_approval_stop.py -v
```

**Acceptance:** Every enabled approval is attributable and exactly bound; direct utility negatives retain no credential or effect. A stop-only release may omit approvals with explicit unavailable state. Per-task closure and emergency scope are visibly and behaviorally distinct.

### Packet O2: Add an optional Omarchy presentation consumer

`boundary_class: detect_only` for hook observation; `advisory_only` for navigation.
`planning_status: ready_after_adr`
`execution_gate: selected optional consumer only; O1 and its projection and read owners, plus S5 when that subscription path is consumed. HOST-M1 review moments are optional follow-ons (COOP-1.12), never gates.`

**Files:** `integrations/omarchy/plugin/{manifest.json,Service.qml,BarWidget.qml,Panel.qml}`, `integrations/omarchy/plugin/components/`, `integrations/omarchy/desktop/computer.chio.desktop.desktop`, `tests/integration/omarchy/test_shell_lifecycle.py`, `tests/integration/omarchy/test_ui_privacy.py` and rendered notes under `integrations/omarchy/acceptance/`.

- [ ] Connect QML to already qualified native read and hook projections: receipt kind, boundary class, host provenance, missing evidence, identity and pending review count. Hook disappearance leaves the session `detect_only` with a gap and never becomes authorization. Basic Observe passes with W1 and recovery owners absent, proved by request and subscription traces; optional task and recovery views (all six `WorkViewV1` observations shown independently) need their own owners.
- [ ] If a browser transport is exposed, qualify Q10 in a real browser against the genuine service: a malicious origin with a live session cookie gets no protected bytes or effect over HTTP or WebSocket; exact origin plus non-ambient proof is required; no cookie-only, origin-only or CORS-only fallback.
- [ ] Implement S5 resynchronization through the owner transport for missed events, old epochs, duplicate hints and slow consumers; no timer polling `InspectWorkflow` and no per-widget subscriptions.
- [ ] Add the minimal manifest (`bar-widget`, `panel`, `service`, `keepLoaded: false`) and the annex adaptations: one client after property injection, generation checks, navigation-only panels. Run late injection, 20 widgets, panel queues, reload during an unknown reply, plugin disable and unsupported replacement bar with stable process and effect counters.
- [ ] Add theme roles with feature probes, Accessible metadata, text plus shape statuses, keyboard focus, large text, reduced motion and IME-safe input; record rendered runs on each selected baseline.
- [ ] Clear sensitive detail on lock and unknown lock. Test persisted notifications (`app_name=Chio`, normal urgency, DND, fixed opener) with canaries in source, prompts, paths and tokens; an old notification refreshes state and cannot grant, retry or publish (Q17).
- [ ] Validate plugin-only loading with no backend: exact unavailable dependency information, with no download, pacman, polkit, service installation, credential import or task launch.

```bash
omarchy plugin validate integrations/omarchy/plugin
python3 -m unittest discover -s tests/integration/omarchy -p test_shell_lifecycle.py -v
python3 -m unittest discover -s tests/integration/omarchy -p test_ui_privacy.py -v
```

**Acceptance:** The optional consumer adds status, review and navigation without becoming a runtime dependency or a second task owner. Accessibility, IME, privacy and multi-monitor behavior are recorded; unsupported combinations stay unavailable.

## HOST-M2 packets

### Packet O3: Qualify native coordination and shared resources

`boundary_class: prevent` at qualified kernel-owned tools and egress; `cannot_see` for undeclared internal activity.
`planning_status: ready_after_adr`
`execution_gate: O1 plus each exposed CASES and owner gate. Required harnesses and Herdr consume their actual work, resource and provider owners. An optional sealed coding workload adds W1, recovery fixes, S3 phase 1, S4 phases 1-2, S7, S8 phase 1, S9 M20 and applicable S10. O2 and unrelated workloads are not dependencies.`

**Files:** Extend landed work, process, resource, federation and binding owners and their tests. Platform cases live in `tests/integration/linux/test_native_consumers.py` and `test_sealed_work.py`, with setup notes under `integrations/linux/compatibility/`. No desktop task enum, runner, resource ledger, sandbox library or model proxy.

Coordination:

- [ ] Run a useful same-harness control for each of Claude Code, Codex, Pi and Hermes, then one mixed scenario with all four as separately identified workers under one root grant, sharing an owner-enforced pool and retained handoffs. Restart one worker and attempt an over-scope handoff (H06a, H06b, C02-C04). Four isolated passes do not prove composition; a mixed demo does not qualify any host's I01-I08.
- [ ] For selected delegation, qualify the actual serving route and supported chain and allocation forms: useful grandchild work, widening, expiry extension, wrong delegator, exhaustion, ancestor revocation and restart (C10, Q25). A one-hop aggregate profile stays one-hop.
- [ ] Where passport or swarm behavior is exposed, run C09/Q24 and C11/Q26 at their actual owners; portable verification or signed fixture joins never qualify native admission or accepted work.
- [ ] Qualify shared resources and capacity through their owners: concurrent reservations, conflicting generation or lease, wrong audience, stale assignment, restart, exhaustion and revocation; reopening an application never resets allowance (C03, C04, Q15, Q27). Megastart's allowance is rebound to a root grant and its holds before it coordinates.
- [ ] Wire Herdr through its actual workspace and plugin binding once the Megastart Linux port lands: useful reads and work and resource operations, attach and detach, replacement, crash and reconnect, wrong principal, stale tuple, expired capability and lost post-effect replies, each with only the selected harness installed. Herdr never renews grants, takes custody or replays originals; pane close and unlink preserve mission state (H07, H08b, C05).

Execution resource safety (applies wherever a selected harness or Herdr operation exposes the boundary; mini-swe applies only when selected):

- [ ] Before any selected capture, qualify the resource owner's repository capture against hostile Git configuration, attributes, filters, fsmonitor and hooks, submodule helpers, lazy fetching, replacement refs, alternates and external object stores. Observers active before import prove no unauthorized reads, helper execution or egress, and a rejected capture dispatches nothing. Apply Q17 operand probes to capture helpers (Q14, Q22).
- [ ] Bound Git object and pack processing before materialization: per-object and aggregate encoded and expanded bytes, staging bytes, object count, graph and delta depth, CPU, time and memory. Malformed objects, inconsistent lengths, compression bombs, cyclic graphs and deep deltas refuse before any model, runner or evaluator dispatch, never truncating input or falling back to a helper or network; exact-bound captures keep their bytes.
- [ ] Bound ordinary working-tree reads separately: per-file and aggregate bytes, entries, depth, CPU, memory and staging; refuse FIFOs, sockets, devices and unproved outside links; huge, sparse and growing files refuse within limits, never as truncated accepted input.
- [ ] Fence mounts at each capture owner: pre-existing and raced bind and FUSE mounts over the root, an ancestor or a subtree, between chunks, across restart and with retained descriptors, require descriptor-bound mount identity enforcement or refusal before outside bytes are read. Outside canaries prove zero disclosure; approved volume roots remain positive controls.
- [ ] Prove whole-generation coherence before dispatch: fixed-length overwrites, pre-opened descriptor and mmap writes, cross-file races, ABA restoration and restart. Accept only an immutable atomic snapshot or a proved writer-complete fence covering every writer; otherwise refuse. Stable metadata, per-file hashes, advisory locks and sequential copies are insufficient. Use an independent whole-tree oracle.
- [ ] If optional mini-swe is selected, adapt its networkless workspace to an explicit rootless Docker backend in the runner owner (the current check rejects rootless and pins the rootful socket), bound to the measured endpoint and configuration. Rootless Podman is a separate evaluation, never an alias. A rootful docker-group profile is a separate opt-in with root-equivalent trust and its own full qualification; lost rootless support never retries rootful.
- [ ] Keep engine access in the trusted host-side runner; deny sockets, API credentials, connected descriptors and docker-group privilege to guests and recipes, verified from inside and outside the guest. Bind runtime closure, mounts, descriptors, policy, recipe and images to the O0 tuple; verify the actual S7 kind (`AgentHostBwrap` or `ProcessContainer`); unknown evidence is unavailable.
- [ ] Measure cgroup v2 delegation and effective CPU, memory and PID limits on the actual cgroup, with bounded pressure and cleanup under pressure. Accepted flags prove nothing.
- [ ] Before admission, enforce per-task and aggregate writable-byte and inode quotas over volumes, layers, temp and cache, plus stdout and stderr ingress, buffering and retention and engine logs, journals and spool files outside the container, reserving measured headroom for receipts, original-operation state, controller, stop and recovery. Run silent exhaustion, separate and combined output floods, stalled consumers, engine-log growth and concurrent tasks; limits hold before the reserve is consumed and authoritative receipts are never pruned (Q19, Q22).
- [ ] Bound storage I/O separately from stored size: per-task and aggregate read and write throughput, operation rates and outstanding-I/O ceilings across buffered, direct, mmap, flush and metadata paths, layered storage and host engine writes. Unsupported paths are denied or the profile stays unavailable. Fixed-size reread and rewrite churn, mapped writes and concurrent quiet tasks must show real device bounds, distinguish cache hits, and keep receipt persistence, stop and reconciliation progressing; pending writes across a kill keep original uncertainty.
- [ ] Bound every allowed descriptor and IPC-object class per task and in aggregate (files, pipes, sockets, eventfds, epoll instances, shared memory, queued messages and buffers), including host allocations triggered by guests, with reserved native control capacity. Deny unneeded classes. Exact-bound, one-over, churn, stalled-receiver and combined pressure keep reads, stop, reconciliation and unrelated work responsive; surviving objects stay accounted until reconciled.
- [ ] Prove fresh task-private state before reuse: writable layers, volumes, home, temp, cache, config and tool paths, descriptors, runner and engine channels and queued authority. Same-user and cross-user, sequential and concurrent tasks with seeded source, prompt, credential, result and tool canaries, across normal end, crash and interrupted cleanup, show no carryover. Shared caches must be declared, immutable and content-addressed; failed cleanup fences reuse.
- [ ] Route provider credentials through the broker and relay and kernel-owned tools through the gateway. Apply the HOST-CONTRACT model-provider boundary to the exact route: required token and spend bounds are enforceable before dispatch (hard output ceiling; worst-case monetary reservation) or the capability refuses before credential release. The pinned Pi fixed Codex-subscription route cannot qualify a bound it does not enforce; there is no automatic downgrade or account fallback (Q13).
- [ ] Run any separate acceptance build or test through the qualified runner with captured input, not an ambient host command; malicious candidates attempting host reads, outside writes, egress, inherited handles, signals, descendant escape, forged results and exhaustion produce no forbidden effect and no accepted result.
- [ ] Extend Linux tests for forbidden filesystem and raw network access, alternate syscalls, inherited descriptors, `/proc`, namespace changes, links, child creation and recipe escape. Do not use or relax `chio-cage` for Node. Test exact x86_64 Linux, then the measured Omarchy tuple.
- [ ] Verify process custody with the shared harness: a fixture worker establishes subreaper custody before launch and reaps within a deadline; double-fork, process-group escape, full pipes, timeout and stop escalation; reconcile engine containers across runner and daemon crashes with a host census as the absence oracle (Q19).
- [ ] Inject a lost reply after a counted effect, gateway, process-host or daemon crash and late history delivery; recover through W1 and recovery originals and S9 classes with no repeated external effect (Q02, Q03).
- [ ] Run each execution tuple's clock suites: suspend past the boottime deadline and past absolute expiry in separate cases, realtime jumps across expiry and restart with a changed or uncertain boot basis. The native fence precedes untrusted continuation on resume; no new protected dispatch or renewed lifetime follows expiry.
- [ ] Test task closure during execution and after an admitted effect; render S4 result kinds and verify descendant absence separately from remote outcome.

```bash
python3 -m unittest discover -s tests/integration/linux -p test_native_consumers.py -v
# Only when the optional sealed reference workload is selected:
python3 -m unittest discover -s tests/integration/linux -p test_sealed_work.py -v
```

**Acceptance:** Each required harness and Herdr keeps its own useful native workflow and owner evidence. Each advertised coordination and resource capability passes its CASES rows through installed owners. Storage, I/O, descriptor and output pressure preserve receipt, controller and stop headroom; capture refuses incoherent, oversized or out-of-closure input before dispatch. An absent mini-swe profile blocks nothing else.

### Packet O5: Qualify the four required harnesses

`boundary_class: prevent` for admitted protected tools; `advisory_only` for launcher selection.
`planning_status: ready_after_adr`
`execution_gate: O1 and implemented harness adapter and profile contracts for candidate assembly; O6 installed candidate and the host's exact I01-I08 for promotion. No O2, prior sealed-coding release or other host pass is required.`

**Files:** Existing harness adapter and launcher owners, `integrations/linux/`, `tests/integration/linux/test_host_launcher.py`; optional desktop and menu fragments under `integrations/omarchy/desktop/`.

- [ ] Order: Pi with its restricted bubblewrap profile first, then Linux restricted launchers for Claude Code, Codex and Hermes one host at a time, following Pi's profile in each plugin repository and `sdks/python/chio-hermes`. Each resolves only a locked, individually qualified tuple; unsupported or drifted hosts refuse with a reason and never fall back to the upstream auto-approved launch.
- [ ] Verify protected mode removes native shell and direct execution, uses gateway tools and denies bypass. Hook-only mode stays `detect_only`; native-shell sandbox interiors stay `cannot_see`. Labels never promote one into the other (Q11, Q22).
- [ ] If the Omarchy consumer is selected, add **Launch default agent in protected mode** as a distinct desktop or Walker entry that resolves and displays the selected host. Never rewrite `omarchy-agent`, aliases, shortcuts or upstream files or shadow `pi`. Test opt-in menu-key install and removal against realistic JSONC; unsafe parses leave the file untouched with a proposal.
- [ ] After O6 installs each locked candidate, run installed acceptance and current I01-I08 independently for Claude Code, Codex, Pi and Hermes with unknown default, stale executable, removed plugin, failed hook and missing gateway negatives. Keep four records; no mini-swe, other harness or Herdr evidence substitutes (H01-H05, H08a).
- [ ] Apply the execution clock cases of O3 through each protected path; sealed-runner evidence alone cannot qualify it.
- [ ] With a passing protected candidate, omit every optional GUI and unrelated sealed-work record and verify it stays eligible; remove each required case and verify promotion refuses. Repeat client loss and replacement without authority renewal or duplicated effects.

```bash
python3 -m unittest discover -s tests/integration/linux -p test_host_launcher.py -v
```

**Acceptance:** Claude Code, Codex, Pi and Hermes each pass their own installed and protected I01-I08 gates with all Chio GUIs absent. A partial release names any missing harness. Optional desktop entries coexist with upstream defaults.

## HOST-M3 packets

### Packet O3, organizational slice: execute foreign work as an independent owner

`boundary_class: prevent` at the executing owner's own door; `detect_only` for the counterpart's evidence.
`planning_status: ready_after_adr`
`execution_gate: the Linux HOST-M2 profile plus W1 facade, W2 owner services and remote co-signer, receiver-owned admission in a serving path (COOP-3), CT-CROSS transport and recovery gates. Missing gates leave cross-organization claims unavailable without blocking local hosting.`

**Files:** Extend the actual federation, treaty, work, disclosure and recovery owners; platform cases in `tests/integration/linux/test_native_consumers.py`.

- [ ] Use separately enrolled organization principals with independent keys in OS custody, independent policies and stores, on hosts controlled by different people. No party holds both co-signer keys; a two-user local simulation cannot pass (C06, Q28).
- [ ] Admit the foreign work at the Linux owner's door under a co-signed, attenuated commitment and run it inside the owner's own HOST-M2 tree and pool under one root grant with holds. Test peer refusal, wrong audience or intent, expired or revoked authority and unavailable freshness.
- [ ] Drop replies after mutation and before remote co-sign persistence; recover by original identity with no second dispatch, keeping execution, acceptance, delivery and settlement as separate facts (C07, Q01, Q02).
- [ ] Export the door's receipts in the evidence package; the requester verifies the package offline against a pinned partner card, including at least one out-of-scope deny (C08, Q14).

**Acceptance:** A Linux executing owner completes useful unpaid work for an independent requester, recovers a lost reply without a second dispatch, and produces evidence the requester verifies offline. A macOS-only party takes part as the requester until macOS HOST-M2 exists.

## Platform packets

### Packet O0: Freeze predecessor and platform evidence

`boundary_class: advisory_only`
`planning_status: ready_after_adr`
`execution_gate: accepted ADR-0038 and HOST-CONTRACT and access to exact predecessor sources; runtime work waits for each owner gate.`

**Files:** `integrations/linux/README.md`, `integrations/linux/compatibility/README.md` and `integrations/linux/compatibility/source-map.md`; an Omarchy overlay only for selected shell support. Reuse the shared qualification evidence format; no parallel requirement catalog or JSON corpus.

- [ ] Locate integrated owner surfaces: revision, file and API, native test entrypoint and retained acceptance for W1 views, recovery, S3, S4, S5 Part B, S7, S8, S28, S9 M20, applicable S10, secure IPC, process custody, broker and relay, CLI and SDK bindings, each required harness adapter and the Herdr binding. Distinguish missing source from present but unqualified source. S11 is conditional on a later injection-safety claim.
- [ ] Reconcile S8 exactly: phase 1 supplies durable `Kernel` stop and S30 routes; S28 is phase 3; `Tenant` and `Recovery` wait for phases 4 and 5. Per-task closure is S4 phases 1-2.
- [ ] Pin Omarchy v4.0.4 and the observed development revision separately. On an owned x86_64 host record distribution, kernel, systemd, bubblewrap, engine, LSM, cgroup and user-namespace state, profile, enrollment, credential context and units; a selected shell adds Qt, Quickshell and Hyprland.
- [ ] For each container-backed profile record runner, CLI, API, daemon and runtime identities, rootless or rootful mode, UID, GID and groups, socket identity, effective configuration, UID maps, drivers and cgroup delegation. Record the mini-swe runner delta (rejects rootless, pins the rootful socket) only if that workload is selected.
- [ ] Map every bound in O1 and O3 to its actual native owner, enforcement mechanism, test command, finite values and independent observation: pre- and post-authentication transport limits, Git parsing and working-tree capture, mount identity, coherent generation, task-private state reuse, descriptor and IPC classes, storage bytes, inodes, output and logs, storage throughput and operation rates, and established-channel revalidation. Include trusted supervisor and engine allocations outside task boundaries. Missing support blocks only that capability; package presence or a descriptor limit is not evidence.
- [ ] Inventory every time-bounded capability (reads, subscriptions, snapshots, approval and challenge credentials, service leases, delegated authority) and its Q31 owner, clock and freshness API, validity bounds and restart and boot reconciliation. Separately map the execution clock contract: boot identity, suspend-inclusive `CLOCK_BOOTTIME` deadline, retained absolute expiry and the resume fence. The optional mini-swe `time.monotonic()` helper does not establish it.
- [ ] Create separate source, API, owner, test and installed-evidence rows for Claude Code, Codex, Pi and Hermes and a distinct Herdr row; label hook-mode sessions `detect_only`. Pi's historical 0.1.0/0.85.1 record is evidence to inspect, not a current pass.
- [ ] Consume shared packet 2a and [RELEASE](../../specs/2026-10-07-desktop-integration/RELEASE.md): record the real release-evidence verifier command and activation call sites before O7. The current self-signed hash `--verify` is not profile readiness.
- [ ] Build the selected-surface case map from CASES (shared packet 1 owns the cross-platform map): each applicable row has a native owner, packet, actual test command, positive control and independent negative. Inventory every effecting mutation (Q02, Q20 for lifecycle) and every reachable helper (Q17) with its owner tests. Unexposed surfaces stay unavailable.
- [ ] Reconcile user-session and service-host enrollment with authority, credential and process owners; locate the `chio-secure-ipc` extension for multi-client authorization and retained process and session identity.

```bash
rg --files crates integrations tests docs spec | rg 'chio-(secure-ipc|process)|claude|codex|hermes|pi-plugin|herdr|priority-agent|recovery'
rg -n 'WorkHandleV1|WorkViewV1|InspectWorkflow|SubmitApproval|ResumeWorkflow|CancelWorkflow|PasskeyCapabilityVerifier' crates integrations spec
git ls-remote --symref https://github.com/omacom/omarchy.git HEAD refs/tags/v4.0.4
pacman -Q
uname -m
uname -r
systemctl --user status graphical-session.target
```

**Acceptance:** Every proposed owner call traces to actual source and tests, and every platform claim to an installed observation or a named unexecuted gate. No public instruction uses a private-only revision.

### Packet O6: Build packages and publish qualification candidates

`boundary_class: prevent` for activation and integrity gates; `advisory_only` for metadata.
`planning_status: ready_after_adr`
`execution_gate: O1 and implemented components of selected profiles, verifiable source and package identities, real public destinations and publication authorization. O2 only for a selected add-on.`

**Files:** `packaging/linux/arch/PKGBUILD`, `packaging/linux/README.md`, `packaging/linux/units/`, `packaging/linux/tests/test_package_contents.py`, optional `packaging/linux/tests/test_plugin_delivery.py`; candidate inventories in the existing release system and its signed manifest format.

- [ ] Package native services, bindings and the `chio` CLI (shared packet 4a) with units, profile configuration and diagnostics, and no workbench, Qt, Quickshell or Hyprland dependency. Optional controller, shim, opener, desktop entry, menu, icons and QML are separate components. No install-time self-download or ambient runtime resolution.
- [ ] Map each installer, updater, activation and removal mutation to its lifecycle owner and run Q02 and Q20 concurrency cases and Q17 operand cases for every invoked helper.
- [ ] Build twice in independently recorded clean Arch chroots from locked public sources; compare contents and retain `.BUILDINFO`, SBOM, license inventory and signed provenance. A mismatch is failed reproducibility.
- [ ] Archive tests: missing or altered binary, binding or unit, wrong mode or owner, setuid or setgid bits, unexpected executables, shell-based `Exec`, implicit enable or linger and package scripts writing user state.
- [ ] Publish an explicitly unqualified candidate through real destinations with protected and execution controls disabled; verify anonymous retrieval of every source, archive and signature. Without publication, record the blocker rather than inventing a URL.
- [ ] For a selected plugin, produce a standalone public Git delivery tree and follow the annex install sequence: `omarchy plugin add "$plugin_repository_url" --yes` (disabled), `git -C "$plugin_install_dir" checkout --detach "$plugin_public_revision"`, full path, mode and digest inventory against the signed lock, `omarchy plugin validate`, then `omarchy plugin enable computer.chio.desktop`. Move the default branch, alter an asset, remove the locked commit and substitute the inventory or protocol pair; the process reproduces the lock or refuses before enablement.

```bash
cd packaging/linux/arch
extra-x86_64-build
python3 -m unittest discover -s ../tests -p test_package_contents.py -v
```

**Acceptance:** Another operator can retrieve the exact native candidate without private credentials, developer files or graphical dependencies. Any selected plugin stays disabled until inventory and compatibility verification. Candidate publication is explicitly unqualified.

### Packet O7: Independently qualify installed native profiles

`boundary_class: detect_only` for independent observations; `prevent` for tested activation refusal; `advisory_only` for support claims.
`planning_status: ready_after_adr`
`execution_gate: retrievable O6 candidate, an actual Linux host, shared 2a-shared verifier and owner tests plus 2a-linux activation wiring, and every applicable gate for the named profile (2a-macos does not gate Linux). Shell and browser gates apply only when selected.`

**Files:** `tests/integration/linux/test_distribution_lifecycle.py`, `test_fault_recovery.py`, `test_diagnostic_privacy.py`; shell adapters under `tests/integration/omarchy/`; raw evidence in the existing release and qualification system with `integrations/linux/acceptance/README.md`. Do not reintroduce the retired Omarchy validator or fixture tree.

- [ ] Keep five first-class records: installed Claude Code, Codex, Pi and Hermes, each with H01-H05, H06a, H08a and protected I01-I08, and the Herdr H07/H08b matrix for all four selections. H06b runs the mixed composition. Remove one required record from a passing manifest and verify completion refuses while individual profiles still promote with exact scope. Repeat with mini-swe absent.
- [ ] An independent tester installs from a clean Linux host with no checkout or Chio GUI, records the tuple and package verification, and runs installed Observe and every selected profile; repeat on the Omarchy tuple for that claim.
- [ ] Run the installed `chio` binary and native consumers under the declared enrollment (shared packet 4a): useful Observe with execution owners absent, wrong peer, stale tuple, expired authority, substituted replies, terminal and operand injection, pipe closure, reconnect, and concurrent original-ID submissions with no duplicate effects (Q02, Q04, Q17, Q23).
- [ ] Execute the selected CASES rows through O0 and O3 mappings with every Chio GUI absent, and repeat O1's session and service enrollment cases.
- [ ] Change one tuple dimension at a time (plugin, binary, runtime, image, provider route, engine, daemon mode, socket or configuration, UID maps, unit override, kernel, namespace or cgroup feature) and insert hostile `node`, `chio` and `mise` shims first in `PATH`. Admission refuses mismatches before effects; canary executables stay unexecuted. Replace the rootless endpoint with a rootful one and assert refusal without retry (Q18, Q20).
- [ ] Upgrade with active and unknown operations; interrupt extraction, migration, activation and recovery start. The outcome is a coherent tuple or explicit unavailability, never mixed-generation execution or repeated effects.
- [ ] Keep authenticated native, subscription and browser channels open across every update fence, migration, activation, admission reopen, supported rollback and generation revocation, with old helpers retained and a response queued before release. The actual owners close each affected channel or revalidate both peers, current authority and the accepted generation before any protected release or dispatch; independent byte and effect counters show nothing new while fenced. Remove each required channel result from a passing manifest and require refusal (Q20, Q31).
- [ ] Test code rollback and a root snapshot rollback with newer home and plugin state; anchors, reservations, revocation and effect knowledge never move backward.
- [ ] Back up and restore through owner consistency APIs, including corrupt, stale, traversal and missing-key archives, reconciling before effects. Inject ENOSPC, inode exhaustion, EIO, read-only state and a missing recovery package; diagnostics are explicit and custody is preserved (Q20).
- [ ] Repeat Q31 read, approval and service-lease cases and the execution clock cases on the installed host through actual owner clock interfaces; remove each required clock case and verify the affected capability cannot promote.
- [ ] Join the O1 and O3 campaigns on the installed candidate: transport saturation, capture bounds, mount and coherence cases, task-private state, storage I/O, descriptor and IPC limits, storage and output pressure, and channel fencing. Remove each required result from a passing manifest and verify refusal. Basic Observe requires only its transport, read, session and lifecycle obligations. Mac evidence never qualifies Linux.
- [ ] Remove presentation clients and the plugin, then stop and remove the backend and attempt purge with unresolved work; only package-owned files and owned menu keys disappear. Test signed runtime revocation and a qualified successor; replacement never auto-resumes or broadens authority.
- [ ] Run sustained observation with slow and disconnected clients and measure CPU, RSS and IPC volume; flood diagnostics with seeded canaries; local export is bounded and never uploads.
- [ ] Publish the qualification report: profiles, artifacts, tuples, CASES outcomes, passed, refused, unknown and skipped cases, limitations, reviewer and owner commands, using only verified public sources. Promote each passing profile independently and document install, upgrade, rollback, restore and uninstall against observed behavior.

```bash
python3 -m unittest discover -s tests/integration/linux -p test_distribution_lifecycle.py -v
python3 -m unittest discover -s tests/integration/linux -p test_fault_recovery.py -v
python3 -m unittest discover -s tests/integration/linux -p test_diagnostic_privacy.py -v
```

A unittest exit alone is insufficient if required cases skipped; verify evidence through the shared verifier recorded in O0 and inspect independent oracles.

**Acceptance:** Public install and real operation reproduce independently on the named tuple; fault and negative cases preserve custody and prevent unqualified activation. Source checks, candidate availability, qualification and promotion are reported separately.

### Completion and scope control

- [ ] Check local links and `git diff --check`; run `python3 scripts/check-native-host-docs.py` for this plan and annex.
- [ ] Any new runtime concept, task state, retry loop, signing authority, peer-auth stack, sandbox or subprocess runner returns to its owner for consolidation.
- [ ] Confirm installation and capabilities work with all Chio GUIs absent, user-session and service-host authority stay distinct, each required harness and Herdr has its own record, and mini-swe stays optional.
- [ ] Record completion only against actual evidence; a checked plan, passing schema or mock cannot qualify an installed profile.

No packet implements compositor tools, configuration repair, desktop-private delegation or a general agent sandbox.
