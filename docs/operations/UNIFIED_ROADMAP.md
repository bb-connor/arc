# Chio unified roadmap

**Status:** design approved by the owner on 2026-10-08, section by section. Nothing in this document starts work. Execution begins only on an explicit start.

**Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.**

*Authority that only narrows. Work that survives. Evidence that travels.*

This roadmap works backwards from one result: outside teams running Chio under their own agents and completing co-signed work across organizations. It has four parts:

- **Gate 0:** the foundation, and the contracts every lane builds against.
- **Seven lanes:** parallel work that agent swarms can execute.
- **Gates G1 to G5:** the points where the lanes join.
- **Registers:** the decisions, dispositions and dates that serialize the work.

## How to read this document

**Evidence base.** Research was read-only on 2026-10-08 against main and every open PR head. It covered:

- code at pinned heads;
- simulated merges (`git merge-tree`);
- PR bodies, checks and review threads;
- the #1160 landing ledger;
- the program documents in #1160, #1170, #1172, #1173, #1174, #1177 and #1179;
- the public plugin repositories;
- package registries and the public installer.

| Ref | Pin |
| --- | --- |
| main | `002b4d14e` |
| #1160 | `fd8bfdc94` |
| #1173 | `cafdc970e` |
| #1174 | `8dffff3da` |
| #1177 | `620c703d8` |
| #1179 | `491bd01b5` |
| #1172 | `de84fc306` |
| #1170 | `666274bae` |
| #1171 | `ad9df87a5` |

Every line citation in this file must be re-verified after #1160 merges (section 13).

**Rules.**

1. **Dependency order, not calendar.** This document projects no internal dates and no engineer-week capacity. Execution uses agent swarms. The real serialization points are:
   - shared contracts and schema slots;
   - merge order;
   - hosted qualification;
   - review of security-critical code;
   - owner decisions;
   - outside teams;
   - fixed external dates (section 10).
2. **Specs may assume their predecessors are shipped** when this ordering makes that true.
3. **Claims follow ADR-0011 at its real scope:**
   - every planning item that touches a trust boundary carries `boundary_class` (`prevent`, `detect_only`, `advisory_only`, `cannot_see`) and `planning_status`;
   - anything claimed as shipped also carries its qualification status.
4. **Program prefixes on every cross-document ID.** Letters such as M, W, S, D, P and F mean different things in different programs. Section 12 is the crosswalk. Inside this document:
   - gates are G0 to G5;
   - lane rungs look like COOP-1;
   - contracts look like CT-ABI;
   - other documents refer to them as `UR-G1`, `UR-COOP-1` and `UR-CT-ABI`.
5. **Clawdstrike is prior art, not a peer.** It is an earlier project. Its Linux observation work (Tetragon, Hubble) and its macOS Endpoint Security and Network Extension plumbing are source material that Chio absorbs into its own crates and host adapters. It is never an integration target, a boundary, an owner or a peer.
6. **"Kernel" means a userspace authority and work-state kernel.** Isolation always comes from the host: bubblewrap, Seatbelt, containers or VMs. ADR-0038 puts it as "isolation denies, Chio grants".

## 1. The success test

**At the 2027-03-26 program review, at least two teams outside the core team each complete a qualifying full HOST-M3 run.** This test replaces #1170's commercial review criterion (STRAT-Q2-12).

A run qualifies only if all of the following hold.

- **(a) Independent operation.**
  - Each party runs its own domain (`chio trust serve`), its own hosts and its own key custody.
  - Backbay holds none of an outside party's keys.
  - No party holds both co-signer keys (STRAT-F15).
- **(b) Their agent, their door.**
  - The requesting organization's own agent proposes the work.
  - The executing organization admits it at its own door under a co-signed, attenuated work commitment.
  - Admission is receiver-owned and runs in a serving path.
- **(c) Work that survives.**
  - The executing organization runs the work in its own HOST-M2 process tree, under one root grant with holds.
  - A lost reply is exercised during the live run and is recovered by original identity, with no second dispatch (REC).
- **(d) Verified outcome.**
  - A named evaluator accepts or rejects the result against the commitment's predicate.
  - The run includes at least one out-of-scope deny.
  - Every decision carries a signed receipt.
- **(e) Evidence that travels.**
  - The requester verifies the whole evidence package offline against pinned partner keys.
  - The package includes the executing door's receipts.
- **(f) Real release.**
  - The run uses a tagged preview release.
  - An independent-operation record (operators, hosts, key fingerprints, versions) is published and reviewed against ADR-0011.
- **(g) Repeatable.** At least one team repeats a qualifying run without Backbay's hands-on help.

**Strongest form.** Two outside teams cooperate with each other. Backbay as the counterparty also counts.

**Stretch.** One outside team writes its own provider. That would also close the verifiable-work paper's open independent-operation gate, which requires "separately operated participants and independently written provider".

## 2. Where everything stands

| Program | PRs | State | What blocks it |
| --- | --- | --- | --- |
| Security and process foundation | #1160 | Mergeable and blocked. Four required checks (build/lint/test, MSRV, cargo-vet, cargo-deny) were pending on the latest push. It merges into main without conflicts. | Review-thread dispositions; coordination items including `MINISW-NATIVE-DENY`. It must land as a **merge commit**. |
| Recovery | #1172 (architecture and lab), #1179 (runtime, draft) | #1172 merges onto #1160 with 0 conflicts. #1179 is not qualified, and its P1s are open (including `NATIVE-FUNDING-AVAILABILITY-01` and the command-pool P1). | #1179 has 279 conflicts with #1160 and 264 with #1173. It sits on #1160's old startup sweep. It needs schema versions v39 to v45. |
| Verifiable work | #1173 (contains #1161, #1159; supersedes #1158; carries #1162's code) | Dynamic delegation, swarm evolution, the A2A v1 edge, execution evidence and unknown-payment release are qualified locally on one host. **WORK-W1 to W4 have no code.** | 112 conflicts with #1160; schema collisions |
| Kernel program | #1174 (docs) | Proposed, revision 4: eleven specs plus a defect register (KDEF-D1 to D12, N1 to N30) | Its baseline: #1160, #1172, #1173, #1179 |
| Strategy | #1170 (docs) | Every founder decision STRAT-F1 to F17 is open. | F-1 publication split; ADR-0023 and ADR-0028 scoping |
| Native host program | #1177 (docs; #1178 folded in) | ADR-0038 is accepted for planning. NORTH-STAR-FLOWS (HOST-M1 to M3) was approved 2026-10-08. The restructure and M1 plans are written but not executed. | Server-first re-cut (section 4) |
| Protocol draft | #1171 | IETF -00 draft, not yet posted | Decision U8; 1 conflict |
| Workbench | #1164 (draft) | Never built or tested since it was written; 12 findings open | Closes (section 7) |

**Distribution today.** No outside team can install a current Chio.

- **Public installer:** resolves to v0.1.0, built 2026-04-22 from source more than 4,000 commits behind main. GitHub still marks v0.1.0 as Latest.
- **Docs contradict that release:** `CHANGELOG.md` and `docs/install/README.md` say nothing has been released.
- **crates.io:** carries `chio-*` 0.1.2 from 2026-08-01, built from the public mirror rather than main.
- **Plugins and bridge:** the harness plugins and `chio-bridge` are unpublished.

**Merged since the previous draft:** #1194 (lane-test CI). Already on main: #1025 (cognition market design) and #966 (four-direction roadmap, including the governed x402 rail).

## 3. Gate 0: foundation and frozen contracts

Gate 0 exists so that parallel lanes do not collide. Everything a lane builds against is fixed here first, as a versioned 0.x preview contract with schemas and test vectors under `spec/`.

### G0.1 Land #1160

- Merge as a **merge commit**. The landing ledger binds evidence to exact source identity, and squash or rebase would break that binding.
- Before merging:
  - pass the required checks;
  - record dispositions for every review thread;
  - close the coordination items, including `MINISW-NATIVE-DENY`.
- After merging:
  - record `main_ancestry_verified`;
  - close #1136, whose patch #1160 contains.

**#1160's post-merge, pre-release obligations** are scheduled in Lane REL, not left open:

- the 35-campaign trusted capture;
- per-PR security App enforcement;
- native mini-swe and cold-platform acceptance.

### G0.2 Integration rules

- **Schema ledger lock.**
  - Admission-store versions are assigned in landing order, at merge time, under a lock recorded in the #1160 landing ledger.
  - Branches use symbolic version names until they rebase.
  - A static reservation (for example "#1179 takes v39 and up") would force every earlier lander to renumber, so it is not used.
- **Collisions to fix before any rebase:**
  - **Duplicate trigger, fails open.** `admission_operation_recovery_no_delete` is defined by #1160 on its deferrals table and by #1179 on its records table, both with `CREATE TRIGGER IF NOT EXISTS`. After a merge, the second delete guard is silently skipped.
  - **Global-commit kind list.** The `authority_global_commits` projection-kind CHECK list is appended separately in #1160, #1173 and #1179.
  - **Tool-outcome store v4.** #1160 uses it for payload compaction; #1173 uses it for execution evidence.
  - **Process ABI v3.** There are two incompatible v3s (#1160 and #1179), so their union is v4 (CT-ABI).
  - **Dead v41 check.** #1179 requires v41 in code (`original_owner.rs`) while declaring v40.
  - **Unreserved bumps.** The planned bumps for KSPEC-08 phase 1, WORK-W1.2, KSPEC-10 and KSPEC-11 are allocated through the same lock.
- **One merge queue.** Merge commits are used wherever evidence is bound to source.
- **ID prefixes and crosswalk:** section 12.

### G0.3 Contracts

| Contract | Freezes |
| --- | --- |
| **CT-ABI** | Process ABI v4. `chio.process.v1` schemas in `spec/schemas` (39 identifiers are unspecified today). `KERNEL_ABI_VERSION`, published from the KSPEC-01 phase 0 census. Operation IDs are never reused. |
| **CT-WORK** | `chio.work.v1` and the WORK-W1 facade (`WorkClient`, `WorkHandleV1`, `WorkViewV1`). These are mapped to #1179's real port names (`RecoveryProcessReservationPort`, `RecoveryProcessOriginPort`, `RecoveryAuthorityPort`), not the doc-only names. Includes an **unpaid** `Agreement` variant. |
| **CT-SETTLE** | The settlement composition rule (#1174 decision 4, spec 9 rules M7a, M7b, M11a, R-9-05), implemented on #1160's paged startup sweep. Details below the table. |
| **CT-COOP** | The **partner card**: org DID, trust-control URL, authority key history, receipt-signer keys, status resolve URL. Issuer-signed passport lifecycle status. DPoP possession for federated grants at the door. The evidence trust-anchor format. |
| **CT-CTRL** | OpenAPI for trust-control and the `chio api protect` sidecar. Per-route principals in place of one shared service token. The KSPEC-08 stop routes. |
| **CT-CROSS** | The cross-org transport for co-signing and bilateral delivery (decision D4). |
| **CT-REL** | The release channel. Details below the table. |
| **CT-WIRE** | The freeze list for the preview window: receipt, capability, passport, challenge, issuance, evidence and co-sign bytes; process ABI v4; `chio.work.v1`. |

**CT-SETTLE in detail.**

- **One sweep owner.** #1179's historical hold becomes a classified, durable per-item deferral inside that sweep, never a `?` that aborts the sweep.
- **Delivery and money are separate facts.**
  - After an unknown outcome, only a co-signed `MutuallyAgreedUnknown` releases money.
  - For a known return with a pending capture, only `ContractualCaptureWaiver` stops the capture.
- **Holds versus successors.** A hold blocks finalization, receipts and delivery, but never a co-signed monetary successor.
- **Read before finalizing.** Every finalizer reads the effective payment journal first.
- **One signer-rotation rule** applies to finalization, release completion and waiver completion (decision D2).

**CT-REL in detail.**

- **Preview versions:** `0.2.0-alpha.N`. This is SEC-M10's developer preview, widened to include what HOST-M3 needs.
- **Repos:** the development repo and the distribution mirror (decision D7).
- **Preview exception:** previews may ship before #1160's full-release obligations close (decision D8).
- **Host compatibility:** tested version ranges for harness hosts, instead of exact pinned hashes.

### G0.4 Work that starts without waiting for Gate 0

- the immediate actions (section 6);
- recruiting, trial terms and legal (Lane OUT);
- drafting every contract above;
- MCP interop research (REL-2).

**Gate 0 exit evidence:**

- #1160 is on main;
- every contract is merged with schemas and vectors;
- the ledger lock is live;
- decisions D1 to D7 are recorded.

## 4. Lanes

Each lane is a ladder of rungs, and each rung ends in exit evidence. Lanes run in parallel and join at the gates in section 5.

### Lane COOP: cooperate across organizations

**What exists on main.**

- The passport, challenge and `trust federated-issue` chain is tested on one host.
- `chio api protect` admits presented capabilities through `X-Chio-Capability` with a pinned `CHIO_TRUSTED_ISSUER_KEY`.
- `chio evidence export` and `chio evidence verify` work offline.

**What does not hold up between two real operators.**

- A's passport revocation never reaches B. Federated issue reads B's own local status.
- At proxied routes a federated capability is a bearer token, because holder possession is not checked.
- The door ignores revocations made after it started.
- `evidence verify` pins no trust anchor.
- Door receipts (`http_receipts`) are missing from the evidence export.
- The issuance inbox design has no way to return the issued capability to the holder.

**Rungs.**

- **COOP-1: HOST-M1, re-cut server-first.**
  - The issuance inbox, with a holder pickup route authenticated by the subject key.
  - B's authority owns the delegation ceiling.
  - Door receipts are exportable.
  - `evidence verify --trust-anchor <partner card>`.
  - OS key custody built on #1160's `signing_custody`: `credential:` or systemd-creds on headless hosts, Keychain or Secret Service on desktops. Plaintext seed files are labelled development-only.
  - Service packaging: systemd units, a LaunchAgent, and a container image.
  - The desktop review moments (Waybar or QML, menu bar, notifier) are optional follow-ons, not gates.
- **COOP-2: a production-grade pair.**
  - `chio partner add` over the CT-COOP partner card.
  - Issuer-signed lifecycle status pulled with a TTL, failing closed when stale.
  - A live revocation feed at the door, and a durable revocation oracle (today only `InMemoryRevocationOracle` exists).
  - DPoP for federated grants.
  - Authority key history, so rotation is not an outage.
  - Safe HTTP methods deny by default for federated doors.
  - A TLS reverse-proxy recipe and a rotation runbook.
- **COOP-3: the HOST-M3 door.**
  - Receiver-owned admission on a serving path, with treaty predicates carried by the process host's admission hook.
  - The remote co-signer over CT-CROSS. This also closes STRAT-F15's relay or mTLS lane.
- **COOP-4: evidence a counterparty can trust without trusting the operator.**
  - C2SP checkpoint compatibility (#1174 north-star bet 6).
  - The MCP edge authorization audit (bet 8).
  - Claims stay labelled "signatures verified against pinned keys; no external witness" until witnessing exists.

**After the test.**

- Multi-hop across independent keys. This needs a partner-key set separate from authority keys, and a chain-binding resolver at the HTTP door, which today rejects any token carrying `attenuation_proof`.
- Discovery across N organizations, with an anchored publisher key.
- Revocation propagation across N organizations.
- Reputation, with Sybil controls.

### Lane WORK: coordinate work

**#1173, split by path rather than by commit.** Its large commits mix concerns, so slices are cut by path.

| Slice | Contents | Lands |
| --- | --- | --- |
| α | Execution evidence and checked output. Carries most of the 25 core conflicts. Drops #1173's own sweep edit in favour of #1160's classifier. | Right after Gate 0 |
| β | D1 dynamic delegation, S1 swarm evolution, A2A v1 edge | Right after Gate 0 (1 conflict) |
| γ | Federation, bilateral DSSE, iroh lanes, treaty runtime-core | After α and β; needed for the remote co-signer |
| c | WORK specs and plans, with the corrections below | With γ |
| d | Paper and research documents, plus research code | Separate docs PR |
| δ | Unknown-payment release, capture waiver, journal overlay, funded work | After CT-SETTLE; off the success-test path |
| ε, ζ | Confined PostgreSQL and broker; security and CI | Re-derived from #1160 or dropped |

**Corrections to the WORK plans.**

- **Split W1.5 and W1.6** into halves that need no recovery (a) and halves that do (b).
- **Add the missing route:** W2.1's route list lacks `/cosign`.
- **W2.5** (operator package and external handoff) is required for outside teams.

**Rungs.**

- **WORK-W1:**
  - W1.0 creates `docs/research/work-abstraction/INTEGRATION.md`, the inventory of real constructors and ports;
  - then W1.1 to W1.4;
  - then W1.5a and W1.6a;
  - then W1.5b and W1.6b, after REC;
  - then W1.7.
- **WORK-W2:**
  - W2.1, owner services including `/cosign`;
  - W2.2, co-signing plus durable bilateral delivery. This has not yet succeeded in a composed run.
  - W2.4, lost-reply recovery, after REC;
  - W2.5.
- **WORK-W3:** the `chio work` CLI, and `WorkClient` wrappers for Python `chio-process` and `@chio-protocol/process`. Outside teams' agents need these.
- **PAPER-1 to PAPER-4** are now scheduled. PAPER-5 follows W4.

**After the test.**

- W2.3, funded work.
- W4, beta convergence with the security and recovery release gates.

### Lane REC: work that survives

- **#1172 lands** after #1160.
- **#1179 is re-scoped as follows.**
  - Rebase onto #1160's paged sweep rather than porting the old loop. #1179's "settlement after operator rotation wedges the startup sweep" P1 mostly comes from that stale base: #1160 already defers a signer mismatch instead of aborting.
  - Adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24).
  - Adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16).
  - Fix KDEF-N15 (wall-clock time in authority evidence) during the rebase.
  - Fix every open P1.
  - Take schema slots through the ledger lock.
  - Regenerate the SDKs rather than merging 161 generated files by hand.
- **Order of landing.**
  - First a REC-P0 + REC-P1 slice: contracts and exact durable recovery.
  - Then REC-P2 to REC-P6, each re-qualified.
- **Exit:** qualified recovery of a lost reply by original identity. This unblocks WORK-W1.5b, W1.6b and W2.4.

### Lane KERNEL: the guarantees outside teams rely on

This is #1174's bug-fix lane, promoted to a preview gate. It runs on post-#1160 main.

- **KERN-1: stop.**
  - KSPEC-08 phase 0 (AC6).
  - KSPEC-08 phase 1 (KDEF-D2, N22, N23): a durable, restart-safe stop with an allocated schema slot.
  - The stop is reachable from the process-host socket and the CLI.
  - Today the emergency stop is a process-local flag, its routes are unmounted, and its token comparison is not constant-time.
- **KERN-2: exactly one terminal receipt per executed call.**
  - KSPEC-03 phase 1 (KDEF-D1, N2, N28, N29), together with the M20 identity-disposition delta.
  - Phase 1 and the delta land together, because KSPEC-08 rule S15 ties `retryable_after_resume` to M20.
- **KERN-3: revocation and closure.**
  - KDEF-D6 and D5.
  - KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure.
  - A new spec for process exit as an authority transition. `ProcessState` has no exit state today.
- **KERN-4: the session door.** KSPEC-05 Part A (KDEF-D3, D4, N26, N30), because doors serve over `chio mcp serve-http`.
- **KERN-5: isolation evidence.** KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim.
- **KERN-6: gates.**
  - KDEF-GT1: one whole hosted CI run passes.
  - KDEF-N4: the Mechanism D gate.
  - KDEF-N1 and N15 become rebase gates, at the #1173 and #1179 merges respectively.
  - KDEF-D7, N6, D11 and D12 each get an owner.

**Owners still to be assigned** for primitives that no spec owns:

- process exit;
- the durable revocation oracle and the portable verifier's lifecycle check;
- the durable sibling-share registry;
- the model-relay spend dimension;
- a versioned control API;
- macOS IPC peer authentication.

**After the test.**

- KSPEC-09 to KSPEC-11 keystones (pure admission machine, crossing records, integrity-gated admission).
- KSPEC-01 shrink.
- KSPEC-02.
- KSPEC-05 Part B.
- KSPEC-08 phases 2 to 7.
- KSPEC-04 phases 3 and 4.

### Lane SHARE: share resources, and HOST-M2 on Linux

Today "share resources" runs on seven or more separate counters:

- grant holds;
- aggregate families;
- basis-point shares;
- process shares;
- D1 slots;
- S1 pools;
- the finding pool.

Only the kernel hold ledger durably records consumption. Money is not pooled across delegated children, and the only pool siblings share counts invocations across one hop.

**Rungs.**

- **SHARE-1: one consumption ledger.**
  - The kernel hold ledger is the only consumption authority.
  - Every other counter becomes a commitment entry or a view, following #1174's sealed-ledger proposal.
  - First slice: a family monetary cap, using #957's co-debit pattern, plus a durable sibling registry.
  - Decide what basis-point shares actually bound; today they are declarations only.
- **SHARE-2: model spend through the kernel.**
  - Model calls route through the broker's provider adapter, using the worst-case-then-reconcile lifecycle.
  - Add a token quota for subscription harnesses.
  - Fix the required-agent profile, which issues a fresh counter per session. Megastart's bound-session pattern is the reference.
  - Today's "model relay" is a Python request counter inside the Hermes SDK.
- **SHARE-3: HOST-M2 on Linux.**
  - One root grant across the harnesses outside teams run: Claude Code and Codex first, then Pi and Hermes.
  - Live cancel and revoke while the host runs.
  - Serving-path swarm admission beyond depth 1 and the `tool_calls` dimension.
  - Restart never replenishes a pool.
- **SHARE-4: cleanup.**
  - Accept ADR-0016 (the authoritative spend contract).
  - Write ADR-0035 (web3-free distribution) at its real scope: the kernel, core, control plane and CLI.
  - Make `finding-market` and `web3` off by default.
  - Move the x402 and ACP clients out of the kernel (KSPEC-01 R13).

**After the test.**

- macOS HOST-M2: a Darwin process runner, a Keychain and XPC broker, and `LOCAL_PEERTOKEN` IPC.
- Economy modules: funded WORK-W2.3, and x402 as a module.
- Sender-funded holds shared across organizations.

### Lane REL: something outsiders can install and connect to

- **REL-1: the preview train.**
  - SEC-M9 packaging and SEC-M10 publishing.
  - #1160's post-merge obligations, or the CT-REL preview exception.
  - The AWS-LC fork audit.
  - Signed binaries for Linux x86_64 and arm64 and macOS arm64.
  - A container image with the dashboard embedded. Today the dashboard is in no release artifact.
  - Fix `CHANGELOG.md` and the install docs, and sync the distribution mirror.
  - Mark v0.1.0 superseded and resolve crates.io (decision D10).
  - Publish the format-stability note.
- **REL-2: the MCP door.**
  - Interop with MCP revision 2026-07-28 (stateless core); today the edge accepts only 2025-11-25.
  - `chio mcp serve-http` accepts presented, federated capabilities, or a bridge-daemon shim adds them.
  - Exit: current Claude Code and Codex connect through ordinary remote MCP, with no plugin.
- **REL-3: harnesses.**
  - Claude Code and Codex are co-first, in MCP mode. Hooks count as coverage, never enforcement, because hook failure does not block either host.
  - Linux restricted launchers for the HOST-M2 harnesses. Today Pi has bubblewrap; Claude Code, Codex, Cursor and Hermes are Seatbelt-only; OpenClaw is a container.
  - Publish Pi, the bridge and the plugins with tested version ranges.
  - Fix `backbay-labs/chio-bridge#3`.
- **REL-4: the operator surface.**
  - The trust-control dashboard is the one operator web client. It is read-only today and served only from a relative path.
  - It gains:
    - approval routes;
    - authentication beyond `?token=`;
    - the issuance panel;
    - authority-tree and pool views.
  - Plus the onboarding kit and runbooks.

### Lane OUT: outside teams, positioning, standards

- **OUT-1: recruiting.**
  - A named owner (STRAT-F4).
  - Candidate teams per the private GTM plan (STRAT-F1).
  - Trial terms; legal groundwork (STRAT-F13).
  - A receipt-privacy rule (STRAT-F10).
  - Teams onboard at G2 so that their infrastructure, keys and working relationship already exist by G5.
- **OUT-2: positioning cleanup** (section 9).
- **OUT-3: standards.**
  - The IETF -00 (decision D11).
  - WIMSE and ODIS positions.
  - NVIDIA is a channel, not a dependency. Build OpenShell middleware only if a candidate team runs OpenShell. Re-check the Agent Policy Fabric monthly.
- **OUT-4: records.** Independent-operation records and ADR-0011 claim reviews for every gate.

## 5. Gates

```text
Gate 0 ─┬─ REL-1,REL-2 + KERN-1,KERN-2,KERN-6 + OUT-2 ──────> G1 preview installable
        │                                                     │
        ├─ COOP-1,COOP-2 + REL-4 + OUT-1 ─────────────────────┴─> G2 outside HOST-M1 ──┐
        │                                                                               ├─> G4 internal HOST-M3 ─> G5 outside HOST-M3 x2
        ├─ SHARE-1..3 + KERN-3,KERN-5 + REL-3 + WORK slice β ──> G3 HOST-M2 on Linux ──┘          ▲
        │                                                                                           │
        └─ WORK-W1,W2,W3 + REC + COOP-3,COOP-4 + KERN-4 ────────────────────────────────────────────┘
```

**G1: an outsider can install the preview.**

- A tagged `0.2.0-alpha.N`.
- A timed install by someone outside the core team, on Linux and on macOS, through to a first receipt.
- Current Claude Code and Codex connect over MCP and produce allow and deny receipts.
- The CT-WIRE freeze list is published.

**G2: HOST-M1 with an outside team.** An outside team and its counterparty each run their own domain end to end:

1. passport;
2. challenge;
3. inbox;
4. holder pickup;
5. allow and deny at the door;
6. offline verification against a pinned partner card.

Exit also requires:

- revocation propagates live;
- rotation has been exercised;
- an independent-operation record is published.

**G3: HOST-M2 on Linux.**

- One root grant across Claude Code and Codex on one Linux host.
- The family money cap and model spend are held.
- Restart never replenishes a pool.
- Live cancel and revoke cascade through the tree.
- Swarm admission runs on the serving path.
- Isolation evidence is recorded by KSPEC-07 kind.

**G4: internal HOST-M3.** Two Backbay-operated domains on separate hosts, with independent keys and no shared keys.

- A complete run satisfying section 1 criteria (a) to (e).
- These drills pass:
  - lost reply;
  - crash;
  - co-signer down;
  - stop;
  - revoke mid-work.
- The requester verifies the package offline.

**G5: the success test.**

- A preview release that contains HOST-M3.
- Two outside teams each complete a qualifying run, satisfying section 1 criteria (a) to (g).
- At least one team repeats its run unassisted.
- The records are published and reviewed.

**Critical path:** Gate 0, then WORK-W1 and W2 together with REC, then G4, then G5.

The two riskiest unproven pieces get the largest swarm allocation and the earliest prototypes:

- #1179's rebase and requalification;
- WORK-W2.2's durable bilateral delivery.

G2 and G3 run in parallel with the critical path. HOST-M1 never depends on #1179.

**Claims each gate permits.** These use ADR-0011's vocabulary. Every claim is limited to kernel-mediated calls and carries the preview label until the qualification in section 11.

| Gate | Claim | `boundary_class` | `planning_status` |
| --- | --- | --- | --- |
| G1 | Calls through the MCP door and `chio api protect` are authorized or denied before effect, each with a signed receipt. | `prevent` | `ready_after_adr` (CT-WIRE, CT-REL) |
| G1 | Harness hooks observe native tool use. | `detect_only` | `ready_after_adr` |
| G2 | B's door admits A's agent only within B-issued, attenuated, holder-bound authority. | `prevent` | `ready_after_adr` (CT-COOP) |
| G2 | A verifies B's receipts offline against operator-pinned partner keys, with no external witness. | `detect_only` | `ready_after_adr` (CT-COOP) |
| G3 | One root grant's holds bound spend and invocations of kernel-mediated calls across harnesses on one host. | `prevent` | `ready_after_adr` (ADR-0016, CT-ABI) |
| G3 | Native effects outside the kernel path. These are `prevent` only where a qualified KSPEC-07 backend confines them, and are otherwise rendered "unconfined". | `cannot_see` | `ready_after_adr` (KSPEC-07) |
| G4, G5 | The receiver admits a co-signed work commitment at its own door. | `prevent` | `ready_after_adr` (CT-WORK, CT-CROSS) |
| G4, G5 | A lost reply is recovered by original identity with no second dispatch. | `prevent` | `blocked_by_adr` until CT-SETTLE and D2 are decided |
| G4, G5 | The evaluator's signed acceptance or rejection is recorded. | `detect_only` | `ready_after_adr` (CT-WORK) |
| After G5 | Rail settlement outcomes and cross-org money. | `detect_only` | `deferred` |

## 6. Start now

None of these depend on #1160.

| # | Action |
| --- | --- |
| U1 | **STRAT-F1:** decide which #1170 documents stay public. |
| U2 | **Void STRAT-F17** and remove Clawdstrike-as-peer framing from #1170 and #1177. Rewrite `research/clawdstrike.md` in #1177 as a prior-art note: Tetragon and Hubble observation on Linux, Endpoint Security and Network Extension on macOS. |
| U3 | **Positioning PR** (section 9). It covers every stale surface on main. |
| U4 | **KDEF-N23:** constant-time comparison of the admin token (`crates/kernel/chio-kernel/src/kernel/emergency.rs`), plus the AC6 stop-scope document. |
| U5 | **x402 fails open.** `X402AuthorizeResponse.settled` defaults to `true` when the field is absent (`crates/kernel/chio-kernel/src/payment.rs`, `default_true`). Default to not settled, failing closed. |
| U6 | **`backbay-labs/chio-bridge#3`:** `approval-decide` does not check the recorded decision or the approval ID. The scope is that utility; the gateway resume path honours the signed decision. |
| U7 | **Recruiting:** a named owner, trial terms and legal groundwork. |
| U8 | **IETF -00:** decide whether to submit by the cutoff (section 10). If it is submitted, fix or flag the single-key multi-hop rule in draft step 7 first. |
| U9 | **CT-CROSS:** decide early, because the free iroh relays end (section 10). |
| U10 | **Stale artifacts:** add deprecation notices to the stale installer and registry artifacts now, and replace them at G1. |

## 7. PR dispositions

**Rule:** no PR closes until its ledger requirements are carried forward. That means:

- 136 requirements on #957 to #959;
- 27 on #956;
- 12 on #1164;
- 2 on #1046;
- 1 on #1073;
- the FV-D3 dependency on #959's netting code;
- #1029's singular-approval ADR decision.

| PR | Disposition |
| --- | --- |
| #1160 | Land at Gate 0 as a merge commit. |
| #1196 | This document. |
| #1172 | Land after #1160 (Lane REC). |
| #1173 | Split by path into slices α, β, γ, c, d and δ; re-derive or drop ε and ζ. Close when the slices land. |
| #1179 | Stays a draft until it is re-scoped and rebased (Lane REC). |
| #1174 | Merge as the KSPEC program. Fix its north-star research document, which still carries a superseded north star and the retired tagline. |
| #1177 | Merge after the restructure and the server-first HOST-M1 re-cut. Mark NORTH-STAR-FLOWS approved. Apply the ADR-0038 amendment. Rewrite the Clawdstrike material as prior art (U2). Move macOS HOST-M2 after the test. HOST-M1 code no longer waits on the docs restructure. |
| #1170 | Split private material per U1. Void F-17. Scope ADR-0023 to ADR-0038 (thin OS adapters allowed; broker, cage and launchers not frozen). Scope ADR-0028 to "where an IdP exists". Replace the review criterion with section 1. Drop the capacity model. Merge the public remainder. |
| #1171 | Rebase. Submit if U8 says so. Federation material goes to companion drafts later. |
| #1164 | Close. Salvage its MCP adoption, activation and preview-distribution machinery into Lane REL. |
| #1161, #1159, #1158 | Close as contained in #1173. #1161's peer transport is example-only and does not satisfy STRAT-F15. |
| #1162 | Archive its evidence and `examples/repair-machine-proof`, then close. |
| #1163 | Decide whether the paper's bilateral-admission benchmark must be regenerated, then close. |
| #1136 | Close after #1160 (patch contained). |
| #1046 | **Salvage into REL-1.** Its workspace dependency versions make `cargo package` work. |
| #1056 | **Salvage into REL-1** as the distribution mirror sync. |
| #1155 | **Salvage into REL-1** as the preview install path. |
| #1073 | **Salvage into REL-1** (release qualification budget). |
| #1043 | Owner review: archive or close. |
| #1029 | Close as superseded by #1160, after checking its three economy items against main (settlement-observer idempotency key, credit election, MustPrepay). Its ADR-0018 collides with main's ADR-0018 and must be renumbered if any of it survives. |
| #956 to #959 | Salvage, then close. From #956: the unforgeable `VerifiedApproval`, settlement terms inside the signed intent, single use keyed on request and intent, and raw builders made `pub(crate)`. From #957: the co-debit pattern. From #958: the escrow `accept()` invariants. From #959: the conformance tests `x402_payment_does_not_authorize_tool_call` and `eas_verax_display_only_projection`. Drop #957's Chio Pass kernel gating and #959's closed-enum wire break. |
| Unmerged branches | Archive `research/genesis-program` (its ADR-0018 also collides), `project/roadmap-04-25-2026`, `docs/native-application-adoption` and `research/funded-work-baseline`. |
| `backbay-labs/chio` | Megastart (#9, #10, #25) and the agentic OS suite (#4, #5) become HOST-M2 showcases after the test. Megastart's allowance is already a kernel-held aggregate-family quota. What remains is moving it to the host's shared admission owner and adding spend. The chio-world app (#228) needs an explicit decision. |

## 8. Owner decision register

| # | Decision | Recommendation | Blocks |
| --- | --- | --- | --- |
| D1 | Settlement composition | Adopt #1174 decision 4 on #1160's sweep (CT-SETTLE). | Gate 0, REC, WORK slice δ |
| D2 | Signer-rotation rule | Sign with the current key and bind the original identity, uniformly across finalization, release and waiver. Today #1160 quarantines, #1179 re-signs and #1173 refuses. | Gate 0, REC |
| D3 | Schema allocation | Landing order under the ledger lock; symbolic names on branches. | Gate 0 |
| D4 | Cross-org transport | Default to HTTPS with mTLS or signed bodies, which fits outside teams' firewalls and operations. iroh stays an optional lane with self-hosted relays. | Gate 0, COOP-3, WORK-W2.2 |
| D5 | Unpaid work agreement | Add an unpaid `Agreement` variant to `chio.work.v1`. | Gate 0 |
| D6 | Holder possession | Require DPoP for federated grants at the door. | Gate 0, COOP-2 |
| D7 | Canonical repositories | `bb-connor/arc` is the development repo; `backbay-labs/chio` is the distribution mirror, synced on every tag. | Gate 0, REL-1 |
| D8 | Preview exception | Allow tagged `0.2.0-alpha.N` previews before #1160's full-release obligations close. They are labelled as previews, with claims limited under ADR-0011. | G1 |
| D9 | Licensing (STRAT-F5) | Apache-2.0 for verifiers, adapters and preview binaries. | G1 |
| D10 | crates.io | Yank 0.1.x with a pointer to the preview channel, unless the Rust library is in the preview's supported surface. | G1 |
| D11 | IETF -00 | Submit as an individual draft, with the multi-hop rule flagged as an open issue. | OUT-3 |
| D12 | Required harnesses | Claude Code and Codex for G1 to G5; Pi and Hermes as additional HOST-M2 harnesses; record a decision on OpenClaw and Cursor after the test. | REL-3, G3 |
| D13 | Recruiting owner and legal (STRAT-F4, F13) | Name the owner and start legal now. | G2 |
| D14 | Receipt privacy (STRAT-F10, ADR-0036) | Argument commitments before any outside run, or at minimum a rule of no personal data in arguments. | G2 |
| D15 | STRAT-F1 | Keep commercially sensitive and GTM material private; publish the rest after review. | #1170 merge |

**Recorded, not open:**

- the success test and the qualifying-run definition (section 1);
- STRAT-F17 void;
- ADR-0023 scoped to ADR-0038;
- ADR-0028 scoped to "where an IdP exists";
- #1170's review criterion replaced;
- demos: Demo C becomes G2; the reduced Treaty Call becomes G5; Demos A, A2 and B are retired as separate builds;
- accept ADR-0016;
- ADR-0035 at full scope.

## 9. Positioning

**Lead with the cross-org clause in every audience.**

- "Agent OS" and "agent kernel" are crowded labels. Microsoft's Agent Governance Toolkit calls itself "the kernel for AI agents", and several open-source and academic projects use "agent OS".
- No shipped product combines all four of:
  - separately operated owners who each admit at their own door;
  - attenuation-only grants;
  - evidence the counterparty verifies offline;
  - durable work identity.
- Scope any uniqueness claim accordingly. NORTH-STAR-FLOWS' "no competing stack claims this verb" needs that scoping.

| Audience | Sentence | First proof |
| --- | --- | --- |
| Builders, harness and plugin authors, OS users | The north star and the supporting line, cross-org clause first | Install, connect their agent, see a deny receipt |
| Counterparty pairs | "Verify the agent's authority at your door, not theirs." | A two-operator run with their own keys |
| NVIDIA, OpenShell and enterprise platforms | #1170's interim category sentence and the Alliance's "policy, identity and governance" layer name; never "kernel" as the category | Coverage table, preview label |
| Standards bodies | No tagline; artifact names only | Interop vectors |

**Stale surfaces on main to fix (U3):**

- **README.md:**
  - line 16: "The kernel your agents answer to";
  - line 22 and `docs/assets/subhead.svg` / `subhead-mobile.svg`: "Agents that pay each other" and the unscoped "every call";
  - lines 78 and 156: "pay each other";
  - the unscoped "every call" wording at lines 73, 128, 172, 177 and 259;
  - lines 44 and 251: the installer links.
- **`docs/reference/COMPETITIVE_LANDSCAPE.md`:** "only protocol".
- **`AGENTS.md`:** lines 5 and 11.
- **`docs/start-here/VISION.md`:** needs a historical banner.
- **`CHANGELOG.md` and `docs/install/README.md`:** they contradict the v0.1.0 release.
- **The `spec/PROTOCOL.md` header.**
- **The ADR indexes:** they stop at ADR-0020 and ADR-0021.

**How to describe payments.** Rails plug in as optional modules. Holds and caps are `prevent` for kernel-mediated calls. Rail settlement outcomes are `detect_only`. Make no on-chain or escrow claims.

## 10. External dates and venues

These are fixed facts, not projections.

| Date | Item |
| --- | --- |
| 2026-10-20 to 22 | NVIDIA GTC Berlin. Watch for Agent Policy Fabric and OpenShell news. |
| 2026-10-22 to 23 | AGNTCon and MCPCon North America, San Jose |
| 2026-11-02 | IETF -00 submission cutoff |
| 2026-11-09 | KubeCon North America co-located Agentics Day, Salt Lake City |
| 2026-11-14 to 15 | IETF 127 hackathon, San Francisco |
| 2026-12-31 | n0's free public iroh relays end (ADR-0014) |
| 2027-03-14 to 18 | NVIDIA GTC 2027, San Jose |
| 2027-03-15 to 18 | KubeCon Europe, Barcelona |
| 2027-03-26 | Program review: the success test |

## 11. After the success test

- **Coordinate:** WORK-W2.3 funded work, then WORK-W4 beta convergence, then PAPER-5.
- **Share:** macOS HOST-M2, sender-funded cross-org holds, economy modules.
- **Cooperate:** multi-hop across independent keys, N-organization discovery and revocation, witnessed evidence, reputation, IETF companion drafts for federation.
- **Kernel:** KSPEC-09 to KSPEC-11 keystones, KSPEC-01 shrink, KSPEC-02, KSPEC-05 Part B, KSPEC-08 phases 2 to 7.
- **Hosts:** Megastart and Herdr showcases; OpenClaw and Cursor per D12; NVIDIA chokepoints if a team needs them.
- **Kernel 1.0 contract.** The following primitives must be qualified:
  - org principal, domain, agent subject and an operator roster (KSPEC-08 S28);
  - attenuation-only capabilities with durable revocation that reaches passports;
  - process trees with an exit state, live cancel and revoke, and ABI v4;
  - exactly one terminal receipt per executed call;
  - durable holds that never replenish on restart;
  - authenticated IPC on each supported OS;
  - a durable stop;
  - closure;
  - offline-verifiable evidence;
  - a host isolation contract;
  - qualified adapters;
  - forward-only migrations;
  - OS key custody.

  **The semver promise** covers wire and contract formats, `KERNEL_ABI_VERSION` and migrations. It does not cover the Rust API of `chio-kernel`, the hint channel or performance.

## 12. ID crosswalk

| Prefix | Program | Legacy IDs |
| --- | --- | --- |
| `SEC-` | Security launch (#1160) | M0 to M11 |
| `HOST-` | Native host (#1177) | M1 to M3 |
| `WORK-` | Verifiable work (#1173) | W1.0 to W4.x |
| `PAPER-` | Verifiable-work paper | P.1 to P.5 |
| `REC-` | Recovery (#1172, #1179) | P0 to P6 |
| `KSPEC-` | Kernel specs (#1174) | specs 1 to 11 (often written S1 to S11) |
| `KDEF-` | Kernel defects (#1174) | D1 to D12, N1 to N30, GT1 |
| `STRAT-` | Strategy (#1170) | F-1 to F-17, D30/D60/D90 items, Q2 items |
| `ECON-` | Economy stack (#956 to #959) | M0 to M6 |
| `MKT-` | Cognition market (historical) | M0 to M11 |
| `UR-` | This roadmap | G0 to G5, lane rungs, CT- contracts, U- actions, D- decisions |
| `FV-` | Formal verification | already prefixed |

**Collisions this removes.** Each pair below has historically shared one letter:

- #1173's D1 (dynamic delegation) and KDEF-D1 (missing receipt);
- #1173's S1 (swarm evolution) and KSPEC-01 (closed ABI);
- REC-P5 and PAPER-5;
- SEC-M1 and HOST-M1.

Dates are calendar dates only; a bare "Q2" is never used.

## 13. Re-grounding after #1160 merges

- **Re-verify every KDEF row against post-merge main.** `chio-kernel/src` changed in 162 files since #1174's pin. KDEF-D1's site changed shape, and KDEF-D6 moved.
- **#1177:** its PROGRAM-MAP foundation pin becomes main. "In F" becomes "main (experimental; broker Linux-only)". `chio-ipc` mailboxes become `crates/kernel/chio-process/src/mailboxes`.
- **#1174:** its pin becomes main, and the acceptance statistics are recomputed from the ledger.
- **The M1 plan** is re-cut per COOP-1:
  - extend `signing_custody` instead of rewriting loaders;
  - handle the fallible `unix_timestamp_now()`;
  - remove "needs nothing from #1160".
- **This document:** refresh section 2 and every pin.

## 14. What this document does not do

- It starts no execution.
- It approves no ADR beyond those recorded in section 8.
- It makes no release, qualification or market claim.
- It projects no internal dates.
