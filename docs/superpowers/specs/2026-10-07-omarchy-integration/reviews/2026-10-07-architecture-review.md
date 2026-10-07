# Architecture review: Chio desktop integration (Omarchy and macOS)

Status: review input, revision 2, 2026-10-07. Not normative. Requested by the
program owner; written by Claude (Opus 5.5). Revision 2 supersedes revision 1.
The corrections are listed in [section 4](#4-corrections-to-revision-1).

The same document is committed to both PR #1177 (Omarchy) and PR #1178 (macOS),
because the main findings apply to both.

Inputs read for revision 2:

- the two desktop PRs;
- the security and process foundation (#1160);
- the workbench (#1164);
- the NVIDIA strategy set (#1170);
- recovery (#1172, #1179);
- verifiable work and the agentic kernel roadmap (#1173);
- the kernel north star and its eleven specs (#1174);
- the public host plugins and `chio-bridge`;
- priority-integrations doc 19 (`docs/strategy/chio-direction/19-priority-agent-integrations.md` on #1160);
- Omarchy upstream at `0f8af9be` and v4.0.4.

Sequencing assumption (owner instruction): a spec may treat its predecessors as
shipped when the order is right. This review therefore asks two things. Is the
order right? Does each spec build on what its predecessors will provide, rather
than redefining it?

> **Agents iterating on this branch:** these findings need owner decisions
> ([section 7](#7-decisions-needed-from-the-owner)). Do not address them
> piecemeal by adding requirements, fixtures or validator checks.

## Governing status while decisions are pending

The numbered specifications and plans in this PR remain the normative
*proposal* for consistency review. This document is non-normative input. It
does not supersede them, and it does not authorize the alternatives it
recommends.

Until the owner records the section 7 decisions in an accepted ADR, and updates
or supersedes the affected specifications in the same change:

- Product direction, the shared ABI and implementation sequencing have
  `planning_status: blocked_by_adr`.
- Only research and correctness repairs to the proposal proceed.
- Neither implementation program is approved to start.
- Every existing safety prerequisite in the proposal remains mandatory. This
  review removes no gate and qualifies no profile.

## 1. Bottom line

1. **Keep the authority invariants.** Both PRs get these right, and they hold
   under every stack scenario in this review.
2. **The desktop should be an operator surface over the stack, not a new
   runtime.** The two PRs between them redefine about a dozen concepts that
   other programs already own: task model, recovery, events, stop, operator
   identity, IPC peer authentication, process trees, credential custody, the
   sealed coding runner, the review UI, host qualification gates and
   confinement evidence. Replace both programs with one shared program that
   references those owners (section 3).
3. **A sealed task is the right first execution product. This corrects
   revision 1.** It must be:
   - host-generic, following doc 19's six-host program;
   - expressed as a #1173 single-owner work commitment;
   - built by reusing `chio-mini-swe`, the Pi restricted session and the
     workbench rather than a desktop-private runner.
4. **Interactive agents get honest observation first.**
   - Hook-mode plugins fail open, so their sessions are `detect_only`.
   - `prevent` exists only in doc 19's protected mode, which removes the
     native shell.
   - Native-shell interactive work is possible only as an OS-boundary profile
     whose inside is `cannot_see`.
5. **The biggest open question is a layer decision, and both PRs answer it
   silently.**
   - #1170 proposes ADR-0023, "host runtime enforcement is out of layer". It
     makes OpenShell the Linux reference sandbox and freezes the cage, the
     secret broker and the host launchers.
   - #1160, #1174 and both desktop PRs assume Chio owns confinement.
   - Resolve it with "isolation denies, Chio grants": isolation backends are
     pluggable adapters that produce #1174 spec-7 confinement evidence (R1).
6. **The prerequisites are the wrong set.** The desktop needs the bug-fix and
   operator lanes of #1174, plus recovery and work W1. It does not need the
   NK-01 to NK-03 keystones (section 6).
7. **Disposition is unchanged.** Convert both PRs to draft. Consolidate them
   into one ADR plus two platform annexes that reference the owning specs.

## 2. The stack the desktop sits on (treated as shipped)

| Program | Owns | State | What the desktop takes from it |
| --- | --- | --- | --- |
| #1160 security and process foundation | `chio-process` (durable process trees), `chio-cage` (Linux x86_64 confinement for tool servers), `chio-secure-ipc` (`SO_PEERCRED`, Linux only), `chio-secret-broker`, `chio-keyring`, `chio-security-kernel`, required-agent protected mode, `chio-mini-swe`, receipt dashboard | Open, blocked on qualification; M0 to M4 locally accepted, M5 to M11 open | Process trees, IPC peer authentication, credential custody, sealed runner, protected-mode contract |
| Doc 19 (on #1160) | The six mandatory hosts (Claude Code, Codex, Cursor, Hermes, Pi, OpenClaw), I01 to I08 gates, "six of six" | 0 of 6 accepted; Pi furthest | Host qualification model; rejects advisory hooks as a boundary |
| #1164 workbench | Local browser operator surface: investigator, editor and reviewer roles; a worktree per task; patch review with SHA-256 | Draft, "not built or tested since it was written" | The task, worktree and review UX; the first operator client |
| #1172 / #1179 recovery | Original-operation recovery; `InspectWorkflow`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`; `recovery_events` table | #1179 "not qualified"; 3 P1, 45 P2, 94 P3 open | Lost-reply lookup, approval and resume flows, recovery states |
| #1173 verifiable work (W1 to W4) | `WorkHandleV1`, `WorkViewV1` (six independent observations), work commands and queries, `WorkTransport` over local authenticated IPC | W1 to W4 planned, 0 of 198 steps done | The task model and its status projection |
| #1174 north star and specs | S1 closed ABI (C-layer placement); S3 receipts for non-durable calls; S4 per-task closure; S5 events (Part A transport fixes, Part B stable subscriptions); S7 confinement evidence; S8 durable stop and S28 operator roster; S9 M20 retry classes; S10 crossing performance; S11 integrity gating | Docs; adversarial review partial | Stop, events, identity, retry safety, confinement evidence, controller placement |
| #1170 NVIDIA strategy set | Positioning ("Authority that only narrows. Evidence that travels."), ADR-0023 to 0037 candidates, founder decisions F-1 to F-17 (all open), OpenShell spike | Docs; all decisions open | Layer decision, positioning, claim cautions |

The ordering among the branches is consistent:

- #1173 builds on `packet/3-retention-accounting`, which is wholly contained
  in #1160.
- #1172 and #1179 build on an earlier #1160 head.
- #1174 treats #1160, #1173 and #1172 as its baseline. It also treats an
  uncommitted recovery worktree as baseline, which is the one input nobody else
  can see.

The desktop PRs sit on top of all of this. That position is legitimate. The
problem is that they neither cite it nor reuse it.

## 3. Reference, don't redefine

| Desktop concept | Owner in the stack | #1177 | #1178 | Action |
| --- | --- | --- | --- | --- |
| Task model and status | #1173 `WorkHandleV1` and `WorkViewV1` (execution, acceptance, result, recovery, settlement and delivery kept separate); #1179 recovery states | Own task states | Own `WorkPhase` enum, which collapses the separate observations | Render from `WorkViewV1` plus recovery states |
| Lost-reply recovery | #1173 W1.6 command and preparation queries; #1179 recovery commands; S5 section 4.6; S9 M20 `Reusable`/`Retained`/`Terminal` | Re-specified | Re-specified | Reference the owners |
| Event subscription | S5 Part B, deferred "until a second surface consumes hints on the wire"; #1179 `recovery_events` | `events.subscribe` | `events.subscribe` and `events.ack` | The desktop is that second surface: make it the trigger for S5 Part B and specify the stream once, in the kernel. Do not poll; see #1179's P1 on `InspectWorkflow` polling draining the settlement reserve |
| Stop | S8 phase 1 (scopes `Kernel`, `Tenant`, `Recovery`), S8 S30 routes and results; S4 closure for one task | `task.cancel`, `task.resume` | `task.stop` mapped to `EmergencyControl` | Per-task stop is S4 closure; reference S8 S30 result kinds |
| Operator identity and attributable approval | S8 S28 roster (until then every record is `SharedCredential`); approval mechanisms unified under north-star bet 5 | Native decision blocker noted | Assumes native endorsement | Hard prerequisite for an approval UI. Today approvals are signed with the sidecar key and `PasskeyCapabilityVerifier` is test-only |
| Local IPC peer authentication | `chio-secure-ipc` (Linux `SO_PEERCRED`; refuses on other platforms) | AF_UNIX re-specified | XPC, new | Reuse on Linux; add a Darwin peer-credential path to the same crate |
| Process trees and child custody | `chio-process`, `ProcessRegistry` | Uses (NQ-01, NQ-02) | Cites north-star bets 4 and 7 as research | Use `chio-process` on both platforms |
| Credential custody and model egress | `chio-secret-broker`; Pi model relay | Pi-specific relay | Pi-specific relay | Broker plus relay; no new proxy |
| Sealed coding runner | `chio-mini-swe` (network-less Docker workspace, mediated `sandbox/execute`, verified patch export); Pi coding resource | Re-specified | Re-specified, with an external oracle | Reuse and extend; add the oracle there |
| Task, worktree and review UI | #1164 workbench | Not referenced | Not referenced | Make the workbench the first operator client; QML and SwiftUI become further clients. #1160 itself says "choose one common runtime path" |
| Host qualification | Doc 19 I01 to I08, six hosts | Pi only | Pi only; others "no qualified host" | Adopt doc 19; Pi first by evidence, contract host-generic |
| Confinement evidence | S7: closed set `LinuxCage`, `FirecrackerGuest`, `ProcessContainer`; anything else renders "not confined by Chio" | Own evidence classes | Own VM, ES and NE evidence | Amend S7 with the new backend kinds (section 5, R1) |
| Boundary wording | ADR-0011 `boundary_class` and `planning_status` | Not used | Not used | Use it in every profile and in onboarding copy |
| Controller placement | S1: a C-layer component outside the TCB (no keys, no trusted fact assertions); the gateway and process host stay inside the TCB | Implicit | Implicit | State it. The UI never shares a process with the gateway or process host |

## 4. Corrections to revision 1

1. **`chio run` is not the vehicle.** Revision 1 was wrong.
   - `cmd_run` speaks Chio's framed native protocol.
   - It intercepts nothing and confines nothing.
   - It registers no tool server, and no plugin uses it.
   - It cannot host Claude Code or Codex.
2. **Hook-mode plugins do not "mediate".** This is `detect_only` or
   `advisory_only` under ADR-0011.
   - The plugins' own acceptance records show the tool runs when a hook
     crashes, times out, is missing or is skipped (Claude Code 2.1.266, Codex
     real-host table).
   - The Bash check sees the command string only.
   - The PRs' "observation only" label for Claude Code and Codex is correct.
   - The arc README's "mediates Bash/Write/Edit/Read and every MCP server" is
     an ADR-0011 violation and should be fixed (R6).
3. **Pi-first follows the evidence.**
   - Pi is the only host with I01 to I07 executed (plugin 0.1.0 with Pi 0.85.1).
   - It has an embeddable SDK, restricted sessions and a model relay.
   - Revision 1's "wrong first product" narrows to two points: Pi *only*, and
     a desktop-private task model.
4. **"Stacked on unmerged kernel programs" is withdrawn as a defect,** per the
   owner. Two concerns stand in its place:
   - the two PRs assume inconsistent bases: #1177 builds on the #1160 process
     host, while #1178 builds on #1174 NK-01 to NK-09;
   - the prerequisite set is wrong (section 6).
5. **The minimal kernel list is corrected.**
   - The durable stop is S8 *phase 1*, not phase 0.
   - Stable subscriptions are S5 *Part B*. Part A fixes hosted transport.
   - Per-task stop needs S4 closure.
   - Operator identity is S8 S28.
   - Add S3 phase 1 (receipts for non-durable calls) and S9 M20 (retry classes).
6. **The "governed session" rung is re-scoped.**
   - With native Bash kept inside an OS sandbox, the boundary is `prevent` at
     the edge and `cannot_see` inside.
   - Only gateway-routed requests and adapter-routed MCP calls can be
     `prevent`, and only where Chio authorizes them before dispatch.
   - Writes the sandbox permits inside the workspace never reach a Chio
     decision point. They are `cannot_see`, with no per-write receipts.
   - Denying direct routes and confining descendant processes each need their
     own evidence. Having a gateway does not establish either.
   - Doc 19's protected mode gets `prevent` by removing the shell.
   - These are two distinct profiles (section 5, R3), not one rung.
7. **The Pi `approval-decide` defect is not "only an issue".** Revision 1 said
   it was "not a P3 prerequisite". It is both:
   - File it as an issue now. The Pi wrapper already refuses the action before
     native invocation, but the bundled bridge binary is unrepaired.
   - The P3 gate stays. Publication remains blocked until the installed
     utility checks both the requested decision and the approval ID before
     retaining a credential, with deny and mismatch regression evidence.
8. **ES/NE scope is clarified.** `native-descendant-v1` (#1178) keeps its ES/NE
   restrictions and its independently qualified network containment.
   - Whether to keep that profile next to the R3 ladder is an owner decision.
   - Nothing in this review removes those gates.

## 5. Findings

### R1. The layer decision is open, and both PRs presuppose one answer

#1170 recommends that Chio "does not isolate agents, hold their credentials,
issue identities or watch the model path". Its ADR-0023 would make OpenShell
the reference Linux sandbox and freeze `chio-cage`, `chio-secret-broker` and
the six-host launchers on that path. #1160 has built exactly those components.
#1177 and #1178 specify their own confinement (a bubblewrap/Landlock agent host
and a custom VZ VM). Neither desktop PR mentions OpenShell. Founder decision
F-2 is open.

The evidence cuts both ways:

- **OpenShell** confines unmodified Claude Code and Codex: Landlock, seccomp, a
  network namespace with a proxy-only exit, and credential placeholders. It
  runs on macOS through Docker Desktop or a MicroVM on Hypervisor.framework.
  Against that:
  - its middleware contract is a research preview;
  - its macOS MicroVM path is unqualified;
  - local shell and file effects are invisible to Chio on that path.
- **`chio-cage`** is a single-process, threadless, socketless profile for tool
  servers, x86_64 only. It cannot run Pi or any Node agent host.
- **The restricted launchers that actually confine agent hosts today** are thin
  OS adapters: `sandbox-exec` on macOS for the Pi, Claude Code and Cursor
  candidates, and bubblewrap on Linux for Pi. Pi's qualified run used the macOS
  `sandbox-exec` profile.

**Recommendation.** Decide F-2 with this split: **isolation denies, Chio
grants.**

1. **Chio does not author a general-purpose agent sandbox.** Accept ADR-0023's
   principle: do not grow `chio-cage` into an agent host.
2. **Chio owns the grant path**, the only routes by which a confined agent can
   reach anything:
   - the gateway and model relay;
   - `chio-secret-broker`;
   - kernel-owned resources (coding resource, file tools, `sandbox/execute`);
   - approvals, receipts, and work and recovery.
3. **Isolation backends are thin adapters that produce S7 evidence.** Amend S7
   with:
   - `AgentHostBwrap` (Linux; the Pi plugin profile);
   - `Seatbelt` (macOS; the restricted launchers);
   - `ProcessContainer` (already present; Docker or Podman, which covers
     `chio-mini-swe`);
   - an external-runtime kind for OpenShell, added once its middleware contract
     stabilizes;
   - a VM kind (`FirecrackerGuest` exists; add a macOS VM).
4. **Scope ADR-0023 accordingly.** Thin adapters over OS mechanisms are allowed
   where no qualified runtime exists. That is the case on macOS without Docker
   today. Without that scoping, ADR-0023 freezes the only working macOS
   backend.

### R2. One controller and one protocol, as a client of the stack

The desktop controller is an S1 C-layer component outside the TCB. Its protocol
is mostly a projection of:

- work views and commands (#1173);
- recovery commands (#1179);
- S5 Part B subscriptions;
- S8 and S4 stop;
- S28 identity.

Concretely:

- Specify it once, as `chio.operator.v1`, in `spec/` next to `PROTOCOL.md`,
  after S5 Part B.
- Retire `chio.omarchy.operator.v1` and `chio.desktop.operator.v1`.
- Make the #1164 workbench (browser) the first client.
- Add the Omarchy QML plugin and the macOS menu bar app as thin shells over the
  same controller.
- Transports: `chio-secure-ipc` on Linux; an XPC or `getpeereid` path added to
  the same crate on macOS.

### R3. Product ladder (revised)

| Rung | What the user gets | ADR-0011 class | Hosts | Depends on |
| --- | --- | --- | --- | --- |
| Observe | Live sessions (hook-mode, protected and sealed), receipts, budgets, recovery inbox, each with its true boundary class | Per session; hook sessions are `detect_only` | All six | S5 Part B, controller |
| Approve and stop | Attributable exact approvals; durable per-task stop | `prevent` (pre-effect gate) | Protected and sealed sessions | S28 roster, S4 phases 1 and 2, S8 phase 1, the `approval-decide` fix, a non-test passkey path |
| Sealed work | Single-owner unpaid work commitment: fixed recipe, kernel-owned tools, review artifact, acceptance contract | `prevent` at kernel-owned tools, plus S7 evidence | Pi first; then doc 19 hosts as they pass | #1173 W1, #1179 P1 fixes, a backend (R1) |
| Protected interactive | Doc 19 protected mode: gateway file tools, no native shell | `prevent` for mediated tools | Six hosts, as each passes I01 to I08 | Doc 19 gates |
| Boundary interactive | Native agent with its shell, inside an OS sandbox with gateway-only egress | `prevent` at the edge, `cannot_see` inside | Any | R1 backend decision, S7 kind |
| Managed endpoint | ES and NE fleet restrictions | Restrictive and `detect_only` | Not applicable | Entitlements, MDM |

The sealed-work rung is where Chio's verifiable-work thesis becomes visible on a
desktop: a fixed request, an attributable history and acceptance under agreed
rules. That makes it a better second rung than an interactive one. Interactive
sessions produce receipts but no acceptance.

### R4. Omarchy (#1177)

**Keep:**

- the QML plugin as presentation only;
- the controller as a systemd user unit;
- pacman packaging;
- the upstream research.

**Upstream facts to design around** (verified at `0f8af9be`):

- `omarchy-agent` (`SUPER+SHIFT+CTRL+A`) and the `cx`/`cy` aliases run most
  agents in auto-approve modes, for example `claude --permission-mode auto`,
  `codex --approve-for-me`, `opencode --auto` and `cursor-agent --yolo --trust`.
- The plugin API shipped in v4.0.0 on 2026-08-14, makes no stability promise,
  and was narrowed on 2026-09-01.
- Docker is installed by default.
- The kernel is `linux-omarchy-bore` 7.2 with Landlock enabled.

**Change:**

- **Confinement.** `chio-cage` cannot run Pi. The agent-host profile is the Pi
  plugin's bubblewrap profile, which needs its own S7 kind. Docker also makes
  `chio-mini-swe` available on day one.
- **Observation.** Unconstrained auto-mode sessions are the local risk, so the
  observe rung (with hook-mode sessions shown as `detect_only`) has immediate
  value here.
- **Launch.** Add a menu or Walker entry, "launch default agent in protected
  mode", for doc 19 hosts as they qualify. Do not edit upstream files.
- **Scope.** Cut P4 (compositor tools) and P5 (configuration repair). Move P6
  (delegation) to the kernel and process programs.

### R5. macOS (#1178)

- **VM.**
  - The bespoke VZ VM, guest image and guest supervisor are the most expensive
    new build in either program.
  - The cage is x86_64 only, while Apple Silicon guests are ARM64.
  - Before building, evaluate existing runtimes: OpenShell's MicroVM driver
    (Hypervisor.framework) and Apple's Containerization framework (one
    lightweight VM per Linux container).
  - Either way, add an S7 VM kind.
- **Seatbelt.**
  - Dismissing `sandbox-exec` in `research/apple-platform.md` contradicts the
    repo's own evidence. Pi's qualified run and the Claude Code and Cursor
    restricted candidates all use it.
  - Keep it as the lower-assurance macOS backend with an S7 kind and an
    ADR-0011 label. Keep the VM for high assurance.
  - Reconcile with ADR-0023's scope (R1).
- **Peer authentication.** `chio-secure-ipc` refuses non-Linux platforms, so
  Darwin support is new work in that crate, not a separate stack.
- **Approvals.** Touch ID and passkey approvals need a production
  `PasskeyCapabilityVerifier` and the S28 roster. Approver-bound approval is
  also the clearest differentiator against OpenShell, whose approvals do not
  record the approver.
- **Durable coverage.** Drop MAC-KER-010 ("MUST require durable coverage" for
  every invocation).
  - Use S10 check-only reads in `SideEffecting` mode.
  - Mediate per tool call or per egress policy, not per HTTP request.
  - The historical mediated-call costs (roughly 130 to 357 ms) make
    durable-everything a poor interactive experience. The S10 target is about
    90 to 95 ms for a read.
- **Kernel mappings.** `task.stop` maps to S4 closure, not `EmergencyControl`.
  NK-09 should cite `chio-process`, not research bets.
- **ES and NE.** Keep the managed-endpoint track separate.
  `native-descendant-v1` keeps its ES/NE restrictions and its network
  containment gates for as long as that profile exists. Whether to keep it is
  an owner decision (section 4, item 8).
- **Entry points.** Lead with the CLI and the menu bar; Finder Services is
  secondary.

### R6. Claims hygiene

ADR-0011 governs every planning artifact that touches a trust boundary. The
#1170 claim review lists 22 places where the docs disagree with the code. The
ones that affect desktop copy:

- README: the Claude Code plugin "mediates Bash/Write/Edit/Read and every MCP
  server". It is hook-level and fails open.
- README and AGENTS.md: tool servers are "sandboxed processes". They are plain
  child processes.
- The hero line, "a Rust kernel for agentic operating systems", is repeated in
  both desktop PRs. #1170 proposes "Authority that only narrows. Evidence that
  travels." Decide the positioning before writing onboarding copy.
- Approvals are signed with the sidecar key, not the approver's.
- `emergency_stop` is process-local and its HTTP routes are not mounted (#1174
  D2, N22, N23).

### R7. Program hygiene

Several large, agent-authored programs are running at once: #1160 (+1.37M),
#1173 (+2.4M), #1179 (+0.94M), #1174, #1170, #1177 and #1178. The two desktop
PRs contain zero references to:

- #1164;
- `chio-mini-swe`;
- `chio-secure-ipc`;
- `WorkViewV1`;
- the recovery commands;
- doc 19;
- the #1174 specs by name;
- OpenShell.

That is how one product ends up specified twice, with a third partial
implementation (the workbench) alongside.

**Recommendation.**

- Add a program map (an ADR or `docs/architecture/PROGRAM-MAP.md`). It names
  the owner of each shared concept: task or work, recovery, events, stop,
  identity, confinement evidence, IPC, credentials and host qualification.
- Adopt a "reference before redefine" rule. A spec that redefines an owned
  concept fails review.
- On volume, revision 1's numbers still apply: 532 requirements and about
  34,000 JSON lines across the two PRs, with requirement catalogs and fixture
  corpora ahead of any implementation. Bind those to tests once code exists.

### R8. Defects to file now (independent of desktop work)

1. **Pi `approval-decide`.** A deny can retain a signed approved credential
   (#1177 `research/chio-readiness.md`).
   - The wrapper refuses the action before native invocation, but the
     bundled bridge binary is unrepaired.
   - Track the fix separately. The P3 publication gate stays in place until
     the installed utility passes the deny and mismatch regressions
     (section 4, item 7).
2. **Emergency stop.** It is process-local, its HTTP routes are unmounted, and
   the admin token comparison is not constant-time (#1174 D2, N22, N23).
3. **#1179 P1.** Read-only `InspectWorkflow` polling can drain the shared
   settlement reserve.
4. **Process host control.** Revoke and cancel work only while the host is
   stopped, and `status` is a one-off snapshot (#1160 `PROCESS_HOST.md`).
5. **README overclaims.** The ADR-0011 violations listed in R6.
6. **Approval signatures.** Approvals are signed with the sidecar key, and
   `PasskeyCapabilityVerifier` is test-only.

## 6. Revised sequencing

1. **#1160 lands.** This delivers the security and process foundation.
2. **#1174 bug-fix lane items the desktop needs.** Some can land against main
   now:
   - S8 phase 1 (durable stop);
   - S5 Part A (transport fixes);
   - S3 phase 1 (receipts for non-durable calls);
   - S9 M20 (retry classes).
3. **Operator-contract delta.**
   - S4 phases 1 and 2 (per-task closure);
   - S5 Part B (the desktop is the trigger);
   - S8 S28 (operator roster);
   - live cancel and revoke on the process host;
   - the `approval-decide` fix;
   - a production passkey verifier.
4. **#1179 recovery P1 fixes, and #1173 W1** (`WorkClient`, local
   authenticated IPC).
5. **ADRs.**
   - F-2 and ADR-0023 scope (R1);
   - positioning;
   - one desktop-integration ADR with the R3 ladder;
   - the S7 amendment.
6. **Observe and approve rungs.** Shared controller; workbench client first,
   then the Omarchy QML shell and the macOS menu bar shell.
7. **Sealed work rung.**
   - Pi restricted under the bubblewrap (Linux) and Seatbelt (macOS) S7 kinds;
   - `chio-mini-swe` on Docker;
   - a VM backend through an existing runtime.
8. **Protected and boundary interactive rungs**, gated on doc 19 and R1.

**Not prerequisites for desktop work:**

- the NK-01 to NK-03 keystones (S9 pure admission, S10 crossing, S1 census);
- S11 integrity gating (needed only for an injection-safety claim; leave it off
  for Claude Code and Codex sessions);
- #1173 W2 to W4;
- #1160 M11;
- the keyring witness topology.

## 7. Decisions needed from the owner

1. **Layer (F-2, ADR-0023).** Adopt "isolation denies, Chio grants", with thin
   backend adapters allowed where no qualified runtime exists and every
   backend producing S7 evidence?
2. **Positioning.** Keep the hero line, or adopt #1170's sentence for all
   desktop copy?
3. **One program.** One desktop-integration program, one controller and one
   `chio.operator.v1`, with the workbench as the first client?
4. **First execution rung.** Sealed single-owner work, host-generic, Pi first?
5. **macOS VM.** Build the bespoke VZ supervisor, or adopt an existing runtime
   (OpenShell MicroVM or Apple Containerization) behind an S7 VM kind?
6. **Disposition of #1177 and #1178.** Convert both to draft. Replace them with
   the ADR from decision 3 plus Omarchy and macOS annexes that reference
   section 3's owners. Keep the research files.

## Appendix: what revision 1 got right and still stands

| Invariant | Where it is stated |
| --- | --- |
| UI, plugin and controller never issue capabilities, sign approvals or receipts, or keep a competing ledger | MAC-ARC-002, MAC-PRD-008, OM-ARC-001 |
| Missing prerequisites make a feature unavailable; there is never an unconfined fallback | OM-PRD-002, MAC-PRD-004 |
| A lost reply is an unknown outcome, recovered through the original operation | OM-PRD-006, MAC-PRD-011, MAC-KER-008 |
| ES, NE and caches only restrict | MAC-KER-011, MAC-ARC-008 |
| OS consent, Chio grant and exact endorsement are separate facts | MAC-PRD-007 |
| The desktop user and installed plugin are trusted; the agent is confined; say so plainly | OM-PRD-008, Omarchy upstream research |
| One protocol, not two | Revision 1 F2, now R2 |
| Cut Omarchy P4 and P5 | Revision 1 F5, now R4 |

These research files remain strong and should be kept:

- Omarchy `research/omarchy-upstream.md`;
- macOS `research/apple-platform.md`;
- macOS `research/distribution.md`;
- macOS `research/clawdstrike.md`.
