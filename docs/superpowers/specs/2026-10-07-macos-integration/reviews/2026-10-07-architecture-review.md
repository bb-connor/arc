# Architecture review: Chio desktop integration (Omarchy and macOS)

Status: review input, 2026-10-07. Not normative. Requested by the program owner;
written by Claude (Opus 5.5). The same document is committed to both PRs because
its main finding spans both:
PR #1177 Omarchy (reviewed at `f2470f0fa`) and PR #1178 macOS (reviewed at
`715a4475f`). Main baseline: `6573b8980`.

Scope: the ideas and the program shape. Line-level contract defects are already
covered by the Greptile and Codex threads and are not repeated here.

> **Agents iterating on this branch:** the findings below need an owner decision
> (see [Decisions needed](#decisions-needed-from-the-owner)). Do not address them
> piecemeal by adding requirements, fixtures or validator checks.

## Verdict

The authority model is right. The product shape, program structure and
sequencing are not.

- **Keep.** These invariants are correct and worth carrying forward verbatim:
  - The controller is never an authority.
  - Missing prerequisites fail closed, with no fallback to an ordinary agent.
  - Recovery always targets the original operation.
  - OS sensors and caches only restrict.
  - The guest is untrusted and the desktop session is trusted.
- **Re-center.** Both programs make the first product a sealed, Pi-only,
  fixed-recipe task runner. They ignore the integrations Chio already ships for
  Claude Code, Codex, Cursor and OpenCode. On the desktop, Chio should first be
  the operator surface for those bonded sessions, then the confinement layer
  underneath them.
- **Merge.** The two PRs specify one product twice. They use two near-identical
  operator protocols and two different kernel dependency bases.
- **Re-sequence.** Both are written against kernel contracts that are not on
  main. macOS depends on PR #1174, which is design documents only. Omarchy
  depends on PR #1160 (+1,359,763 lines, open).
- **Shrink.** The two PRs add about 47k lines, 532 requirements and 268 fixtures,
  with zero implementation. Five review-fix rounds hardened validators and
  example snippets. The expensive decisions went unreviewed.

Recommendation: do not merge either PR as-is. Convert both to draft and make the
decisions listed at the end. Then replace the two programs with one shared ADR
plus thin platform annexes. Keep the research files; they are good.

## What is right and should survive

| Invariant | Where it is stated |
| --- | --- |
| UI, plugin and controller never issue capabilities, sign approvals or receipts, or keep a competing ledger | MAC-ARC-002, MAC-PRD-008, OM-ARC-001 |
| Missing prerequisites make a feature unavailable; never fall back to an unconfined agent | OM-PRD-002, MAC-PRD-004 |
| A lost reply is an unknown outcome, recovered through the original native operation, never a fresh one | OM-PRD-006, MAC-PRD-011, MAC-KER-008 |
| OS sensors and caches (ES, NE, extension allow views) can only restrict and never mint authority | MAC-KER-011, MAC-ARC-008 |
| OS consent, Chio grant and exact endorsement are three separate facts | MAC-PRD-007 |
| Trust the desktop user and installed plugin, confine the agent, and say so plainly | Omarchy `research/omarchy-upstream.md`, OM-PRD-008 |
| Do not shadow `pi` or rewrite user menus; keep notification bodies generic | Omarchy `research/omarchy-upstream.md` |
| A zero-NIC VM with a narrow vsock broker is a sound high-assurance profile | macOS `07-vm-execution.md` |
| Source, component, installed and qualified evidence are separate classes | Both |

Several research files are strong and should be kept whatever happens to the
rest: Omarchy `research/omarchy-upstream.md`, and macOS
`research/apple-platform.md`, `research/distribution.md` and
`research/clawdstrike.md`.

## Findings

### F1. The first product ignores the agents Chio already integrates with (both; highest impact)

Chio main already has three relevant integrations:

- `chio run --policy <p> -- <agent command>`, described as "Spawn an agent
  subprocess and enforce policy via the kernel"
  (`crates/products/chio-cli/src/cli/types.rs:342`).
- `chio mcp wrap`, which gates stdio MCP servers and emits client configs for
  Cursor, Claude Desktop, Continue and Zed.
- Public host plugins built on `@chio/bridge`, listed in the README's companion
  plugins table:
  - `chio-claude-code-plugin` ("mediates Bash/Write/Edit/Read and every MCP
    server, metered and receipt-signed").
  - `chio-cursor-plugin`.
  - `chio-codex-plugin`.
  - `chio-open-code-plugin`.
  - `chio-open-claw-plugin`, which supports passkey countersigning.

Neither PR mentions any of these. Both have zero references to the plugins,
`@chio/bridge` or `chio run`. Instead, each picks a narrow first workflow:

- **Omarchy.** P2 is "One confined Pi project task". The pilot is "a small pinned
  Node fixture with a single-process fixed recipe (2 seconds plus 100 ms
  termination grace, 16 KiB output)" (`01-product-scope.md`).
- **macOS.** The first candidate host is "Pi's restricted SDK/print entry mode".
  The row for "General CLI, IDE agent, Claude Code, Codex CLI ..." reads "No
  qualified Mac host entry ... Protected execution unavailable"
  (`15-host-adapters.md`). The first task requires all of the following:
  - a committed tree only, with dirty state excluded;
  - a portable Linux toolchain;
  - preprovisioned dependencies;
  - no live package downloads.

This product asks developers to give up their current agent and workflow. Today
that means interactive Claude Code, Codex, Cursor or OpenCode in their own
working tree. What they get instead is a batch runner, a space hosted background
agents already occupy. Meanwhile, the bonded Chio sessions these same users can
run today get no desktop surface at all.

The macOS decision record rejects "native process wrapper plus MCP hooks" as
observation-only, because "direct networking, subprocesses, plugins and
inherited credentials may bypass hooks" (`research/decision-record.md`). That is
true of an unsandboxed wrapper. It is not true of a sandboxed launcher whose only
egress routes are Chio-mediated. The Omarchy program already specifies that
mechanism for Pi (bubblewrap, Landlock, seccomp and a private relay socket, in
`08-linux-confinement.md`), and it applies equally to any agent's process tree.

**Recommendation.** Make bonded sessions the center of the first two profiles,
and move the sealed runner to the third:

1. **Operator surface (read and approve), any host.** Show:
   - live bonded sessions from every plugin;
   - pending exact approvals;
   - receipts, budgets and spend;
   - a kill switch;
   - each session's ADR-0011 `boundary_class`, stated honestly. A hook-bonded
     session is `prevent` for mediated tools and `cannot_see` for raw subprocess
     effects.

   This is where users need Chio on the desktop first, and it needs no new
   confinement.
2. **Governed session (confinement upgrade).** Give `chio run <agent>` a
   platform sandbox backend:
   - Filesystem writes are confined to the workspace and the agent's state
     directories.
   - The only network route is a Chio egress gateway that serves the model
     provider and allowlisted hosts. Every request is capability-checked,
     budgeted and receipted, and the gateway injects credentials where the
     provider allows it.
   - MCP servers are reachable only through `chio-mcp-adapter`.

   This moves file and network effects from `cannot_see` to `prevent` for an
   unmodified agent.
3. **Sealed task (what these PRs specify today).** Pi's closed registry, a
   zero-NIC VM or strict cage, and an external test oracle form the
   high-assurance profile. It suits untrusted repositories and unattended runs.
   It is valuable, but it is the third rung, not the first.

The ADR should state the trade-off explicitly:

| | Boundary-level (governed session) | Tool-level (sealed task) |
| --- | --- | --- |
| Agents | Any, unmodified | Hosts with a closed registry (Pi today) |
| Workflow | Interactive, working tree | Batch, committed tree, fixed recipe |
| Receipts | Every mediated effect: egress, MCP, plugin-mediated tools | Every tool call |
| Blind spot | Computation inside the sandbox; writes inside the workspace | Narrow scope; Darwin toolchains on Mac |
| Time to useful | Short; mostly existing parts | Long; gated on #1160 and #1174 |

### F2. One product, specified twice, with two protocols

| | #1177 Omarchy | #1178 macOS |
| --- | --- | --- |
| Protocol ID | `chio.omarchy.operator.v1` | `chio.desktop.operator.v1` |
| Methods | 13, including `task.cancel`, `task.resume`, `receipts.export`, `scope.get` | 12, including `task.stop`, `events.ack`, `evidence.export` |
| Transport | AF_UNIX | XPC |
| Kernel base | NQ-CANDIDATE (process host from #1160) | CHIO-NORTHSTAR NK-01 to NK-09 (#1174) |
| First worker | Pi in bubblewrap/Landlock; project copy may include disclosed dirty changes | Pi in a zero-NIC Linux VM; committed tree only; external oracle |
| Recovery, delegation, qualification | Own specs 14, 13, 15 | Own specs 11, 16, 17 |

The macOS spec then requires preserving "the existing Omarchy ABI through
explicit versioned mapping and conformance vectors" (MAC-ARC-014, MAC-IPC-014,
decision D08). That ABI has never shipped. The program is specifying a
migration layer between two unshipped proposals.

**Recommendation.** Share everything that is not platform-specific:

- **Shared:** one controller crate, one protocol, one task model, one resource
  import and publication model, and one recovery, delegation and qualification
  framework.
- **Per platform:** only the shell UI, IPC transport with peer authentication
  (`SO_PEERCRED` versus the XPC audit token), the isolation backend and
  packaging.

Specify the operator protocol once, next to `spec/PROTOCOL.md`, and only when
the controller crate starts. CLAUDE.md requires wire-level changes to agree
with that spec. Delete the migration requirements.

### F3. Both programs are stacked on unmerged kernel programs, and on different ones

- **Omarchy** depends on `chio-process`, `chio-cage` and session-credential
  transport. These exist only on PR #1160 (`integration/process-security-m4`).
  The research pins "CORE-PUBLIC" to `5b8bec41d`, which is 41 commits behind
  main, and identifies NQ-CANDIDATE only by file hashes.
- **macOS** depends on NK-01 to NK-09: pure admission machine, crossing
  primitive, closed kernel ABI, durable stop epoch, integrity-gated admission,
  teardown, typed reservations and unified event queue. These are design
  documents in PR #1174 (`docs/ftl-lessons-specs-20261004`), which
  `research/chio-readiness.md` cites as a "separate local source checkout"
  `8dffff3d`.
- **Some inputs cannot be reviewed at all.** One example: "Approved `research.md`
  retained beside this report by the package owner".

Writing about 47k lines of desktop contract against an unaccepted kernel
redesign freezes assumptions that will move. #1174 will be revised. When it is,
the 323 macOS requirements and their 712 task bindings go stale together, and
the validators make that drift expensive to correct.

**Recommendation.** Decide the kernel programs first: review #1174 and merge or
revise it, and land or split #1160. Then define the *minimal* desktop-facing
kernel contract against main. The readiness research shows the list is short:

| Desktop need | Main today |
| --- | --- |
| Look up the original operation after a lost reply | Present: `AdmissionOperationStore::{load_by_operation_id, load_by_replay_key, list_recoverable}` |
| Exact approval bound to request, subject and expiry | Present: `approval.rs`, `ApprovalToken::verify_against`. The Pi utility has a decision-binding defect (F6) |
| Stop that survives restart | Missing: `emergency_stopped` is an in-memory `AtomicBool` (`kernel/construction.rs:326`) |
| Stable event subscription for the UI | Missing |
| Authenticated local operator principal | Missing |

Three missing items make a tractable kernel ticket set. NK-01 to NK-09 amounts
to a kernel rewrite and should not gate a desktop surface.

### F4. macOS: VM-only execution is a Linux product on a Mac (#1178)

Decision D04 makes a zero-NIC Linux VM the only local execution profile.
`research/apple-platform.md` dismisses Seatbelt in one line: "custom sandbox-exec
profiles are not the supported product foundation". The native path waits on
macOS 27 descendant-scoped Endpoint Security, which is entitlement-gated and,
by the spec's own account, has inconsistent beta metadata.

That choice has two consequences:

- **Darwin toolchains are excluded.** Xcode, Swift, iOS and Homebrew-native
  toolchains fall outside the first Mac product. D06 backfills them with
  "trusted native build brokers", which the spec itself notes are arbitrary-code
  runners.
- **The first Mac experience solves an uncommon problem.** That experience is
  "run a portable Linux project in a VM", and most Mac developers do not have
  that problem.

Seatbelt is formally deprecated. It is still the de facto confinement mechanism
for CLI agents on macOS, used by the Codex CLI and Claude Code sandboxes,
Chromium and Bazel. Clawdstrike's `nono` already includes Seatbelt capability
code, and its known defects are recorded in
`docs/superpowers/plans/2026-07-09-enterprise-hardening.md`.

**Recommendation.** Offer two Mac profiles and adjust the entry points:

- **`darwin-sandbox-v1` (Seatbelt).** Writes go only to the workspace. Network is
  denied except the loopback Chio gateway. There is no Keychain access and no
  home reads outside allowlisted agent state. The profile runs native
  toolchains, uses honest ADR-0011 wording and records the deprecation risk.
- **`vm-sealed-v1`.** This is the current zero-NIC VZ design, for untrusted
  repositories and high assurance.
- **ES/NE.** Keep these on the managed-endpoint track only, as the PR already
  does.
- **Entry points.** Lead with the CLI and the menu bar. Developers start agent
  work from terminals and editors, so Finder Services "Run with Chio" is a
  secondary affordance.

### F5. Omarchy: right UI hook, wrong target, scope too wide (#1177)

I checked the spec's upstream claims read-only against `omacom/omarchy`
`0f8af9be` and the v4.0.4 tag. Almost all of them hold. The shape is right for
Omarchy:

- the QML shell plugin as presentation only;
- the controller as a systemd user unit;
- pacman packaging.

`omarchy plugin add` never runs install hooks, so a native controller has to
arrive as a package anyway. Some facts the program should design around:

- **Agent launch modes.** Omarchy users start agents through `omarchy-agent`
  (`SUPER+SHIFT+CTRL+A`) and the `cx` and `cy` aliases. That launcher runs every
  supported agent in an auto-approve mode except Pi and Ori, which get no flag:
  - `claude --permission-mode auto`
  - `codex --approve-for-me`
  - `opencode --auto`
  - `cursor-agent --yolo --trust`
  - `grok --permission-mode bypassPermissions`
  - `agy --dangerously-skip-permissions`

  Omarchy also offers a 15-minute passwordless-sudo toggle aimed at agents
  (`manual/48-security.md`). The real governance gap on Omarchy is therefore
  unconstrained auto-mode sessions of the agents the existing Chio plugins
  already bond. Making a single confined Pi recipe the first product leaves that
  gap untouched.
- **Primitives.** The default kernel is `linux-omarchy-bore` 7.2.x with
  `landlock` in `CONFIG_LSM`. Unprivileged user namespaces are on, seccomp and
  BPF LSM are enabled, and bubblewrap is present transitively (Chio should still
  declare it). A governed-session backend is practical on a stock install today.
  Probe the Landlock ABI at runtime rather than assuming one.
- **Plugin API stability.** The plugin API shipped in v4.0.0 on 2026-08-14 and
  makes no stability promise beyond `schemaVersion: 1`. Upstream narrowed
  third-party plugin capabilities on 2026-09-01 (`1702cf0b`, backported to
  v4.0.3). v4.0.4 was cut from a patch branch, so it is not an ancestor of
  HEAD, and the default branch is now `quattro`. Keep the plugin thin and expect
  churn.

Scope changes:

- **Cut P4 (compositor tools) and P5 (configuration repair).** They are Omarchy
  feature work unrelated to Chio's authority value: about 520 plan lines plus
  specs 10 and 11. Keep one paragraph of future work.
- **Move P6 (delegation) into the kernel program.** Both PRs specify delegation
  separately, and neither should own it.
- **Reconsider "never touch `omarchy-agent`".** An opt-in governed launch mode
  (`omarchy-agent` through `chio run`) is the highest-leverage integration point
  on this desktop. Contribute it upstream once the governed-session profile
  qualifies. Until then, a Chio menu entry and keybinding that launch the user's
  default agent through `chio run` give the same reach without editing upstream
  files.

### F6. Real defects are buried in research tables

These defects are independent of the desktop programs and should be filed as
issues now:

1. **Pi `approval-decide` decision confusion.** Omarchy
   `research/chio-readiness.md` records that the bundled utility "can retain a
   signed approved credential despite requested denial because requested
   decision and approval ID are not compared before retention". This is a
   security defect in a public package (`chio-pi-plugin`), not a P3
   prerequisite.
2. **Emergency stop is not durable.** `chio-kernel` holds `emergency_stopped`
   in memory, so it does not survive a restart. Any operator surface's kill
   switch inherits this.
3. **The Pi protected CLI accepts the task through `--prompt`.** That exposes
   the prompt in argv (P2-PRIVATE-PROMPT).
4. **`ensure_capability_issuance_supported` returns `Ok(())` unconditionally**
   (CK-10). Confirm whether this is intended.

### F7. Neither program uses the repository's governance

- **ADR-0011 is not followed.** It requires "every planning artifact and
  implementation ticket that touches a trust boundary" to carry
  `boundary_class` and `planning_status`. Neither PR does; each invents its own
  vocabulary of profiles and evidence classes. Neither program cites a single
  ADR.
- **The structure is new to the repo.** Both introduce `requirements.json`,
  `verify.py`, fixture corpora and `reviews/` directories, which no earlier
  program in `docs/superpowers/` uses. Earlier programs, at a fraction of this
  size, are still only partly implemented. For example, the 2026-07-09
  security-folder spec's `crates/security` is still waiting in #1160.

### F8. Volume has become a liability

| | #1177 | #1178 |
| --- | --- | --- |
| Files | 125 | 280 |
| Spec and plan Markdown lines | 5,556 | 7,150 |
| JSON lines (schemas, fixtures, coverage) | 6,219 | 27,536 |
| Requirements | 209 | 323 |
| Implemented | 0 | 0 |

The review-fix rounds on #1178 fixed real but incidental defects:

- bidi-control escaping in a Swift helper that does not exist yet;
- FIFO blocking in an example qualification reader;
- Boolean percentile samples;
- cursor correlation fixtures.

Each fix is correct, and none of them bears on whether the product is right. The
requirements restate about a dozen invariants many times over. The validators
enforce internal consistency, which makes the documents expensive to change at
exactly the moment the direction should change.

**Recommendation.** Replace both programs with four pieces:

1. One ADR, "Desktop integration architecture" (about 300 lines), containing:
   - the invariants table above;
   - the component split;
   - the profile ladder below, with ADR-0011 classes;
   - the platform matrix.
2. An Omarchy annex and a macOS annex (about 300 lines each), covering the shell
   surface, IPC peer authentication, isolation backend and packaging.
3. The existing research files, mostly unchanged.
4. The operator protocol spec and schemas, written alongside the controller
   crate rather than before it, and placed in `spec/` next to `PROTOCOL.md`.

Requirement catalogs, acceptance IDs, fixture corpora and validators should come
after implementation and bind to real tests.

## Proposed shape

```text
 Omarchy QML plugin ---+                           +-- Linux: bwrap + Landlock + seccomp + netns
 macOS menu bar app ---+-- chio desktop controller -+-- macOS: Seatbelt, or VZ VM with zero NIC (sealed)
 chio CLI -------------+   (one operator protocol)  +-- egress gateway + chio-mcp-adapter
 host plugins (@chio/bridge) ------------------------> chio kernel: capabilities, approvals, budgets, receipts
```

| Profile | Adds | Depends on |
| --- | --- | --- |
| `observe` | Bonded-session list, receipts, budgets, kill switch | Main plus stable event subscription |
| `approve` | Exact approvals from the desktop | Operator principal binding; approval decision fix |
| `governed-session` | OS sandbox plus Chio-only egress for any agent | Per-platform sandbox backend; egress gateway |
| `sealed-task` | Closed registry, VM or strict cage, external oracle | #1160; Pi qualification |
| `managed-endpoint` | ES/NE, fleet policy | Entitlements, MDM |

## Decisions needed from the owner

1. **First execution product.** A governed session for existing agents, or a
   sealed Pi task runner? This review recommends the governed session.
2. **One program.** Should one shared desktop program, with platform annexes,
   replace these two?
3. **Kernel sequencing.** Should #1174 and #1160 be decided first, with the
   minimal kernel contract list in F3 adopted as the desktop gate?
4. **macOS.** Should Seatbelt be a first-class, honestly labeled profile next to
   the VM?
5. **These PRs.** The recommendation is to convert both to draft and stop the
   bot-review iteration. Once the decisions above are made, merge only the
   research files plus the new ADR.
