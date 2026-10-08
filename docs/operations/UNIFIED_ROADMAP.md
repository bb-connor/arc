# Chio unified roadmap

Status: proposed for owner review, 2026-10-08. This document sequences every open program and PR toward one north star. It records order, gates and decisions. It does not start any work.

**Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.**

*Authority that only narrows. Work that survives. Evidence that travels.*

## How to read this document

**Evidence base.** The research was done read-only on 2026-10-08 against main (`5bb4ae6a5`) and every open PR head. It covered:

- ancestry and simulated merges (`git merge-tree`);
- the #1160 landing ledger and coordination board;
- PR bodies, check runs and review threads;
- the program documents in #1160, #1170, #1173, #1174, #1177, #1179 and #1164;
- the public plugin repositories.

**Standing rules.**

1. **Specs may assume their predecessors are shipped.** A spec can treat the programs it builds on as landed when that is the right sequence. This roadmap is what makes that sequence true.
2. **Claims follow ADR-0011.** Every public claim carries `boundary_class` and `planning_status`.
3. **Clawdstrike is prior art, not a peer.** It is an earlier project. Its Linux observation work (Tetragon, Hubble) and its macOS Endpoint Security and Network Extension plumbing are useful source material. Chio absorbs what it needs into its own crates and host adapters. Clawdstrike is never an integration target, a boundary, an owner or a peer.
4. **Approving a plan does not start it.** Execution begins only on an explicit start.

## 1. Where everything stands

| Program | PRs | State today | What it delivers | What blocks it |
| --- | --- | --- | --- | --- |
| Security and process foundation | #1160 (contains #1136's patch) | Ready, mergeable, BLOCKED. 1,360 commits ahead of main. Merge into main is conflict-free. | `chio-process` (durable process trees, mailboxes, swarm admission), process host CLI, `chio-cage`, `chio-secure-ipc`, `chio-secret-broker`, `chio-keyring`, `signing_custody`, active-defense stack (M7), required-agent resource, `chio-mini-swe`, doc 19 | 3 pending required checks; 33 open review threads; 5 in-progress board items, including P1 `MINISW-NATIVE-DENY`. Must land as a **merge commit**. |
| Lane-test CI | #1194 | Mergeable | CI workflow | Independent |
| Recovery | #1172 (docs and OpenAPPA lab), #1179 (runtime, draft) | #1172 merges cleanly onto #1160. #1179 is "not qualified". | Original-operation recovery, recovery commands, `chio-recovery`, `chio-semantic-contracts`, control-plane recovery | #1179: 3 open P1s plus a new Greptile P1; 10 failing checks; 233 conflicts with #1160 and 220 with #1173; schema collision (section 2) |
| Verifiable work | #1173 (contains #1161, #1159; supersedes #1158; carries #1162's code) | Mergeable against its base. 112 conflicts with #1160. | D1 dynamic delegation, S1 swarm evolution, A2A v1 edge, funded native work, unknown-payment release, confined PostgreSQL, W1-W4 plans (unimplemented), the verifiable-work paper | Schema collision; retarget to main; new-head review; enterprise evidence jobs |
| Kernel north star | #1174 (docs) | Design review. Spec 9, spec 10 and three others had adversarial review; spec 11, spec 7, spec 4, spec 2, spec 1 and spec 6 have not. | Bug-fix lane, keystone refactors (S9 pure admission, S10 crossing, S1 closed ABI), later specs | Its stated baseline (#1160, #1172, #1173, #1179) |
| Strategy | #1170 (docs) | Open. Every founder decision F-1 to F-17 is open. | Positioning evidence, ADR candidates 0023-0037, a 90-day plan, demos | F-1 publication decision (section 3); conflicts with ADR-0038 |
| Native host program | #1177 (with #1178 folded in) | Open; docs only; merges cleanly | ADR-0038, PROGRAM-MAP, NORTH-STAR-FLOWS (M1/M2/M3), restructure plan, M1 Cooperate-0 plan | Re-pin after #1160; restructure; product-face decision |
| Workbench | #1164 (draft) | Conflicting. Not built or tested since written; 12 findings open. | Browser task and worktree UI | Product-face decision |
| Protocol draft | #1171 | 1 conflict | IETF draft | Rebase; excludes passports and federation |
| Stale | #1029, #956-#959, #1046, #1073, #1043, #1155, #1163, #1056 | 1 to 9 weeks old; most conflicting | n/a | Reconcile requirements, then close |

Megastart is the mission-console example in the public `backbay-labs/chio` repo (PRs #9 and #10). It is the coordinator application for desktop M2.

The six priority host plugins (doc 19) are all candidates. Only Pi has a Linux restricted launcher.

## 2. Hard blockers to settle before any rebase

1. **Admission schema numbering.** Three branches each define v35 and v36 differently:
   - #1160: recovery deferral status, security participant checkpoints;
   - #1173: unknown-payment release, capture waiver;
   - #1179: recovery workflows and deployment history, then through v40.

   Migrations fail closed, so a database written by one branch is refused by the other. Record one allocation in the #1160 landing ledger:
   - #1160 keeps v35 and v36;
   - #1173 takes v37 and v38;
   - #1179 starts at v39.
2. **Settlement semantics for an uncertain captured operation.**
   - #1173 releases a hold through a co-signed unknown-payment release.
   - #1179 quarantines the operation behind a durable historical hold.

   Both extend the same startup reconciliation sweep (`admission_coordinator/recovery.rs`). One model must be authoritative, or the rule for when a release may settle a held operation must be written down. #1179's P1 ("settlement after operator rotation wedges the startup sweep") sits in this same code.
3. **#1160 merge method.** The landing ledger and evidence bindings require a merge commit, because exact source identity must stay reachable. The repository also allows squash and rebase, so the person merging must choose "Create a merge commit" deliberately.

## 3. This week: urgent and cheap

| # | Action | Why now |
| --- | --- | --- |
| U1 | **Decide F-1:** which #1170 strategy documents belong in a public repository. | #1170 itself recommends keeping some of them private, and its branch is already public. |
| U2 | **Void F-17** and the "Clawdstrike owns sensing" text in #1170. In #1177, remove Clawdstrike-as-peer framing from the macOS annex, README, CAPABILITIES and the macOS plan. Rewrite `research/clawdstrike.md` as a prior-art note that lists what Chio takes from it: Tetragon and Hubble observation on Linux, Endpoint Security and Network Extension on macOS. | Standing rule 3. F-17's day-14 deadline (10-13) becomes moot. |
| U3 | **Agree schema numbering** (blocker 1) and record it in the ledger. | Every later rebase depends on it. |
| U4 | **Fix the main README positioning** (lines 16 and 22) in a small PR. Use the north star and supporting line, and retire "The kernel your agents answer to" and "Agents that pay each other". | Main still carries both. This also settles part of #1182 without waiting for #1177. |
| U5 | **Constant-time admin token comparison** (#1174 N23 / #1180) and the AC6 stop-scope document. | Security fix. Applies to main and #1160 alike (the file differs by 15 lines). |
| U6 | **Fix `approval-decide`** (`backbay-labs/chio-bridge#3`). | Any approval flow through the bridge depends on it. |

## 4. Waves

Each wave lists entry gate, contents and exit evidence. Quarters are planning targets, not commitments; section 6 explains why.

### Wave 0: land the foundation (now)

- **Entry:** today.
- **Contents:**
  - U1 to U6.
  - Finish #1160's merge gate: required checks, review-thread dispositions, and board items F077, MINISW-NATIVE-DENY, NCD001, XTC001 and CLOCK001.
  - Merge #1160 as a merge commit. Land #1194.
- **Exit:**
  - #1160 is on main, and `main_ancestry_verified` is recorded.
  - Close #1136 (patch already present).

#1160's own post-merge obligations stay open after it lands, and no tag or release is permitted until they close:

- trusted 35-campaign capture;
- per-PR security app enforcement;
- native mini-swe and cold-platform acceptance.

### Wave 1: absorb and clean up (Q4 2026, right after #1160)

**Integration**

- **Retarget and land #1172**; it has 0 conflicts.
- **Close superseded PRs:**
  - #1161, #1159 and #1158 as contained;
  - #1162, after its 3,164 evidence files and `examples/repair-machine-proof` are archived.
- **Split and rebase #1173 onto main, in order:**
  - a. D1, S1 and the A2A v1 edge (own tables; the fastest landable code);
  - b. funded native work, unknown-payment release and capture waiver at v37/v38, and confined PostgreSQL (resolve 5 broker conflicts);
  - c. W1-W4 specs and plans;
  - d. paper and research evidence, as a separate docs PR of about 5,400 files.
- **Start the #1160 HAMMER follow-up trains, one train at a time:**
  - KERNEL, STORE, CRYPTO, CP, MISC;
  - IPC, CONTRACTS (`chio.process.v1`), ASYNC, TYPES;
  - SECUREFS (`chio-secure-fs`), KERNEL-ERRORS.

**Kernel bug-fix lane** (#1174, on post-#1160 main, in this order)

1. **Kill switch:** S8 phase 1 (D2, N22, EV11). This replaces #1170's deferral of the governed stop.
2. **Missing evidence:** S3 phase 1 (D1, N28, N29, N2).
3. **Authority staleness:**
   - N1 and N15 (authority clock instead of wall clock);
   - D6;
   - D5, which currently has no owning spec. Assign one.
4. **Transport:** S5 Part A (D3, D4, N26, N30).
5. **Others:** D8, N3, then the narrow S9 M20 identity-disposition delta.

**Native host program**

- Re-pin #1177 to landed SHAs (section 7).
- Run the restructure plan, amended by section 8.
- Record the product-face decision in the ADR-0038 amendment.
- Begin M1 Cooperate-0 code on post-#1160 main. The M1 plan is re-cut first: it must extend `signing_custody` and handle the now-fallible clock.

**Strategy**

- **Rewrite ADR-0023 to ADR-0038's scope:**
  - isolation denies, Chio grants;
  - thin OS adapters are allowed where no qualified runtime exists;
  - the secret broker, cage and launchers are not frozen.
- **Reconcile positioning by audience:**
  - the north star for builders and OS contexts;
  - #1170's category sentence inside other runtimes.
- **Align the demos with M1.** M1 Cooperate-0 is a counterparty-verification demo with real separate operators. Use it for Demo A (fallback 11-10) or Demo C, instead of building a separate demo.

**Exit evidence**

- #1172 and #1173 (a) to (d) are on main.
- The bug-fix lane through S5 Part A has hosted evidence (GT1).
- #1177 is merged.
- The M1 inbox and custody code are in review.

### Wave 2: first independent evidence (Q4 2026 into Q1 2027)

- **Recovery:** remediate #1179 (the 3 P1s plus the command-pool P1). Re-qualify P5/P6, rebase over #1173 at v39+, and settle blocker 2. Land it.
- **Work:** W1.0 (`INTEGRATION.md`), then W1.1 to W1.5. Recovery-dependent behaviour is recorded as pending until #1179 lands.
- **M1 Cooperate-0:**
  - Ship the issuance inbox, OS key custody, user-session services, the dashboard review panel and the notifier.
  - Run the real two-person, two-machine evidence run: Omarchy as Org A, a Mac as Org B. This produces the first independent-operation record for the paper's open gate.
- **Long-lead M2 work:**
  - Pi 0.2.0 kernel qualification on native x86_64 Omarchy;
  - a Claude Code bubblewrap launcher (the most active plugin);
  - Megastart's allowance moved onto kernel holds, plus its Linux port.
- **Kernel:**
  - S5 Part B, with the desktop as its second consumer;
  - S4 phase 1 (per-task closure behind a flag);
  - the S8 S28 operator roster prerequisites;
  - the production passkey approval path.
- **Exit:** #1179 on main; W1 facade on main; M1 record published; Pi and Claude Code each have a Linux restricted launcher candidate.

### Wave 3: coordinate and share on one host (Q1 2027)

- **M2 on Omarchy:**
  - one root grant across Pi and Claude Code;
  - durable sibling-share registry;
  - live process cancel and revoke;
  - token or spend dimension at the model relay;
  - serving-path swarm admission.
  - The dashboard gains the authority-tree and pool views; Megastart in Herdr on Linux links to them.
- **Work:** W1.6, then W2.1 to W2.3 (owner services; no recovery needed yet).
- **Kernel keystones, phase 0 only:**
  - S9 model plus differential run;
  - S10 shared-writer baseline measurement;
  - S1 census generated from main.

  These follow the umbrella's step 1: freeze the M/V/W contract, process ABI v4 (N13) and the P6 inventory.
- **Security:** continue M5 to M10 and the 1,045 follow-up requirements.
- **Exit:** M2 Omarchy criteria met (NORTH-STAR-FLOWS section 8). W2.1 to W2.3 on main.

### Wave 4: cooperate on work across organizations (Q2 2027)

- **Work:** W2.4 (needs recovery ports), then W3 (SDK and CLI surface).
- **M3:** co-signed, unpaid work commitments between the M1 hosts, with B executing in its own M2 tree. It needs receiver-owned admission in a serving path and the remote co-signer. Per F-15, no party holds both co-signer keys.
- **M2 on macOS:** Darwin process runner, a broker backed by Keychain and XPC, `LOCAL_PEERTOKEN` IPC, and the selected VM backend.
- **Security:** M11 observation windows begin (at least 14 days and 100K invocations, or 30 days for low-volume cohorts) once M5 to M10 allow.
- **Strategy:** the kill-or-continue review on 2027-03-26 uses the M1 and M3 evidence, not slideware.
- **Exit:** the M3 record, and macOS M2 criteria met.

### Wave 5: converge (H2 2027)

- W4 beta convergence, joining the security and recovery release gates; paper step P.5.
- Keystone phases 1+:
  - S9 driver replacement;
  - S10 crossing transaction, fusion and group commit;
  - S1 shrink, which is the same cut as #1170's web3-free distribution ADR.
- S11 integrity-gated admission (needs #1179's journal, S10 and S2).
- The IETF draft gains passports and federation.

## 5. Critical path

```text
U3 schema allocation ─┐
#1160 merge-gate ─────┴─> #1160 (merge commit) ─┬─> #1172 ─────────────────┐
                                                ├─> #1173 a/b/c/d ─────────┼─> #1179 (remediated, v39+) ─> W1.6, W2.4 ─> M3
                                                ├─> #1174 bug-fix lane ─> S5 Part B ─> desktop streaming
                                                ├─> #1177 re-pin + restructure ─> M1 code ─> M1 two-machine record
                                                └─> M2 long-lead (Pi, Claude Code launcher, Megastart holds) ─> M2 Omarchy ─> M2 macOS
```

The longest pole is #1179: remediation, re-qualification and two large rebases. It gates W1.6, W2.4 and M3. M1 does not depend on it.

## 6. Capacity reality

#1170 sizes its own 90-day scope at 49 to 73 engineer-weeks against about 22 available. Even that budget leaves out:

- the #1174 bug-fix lane;
- the #1160 follow-up trains and 1,045 requirements;
- the #1173 split and rebase;
- #1179 remediation;
- M1 to M3.

Much implementation runs in agent lanes. The binding constraint is review, qualification and owner attention, not typing.

Recommended limits:

1. **At most two integration rebases in flight at once.** Wave 1 runs #1173 (a) to (d) sequentially while #1172 lands alongside.
2. **One kernel lane at a time.** The bug-fix lane completes before any keystone phase 0 starts.
3. **One desktop milestone in implementation at a time.** M1 code waits for the restructure to land. M2 long-lead work is limited to qualification and launcher work in other repositories.
4. **#1170's dated demos are re-based on M1.** A separate Demo A build competes with M1 for the same people.
5. **Cut list, to be decided by the owner:**
   - the economy stack #956 to #959 (stale);
   - Demo B and the reduced Treaty Call until M3;
   - macOS M2 until Omarchy M2 qualifies;
   - healthcare (F-7).

## 7. Re-grounding after #1160 merges

| Document | Change |
| --- | --- |
| #1177 PROGRAM-MAP | Pin F (`1267f9bf3`, 290 commits behind) becomes main. Foundation status changes from "implemented candidate" to "merged, pre-release gates open". Shifted T-line citations are updated: `router.rs` +4 lines, `authority_handlers.rs:446-486` moves to 489-529, `paths.rs:12-19` moves to 13-20. |
| NORTH-STAR-FLOWS | Every "in F" becomes "main (experimental; broker Linux-only)". `chio-ipc` mailboxes becomes `crates/kernel/chio-process/src/mailboxes`. Status changes from "proposed" to "approved 2026-10-08". |
| M1 plan | Base is post-#1160 main. Task 2 extends `signing_custody` (`load_existing_authority_keypair`) with key references instead of rewriting the loaders. The inbox code uses the fallible `unix_timestamp_now()`. Remove "needs nothing from #1160". |
| Restructure plan | Baseline counts are recomputed. The M2 Omarchy gate "#1160 lands" is met. |
| #1174 specs | M: pin (`19df31ad9`) becomes main. Three line citations move (`store.rs:395` to 403, `native_mcp.rs:226` to 229, ledger EV11/AC6 lines). The open-acceptance statistic becomes 1,022 of 1,794. |
| #1170 | It records ADR-0038's scoping of ADR-0023, and F-17 is voided. |

## 8. Changes this roadmap makes to the north-star program

1. **One product face.** The trust-control web dashboard (`crates/products/chio-cli/dashboard`) is Chio's one web client.
   - It already ships on main.
   - Only `chio trust serve` runs on both organizations' hosts, so only the dashboard can show cooperation.
   - Megastart in Herdr is the flagship coordinator application for M2. Its console links to the dashboard's authority-tree view rather than keeping its own ledger UI.
   - Close the workbench (#1164) as a product face, and move its worktree and patch-review ideas into Megastart's review step.
2. **M1 builds on post-#1160 main**, as in section 7.
3. **The second M2 host is Claude Code**, because it is the only active plugin besides Pi. Codex and Hermes follow with bubblewrap launchers modelled on Pi's.
4. **Sensing is Chio's own.** Any observation evidence the desktop hosts need (`detect_only` under ADR-0011) comes from Chio's own host adapters. Clawdstrike's Tetragon, Hubble, Endpoint Security and Network Extension work is source material for those adapters, and the peer framing leaves #1177 (U2).
5. **Demo alignment.** M1 serves as #1170's counterparty-verification demo.

## 9. Owner decision register

| Decision | Recommendation | Blocks | By |
| --- | --- | --- | --- |
| F-1: which #1170 strategy documents stay public | Follow #1170's own recommendation; keep the commercially sensitive ones private | Merging #1170; further pushes | Now |
| Schema allocation (blocker 1) | #1160 v35-v36, #1173 v37-v38, #1179 v39+ | Every rebase in Waves 1-2 | Before #1173 rebase |
| Settlement semantics (blocker 2) | Write the rule for when an unknown-payment release may settle a held operation; one sweep owner | #1179 rebase, #1173 (b) | Before #1179 rebase |
| ADR-0023 scope | Adopt ADR-0038's scoping; no freeze of broker, cage or launchers | #1170 merge, D30-01, M2 launchers, S7 backend kinds | Wave 1 |
| Product face | Dashboard as the one web client; Megastart as coordinator; close the workbench | #1177 restructure, M1 UI, #1164 | Wave 1 |
| Capacity split (F-3, F-4) | One combined plan across programs with the section 6 limits | Every dated item | Wave 1 |
| Receipt privacy (F-10, ADR-0036) | Decide before any personal-data pilot | Pilots, D30-09 | Wave 1 |
| Legal (F-13) | Before outreach offers | D60-07/08 | Wave 2 |
| D5 owner | Assign the freeze-on-`Delegate` defect to a spec owner | Bug-fix lane completeness | Wave 1 |
| S5 Part B un-deferral | Un-defer with the desktop as consumer | Desktop streaming | Wave 2 |
| Cut list | Section 6 | Capacity | Wave 1 |
| F-17 | Void (standing rule 3) | n/a | Done by this roadmap |

## 10. What this roadmap deliberately does not do

- It starts no execution.
- It approves no ADR beyond what the owner already accepted: the north star and the cooperate-first NORTH-STAR-FLOWS design (including its planned ADR-0038 amendment and F-15's co-signer rule).
- It makes no release, qualification or market claim.
- Everything listed as Wave 2 or later is dependency-ordered intent. It is not a calendar commitment.
