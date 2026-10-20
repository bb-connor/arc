# Chio unified roadmap

**Status:** design approved by the owner on 2026-10-08, section by section. Decisions D1 to D7 were recorded on 2026-10-09 (section 8). The Computer lane (COMP) and decisions D21 to D23 were added on 2026-10-09. Re-grounded on 2026-10-12 against main `b6ad31043`, after #1160 and the landings that followed it (sections 2 and 13). Nothing in this document starts work. Execution begins only on an explicit start.

**Chio is a Rust kernel for agentic operating systems that coordinate work, share resources, and cooperate across organizational boundaries.**

*Authority that only narrows. Work that survives. Evidence that travels.*

This roadmap works backwards from one result: outside teams running Chio under their own agents and completing co-signed work across organizations. It has four parts:

- **Gate 0:** the foundation, and the contracts every lane builds against.
- **Eight lanes:** parallel work that agent swarms can execute. Seven build the substrate; COMP, the Computer developer surface, sits on top of them.
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

| Ref | Research pin (2026-10-08) | State on 2026-10-12 |
| --- | --- | --- |
| main | `002b4d14e` | `b6ad31043` |
| #1160 | `fd8bfdc94` | Squash-merged as `28d826e3e` from reviewed head `29327c5d7` |
| #1173 | `cafdc970e` | Open, same head |
| #1174 | `8dffff3da` | Squash-merged as `7b293ab37` |
| #1177 | `620c703d8` | Merged as `3af65d2d2` (merge commit, 2026-10-09) |
| #1179 | `491bd01b5` (research); head moved to `f217de1fb` later on 2026-10-08, and the #1179 schema figures below were re-checked there on 2026-10-09 | Open, head `4b9229dca`, no longer a draft |
| #1172 | `de84fc306` | Open, same head |
| #1170 | `666274bae` | Squash-merged as `344a9bc58` |
| #1171 | `ad9df87a5` | Merged as `3e5f45307` (merge commit, 2026-10-09) |

The KDEF rows this document cites, the schema version and section 2 were re-verified against main `b6ad31043` on 2026-10-12 (section 13). Other line citations still carry their research pin.

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
   - every gate claim (the table at the end of section 5) carries `boundary_class` (`prevent`, `detect_only`, `advisory_only`, `cannot_see`) and `planning_status`;
   - this document does not classify lane rungs. A lane item that touches a trust boundary gets both fields when the Gate 0 contract it builds against freezes, or when its implementation ticket is cut if no contract covers it, and always before a gate claims it;
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

**Which team executes (ruling of 2026-10-09, made under the owner's delegation).** The executing organization runs HOST-M2 (criterion c), and HOST-M2 is Linux-only before the test. So the executing organization runs Linux. Outside teams that are macOS-only take part as the counterparty (requesting) organization. macOS HOST-M2 is not pulled forward: that would reopen the approved design and put Apple's Endpoint Security entitlement approval, an outside party, on the critical path. G1 still requires a timed outsider install on both Linux and macOS.

**Strongest form.** Two outside teams cooperate with each other. Backbay as the counterparty also counts.

**Stretch.** One outside team writes its own provider. That would also close the verifiable-work paper's open independent-operation gate, which requires "separately operated participants and independently written provider".

## 2. Where everything stands

| Program | PRs | State | What blocks it |
| --- | --- | --- | --- |
| Security and process foundation | #1160 | **On main.** Landed on 2026-10-11 as squash commit `28d826e3e` from reviewed head `29327c5d7`; the two trees are identical (`9000ce6bb`), and the reviewed head is kept on `archive/pr1160-reviewed-29327c5d7c`. It merged on the owner's instruction to bypass required CI: cargo-vet and cargo-deny were green, while build/lint/test and MSRV were still incomplete. The landing ledger records the state `merged-qualification-incomplete` (`docs/security/audits/foundation-postmerge-20261011.json`) and infers no requirement closure from the merge. KDEF-GT1 (one whole hosted CI run passes) is not met. The follow-up landings #1201 to #1232 repaired residual findings, CI and the ledger (G0.1). | Its post-merge, pre-release obligations (Lane REL) |
| Recovery | #1172 (architecture and lab), #1179 (runtime) | Both open. #1179 is no longer a draft (head `4b9229dca`, based on #1172's branch), is not qualified, and its P1s are open (including `NATIVE-FUNDING-AVAILABILITY-01` and the command-pool P1). | Both were cut from pre-squash #1160 history that main does not contain. Merged directly onto main `b6ad31043`, #1172 conflicts on 1,572 paths (1,140 add/add) and #1179 on 1,673 (1,195 add/add), so both must be rebased onto main rather than merged. #1179 sits on #1160's old startup sweep. It declares admission schema v35 to v40 on a v34 base and checks for v41 in code, while main is at v37; it takes its slots through the ledger lock (G0.2). |
| Verifiable work | #1173 (contains #1161, #1159; supersedes #1158; carries #1162's code) | Dynamic delegation, swarm evolution, the A2A v1 edge, execution evidence and unknown-payment release are qualified locally on one host. **WORK-W1 to WORK-W4 have no code.** | Also cut from pre-squash #1160 history: 1,357 conflicted paths against main (877 add/add); schema collisions |
| Kernel program | #1174 (docs) | **On main** (2026-10-12, `7b293ab37`), revision 4: eleven specs plus the defect register (KDEF-D1 to D12, N1 to N30) in `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md` section 3. Its north-star research document now carries the historical banner. | Its baseline still names #1172, #1173 and #1179, which are open |
| Strategy | #1170 (docs) | **On main** (2026-10-12, `344a9bc58`). STRAT-F1 to F16 are open. STRAT-F17 is voided and its Clawdstrike portfolio-boundary framing is removed (U2). | F-1 publication split; ADR-0023 and ADR-0028 scoping |
| Native host program | #1177 (docs; #1178 folded in) | **On main** (2026-10-09, merge commit `3af65d2d2`). ADR-0038 is accepted for planning. NORTH-STAR-FLOWS (HOST-M1 to M3) is approved. The macOS Clawdstrike review is a prior-art note. The restructure and M1 plans are written but not executed. | Server-first re-cut (section 4) |
| Protocol draft | #1171 | **On main** (2026-10-09, merge commit `3e5f45307`). The IETF -00 is not yet posted. | Decision U8 |
| Computer | #1200 (roadmap amendment), #1199 (design) | **On main** (2026-10-12): #1200 as squash `d9ecdfe2d`, then #1199 as `ee0f29134`. #1216 re-pinned #1199's source evidence from the #1200 branch head to `d9ecdfe2d`. | Lane COMP |
| Workbench | #1164 (draft) | Never built or tested since it was written; 12 findings open | Closes (section 7) |

**Distribution today.** No outside team can install a current Chio.

- **Public installer:** resolves to v0.1.0, built 2026-04-22 from source more than 4,000 commits behind main. GitHub still marks v0.1.0 as Latest.
- **Docs contradict that release:** `CHANGELOG.md` and `docs/install/README.md` say nothing has been released.
- **crates.io:** carries `chio-*` 0.1.2 from 2026-08-01, built from the public mirror rather than main.
- **npm and PyPI:** `@chio-protocol/*` 0.1.0 (including `sdk`, `node-http`, `express`, `fastify`) and PyPI `chio-sdk` 0.1.0 were published on 2026-04-22. The PyPI name `chio` belongs to an unrelated project.
- **Stray tags:** `v3.20.0-trj4`, `v3.18.1-trj3.1` and `v0.0.0-m03-probe` sit beside `v0.1.0` on the development repo.
- **Plugins and bridge:** the harness plugins and `chio-bridge` are unpublished.

**Merged since the previous draft:**

- 2026-10-09: #1196 (this document), #1171, #1177.
- 2026-10-11: #1160.
- 2026-10-12, programs and documents: #1174, #1170, #1200, #1199, #1197 (agent swarm design), #1056 (mirror sync script, REL-1), #1203 to #1206 (crate documentation).
- 2026-10-12, follow-ups to #1160:
  - CI: #1201, #1209, #1213, #1222, #1223, #1224;
  - landing ledger and auditor, including the squash landing model: #1202, #1225, #1231, #1232;
  - security, kernel and store fixes: #1207, #1208, #1210, #1211, #1212, #1214, #1215, #1217 to #1221, #1226 to #1230. #1215 raised the admission schema to v37; #1221 carries #1046's MCP `nextCursor` fix.

Earlier: #1194 (lane-test CI), #1025 (cognition market design) and #966 (four-direction roadmap, including the governed x402 rail).

No CI or Release Qualification run on main has completed since #1160 landed; every run for the 2026-10-12 landings was still queued when this was re-grounded.

## 3. Gate 0: foundation and frozen contracts

Gate 0 exists so that parallel lanes do not collide. Everything a lane builds against is fixed here first, as a versioned 0.x preview contract with schemas and test vectors under `spec/`. Today `spec/schemas/VERSION` reads 1.0.0 and the `spec/PROTOCOL.md` header reads "Version 1.0", so CT-WIRE records the preview version explicitly and U3 fixes the PROTOCOL header.

### G0.1 Land #1160

**Done, on 2026-10-11, by a different route than planned.** This step prescribed a merge commit, because the landing ledger binds evidence to exact source identity. #1160 landed instead as squash commit `28d826e3e`, with sole parent `2b1d467e1`.

- **Source identity.** The squash tree equals the reviewed head's tree (`29327c5d7`, tree `9000ce6bb`). The reviewed head stays reachable on `archive/pr1160-reviewed-29327c5d7c`.
- **Squash landing model.** #1202 taught the post-merge auditor this model (`docs/security/audits/landing-auditor-repair-20261012.json`), and #1232 reconciled the ledger. A one-parent landing passes only if:
  - its sole parent is the qualified base;
  - its tree equals both the reviewed head's tree and the qualified tree;
  - the reviewed head is strictly ahead of that base.

  Two-parent merges keep their ordered-parent check. All CI, App-authority and attribution requirements are unchanged.
- **`main_ancestry_verified`.** Main does not contain the reviewed commit, so ancestry cannot be recorded. The landing-event record (`foundation-postmerge-20261011.json`) carries tree equality to the reviewed head (`identical_source_and_merge_tree`) instead. Per-requirement `main_ancestry_verified` values in the ledger stay `false`, and no requirement closure is inferred from the squash.
- **Merge requirements not met at merge.** #1160's `foundation-landing-boundary-20261008.json` required the four required checks to pass on the exact candidate. They had not: build/lint/test and MSRV were incomplete when the owner instructed the merge. The ledger records `merged-qualification-incomplete` for #1160, and #1201 also landed unqualified. Neither is relabelled verified.
- #1136 was closed on 2026-10-12 as superseded; main carries its `chio-sqlite-file-identity` fix through #1160.

**#1160's post-merge, pre-release obligations** are scheduled in Lane REL, not left open:

- the 35-campaign trusted capture;
- per-PR security App enforcement;
- native mini-swe and cold-platform acceptance. This includes what remains of `MINISW-NATIVE-DENY`: its diagnostic and bounded-journal source repair is integrated, and its open acceptance is the enforcing native trajectory, which #1160's merge bar leaves to this obligation.

### G0.2 Integration rules

- **Schema ledger lock** (D3, decided 2026-10-09; the lock goes live as policy).
  - Admission-store versions are assigned in landing order, at merge time, under a lock recorded in the #1160 landing ledger.
  - Branches use symbolic version names until they rebase.
  - A static reservation (for example "#1179 takes v39 and up") would force every earlier lander to renumber, so it is not used.
  - The lock covers every shared slot, not only admission versions:
    - every store's schema version, the tool-outcome store included;
    - the `authority_global_commits` projection-kind order;
    - `KernelOp` ids (KSPEC-01 plans 27 for #1173's execution-evidence export and 28 and 29 for #1179's recovery ops);
    - trigger names;
    - module paths (#1160 and #1179 both add `chio-store-sqlite/src/admission_operation_store/recovery.rs`, an add/add conflict).
- **Collisions to fix before any rebase:**
  - **Duplicate trigger, fails open.** `admission_operation_recovery_no_delete` is defined by #1160 on its deferrals table and by #1179 on its records table, both with `CREATE TRIGGER IF NOT EXISTS`. After a merge, the second delete guard is silently skipped.
  - **Global-commit kind list.** The `authority_global_commits` projection-kind CHECK list is appended separately in #1160, #1173 and #1179.
  - **Tool-outcome store v4.** #1160 uses it for payload compaction; #1173 uses it for execution evidence.
  - **Process ABI v3.** There are two incompatible v3s (#1160 and #1179), so their union is v4 (CT-ABI).
  - **Dead v41 check.** #1179 requires v41 in code (`original_owner.rs`) while declaring v40.
  - **Unreserved bumps.** The planned bumps for KSPEC-08 phase 1, WORK-W1.2, KSPEC-10 and KSPEC-11 are allocated through the same lock.
- **One merge queue.** Where evidence is bound to source, a landing is either a merge commit or a squash whose tree equals the reviewed head's tree under the auditor's squash model (G0.1). Evidence pinned to a branch head is re-pinned to the squash commit, as #1216 did for #1199.
- **ID prefixes and crosswalk:** section 12.

### G0.3 Contracts

| Contract | Freezes |
| --- | --- |
| **CT-ABI** | Process ABI v4. `chio.process.v1` schemas in `spec/schemas`: on post-#1160 main, 39 distinct `chio.process*` identifiers in Rust source have no schema there. The worker protocol has seven ops, including `prepare_invocation`, which `WORKER_PROTOCOL.md` omits and KSPEC-01 (which counts six) misses. `KERNEL_ABI_VERSION`, published from the KSPEC-01 phase 0 census. Operation IDs are never reused. |
| **CT-WORK** | `chio.work.v1` and the WORK-W1 facade (`WorkClient`, `WorkHandleV1`, `WorkViewV1`). These are mapped to #1179's real port names (`RecoveryProcessReservationPort`, `RecoveryProcessOriginPort`, `RecoveryAuthorityPort`), not the doc-only names. Includes an **unpaid** `Agreement` variant (D5, decided 2026-10-09). The schema path needs a choice: #1173's experimental funded-work envelopes already occupy `spec/schemas/chio-work/v1`, and SDK codegen reads only `spec/schemas/chio-wire/v1`, so CT-WORK names its directory and adds it to codegen. |
| **CT-SETTLE** | The settlement composition rule (#1174 decision 4, spec 9 rules M7a, M7b, M11a, R-9-05), implemented on #1160's paged startup sweep (D1, decided 2026-10-09). Details below the table. |
| **CT-COOP** | The **partner card**: org DID, trust-control URL, authority key history, receipt-signer keys, status resolve URL. Issuer-signed passport lifecycle status. DPoP possession for federated grants at the door (D6, decided 2026-10-09). The evidence trust-anchor format. |
| **CT-CTRL** | OpenAPI for trust-control and the `chio api protect` sidecar. Per-route principals in place of one shared service token. The KSPEC-08 stop routes. |
| **CT-CROSS** | The cross-org transport for co-signing and bilateral delivery: HTTPS with mTLS or signed bodies by default; iroh as an optional lane with self-hosted relays (D4, decided 2026-10-09). |
| **CT-REL** | The release channel. Details below the table. |
| **CT-WIRE** | The freeze list for the preview window: receipt, capability, passport, challenge, issuance, evidence and co-sign bytes (which co-sign bytes: D18); process ABI v4; `chio.work.v1`. The preview version number is D20. |

**CT-SETTLE in detail.**

- **One sweep owner.** #1179's historical hold becomes a classified, durable per-item deferral inside that sweep, never a `?` that aborts the sweep.
- **Delivery and money are separate facts.**
  - After an unknown outcome, only a co-signed `MutuallyAgreedUnknown` releases money.
  - For a known return with a pending capture, only `ContractualCaptureWaiver` stops the capture.
- **Holds versus successors.** A hold blocks finalization, receipts and delivery, but never a co-signed monetary successor.
- **Read before finalizing.** Every finalizer reads the effective payment journal first.
- **One signer-rotation rule** applies to finalization, release completion and waiver completion: sign with the current key and bind the original identity (D2, decided 2026-10-09).
  - Still to settle inside CT-SETTLE (raised by #1179): whether a finalization under a rotated signer may deliver output, or only withhold it.

**CT-REL in detail.**

- **Preview versions:** `0.2.0-alpha.N`. This is SEC-M10's developer preview, widened to include what HOST-M3 needs.
- **Repos:** `bb-connor/arc` is the development repo; `backbay-labs/chio` is the distribution mirror, synced on every tag (D7, decided 2026-10-09).
- **Preview exception:** the owner approved D8 on 2026-10-14, and the amendment is recorded in the landing ledger as `preview_exception_20261014` (`docs/security/audits/preview-exception-20261014.json`). Tagged `0.2.0-alpha.N` previews may ship before #1160's full-release obligations close; a non-preview release still waits for them.
- **Host compatibility:** tested version ranges for harness hosts, instead of exact pinned hashes.

### G0.4 Work that starts without waiting for Gate 0

- the immediate actions (section 6);
- recruiting, trial terms and legal (Lane OUT);
- drafting every contract above;
- MCP interop research (REL-2).

**Gate 0 exit evidence:**

- #1160 is on main (done on 2026-10-11, G0.1);
- every contract is merged with schemas and vectors;
- the ledger lock is live;
- decisions D1 to D7 are recorded (done on 2026-10-09, section 8).

## 4. Lanes

Each lane is a ladder of rungs. Each rung (and Lane REC as a whole) states one roadmap-level **Exit**: the objective evidence that tells a dependent lane the rung is done. Finer per-item evidence lives in the swarm backlog generated from this roadmap, where every item carries testable acceptance criteria. The gates in section 5 carry the exit evidence where lanes join. Lanes run in parallel.

### Lane COOP: cooperate across organizations

**What exists on main.**

- The passport, challenge and `trust federated-issue` chain is tested on one host.
- `chio api protect` admits presented capabilities through `X-Chio-Capability` with a pinned `CHIO_TRUSTED_ISSUER_KEY`.
- `chio evidence export` and `chio evidence verify` work offline.

**What does not hold up between two real operators.**

- A's passport revocation never reaches B. Federated issue reads B's own local status.
- At proxied routes a federated capability is a bearer token, because holder possession is not checked.
- The door ignores revocations made after it started.
- `evidence verify --trust <file>` checks every receipt and checkpoint signer against the keys a verifier-owned `chio.verifier-trust.v1` file pins, so a partner's keys can be pinned by hand. What is missing is partner-card ingestion and discovery: nothing reads a partner's published card or key history into the verifier.
- The issuance inbox design has no way to return the issued capability to the holder.
- As written in #1177's NORTH-STAR-FLOWS, the HOST-M1 flow fails on #1160 in two places:
  - B rejects an A-signed delegation ceiling: federated issue requires the policy signer to be a key B's own capability authority trusts (the IETF draft's Delegated Issuance step 7 states the same rule);
  - challenge submit and federated issue each consume the same challenge.

**Rungs.**

- **COOP-1: HOST-M1, re-cut server-first.**
  - The issuance inbox, with a holder pickup route authenticated by the subject key.
  - B's authority owns the delegation ceiling.
  - The challenge is consumed once across challenge submit and federated issue.
  - Door receipts are exportable, and the verifier checks the embedded `HttpReceipt`.
  - `evidence verify` ingests a partner card into the pinned-key verifier's `chio.verifier-trust.v1` trust file, in place of hand-pinned keys.
  - OS key custody built on #1160's `signing_custody`: `credential:` or systemd-creds on headless hosts, Keychain or Secret Service on desktops. Plaintext seed files are labelled development-only.
  - Service packaging: systemd units, a LaunchAgent, and a container image.
  - The desktop review moments (Waybar or QML, menu bar, notifier) are optional follow-ons, not gates.
  - **Exit:** a two-domain test passes: B issues to A's agent through the inbox and holder pickup, B's door allows an in-scope call and denies an out-of-scope one with receipts, and `evidence verify` accepts those receipts, embedded `HttpReceipt` included, against an ingested partner card.
- **COOP-2: a production-grade pair.**
  - `chio partner add` over the CT-COOP partner card.
  - Issuer-signed lifecycle status pulled with a TTL, failing closed when stale.
  - A live revocation feed at the door, and a durable revocation oracle. Today the sparse-Merkle `RevocationOracle` has only `InMemoryRevocationOracle`; `chio-custody-hw`'s `SqliteCredentialRevocationOracle` already persists credential revocations over it and is the nearest base.
  - DPoP for federated grants.
  - Authority key history, so rotation is not an outage.
  - Safe HTTP methods deny by default for federated doors.
  - A TLS reverse-proxy recipe and a rotation runbook.
  - **Exit:** tests show that a passport revocation at A denies at B's door without a restart, stale partner status fails closed, a federated grant presented without a DPoP proof is denied, and a key rotation mid-run keeps the door serving while older receipts still verify.
- **COOP-3: the HOST-M3 door.**
  - Receiver-owned admission on a serving path, with treaty predicates carried by the process host's admission hook.
  - The remote co-signer over CT-CROSS. This also closes STRAT-F15's relay or mTLS lane.
  - **Exit:** B's serving-path door denies a federated call without a treaty and admits one within it, each with a receipt; with the remote co-signer down, the work stays pending and is never re-dispatched.
- **COOP-4: evidence a counterparty can trust without trusting the operator.**
  - C2SP checkpoint compatibility (#1174 north-star bet 6).
  - The MCP edge authorization audit (bet 8).
  - Claims stay labelled "signatures verified against pinned keys; no external witness" until witnessing exists.
  - **Exit:** checkpoints pass published C2SP test vectors, the audit maps each MCP edge authorization control to a passing test, and every evidence output prints the label above.

**After the test.**

- Multi-hop across independent keys. This needs a partner-key set separate from authority keys, and a chain-binding resolver at the HTTP door, which today rejects any token carrying `attenuation_proof`.
- Discovery across N organizations, with an anchored publisher key.
- Revocation propagation across N organizations.
- Reputation, with Sybil controls.

### Lane WORK: coordinate work

**#1173, split by path rather than by commit.** Its large commits mix concerns, so slices are cut by path.

| Slice | Contents | Lands |
| --- | --- | --- |
| α | Execution evidence and checked output: the tool-outcome store and terminal-path hunks. The core conflicts with #1160 are spread across α, δ (funded work and payment) and ζ (security) by path, so α does not carry most of them. Drops #1173's own sweep edit in favour of #1160's classifier. | Right after Gate 0 |
| β | WORK-D1 dynamic delegation, WORK-S1 swarm evolution, A2A v1 edge | Right after Gate 0 (1 conflict) |
| γ | Federation, bilateral DSSE, iroh lanes, treaty runtime-core | After α and β; needed for the remote co-signer |
| c | WORK specs and plans, including `docs/research/work-abstraction/`, with the corrections below | Before WORK-W1.0, which builds on these plans and writes its inventory into that directory |
| d | Paper and research documents, plus research code | Separate docs PR |
| δ | Unknown-payment release, capture waiver, journal overlay, funded work | After CT-SETTLE; off the success-test path |
| ε, ζ | Confined PostgreSQL and broker; security and CI | Re-derived from #1160 or dropped |

**Corrections to the WORK plans.**

- **Split WORK-W1.5 and WORK-W1.6** into halves that need no recovery (a) and halves that do (b). WORK-W1.0's inventory also decides whether WORK-W1.3 and WORK-W1.4 need the same split: WORK-W1.4's original-ID issuance readback may depend on #1179's recovery ports.
- **Add the missing route:** WORK-W2.1's route list lacks `/cosign`.
- **WORK-W2.5** (operator package and external handoff) is required for outside teams.

**Rungs.**

- **WORK-W1:**
  - WORK-W1.0 creates `docs/research/work-abstraction/INTEGRATION.md`, the inventory of real constructors and ports;
  - then WORK-W1.1 to WORK-W1.4;
  - then WORK-W1.5a and WORK-W1.6a;
  - then WORK-W1.5b and WORK-W1.6b, after REC;
  - then WORK-W1.7.
  - **Exit:** the WORK-W1 plans' test cases pass for WORK-W1.1 to WORK-W1.7, including the post-REC cases in WORK-W1.5b and WORK-W1.6b, where an unknown effect is never re-dispatched.
- **WORK-W2:**
  - WORK-W2.1, owner services including `/cosign`;
  - WORK-W2.2, co-signing plus durable bilateral delivery. This has not yet succeeded in a composed run.
  - WORK-W2.4, lost-reply recovery, after REC;
  - WORK-W2.5.
  - **Exit:** a composed co-signed run survives a kill at every bilateral-delivery point with one tool call and no second dispatch, WORK-W2.4 recovers a lost reply, and the WORK-W2.5 package runs on separate hosts with an independent-operation record.
- **WORK-W3:** the `chio work` CLI, and `WorkClient` wrappers for Python `chio-process` and `@chio-protocol/process`. Outside teams' agents need these.
  - **Exit:** the CLI and both wrappers pass against the CT-WORK test vectors.
- **PAPER-1 to PAPER-4** are now scheduled. PAPER-5 follows WORK-W4.
  - **Exit:** the reviewed manuscript builds, every claim maps to its evidence, and the paper's independent-operation gate stays open.

**After the test.**

- WORK-W2.3, funded work.
- WORK-W4, beta convergence with the security and recovery release gates.

### Lane REC: work that survives

- **#1172 lands** after #1160.
- **#1179 is re-scoped as follows.**
  - Rebase onto #1160's paged sweep rather than porting the old loop. #1179's "settlement after operator rotation wedges the startup sweep" P1 mostly comes from that stale base: #1160 already defers a signer mismatch instead of aborting.
  - Adopt CT-SETTLE and the KSPEC-08 stop chain (KDEF-N24).
  - Adopt process ABI v4 (KDEF-N13) and the cage port (KDEF-N16).
  - Fix KDEF-N15 (wall-clock time in authority evidence) during the rebase.
  - Fix every open P1.
  - Take schema slots through the ledger lock (whether to collapse its intermediate formats: D17).
  - Regenerate the SDKs rather than merging 159 conflicted generated files by hand (158 Python, 1 TypeScript, at head `f217de1fb`).
- **Order of landing.**
  - First a REC-P0 + REC-P1 slice: contracts and exact durable recovery.
  - Then REC-P2 to REC-P6, each re-qualified.
- **Exit:** qualified recovery of a lost reply by original identity. This unblocks WORK-W1.5b, WORK-W1.6b and WORK-W2.4.

### Lane KERNEL: the guarantees outside teams rely on

This is #1174's bug-fix lane, promoted to a preview gate. It runs on post-#1160 main.

- **KERN-1: stop.**
  - KSPEC-08 phase 0 (AC6).
  - KSPEC-08 phase 1 (KDEF-D2, N22, N23): a durable, restart-safe stop with an allocated schema slot.
  - The stop is reachable from the process-host socket and the CLI.
  - Today (main `b6ad31043`) the emergency stop is a process-local flag, its routes are unmounted, and its token comparison is not constant-time (KDEF-D2, N22, N23; section 13).
  - **Exit:** one hosted run stops the kernel through a mounted route, restarts into a stopped state that still denies, and resumes; the process-host socket and the CLI reach the same stop, and the admin token is compared in constant time.
- **KERN-2: exactly one terminal receipt per executed call.**
  - KSPEC-03 phase 1 (KDEF-D1, N2, N28, N29), together with the M20 identity-disposition delta.
  - Phase 1 and the delta land together, because KSPEC-08 rule S15 ties `retryable_after_resume` to M20.
  - **Exit:** a property test that injects a failure at each post-effect step shows every executed call ending in exactly one terminal receipt, and every legacy non-allow receipt carries its M20 identity disposition.
- **KERN-3a: capability and process closure (gates G3).**
  - KDEF-D6 and KDEF-D5.
  - KSPEC-04 phases 1 and 2: subtree closure with the dispatch-commit fence, then ProcessTree closure.
  - [Process exit as an authority transition](../superpowers/specs/2026-10-13-process-exit-design.md) defines the proposed contract; implementation remains pending.
  - **Exit:** a suspension after admission denies at dispatch (KDEF-D6), a frozen lineage cannot mint delegates (KDEF-D5), closing one process subtree leaves its parent and siblings untouched, and an exited process can no longer be invoked. This exit is independently qualifiable and does not wait for WORK-W1 or KERN-3b.
- **KERN-3b: graph and delegation closure (gates COMP-3 and G4).**
  - KSPEC-04 phase 3: graph tombstones at continuation consumption and extension, WORK-D1 DelegationRoot fences at subdivision/selection/sealing, and stranded-capacity accounting. Land after WORK-W1's qualified issuer, against its serving store in its canonical issuance transactions; retain closure generations and records in its migration/recovery inventory. This work belongs to the KERNEL and WORK owners, not a new Computer closure store.
  - COMP-3 requires both KERN-3a and KERN-3b. Sealed permits remain outstanding until their native disposition is known; closing issuance does not cancel them or refund their exposure.
  - **Exit:** the phase-3 conformance cases pass, including retained-capacity accounting. Race graph extension, continuation consumption and WORK-D1 issuance against their canonical fences, then restart/migrate: a winning admission stays in closure membership, a losing admission commits nothing, fence generations survive, and sealed outstanding work remains accounted for until its required native disposition is known. COMP-3 consumes this evidence in its composed join cases; KERN-3b qualification does not depend on Computer.
- **KERN-4: the session door.** KSPEC-05 Part A (KDEF-D3, D4, N26), because doors serve over `chio mcp serve-http`.
  - KDEF-N30 is fixed on main by #1160 (`28d826e3e`): the GET stream subscribes before it snapshots the replay window.
  - KDEF-D3 changed shape on main: a lagged consumer, POST or initialize, now closes the session and reports an uncertain effect instead of hanging. What remains is the per-session POST lock: an SSE stream holds it until a terminal response, so an upstream that never answers still blocks later POSTs, with no request timeout. Part A re-checks D3 against that behaviour.
  - Done on main: the POST-lock wedge is bounded by a per-request response deadline (#1238). KDEF-D4 restored sessions seed event ids above every earlier incarnation (#1246); A22 low-bit exhaustion is deferred. KDEF-N26 standard subscriptions persist in a signed resume record, are re-authorized at restore and stay authority-checked after activation (#1251, #1253, #1255, #1266, #1274).
  - Open in Part A: the per-request response slots and session-side `finish_call` (A1-A4, section 4.2), the lag resync (A7-A11) and the retry rule (section 4.6).
  - **Exit:** Part A's acceptance cases pass on `chio mcp serve-http`: responses route without loss on live streams and eligible retries replay by request identity without redispatching the effect (with KSPEC-05 section 4.6's disconnect exceptions), a lagged consumer never hangs, a stale cursor after a restore is refused, and subscriptions survive restarts.
- **KERN-5: isolation evidence.** KSPEC-07 steps 1 and 2, plus `AgentHostBwrap` and `Seatbelt` backend kinds, before any HOST-M2 isolation claim.
  - KSPEC-07 revision 6 adds both kinds. The closed `ConfinementBackendKind` in `chio-cage-plan` carries all five, and `chio_cage::render_tool_confinement` renders a receipt confined only for a verified `FullyEnforced` Linux cage launch bound at dispatch (#1265).
  - Step 1: an adapted server binds its spawn receipt while its child runs, and delivery preparation refuses after exit (#1265). Step 2: the process runner signs `chio.process.container-launch.v1` and binds `worker_profile` from the signed record (#1292).
  - **Status:** the exit is met on main. The native `mcp_serve_http_adapted_server_call_binds_its_verified_cage_launch` case renders a real caged call confined against its persisted launch receipt, and unconfined without the launch or under an unpinned launch signer.
  - **Exit:** the amended backend kinds exist in code, and a receipt renders as confined only when a verified `FullyEnforced` launch record is bound at dispatch; every other native effect renders "unconfined".
- **KERN-6: gates.**
  - KDEF-GT1: one whole hosted CI run passes.
  - KDEF-N4: the Mechanism D gate.
  - KDEF-N1 and N15 become rebase gates, at the #1173 and #1179 merges respectively.
  - KDEF-D7, N6, D11 and D12 each get an owner.
  - **Exit:** a hosted run URL with every required job passing is recorded, the Mechanism D and clock gates fail on violating fixtures and pass on main, and the KDEF register names an owner for each of D7, N6, D11 and D12.
  - **Status on 2026-10-12:**
    - N4 is met: the Mechanism D gate is on main (#1262, `85b74cf023`). Its test fails on nine violating fixtures and passes on main.
    - Owners are named in the register. N6 goes to Root (Codex) under CT-CTRL. D7, D11 and D12 go to Root (Codex) as proposals, because each one needs an owner decision: wiring or deleting `ApprovalGuard` (D7), ADR-0035's scope under SHARE-4 (D11), and whether a production lineage store ships before KSPEC-04 phase 4 (D12).
    - N1 is enforced at the #1173 merge by `scripts/check-security-clocks.py`, which no longer lists `chio-process/src/worker.rs`, so a reverted wall-clock read fails, and by `chio-process/tests/worker_protocol/authority_clock.rs`.
    - N15 is enforced at the #1179 merge by the same clock gate. `chio-control-plane` is in its scope, and the gate refuses inventory entries absent from the pinned scope evidence, so the three new `SystemTime::now()` sites cannot be listed.
    - GT1 is not met. No ci.yml run on main has completed with every job passing since #1160. The last completed run, [38183162158](https://github.com/bb-connor/arc/actions/runs/38183162158) on `28d826e3e`, was cancelled after two hours. In it, cargo-deny, cargo-vet, four apalache jobs, the threat-model coverage gate, the three nonce/FIPS jobs and the enterprise portable contracts passed. Two jobs failed on setup: enterprise real Linux enforcement and enterprise adversarial evidence both stopped at the trusted-file pin, because the repository variable `CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` still names the #1160 review head `d0496c14d`. Build, lint, test, Security contract and apalache-subset failed only as aggregates of cancelled or failed jobs. Seventeen jobs, including Workspace tests, MSRV, Build and lint and kani-public-pr, were cancelled with no verdict, and one was skipped. The 68 runs on main since then are queued and none has started.

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
- KSPEC-04 phase 4. Phase 3 is KERN-3b, a prerequisite of COMP-3 and G4.

### Lane SHARE: share resources, and HOST-M2 on Linux

Today "share resources" runs on seven or more separate counters:

- grant holds;
- aggregate families;
- basis-point shares;
- process shares;
- WORK-D1 slots;
- WORK-S1 pools;
- the finding pool.

Only the kernel hold ledger durably records consumption. Money is not pooled across delegated children, and the only pool siblings share counts invocations across one hop.

**Rungs.**

- **SHARE-1: one consumption ledger.**
  - The kernel hold ledger is the only consumption authority.
  - Every other counter becomes a commitment entry or a view, following #1174's sealed-ledger proposal.
  - First slice: a family monetary cap, using #957's co-debit pattern, plus a durable sibling registry.
  - Basis-point shares already have sibling-sum enforcement at admission: `admit_capability_budget` submits `budget_share_bps` to `try_admit_child`, and an oversubscribing child is denied before dispatch. #1160's foundation also makes caller shares durable: `validation/caller_budget.rs` loads durable caller budget shares and combines them with live admissions, and `restart_preserves_the_delegated_share_of_a_live_caller_reservation` covers restart. What is missing is the consumption binding and the legacy path: a share never bounds what the child actually spends, and the legacy `InMemoryBudgetRegistry` path on main still fails closed after a restart until prior reserved holds close. Decide what a share bounds in the hold ledger, and retire the legacy in-memory path in favor of the foundation's durable sibling registry after Gate 0.
  - **Exit:** tests show a child denied once its siblings exhaust the family monetary cap, no share or hold replenished by a restart, and the decided rule for what a share bounds enforced in the hold ledger; the legacy in-memory registry path is retired.
- **SHARE-2: model spend through the kernel.**
  - Model calls route through the broker's provider adapter, using the worst-case-then-reconcile lifecycle.
  - Add a token quota for subscription harnesses.
  - Fix the required-agent profile, which issues a fresh counter per session. Megastart's bound-session pattern is the reference.
  - Today's "model relay" is a Python request counter inside the Hermes SDK.
  - **Exit:** a model call reserves its worst case before dispatch and reconciles down after, a lost model reply keeps its reservation, the token quota denies at exhaustion, and two sessions of the required-agent profile draw down one counter.
- **SHARE-3: HOST-M2 on Linux.**
  - One root grant across the harnesses outside teams run: Claude Code and Codex first, then Pi and Hermes.
  - Live cancel and revoke while the host runs.
  - Serving-path swarm admission beyond depth 1 and the `tool_calls` dimension.
  - Restart never replenishes a pool.
  - **Exit:** on one Linux host, exhausting the root grant from one harness denies the other, revoking the root mid-run denies every child with a receipt, a swarm deeper than one level is admitted within its limits and denied beyond them, and a kill-and-restart suite across pool kinds replenishes nothing.
- **SHARE-4: cleanup.**
  - Accept ADR-0016 (the authoritative spend contract).
  - Write ADR-0035 (web3-free distribution) at its real scope: the kernel, core, control plane and CLI. ADR-0035 is a candidate number in #1170; no such file exists yet.
  - Make `finding-market` and `web3` off by default.
  - Move the x402 and ACP clients out of the kernel (KSPEC-01 R13).
  - **Exit:** ADR-0016 reads Accepted, ADR-0035 is merged, default builds of the kernel, core, control plane and CLI pull in no web3 or finding-market code, and the kernel crate no longer contains the x402 and ACP clients.

**After the test.**

- macOS HOST-M2: a Darwin process runner, a Keychain and XPC broker, and `LOCAL_PEERTOKEN` IPC. It stays after the test (ruling of 2026-10-09, section 1): the executing organization at G5 runs Linux, and macOS-only teams take part as the counterparty.
- Economy modules: funded WORK-W2.3, and x402 as a module.
- Sender-funded holds shared across organizations.

### Lane REL: something outsiders can install and connect to

- **REL-1: the preview train.**
  - SEC-M9 packaging and SEC-M10 publishing.
  - #1160's post-merge obligations for a full release; previews ship under the D8 exception recorded in the landing ledger.
  - Close out the AWS-LC fork audit (review sufficiency: D16). The source audit and its independent review are already on main (`docs/security/audits/aws-lc-rs-1.18.1-fork.md`, `aws-lc-rs-1.18.1-independent-review.md`). The audit states that it is not an approval to publish a release.
  - Turn the Release Qualification workflow green. `docs/release/RISK_REGISTER.md` requires hosted CI and Release Qualification success before tagging, and Release Qualification has failed on every recent push to main.
  - Signed binaries for Linux x86_64 and arm64 and macOS arm64.
  - A container image with the dashboard embedded. Today the dashboard is in no release artifact.
  - Carry #1046's workspace dependency versions so that `cargo package` works; #1046 closed without them (section 7).
  - Fix `CHANGELOG.md` and the install docs, and sync the distribution mirror with `scripts/mirror-to-chio.sh` (#1056).
  - Mark v0.1.0 superseded and resolve crates.io (decision D10), the npm and PyPI 0.1.0 packages, and the stray tags (section 2).
  - Publish the format-stability note.
  - **Exit:** a signed `0.2.0-alpha.N` tag whose commit has Release Qualification green; the published installer verifies and installs it on Linux x86_64 and arm64 and macOS arm64; the distribution mirror carries the tag; the GitHub release is a prerelease, not Latest.
- **REL-2: the MCP door.**
  - Interop with MCP revision 2026-07-28 (stateless core); today the edge accepts only 2025-11-25.
  - `chio mcp serve-http` accepts presented, federated capabilities, or a bridge-daemon shim adds them.
  - **Exit:** current Claude Code and Codex connect through ordinary remote MCP, with no plugin.
- **REL-3: harnesses.**
  - Claude Code and Codex are co-first, in MCP mode. Hooks count as coverage, never enforcement, because hook failure does not block either host.
  - Linux restricted launchers for the HOST-M2 harnesses. Today Pi has bubblewrap; Claude Code, Codex, Cursor and Hermes are Seatbelt-only; OpenClaw is a container.
  - Publish Pi, the bridge and the plugins with tested version ranges.
  - The bridge operator checks the requested approval ID and signed decision before retaining a response ([implementation and regression tests](https://github.com/backbay-labs/chio-bridge/pull/4)); [`chio-bridge#3`](https://github.com/backbay-labs/chio-bridge/issues/3) is closed. Archive publication and tested plugin version ranges remain required.
  - **Exit:** on Linux, each HOST-M2 harness's restricted launcher leaves the kernel port unreachable, denies arbitrary egress and records its KSPEC-07 evidence; Pi, the bridge and the plugins are published with tested version ranges; `chio-bridge#3` is closed.
- **REL-4: the operator surface.**
  - The trust-control dashboard is the one operator web client. It is read-only today and served only from a relative path.
  - It gains:
    - approval routes;
    - per-operator authentication beyond the shared bearer token entered at login;
    - the issuance panel;
    - authority-tree and pool views.
  - Plus the onboarding kit and runbooks.
  - **Exit:** an operator following only the onboarding kit on two clean hosts completes G2's six steps, and dashboard tests deny a viewer on approval routes and reject a token in the query string.

### Lane OUT: outside teams, positioning, standards

- **OUT-1: recruiting.**
  - A named owner (STRAT-F4).
  - Candidate teams per the private GTM plan (STRAT-F1).
  - Trial terms; legal groundwork (STRAT-F13).
  - A receipt-privacy rule (STRAT-F10).
  - Teams onboard at G2 so that their infrastructure, keys and working relationship already exist by G5.
  - **Exit:** D13 and D14 are recorded, and at least two outside teams have accepted trial terms and onboarded by G2.
- **OUT-2: positioning cleanup** (section 9).
  - **Exit:** every stale surface listed in section 9 is fixed on main.
- **OUT-3: standards.**
  - The IETF -00 (decision D11).
  - WIMSE and ODIS positions.
  - Platform interoperability is technical only, and no platform is a dependency. Build OpenShell middleware only if a candidate team runs OpenShell. Track the Agent Policy Fabric for interop changes. Channels and audiences are in the private GTM plan.
  - **Exit:** D11 is recorded and carried out, and the WIMSE and ODIS position notes are merged.
- **OUT-4: records.** Independent-operation records and ADR-0011 claim reviews for every gate.
  - **Exit:** each gate's claims have a recorded ADR-0011 review before they are made, and G2 and G5 each publish an independent-operation record.

### Lane COMP: the Computer developer surface

Chio Computer (#1199) is the developer face of the substrate lanes. A developer forks a project, composes work, grants bounded access to another organization's computer, joins the run and applies the exact accepted change. Computer composes the existing owners. It adds no authority engine, ledger, scheduler or recovery reducer.

**Computer-0** is the profile the success test uses (D21). G4's substrate includes KSPEC-04 phase 3 through KERN-3b, promoted for the CMP-C5 join contract. The remaining post-test scope stays excluded:

- **Backend:** git-native. Snapshots are tree objects, revision heads are refs, and apply is a compare-and-swap of a ref against the expected base. Apply uses the resource owner's commit fence. KSPEC-10's crossing primitive is adopted when it lands after the test.
- **Independent organizations:** a receiver-local overlay plus sealed import. Computer-0 offers the source-owned branch service only for same-domain placement; an independent-organization service would require a separately qualified profile.
- **Resources are charged at their owner's door.** Grants over source-owned resources, such as a model route, are enforced and charged by the source's own hold ledger through the source's broker. This requires no funding transfer between the two organizations. The source cap does not cover the receiver's independently billed compute or harness/model use.
- **Delegation stays inside the receiver.** The receiver's broker holds the foreign grant as one authenticated hop and enforces each helper's current local authority, exact work/resource binding and release context before forwarding. The source authenticates that broker and applies its own current grant/consumption checks. Local forwarding and source dispatch retain their separate owner fences and original operation identities; neither promises an atomic cross-owner revocation instant. Multi-hop across independent keys stays after the test (COOP).
- **Security profile:** REC supplies retained labels/influence, current release, exact artifacts and protected acceptance; KERN-1 supplies KSPEC-08 phases 0 and 1, and KERN-3a and KERN-3b supply KSPEC-04 phases 1 to 3. Computer-0 does not claim KSPEC-09 to KSPEC-11 mechanisms or later KSPEC-08 phases. A request requiring an unavailable integrity/endorsement profile is refused, never silently downgraded to ordinary work acceptance.
- **Agreements:** unpaid (D5).
- **Two leaf kinds (D22):**
  - a **TaskLeaf** is a contract that one of the receiver's own admitted harness profiles performs;
  - a **ProgramLeaf** is the source's pinned bundle, run under the receiver's code admission and a qualified KSPEC-07 confinement kind.

**Rungs.**

- **COMP-1: closed descriptions.** CMP-C1 records, CMP-C3 descriptors for both leaf kinds, the canonical compiler, and Rust, Python and TypeScript vectors. It is unblocked now, because it depends on nothing on the critical path. Like every rung, it starts on the explicit start. CT-WORK freezes the compile target.
  - **Exit:** shared vectors, bounds, occurrence identity, operator-precedence vectors (D23) and refusal of forged plans.
- **COMP-2: git-native managed branches.** Snapshot, branch, freeze, seal, release-checked diff, and apply by ref compare-and-swap. It is unblocked now and starts on the explicit start. It binds REC-P4 labels when they land. It salvages #1164's worktree and patch-review code.
  - **Exit:** branch isolation, recovery from interrupted publication, base conflict, and fencing of stale writers.
- **COMP-3: composition on WORK.** Compile into WORK-W1 allocation, acceptance and graph extension; protected verification; the CMP-C5 view and `join_tree` closure. It depends on WORK-W1, KERN-3a and KERN-3b, including KSPEC-04 phase 3. Computer retains owner fence references and completeness evidence, never a second issuance head.
  - **Exit:** real native execution with exact acceptance, the six-dimension view, and evidence from admission and closure races.
- **COMP-4: independent computers.** CMP-C4 bindings:
  - TaskLeaf to the receiver's harness profiles (REL-3, SHARE-3);
  - ProgramLeaf to KERN-5 confinement;
  - door-charged resources (COOP-3, SHARE-2);
  - helper-to-broker authority intersection, holder/proof-of-possession checks, context preservation and original-operation recovery (CMP-C4-10 to CMP-C4-15);
  - lost-reply recovery (REC).

  It depends on WORK-W2, REC, COOP-3, SHARE-2, KERN-5 and G3.
  - **Exit:** G4's complete run executes as the Computer proposal's Application A.
- **COMP-5: installed surface.** The SDK and CLI from installed packages, through WORK-W3, shipped in the preview (REL-1).
  - **Exit (gates G5):** the full hero, including Application A's lost-reply and source-conflict cases, runs from installed packages outside the source checkout. The exit first passes on a preview build. G5 requires it to pass again on the release G5 uses.
- **COMP-6: dogfood.** After the COMP-2 and COMP-3 exits pass, #1197's development swarm runs its lanes as Computer forks, and its merge gate becomes an expected-base apply with exported evidence. This is same-domain, so it never counts toward independence.
  - **Exit:** Chio's own merges land through Computer.
- **COMP-7: second-application reuse (required; never gates G5).** Application C (versioned data curation) runs on the installed Computer-0 surface. It depends on the COMP-5 Exit's first pass on a preview build, which proves the full installed hero, including managed branches, accepted work and lost-reply recovery. Package installation alone does not satisfy this prerequisite. Because it can start before the G5 release is cut, a second consumer finds API problems while they can still be fixed in that release. Its final evidence is recorded on the release G5 uses. It may run internally and never substitutes for G5's outside-team runs. COMP-6 is not a prerequisite. Application B (confined work beside private data) remains optional stretch scope.
  - **Exit:** Application C produces an accepted, sealed CSV/JSON dataset revision, releases its governed diff and publishes by expected-base apply. A source-conflict drill refuses stale publication and a lost-reply drill recovers the original operation. Record installed package identities and reuse evidence outside the source checkout. The application reuses the same owners and adds no custom signing, retry, verifier service or consumption ledger; domain predicates and transformations remain application code.

## 5. Gates

```text
Gate 0 ─┬─ REL-1,REL-2 + KERN-1,KERN-2,KERN-6 + OUT-2 ──────> G1 preview installable
        │                                                     │
        ├─ COOP-1,COOP-2 + REL-4 + OUT-1 ─────────────────────┴─> G2 outside HOST-M1 ──┐
        │                                                                              │
        ├─ SHARE-1..3 + KERN-3a,KERN-5 + REL-3 + WORK slice β ─> G3 HOST-M2 on Linux ──┤
        │                                                                              │
        ├─ WORK-W1..3 + REC + COOP-3 + KERN-3b,KERN-4 + COMP-1..4 ─────────────────────┴─> G4 internal HOST-M3 ──┐
        │                                                                                                        ├─> G5 outside HOST-M3 x2
        └─ COOP-4 + COMP-5 ──────────────────────────────────────────────────────────────────────────────────────┘
```

KERN-3a has its own capability/process closure and process-exit evidence for G3. KERN-3b qualifies graph/delegation closure after WORK-W1 and before COMP-3/G4; it does not gate G3. Required second-application reuse is COMP-7. It depends on the COMP-5 Exit's first pass on a preview build, may finish before or after G5, and never gates G5.

WORK, REC, COOP-3, KERN-3b, KERN-4 and COMP-1 to COMP-4 join at G4. G4's complete run needs co-signed work, lost-reply recovery, the HOST-M3 door and the Computer-0 hero that executes it. COOP-4 and COMP-5 join at G5 directly. G4 verifies evidence against pinned partner keys (COOP-1). COOP-4's checkpoint compatibility and edge audit serve outside counterparties. COMP-5 puts the hero into the installed release that outside teams run.

**G1: an outsider can install the preview.**

- A tagged `0.2.0-alpha.N`.
- A timed install by someone outside the core team, on Linux and on macOS, through to a first receipt.
- Current Claude Code and Codex connect over MCP and produce allow and deny receipts.
- The CT-WIRE freeze list is published.
- Not blocking: if COMP-2 has passed when the preview is cut, the preview carries a local fork, diff and apply, so recruits can try them early. G1 does not wait for any COMP rung.

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
- The run executes as the Computer proposal's Application A, through the Computer-0 hero. It exercises a TaskLeaf on B's own harness and a confined ProgramLeaf (COMP-4).

**G5: the success test.**

- A preview release that contains HOST-M3.
- Two outside teams each complete a qualifying run, satisfying section 1 criteria (a) to (g).
- At least one team repeats its run unassisted.
- Each team runs the installed Computer hero (COMP-5) in its qualifying role under section 1. An executing team performs at least one TaskLeaf on its own admitted harness. A requesting team's own agent proposes and composes the work (criterion b). Both roles qualify, including a macOS-only team requesting work that Backbay executes on Linux.
- At least one ProgramLeaf runs in a qualifying G5 run, whichever organization executes it, Backbay included. Cooperation between the two outside teams stays the strongest form, not a requirement.
- Stretch: the Computer proposal's Application B, confined work beside another owner's private data.
- The records are published and reviewed.

**Critical path.** This document makes no capacity or duration projections, so it cannot say which branch finishes last. Every prerequisite of G4 in the graph above therefore stays on the critical path until it closes:

- Gate 0;
- G2, which joins G1 (REL-1, REL-2, KERN-1, KERN-2, KERN-6 and OUT-2) with COOP-1, COOP-2, REL-4 and OUT-1;
- G3: SHARE-1 to SHARE-3, KERN-3a, KERN-5, REL-3 and WORK slice β;
- WORK-W1, WORK-W2 and WORK-W3, with KERN-3b after WORK-W1's qualified issuer;
- REC;
- COOP-3;
- KERN-4;
- COMP-1 to COMP-4.

G5 then waits on G4, COOP-4 and COMP-5.

The three riskiest unproven pieces get the largest swarm allocation and the earliest prototypes:

- #1179's rebase and requalification;
- WORK-W2.2's durable bilateral delivery;
- COMP-3's `join_tree` closure, which needs KERN-3a's process fences and KERN-3b's graph/delegation fences after WORK-W1's qualified issuer.

G2 and G3 run in parallel with the WORK, REC, COOP-3 and KERN-4 branches, but G4 waits on both, so neither is slack. HOST-M1 never depends on #1179.

**Claims each gate permits.** These use ADR-0011's vocabulary. Every claim is limited to kernel-mediated calls and carries the preview label until the qualification in section 11.

| Gate | Claim | `boundary_class` | `planning_status` |
| --- | --- | --- | --- |
| G1 | Calls through the MCP door and `chio api protect` are authorized or denied before effect, each with a signed receipt. | `prevent` | `ready_after_adr` (CT-WIRE, CT-REL) |
| G1 | Harness hooks observe native tool use. | `detect_only` | `ready_after_adr` |
| G2 | B's door admits A's agent only within B-issued, attenuated, holder-bound authority. | `prevent` | `ready_after_adr` (CT-COOP) |
| G2 | A verifies B's receipts offline against operator-pinned partner keys, with no external witness. | `detect_only` | `ready_after_adr` (CT-COOP) |
| G3 | One root grant's holds bound spend and invocations of kernel-mediated calls across harnesses on one host. | `prevent` | `ready_after_adr` (ADR-0016, CT-ABI) |
| G3 | Native effects outside the kernel path where a qualified KSPEC-07 backend confines them (a verified `FullyEnforced` launch record bound at dispatch) are denied before effect outside that confinement. | `prevent` | `ready_after_adr` (KSPEC-07) |
| G3 | Native effects outside the kernel path with no qualified KSPEC-07 backend are out of layer and not covered; receipts render them "unconfined". | `cannot_see` | `ready_after_adr` (KSPEC-07) |
| G4, G5 | The receiver admits a co-signed work commitment at its own door. | `prevent` | `ready_after_adr` (CT-WORK, CT-CROSS) |
| G4, G5 | A lost reply is recovered by original identity with no second dispatch. | `prevent` | `blocked_by_adr` until CT-SETTLE is frozen (D1 and D2 decided 2026-10-09) |
| G4, G5 | The evaluator's signed acceptance or rejection is recorded. | `detect_only` | `ready_after_adr` (CT-WORK) |
| G4, G5 | Apply publishes the exact accepted ChangeSet only while the source ref still equals the expected base; a moved base is a conflict. | `prevent` | `ready_after_adr` (CT-WORK, D21) |
| G4, G5 | Grants over source-owned resources are enforced and charged by the source's own hold ledger at the source's door. | `prevent` | `ready_after_adr` (CT-COOP, ADR-0016, D21) |
| G4, G5 | A ProgramLeaf runs only under the receiver's code admission and a qualified KSPEC-07 confinement kind. | `prevent` | `ready_after_adr` (KSPEC-07, D22) |
| After G5 | Rail settlement outcomes and cross-org money. | `detect_only` | `deferred` |

## 6. Start now

None of these depended on #1160, which is now on main. Status is as of main `b6ad31043`.

| # | Action |
| --- | --- |
| U1 | **STRAT-F1:** decide which #1170 documents stay public. |
| U2 | **Done.** STRAT-F17 is voided and the Clawdstrike portfolio-boundary framing is removed from `docs/research/nvidia/`. #1177's macOS Clawdstrike review landed earlier as a prior-art note (`docs/superpowers/specs/2026-10-07-macos-integration/research/clawdstrike.md`). |
| U3 | **Positioning PR** (section 9). It covers every stale surface on main. |
| U4 | **In progress.** **KDEF-N23:** constant-time comparison of the admin token (`crates/platform/chio-http-core/src/emergency.rs:193`, the `token == self.expected_admin_token` match arm, still present on main), plus the AC6 stop-scope document. |
| U5 | **In progress.** **x402 fails open.** `X402AuthorizeResponse.settled` defaults to `true` when the field is absent (`crates/kernel/chio-kernel/src/payment.rs:496`, `default_true` at `:958`, still present on main). Default to not settled, failing closed. |
| U6 | **Done.** [`backbay-labs/chio-bridge#3`](https://github.com/backbay-labs/chio-bridge/issues/3): `approval-decide` binds both approval IDs and the verified decision to the operator's request before retaining a response. A matching signed denial cannot activate a resumed action. [Implementation and regression tests](https://github.com/backbay-labs/chio-bridge/pull/4). REL-3 publication remains open. |
| U7 | **Recruiting:** a named owner, trial terms and legal groundwork. |
| U8 | **IETF -00:** decide whether to submit by the cutoff (section 10). If it is submitted, fix or flag the single-key multi-hop rule first: step 7 of the draft's Delegated Issuance section (the delegation policy's signer must be a key the issuing authority itself trusts), read with the one-link limit in its Chain Binding section. |
| U9 | **CT-CROSS:** decided on 2026-10-09 (D4). Draft the contract early, because the free iroh relays end (section 10). |
| U10 | **Notices done.** Deprecation notices are in `docs/install/README.md`, `CHANGELOG.md` and the `chio-sdk-python` README. The live website installer, the GitHub `v0.1.0` release and the npm, PyPI and crates.io packages are outside this repository and are replaced at G1 (REL-1). |

## 7. PR dispositions

**Rule:** no PR closes until its ledger requirements are carried forward. That means:

- 136 requirements on #957 to #959;
- 27 on #956;
- 15 on #1159;
- 12 on #1164;
- 5 on #1171 (merged on 2026-10-09);
- 2 on #1046 (closed on 2026-10-12; one carried, one not, see its row);
- 2 on #1172;
- 1 on #1073;
- 1 on #1158;
- the FV-D3 dependency on #959's netting code;
- #1029's singular-approval ADR decision.

| PR | Disposition |
| --- | --- |
| #1160 | **Merged** on 2026-10-11 as squash `28d826e3e`, tree-equal to reviewed head `29327c5d7`, with qualification recorded as incomplete (G0.1). |
| #1196 | **Merged** on 2026-10-09 (`fe62a6b39`). This document. |
| #1172 | Rebase onto main, then land (Lane REC). It was cut from pre-squash #1160 history, so it no longer merges cleanly (section 2). |
| #1173 | Split by path into slices α, β, γ, c, d and δ; re-derive or drop ε and ζ. Close when the slices land. Before closing, tag the paper's pinned source commits (`71e5cbc3b`, `7755d3762`, `611660eb2`), which main does not contain and only unmerged branches reach; otherwise `paper-artifact-check` loses them when those branches go. |
| #1179 | No longer marked draft, but not ready to land until it is re-scoped and rebased onto main (Lane REC). |
| #1174 | **Merged** on 2026-10-12 (`7b293ab37`) as the KSPEC program, by merging the PR (owner decision 2026-10-09). Its north-star research document carries a historical banner pointing to the approved north star. |
| #1177 | **Merged** on 2026-10-09 (`3af65d2d2`) by merging the PR (owner decision 2026-10-09), before the restructure and the server-first HOST-M1 re-cut. NORTH-STAR-FLOWS is marked approved, ADR-0038 carries its 2026-10-08 amendment, and the macOS Clawdstrike review is a prior-art note (U2). The restructure, the HOST-M1 re-cut and moving macOS HOST-M2 after the test are follow-ups on main. HOST-M1 code does not wait on the docs restructure. |
| #1170 | **Merged** on 2026-10-12 (`344a9bc58`). F-17 was voided after the merge (U2). The other steps now apply to the merged documents on main: split private material per U1; scope ADR-0023 to ADR-0038 (thin OS adapters allowed; broker, cage and launchers not frozen); scope ADR-0028 to "where an IdP exists"; replace the review criterion with section 1; drop the capacity model. |
| #1171 | **Merged** on 2026-10-09 (`3e5f45307`) by merging the PR (owner decision 2026-10-09). Submit the -00 if U8 says so. Federation material goes to companion drafts later. |
| #1164 | Close. Salvage its MCP adoption, activation and preview-distribution machinery into Lane REL, and its worktree and patch-review machinery into COMP-2. |
| #1200 | **Merged** on 2026-10-12 as squash `d9ecdfe2d`, before #1199. Because it was squashed, #1216 re-pinned #1199's `research/source-evidence.json` and crosswalk from the #1200 branch head to `d9ecdfe2d` and regenerated `validation.json` with no errors. |
| #1199 | **Merged** on 2026-10-12 (`ee0f29134`), after #1200, as the Computer design (Lane COMP; D21 to D23), with explicit Computer-0 prerequisites and acceptance profiles. Its evidence is pinned to the #1200 squash commit (#1216). |
| #1197 | **Merged** on 2026-10-12 (`17c6a4bc4`). Internal development tooling. COMP-6 runs its lanes on Computer after COMP-2 and COMP-3. |
| #1161, #1159, #1158 | Close as contained in #1173. #1161's peer transport is example-only and does not satisfy STRAT-F15. |
| #1162 | Archive its evidence and `examples/repair-machine-proof`, then close. Its outcome-continuation code, carried in #1173, needs a slice or a drop (D19). |
| #1163 | Decide whether the paper's bilateral-admission benchmark must be regenerated, then close. |
| #1136 | **Closed** on 2026-10-12 as superseded: main carries its `chio-sqlite-file-identity` fix through #1160. |
| #1046 | **Closed** on 2026-10-12. Its MCP `nextCursor` fix landed separately as #1221. Its empty-roots allowlist change was deliberately not carried, because main fails closed. **Its workspace dependency versions, which make `cargo package` work, were not carried:** workspace packaging stays `publish = false`, and that salvage remains open in REL-1. |
| #1056 | **Merged** on 2026-10-12 (`cecea4ccf`) as `scripts/mirror-to-chio.sh`, the distribution mirror sync REL-1 uses. |
| #1201 to #1232 | **Merged** on 2026-10-12 as follow-ups to #1160: CI, the landing ledger and auditor, security, kernel and store fixes, and crate documentation (section 2). |
| #1155 | **Salvage into REL-1** as the preview install path. |
| #1073 | **Salvage into REL-1** (release qualification budget). |
| #1043 | Owner review: archive or close. |
| #1029 | Close as superseded by #1160, after checking its three economy items against main (settlement-observer idempotency key, credit election, MustPrepay). Its ADR-0018 collides with main's ADR-0018 and must be renumbered if any of it survives. |
| #956 to #959 | Salvage, then close. From #956: the unforgeable `VerifiedApproval`, settlement terms inside the signed intent, single use keyed on request and intent, and raw builders made `pub(crate)`. From #957: the co-debit pattern. From #958: the escrow `accept()` invariants. From #959: the conformance tests `x402_payment_does_not_authorize_tool_call` and `eas_verax_display_only_projection`. Drop #957's Chio Pass kernel gating and #959's closed-enum wire break. |
| Unmerged branches | Archive `research/genesis-program` (its ADR-0018 also collides), `project/roadmap-04-25-2026`, `docs/native-application-adoption` and `research/funded-work-baseline`. Retarget `release-tagged.yml` off `project/roadmap-04-25-2026` first (REL-1). |
| `backbay-labs/chio` | Megastart (#9, #10, #25) and the agentic OS suite (#4, #5) become HOST-M2 showcases after the test. Megastart's allowance is already a kernel-held aggregate-family quota. What remains is moving it to the host's shared admission owner and adding spend. The chio-world app (#228) needs an explicit decision. |

## 8. Owner decision register

| # | Decision | Recommendation | Status | Blocks |
| --- | --- | --- | --- | --- |
| D1 | Settlement composition | Adopt #1174 decision 4 on #1160's sweep (CT-SETTLE). | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes CT-SETTLE; also gates the REC re-scope and the WORK slice δ. | Gate 0, REC, WORK slice δ |
| D2 | Signer-rotation rule | Sign with the current key and bind the original identity, uniformly across finalization, release and waiver. Today #1160 quarantines, #1179 re-signs and #1173 refuses. | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes the CT-SETTLE rotation rule. Open sub-question, to be settled inside CT-SETTLE: whether a finalization under a rotated signer may deliver output, or only withhold it (#1179). | Gate 0, REC |
| D3 | Schema allocation | Landing order under the ledger lock; symbolic names on branches. | **Decided 2026-10-09:** the owner accepted the recommendation. The ledger lock goes live as policy. | Gate 0 |
| D4 | Cross-org transport | Default to HTTPS with mTLS or signed bodies, which fits outside teams' firewalls and operations. iroh stays an optional lane with self-hosted relays. | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes CT-CROSS. | Gate 0, COOP-3, WORK-W2.2 |
| D5 | Unpaid work agreement | Add an unpaid `Agreement` variant to `chio.work.v1`. | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes the CT-WORK `Agreement` variant. | Gate 0 |
| D6 | Holder possession | Require DPoP for federated grants at the door. | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes the CT-COOP DPoP profile; COOP-2 implements it. | Gate 0, COOP-2 |
| D7 | Canonical repositories | `bb-connor/arc` is the development repo; `backbay-labs/chio` is the distribution mirror, synced on every tag. | **Decided 2026-10-09:** the owner accepted the recommendation. Freezes the CT-REL repos; the REL-1 mirror sync assumes it. | Gate 0, REL-1 |
| D8 | Preview exception | Allow tagged `0.2.0-alpha.N` previews before #1160's full-release obligations close. They are labelled as previews, with claims limited under ADR-0011. | **Decided 2026-10-14:** the owner adopted it. The amendment to #1160's operator ruling of 2026-10-08 (`release_permitted: false` in `docs/security/audits/foundation-landing-boundary-20261008.json`) is recorded as `preview_exception_20261014` in the landing ledger; non-preview releases stay not permitted. | G1 |
| D9 | Licensing (STRAT-F5) | Apache-2.0 for verifiers, adapters and preview binaries. | Open | G1 |
| D10 | crates.io | Yank 0.1.x with a pointer to the preview channel, unless the Rust library is in the preview's supported surface. | Open | G1 |
| D11 | IETF -00 | Submit as an individual draft, with the multi-hop rule flagged as an open issue. | Open | OUT-3 |
| D12 | Required harnesses | Claude Code and Codex for G1 to G5; Pi and Hermes as additional HOST-M2 harnesses; record a decision on OpenClaw and Cursor after the test. | Open | REL-3, G3 |
| D13 | Recruiting owner and legal (STRAT-F4, F13) | Name the owner and start legal now. | Open | G2 |
| D14 | Receipt privacy (STRAT-F10, ADR-0036) | Argument commitments before any outside run, or at minimum a rule of no personal data in arguments. | Open | G2 |
| D15 | STRAT-F1 | Keep commercially sensitive and GTM material private; publish the rest after review. | Open | #1170 merge |
| D16 | AWS-LC review sufficiency | None yet. The fork's source audit and its independent review were both done by agents. Do agent-only reviews suffice for a preview release, or does the fork need a human or external review? | Open (raised 2026-10-09) | REL-1 |
| D17 | #1179's intermediate store formats | None yet. #1179 steps its never-released admission store through six formats (v35 to v40 on its branch). They could collapse into fewer slots when #1179 takes slots under the ledger lock (D3). Collapsing them breaks #1179's ignored legacy-capture tests. | Open (raised 2026-10-09) | REC rebase |
| D18 | Co-sign bytes in CT-WIRE | None yet. Freeze #1160's bilateral DSSE predicate, or #1173 slice γ's revised specification with `reconstruct_dsse_pae`. γ lands after Gate 0, so freezing γ's bytes means CT-WIRE takes them before γ merges. | Open (raised 2026-10-09) | Gate 0 (CT-WIRE), slice γ |
| D19 | #1162's outcome-continuation code | None yet. #1173 carries #1162's `chio-runtime-core` outcome continuation (`src/outcome_continuation.rs` and its SQLite store), but no slice names it. Assign it to γ with the treaty runtime-core, or drop it. | Open (raised 2026-10-09) | #1173 and #1162 closure |
| D20 | Contract version number | Keep `spec/schemas/VERSION` at 1.0.0 and label `spec/PROTOCOL.md` "1.0 preview, not stable". | **Decided 2026-10-27.** | CT-WIRE, G1 |
| D21 | Computer-0 profile | Computer is the face of the success test, on G4's substrate including KSPEC-04 phase 3 through KERN-3b. The backend is git-native; independent organizations get a receiver-local overlay plus sealed import; resources are charged at their owner's door; receiver-local delegation preserves each helper's rights at the broker; agreements are unpaid. Later integrity and financial profiles remain excluded. | **Decided 2026-10-09:** the owner accepted the recommendation. Review on the same day added the closure prerequisite (KSPEC-04 phase 3 in KERN-3b), which the CMP-C5 join contract requires. | COMP, G4, G5 |
| D22 | Computer leaf kinds | TaskLeaf (the receiver's own admitted harness performs a contract) and ProgramLeaf (the source's pinned bundle under receiver code admission and KSPEC-07 confinement). | **Decided 2026-10-09:** the owner chose both from day one. | COMP-1, COMP-4, KERN-5 |
| D23 | Composition syntax | `&` for parallel and `\|` for sequence, so `a & b & c \| d \| e` needs no parentheses in Python or Rust; canonical `parallel(...).pipe(...)` for TypeScript and every other language. | **Decided 2026-10-09:** the owner accepted the recommendation. | COMP-1 |

**Recorded, not open:**

- decisions D1 to D7 and D21 to D23 (2026-10-09, table above);
- the executing team at the success test runs Linux; macOS-only outside teams take part as the counterparty; macOS HOST-M2 stays after the test (ruling of 2026-10-09, delegated by the owner; section 1);
- #1174, #1177 and #1171 land by merging their PRs (owner decision 2026-10-09; section 7);
- the success test and the qualifying-run definition (section 1);
- STRAT-F17 void;
- ADR-0023 scoped to ADR-0038;
- ADR-0028 scoped to "where an IdP exists";
- #1170's review criterion replaced;
- demos: Demo C becomes G2; the reduced Treaty Call becomes G5; Demos A, A2 and B are retired as separate builds;
- accept ADR-0016;
- ADR-0035 at full scope.

ADR-0023, ADR-0028, ADR-0035 and ADR-0036 are candidate numbers inside #1170's strategy documents; none of those files exists yet. ADR-0038 is on main with #1177. Otherwise the ADRs on main run to ADR-0022, and main's ADR-0018 (Radicle carrier) is the number that #1029 and `research/genesis-program` collide with.

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
| Standards bodies | No tagline; artifact names only | Interop vectors |

**The developer example.** The Computer hero (#1199) is the README and recruiting example. It stays labelled as a preview until the rung behind each of its claims passes. Its builder line, cross-org clause first: "Across organizations, Chio gives agentic operating systems the Unix process model with authority attached: fork, exec, join and apply."

Platform and vendor audiences, channels and messaging are in the private GTM plan. This document keeps only the technical interoperability requirements (OUT-3).

**Stale surfaces on main to fix (U3):**

- **README.md** (line numbers are against main `002b4d14e`; #1160 shifted them, so U3 matches on the text):
  - line 16: "The kernel your agents answer to";
  - line 22 and `docs/assets/subhead.svg` / `subhead-mobile.svg`: "Agents that pay each other" and the unscoped "every call";
  - lines 78 and 156: "pay each other";
  - the unscoped "every call" wording at lines 73, 128, 172, 177 and 259;
  - lines 44 and 251: the installer links, which #1160 already removes;
  - the from-source `git clone` of `backbay-labs/chio` (line 254; line 260 after #1160), which clones the distribution mirror while it is stale (REL-1 syncs it);
  - line 242 (line 251 after #1160): the "Settlement and anchoring" row's on-chain settlement and cross-chain anchoring claim, "backed by the Chio settlement contracts", which the payments rule below forbids.
- **`docs/reference/COMPETITIVE_LANDSCAPE.md`:** "only protocol".
- **`AGENTS.md`:** lines 5 and 11.
- **`docs/start-here/VISION.md`:** needs a historical banner.
- **`CHANGELOG.md` and `docs/install/README.md`:** they contradict the v0.1.0 release.
- **The `spec/PROTOCOL.md` header.**
- **The ADR indexes:** `docs/README.md` stops at ADR-0020 and `docs/adr/README.md` at ADR-0021, while ADR-0022 exists.

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
| `WORK-` | Verifiable work (#1173) | W1.0 to W4.x; D1 dynamic delegation; S1 swarm evolution |
| `PAPER-` | Verifiable-work paper | P.1 to P.5 |
| `REC-` | Recovery (#1172, #1179) | P0 to P6 |
| `KSPEC-` | Kernel specs (#1174) | specs 1 to 11 (often written S1 to S11) |
| `KDEF-` | Kernel defects (#1174) | D1 to D12, N1 to N30, GT1 |
| `STRAT-` | Strategy (#1170) | F-1 to F-17, D30/D60/D90 items, Q2 items |
| `ECON-` | Economy stack (#956 to #959) | M0 to M6 |
| `MKT-` | Cognition market (historical) | M0 to M11 |
| `UR-` | This roadmap | G0 to G5, lane rungs, CT- contracts, U- actions, D- decisions |
| `CMP-` | Chio Computer (#1199) | contracts C1 to C5, acceptance cases `C<n>-<nn>`, increments I1 to I6 |
| `FV-` | Formal verification | already prefixed |

**Collisions this removes.** Each pair below has historically shared one letter:

- WORK-D1 (dynamic delegation) and KDEF-D1 (missing receipt);
- WORK-S1 (swarm evolution) and KSPEC-01 (closed ABI);
- REC-P5 and PAPER-5;
- SEC-M1 and HOST-M1.

Dates are calendar dates only; a bare "Q2" is never used.

## 13. Re-grounding after #1160 merges

#1160 merged on 2026-10-11 (G0.1). The items below were re-checked on 2026-10-12 against main `b6ad31043` by reading current source; nothing was built.

- **KDEF rows this document cites.** The register is section 3 of `docs/superpowers/specs/2026-10-04-ftl-lessons-program-design.md`, on main since #1174. Its "M:" citations predate #1160. Paths below are relative to `crates/kernel/chio-kernel/src` unless they name a crate.

  | Row | Verdict on `b6ad31043` | Where it is now |
  | --- | --- | --- |
  | D1 | Still present; moved | The non-durable disarm moved to `kernel/evaluation/return_recording.rs:55-57`, called from `async_evaluation_core.rs:1929`. The receipt is built, signed and appended afterwards (`:1980`), and `:1970` can return before it. Nested: `nested_flow_evaluation.rs:1722`, `:1773`. Durability gate: `admission_operation/identity.rs:384-391`. |
  | D2 | Still present | Stop state is in-memory atomics (`kernel/construction.rs:369-371`; stop and resume at `:1677-1707`). Unchecked by `validation/issuance.rs:10` and `:51`, the api-protect sidecar mint (`crates/products/chio-api-protect/src/proxy/sidecar.rs:205`, signing at `:265`), trust-control passport issuance (now `chio-control-plane/src/trust_control/passport_handlers.rs:187`, `:238`, `:268`) and governed active response. |
  | D3 | Changed shape; partly fixed by #1160 | A lagged POST stream or initialize now closes the session and reports an uncertain effect (`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs:572-585`, `:667-677`). Still open: the SSE stream holds the per-session lock (`:457`, `:521`) until a terminal response, and there is no request timeout (`:170`), so an upstream that never answers still blocks later POSTs and initialize. |
  | D4 | Still present | Restore still starts event ids at 0 (`chio-mcp-remote/src/remote_mcp/session_core/factory.rs:689`; fresh spawn `:469`), and ids carry no restore generation. |
  | D5 | Still present; moved | Delegate handling is at `crates/platform/chio-store-sqlite/src/security_state/issuance_freeze.rs:1246`. Production queries use only `Issue` (`validation/issuance.rs:76`, `:123`); `Delegate` is constructed only in tests. |
  | D6 | Still present; moved | The `Guard` defaults are at `kernel/mod.rs:917` (`requires_dispatch_revalidation` returns `false`) and `:933` (`revalidate_before_dispatch` returns `Ok(())`). Dispatch runs a revalidation loop (`kernel/dispatch.rs:781-787`), but `ContainmentGuard` and `CapabilitySetSuspensionGuard` in `chio-security-kernel` override neither method. |
  | D7 | Still present | `approval.rs:15` still links the nonexistent `evaluate_tool_call_with_hitl`; `ApprovalGuard::new` has only test callers. |
  | D11 | Still present | `chio-kernel/Cargo.toml:92` takes `chio-settle` with default `web3` (alloy, reqwest); `:106` takes `ureq`; `:53` takes `chio-core`. Sigstore arrives through `chio-weights` (`:81`) and `chio-attest-verify`, not `chio-core` as the register says. |
  | D12 | Still present | `crates/security/chio-security-types/src/ports/lineage.rs:294`; only test implementations exist. |
  | N2 | Still present; moved | `outcome.record_released()` runs right after dispatch, before finalization (`async_evaluation_core.rs:1768-1773`; nested `nested_flow_evaluation.rs:1517-1521`). |
  | N4 | Gate on main (#1262) | `scripts/check-escape-hatches.py` pins 112 hatches in `scripts/escape-hatch-inventory.json` (`85b74cf023`) and runs in CI's workspace structural gates step. The landing ledger still records the spec requirement as `open-acceptance`. |
  | N5 (GT1) | Not met | #1160 merged with build/lint/test and MSRV incomplete; no whole CI run on main has completed since (section 2). |
  | N6 | Still present | `crates/products/chio-api-protect/src/proxy/state.rs:445` builds the collector only with a context resolver, which defaults to `None` and is set only in a test. |
  | N22 | Still present | `crates/platform/chio-http-core/src/routes.rs:33`; `emergency_route_registrations` (`:114-124`) and `handle_emergency_*` have no consumer outside `chio-http-core` and its tests. |
  | N23 | Still present | `crates/platform/chio-http-core/src/emergency.rs:193` compares with `==` (U4, in progress). |
  | N26 | Still present | `RemoteSessionResumeRecord` has no subscription set (`chio-mcp-remote/src/remote_mcp/session_core.rs:270-288`); the kernel drops unsubscribed updates (`session.rs:1129-1133`). |
  | N28 | Still present; changed shape | Moved to `kernel/evaluation/return_recording.rs:80-102`. The evaluator now terminalizes the operation as outcome-unknown itself and returns `Ok` with a signed `Deny`, so the two contradictory terminal records land together. |
  | N29 | Still present; lines drifted | `kernel/validation.rs:1700-1733`: both `adapter.release` results are still discarded and the executed call is denied. #1229 did not change this path. |
  | N30 | Fixed by #1160 (`28d826e3e`) | GET subscribes before it snapshots the retained window and drops duplicates (`chio-mcp-remote/src/remote_mcp/http_service.rs:795-802`, `:835`). |

  N1, N15, N16 and N24 cite branch code ("V:" or "W:") that main does not carry; they are checked at the #1173 and #1179 rebases (KERN-6). N13 still holds: main's `chio-process/src/lib.rs:65` is `chio.process.abi.v3`, so the union with #1179's v3 is still v4 (CT-ABI). Outside this document's citations, N3 is still present (long-lived `AdaptedMcpServer` receipts carry no `native_launch`), and D8 is partly fixed by #1160 (ids are unique within one Gemini response but repeat across responses).
- **#1177:** merged on 2026-10-09. Its PROGRAM-MAP foundation pin becomes main. "In F" becomes "main (experimental; broker Linux-only)". `chio-ipc` mailboxes become `crates/kernel/chio-process/src/mailboxes`.
- **#1174:** merged on 2026-10-12. Its pin becomes main, and the acceptance statistics are recomputed from the ledger. KSPEC-08 section 2 is stale on three facts:
  - the admission schema version on main is 37 (`ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION` in `crates/platform/chio-store-sqlite/src/admission_operation_store.rs:230`), not 34. #1160 brought it to 36, and #1215 (F038) raised it to 37 to index delegated caller-share accounting by parent;
  - #1160 already reserves the `chio_runtime` receipt-metadata key;
  - #1160's startup sweep already defers per item instead of aborting.
- **The M1 plan** is re-cut per COOP-1:
  - extend `signing_custody` instead of rewriting loaders;
  - handle the fallible `unix_timestamp_now()`;
  - remove "needs nothing from #1160".
- **This document:** section 2 and the pins were refreshed on 2026-10-12 against `b6ad31043`. Line citations outside the KDEF rows above still carry their research pin.

## 14. What this document does not do

- It starts no execution.
- It approves no ADR beyond those recorded in section 8.
- It makes no release, qualification or market claim.
- It projects no internal dates.
