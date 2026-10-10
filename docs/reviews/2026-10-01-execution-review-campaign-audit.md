# Execution review: campaign audit (program level), October 1, 2026

Scope: the whole executed range `07e963e8f5..a2630c20a1` on
`packet/3-retention-accounting` (112 commits including one merge, 4,493 files,
+341,132/-101,281 lines), judged at the program level rather than commit by commit.
Plans: the umbrella addendum `docs/superpowers/plans/2026-09-26-security-engineering-excellence.md`,
the dispatch plan `2026-09-26-security-execution-dispatch.md`, the Acceptance section of
`docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`, the ledger
`docs/reviews/2026-09-28-remaining-security-work.md` and `docs/security/signed-json-boundaries.md`.
Inputs: all 38 execution records added in the range (37 batch records plus the ledger), the
17 artifact directories under `docs/reviews/artifacts/`, `docs/security/trust-boundary-inventory.json`,
`scripts/check-*.py`, `scripts/security-clock-inventory.json`,
`scripts/negative-assertions-baseline.txt`, `spec/wire-schemas.lock`, `.github/workflows/` and the
GitHub ruleset and check runs. Method: source and history reading, per-commit inventory
reconstruction (`git show <c>:<inventory>`), local runs of the eight Python gates at the tip,
an in-memory self-certification experiment against `check-trust-boundaries.py`, and three
read-only `gh api` queries. No cargo was run.

**Judgment: The campaign delivered real engineering, but most of its effort went to a
lexical census whose value fell sharply after its second day. The defects it demonstrably
found came early and inside the S2 scope: four tamper-evidence gaps in TCB store and keyring
readers on September 26 and 27, plus ten correctness defects outside the reader work, eight of
them by September 27. The eight late reader batches (September 30 and October 1, 232 readers,
22,414 crate lines and 49,866 evidence lines) demonstrated no pre-existing defect. Their one significant catch, a Vertex guard
that allowed content Vertex itself had blocked, is verdict logic that a review of the guard
found by the way, not a parsing defect. The most important problem is the gap between what is
claimed and what is proven. Sixty-four commits have never run in hosted CI, and the last hosted
run of the required job was red before any new gate executed. The headline metric (447 to 45
baseline files) can be driven to zero by editing a JSON file, and it cannot see the
control-plane HTTP handlers that accept signed documents. The design's acceptance counts were
met partly by renaming types. Finish the 13 TCB baseline files, stop the census for everything
else, and split the branch before anyone attempts to merge it.**

## Plan conformance

Addendum packets and corrections (`2026-09-26-security-engineering-excellence.md`):

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| 0.1 hygiene gate | done | Done | gate passes at tip; caps ratcheted |
| 0.2 overflow checks | 2 of 4 boxes | Partial: profile and probe done; release-tier tests and cost measurement not started | `3b596d22bb`; ledger :253-254 "remain acceptance work" |
| 0.3 accounting lint | compiler-lint box unchecked | Done, unrecorded: `deny(clippy::arithmetic_side_effects)` in 49 files (0 at base) | `git grep -l` count; compiler-secret record :25-26 |
| 0.4 domain gate | debt box unchecked | Partial: 0 duplicate byte domains (was 10), 32 shape exceptions remain | `check-domain-separation.py` output |
| 0.5 assertion gate | done | Done | baseline 1,298 to 1,257 |
| 1D rejection provenance | partial | Partial: `map_err(\|_\|` in quarantine plus kernel active-response 119 to 50 | per-revision `git grep -c` |
| 1A binding | done | Done | `response_execution.rs:35` try_from; compile_fail doctest present |
| 1B authority types | negative-test box open | Done in types; `require_execution_mode` has 0 callers; committed authorities lack compile_fail tests | CA12 |
| 1C mandatory binding | done | Done | simulation record :3-7 |
| 1E response domains | done | Done | domain gate 0 duplicates |
| 1F boundary enumeration | all 5 boxes unchecked | Done, unrecorded: enumeration in `signed-json-boundaries.md`, receipt P1 repaired, canonical.rs comment preserved | `canonical.rs:148,166` |
| 2A arch probe | done | Source done; native execution never run | runtime record :104-108 |
| 2B syscall key | done | Done | `seccomp_plan.rs:178` |
| 3A clamp sweep | partial | Partial: 85 of 638 pending; 320 of 638 rows are fixtures | TSV classification counts |
| 4A clock port | partial | Partial: 154 occurrences at 149 keys remain | `check-security-clocks.py` |
| 4B weak assertions | not started | 41 of 1,298 converted (3.2 percent) | baseline per revision |
| Packet 7 structure | ranks 1-5 | Done for ranks 1-5, but out of sequence (CA9) | addendum :93, :599 |
| Packet 8 type safety | partial | Partial as recorded (budget done, quota/lease open) | checked-budget record :10-38 |
| 9.1, 9.2, 9.3, 9.5 | done | Done (local) | records |
| 9.4 connection pool | deferred | Deferred as planned | addendum :781 |
| 10.1 poison fence | done | Done (local); no `parking_lot` in store crate | `git grep` |
| 10.2 untrusted text | partial | Partial: 45 baseline files remain; the census does not cover framework extractors (CA3) | inventory |
| 10.3 tenant classification | partial | Partial as recorded | ledger :18 |
| 10.4 typed predecessor | done | Done | writer-checkpoint record :35-57 |
| Parent Packets 5 and 6 (audit, freeze, hosted qualification) | open | Not started; no hosted CI since `f25cd61f49` | CA1 |

Design acceptance (`unrepresentable-defects-design.md:487-501`):

| Criterion | Verified status | Evidence |
| --- | --- | --- |
| compile_fail test per mechanism A type | Partial: 8 of 17 types (14 sealed proofs plus three response authorities); none of the 32 compile_fail doctests pins its failure reason | CA12 |
| try_from rejection test per mechanism B type | Partial: `ResponseExecutionBinding` and `SeccompProfilePlan` use `try_from`; `ExposureUnits`/`InvocationCount` have no serde (full-domain values, so nothing to reject); the `Domain` enum was replaced by a gate | `seccomp_plan.rs:178`, `response_execution.rs:35`, `accounting.rs:16-47` |
| `DispatchRejection` negative tests, mutation-checked | Partial: mutation-checked tests named in `ea6c0a27cc`; 1B box still open | commit body |
| Escape-hatch gate | Not started: no gate and no record mentions it; escape hatches 7 to 8 (new one gated by the `enforcement-mutants` feature) | `seccomp_plan.rs:235-237` |
| All-pub `Verified*`/`Authorized*` in TCB 18 to 0; Deserialize 4 to 0 | Done differently: the named types were sealed (4) or renamed to `*Record`/`*Body` (7). Under the campaign's own 27-library TCB the census goes 29 to 18, Deserialize 11 to 7 | CA5 |
| One error-code registry | Partial: URN registry 114 to 264, but `PortError` keeps five unregistered string codes and two new unregistered URNs were added | CA7 |

Dispatch plan (`2026-09-26-security-execution-dispatch.md`): lanes were superseded by inline
execution under the user's directive (recorded at :3-6), which is legitimate. Two principles were
not: "no new `map_err(|_| ...)`" (:70-74, broken in the broker, CA6) and the Wave 3 rule that
Packet 7 runs against a separately qualified follow-up candidate (:180-185, CA9). The status
documents disagree with the inventories in several places (CA8).

## Value tally

Classes: **D** demonstrated pre-existing defect fixed (red before repair, or an unambiguous source
trace that the new test fails on the old production code); **P** plausible pre-existing defect
closed (bounds, removed fallbacks, added checks, no demonstration); **I** inventory or
disposition only; **R** refactor or type migration without a changed decision; **N** new
capability or assurance infrastructure (the brief's five classes have no slot for new features,
so this column is added); **E** documentation or evidence only; **Self** a defect the range
itself introduced and then fixed, which is not value. Counts follow each record's own
granularity, so one row means one named change. The counts are my classification, not the
records'.

| Record (commit) | D | P | I | R | N | E | Self | Notable items (record:line) |
| --- | --:| --:| --:| --:| --:| --:| --:| --- |
| 09-26 execution-boundaries (`3f279844e4`, `a9ae42ed69`) | 3 | 0 | 0 | 0 | 1 | 2 | 0 | keyring alias acceptance :52-57; auditor snapshot TOCTOU with mutation :61-75; projection Live rule :35-40 (superseded the next day) |
| 09-26 resumed-execution (09-26 lane commits) | 3 | 2 | 0 | 1 | 2 | 1 | 0 | FFI provenance UB under Miri :24; analytics corruption :26,:47; receipt raw_json alias :28 |
| 09-27 signed-readback (`18be6b39be`) | 2 | 0 | 1 | 1 | 0 | 0 | 0 | 40 economy readers never verified on read :18-24,:70-73; lineage child substitution :32-36 |
| 09-27 production-response-simulation (`f25cd61f49`) | 1 | 1 | 0 | 0 | 1 | 0 | 0 | divergent duplicate outbox schemas :46-48,:70-72; dry-run simulation :15-41 |
| 09-27 runtime-boundary (`4c35ce7867`) | 0 | 3 | 0 | 1 | 0 | 2 | 0 | keyring seed restart :15-20; native probes compile-only :104-108 |
| 09-27 retention-accounting (`4713fef1b4`) | 2 | 2 | 1 | 0 | 0 | 0 | 0 | nested transaction and caller deadline "demonstrated" :81 |
| 09-27 authority-accounting (`916e5d8364`) | 0 | 6 | 1 | 0 | 0 | 0 | 0 | rotation and leader races :9-23 |
| 09-27 writer-checkpoint (`995b9f1c74`) | 0 | 3 | 1 | 2 | 0 | 0 | 0 | unused BatchApproval authority removed :59-67 |
| 09-27 authentication-replay-leases (`8288bd56be`) | 0 | 6 | 1 | 0 | 0 | 0 | 0 | :12-60 |
| 09-27 checked-budget-accounting (`0fbe22e0f0`) | 0 | 1 | 1 | 3 | 0 | 0 | 0 | SQL compare-and-set :20-26 |
| 09-27 shared-clock-response-assurance (`00536cc902`) | 0 | 1 | 0 | 3 | 1 | 0 | 0 | freshness recheck under lock :31-35 |
| 09-27 trust-boundary (`21c831d396`) | 1 | 2 | 2 | 1 | 1 | 0 | 0 | tenant NULL fallback removed :27-35; record renames :22-25; broker URN :55-60 |
| 09-27 frost-sealed-ceremony (`60555a64da`) | 0 | 1 | 0 | 0 | 1 | 0 | 1 | sealed round two :9-37; own reseal defect :74 |
| 09-28 reader-accounting-recovery (`253be7fe04`) | 0 | 3 | 1 | 2 | 0 | 0 | 0 | :9-52 |
| 09-28 replay-expiry (`2b73690f7c`) | 0 | 3 | 0 | 1 | 0 | 0 | 0 | expiry-free nonce API removed :27-35 |
| 09-28 replay-clock-completion (`0460314617`) | 0 | 3 | 0 | 1 | 0 | 0 | 0 | epoch-zero commit fallback removed :7-35 |
| 09-28 signed-reader-tenant (`f16d4e781c`) | 0 | 7 | 2 | 0 | 0 | 2 | 0 | IOU readback unsigned :40-45; challenge substitution :49-51; registry identity :46-48 |
| 09-28 kernel-admission-reader (`a3217b9145`) | 0 | 3 | 2 | 3 | 0 | 1 | 1 | egress checks removed then restored :131-137 |
| 09-28 authority-boundary-closure (`a76864ad1a`) | 0 | 2 | 3 | 3 | 0 | 0 | 0 | "rather than claiming a new future-time exploit" :25-28 |
| 09-29 compiler-secret-hardening (`d51afb4a5f`) | 0 | 3 | 0 | 0 | 2 | 0 | 1 | 580 Rust files in one commit; gate defects :116-128 |
| 09-29 security-module-boundaries (`4c82a9178e`..`938b76c311`) | 0 | 1 | 0 | 4 | 1 | 1 | 0 | ownership gaps sealed :77-84 |
| 09-29 native-clock-test-ownership (`040244e3a6`..`a3669c03d1`) | 0 | 0 | 1 | 3 | 0 | 1 | 1 | emergency stop :80-84 (CA11) |
| 09-29 sqlite-performance-retention (`8aa3cf1785`..`7177be5092`) | 0 | 0 | 0 | 2 | 0 | 2 | 0 | measured compile/read counts :26-30 |
| 09-29 retention-lifecycle-assurance (`d841931148`..`1d4f3b4ad3`) | 0 | 0 | 0 | 0 | 1 | 3 | 1 | own checker gaps :105-108 |
| 09-29 protocol-authority-boundaries (`53858afa39`, `68fb96f436`) | 1 | 4 | 1 | 0 | 0 | 0 | 4 | 4 of 6 red regressions were in the candidate's new code (artifact final-review.md items 1-4) |
| 09-29 enforced-native-protocol (`93fbf2eb4d`..`9cb2ac5679`) | 0 | 3 | 1 | 2 | 0 | 0 | 0 | compatibility surface was default-off and enabled by no manifest |
| 09-29 remote-lifecycle-acp-native-ci (`cacaf69fc9`) | 0 | 3 | 0 | 0 | 1 | 0 | 1 | Ready/touch published before persistence :33-37 |
| 09-29 native-consumers-acp-errors-openapi (`55e7439da3`) | 0 | 1 | 0 | 2 | 1 | 1 | 0 | OpenAPI YAML budgets :10-16 |
| 09-29 native-multiroute-consumers (`2a4c2fbe4f`, `7525fcdf0c`) | 1 | 0 | 0 | 0 | 2 | 1 | 0 | MCP exit race, red before fix :38-45 |
| 09-30 product-authority-readers (`943482d2cb`) | 0 | 2 | 1 | 1 | 0 | 0 | 0 | "not evidence of a demonstrated failing regression test" :83-84 |
| 09-30 cli-authority-proof-readers (`da4086017f`) | 0 | 4 | 1 | 0 | 0 | 0 | 0 | manifest v1 converter removed :25-28 |
| 09-30 cli-remaining-readers (`82eec927b2`) | 0 | 3 | 1 | 0 | 0 | 0 | 0 | publish acknowledgement binding :11-12; no per-fix red/green (artifact review-resolutions.md:16) |
| 09-30 provider-reader-boundaries (`6ef28e8f4d`) | 0 | 3 | 1 | 1 | 0 | 0 | 0 | unfinished stream choices :19-21 |
| 09-30 trust-reader-boundaries (`90e8f0683b`) | 0 | 3 | 1 | 0 | 0 | 0 | 0 | delivery report bound to batch :26-29; mobile shape-only verifier :22-23 |
| 09-30 guard-security-readers (`377ee5b773`) | 0 | 4 | 1 | 1 | 0 | 0 | 0 | Vertex SAFETY allowed (artifact review.md); missing verdict became Allow :13 |
| 10-01 platform-authority-readers (`593b642da9`) | 0 | 2 | 1 | 2 | 0 | 0 | 2 | R1/R2 were the batch's own over-restriction (artifact review.md) |
| 10-01 economy-authority-readers (`a2630c20a1`) | 0 | 3 | 1 | 1 | 0 | 0 | 0 | purchase digest erased duplicate keys :28-29; Rekor time :33-35 |
| **Totals (37 records)** | **14** | **88** | **27** | **41** | **15** | **17** | **12** | |

**The reader campaign specifically.** Packet 10.2 and the batches it spawned run from
`1e791271dc` (September 26) to `a2630c20a1` (October 1): 18 commits that disposed 402 baseline
reader files. Four pre-existing reader defects were demonstrated, and all four were fixed
by September 27, before the workspace census existed:

1. Stored receipt `raw_json` was parsed into `serde_json::Value` (last key wins) before signature
   verification, so a stored text with a shadow duplicate key verified
   (resumed-execution:28; `signed-json-boundaries.md:28`; test `stored_child_json_rejects_duplicate_keys`).
2. Forty signed economy export readers never verified signatures on readback (signed-readback:18-24).
   `signed_readback_reports_reject_changed_signed_bodies`
   (`crates/platform/chio-store-sqlite/src/receipt_store/tests/signed_readback.rs:74`) rewrites a
   stored premium and calls the production query API. Before the repair that API returned the
   altered value.
3. Signed lineage returned a valid statement belonging to another child (signed-readback:32-36).
4. Keyring canonical readers accepted noncanonical encodings of signed records
   (execution-boundaries:52-57, red log retained in `/tmp`).

**None of the four is an exploitable signature or authority bypass by an unprivileged party.**
Each needs write access to the SQLite store or the keyring files. They are real gaps in
the product's tamper-evidence promise for an auditor reading stored evidence. After the census
began at `f16d4e781c` (September 28, 17:40), the reader batches demonstrated no further
pre-existing defect.
They closed about 45 plausible ones. The security-relevant pre-existing ones are IOU readback
without verification (signed-reader-tenant:40-45), challenge substitution on reopen (:49-51),
registry key and record identity (:46-48), delivery reports not bound to the sent batch
(trust:26-29), purchase digests that erased duplicate keys (economy:28-29), and Rekor receipt time
not bound to the signed entry (economy:33-35). The strongest is the Vertex guard. Before
`377ee5b773`, `vertex_safety.rs` returned Allow whenever the highest rating
probability was below the threshold, even when Vertex had blocked the candidate with
`finishReason: SAFETY` or `blocked: true`. The finish reason was deserialized and never read
(pre-repair `377ee5b773^:crates/guards/chio-external-guards/src/external/vertex_safety.rs:177`
and `:351-381`).
That is a content-policy fail-open that an attacker can influence through the content. It
is guard verdict logic, not the S2 class, and the batch reviewer found it by the way. No red
run was recorded.

Reading the remaining 45 files cannot be justified by the yield so far. The case for the 13 of
them in TCB libraries is that they belong to the original S2 scope (CA4).

## Gate integrity

The new gates (`check-trust-boundaries`, `check-security-clocks`, `check-negative-assertions`,
`check-accounting-arithmetic`, `check-domain-separation`, `check-lint-parity`,
`check-rust-hardening`, `check-wire-schemas`, `check-dependency-budget`, `check-release-overflow`)
run in the "Workspace structural gates" step of the `Build, lint, test` job
(`.github/workflows/ci.yml:97`, gates at :175-197). The job triggers on pull requests to `main`
(:24-29). The active ruleset `main-required-checks` (id 22033486) requires the `Build, lint,
test` context, so the gates are wired and required. `check-response-lifecycle`,
`check-revocation-progress` and `check-revocation-propagation` run only in
`apalache-safety.yml` and `apalache-temporal.yml` (schedule and dispatch). The new `miri.yml`
and `sanitizers.yml` are also schedule and dispatch only. Scheduled runs execute `main`, so none of these runs on
this branch until it merges. The `nextest-security` job is additive and not required.
`check-retention-liveness.py` is a diagnostic runner, not a gate, and nothing invokes it. I ran
the eight Python gates and the schema-registry check at the tip; all pass. The step as a whole
does not: it runs `check-review-slices.py` first (`ci.yml:115`), which exits 1 at the tip on four
unclassified paths (`.config/miri-crates.toml`, `.config/nextest.toml` and the two
`chio-profile-probe` files), and the domain-separation and lint-parity self-tests also exit 1.
The orchestrator reproduced all three at `a2630c20a1`; the gates-toolchain review records them
as GT1. In practice these gates have never executed in hosted CI (CA1).

## CA1. Medium: no hosted CI has run on the last 64 of the 112 commits, and the last hosted run of the required job failed before any new gate executed

PR #1160 (`integration/process-security-m4`, draft) has head `f25cd61f49`, the 48th of the 112
commits (counting the Lane K merge and its branch). Its check runs show 16 failures, among them the required `Build, lint, test`,
`cargo-vet` and `cargo-deny`. The failing step of `Build, lint, test` is "Workspace structural
gates". Its log ends with `MANIFEST.sha256 bytes do not match deterministic regeneration` from
`check-chio-schema-registry.sh`. That script runs at `ci.yml:145`, ahead of every security gate
from :175 on, and the step stops at the first failure. So the trust-boundary, clock,
assertion, arithmetic, wire-schema and hardening gates have never executed in hosted CI. The
working branch `packet/3-retention-accounting` was pushed at `593b642da9` and has zero check
runs. No PR targets it, and `ci.yml` triggers only on pull requests and pushes to `main`. Nor
has `a2630c20a1` been pushed.

Every record correctly says its qualification is local. The program-level consequence is that
4,493 files' worth of change has no integration signal at all. The gates were
written to prevent false assurance (standard 12.6) and have themselves never run where it
counts. The schema-registry check passes locally at the tip, so the original red is probably
repaired, but that is unproven. The fix is to open a PR for the first slice of the split
recommended under Repository hygiene and treat its CI as the next acceptance step.
**Confidence:** Confirmed. `gh api` check runs for `f25cd61f49` and `593b642da9`, the job log
and `ci.yml` ordering.

## CA2. Medium: `check-trust-boundaries.py` is satisfied by editing its JSON inventory alone, so "baseline to zero" is self-certifiable

The gate compares a source scan with `trust-boundary-inventory.json`. A file leaves the baseline
when its `decoder_file_contracts[path].kind` changes and `contract` is any non-empty string
(`scripts/check-trust-boundaries.py:183-186`). Registration as a reviewed owner checks only
that the path appears in `signed_input_files` and that the review has a truthy `contract`
(:175-182). Raw decoder sites must equal a list the inventory itself supplies (:187-191). No check ties a contract to code:
nothing requires a bounded read, `UntrustedJsonText` or any other property of the file.

Experiment (in memory, no file changed): I loaded the tip inventory and set all 45
`raw-input-baseline` entries to `{"kind": "reviewed-bounded-input", "contract": "reviewed"}`.
`check()` returned no errors. In a second variant I also registered all 45 as reviewed product
readers, filling `raw_decoders` from the gate's own `--scan` output, and `check()` again returned
no errors. The negative-assertion and clock gates have the same property. Their baselines
are hand-editable data files, and "counts only shrink" is enforced only when the `--ratchet`
tool writes them. `.github/CODEOWNERS` lists none of these inventories, and the ruleset requires
no code-owner review. On a single-maintainer repository that makes inventory edits
self-approved.

This matters because the ledger reports progress as these counts (`remaining-security-work.md:14`
and :170-189). A count that moves on a data edit is a ledger of reviewer intent, not a
measurement. The census still catches new decoder spellings, which is its real value. The fix
is either to put the inventories under CODEOWNERS with a required second reviewer, or to
require each non-baseline kind to name a symbol (the reader function) that the gate checks
calls a bounded or constrained API, which turns the contract into a checked claim.
**Confidence:** Confirmed. The experiment ran `check()` from the gate module on the tip
catalog.

## CA3. Medium: the lexical census cannot see the main network ingress, so 45 is not the size of the S2 problem

**October 2 follow-up:** CA3 now has extractor/format/shared-reader observations and original-byte validation on all 104 control-plane JSON bindings. Other API and format risks remain explicit. See the
[lease and ingress record](2026-10-02-lease-fencing-framework-ingress-execution.md)
for source, local evidence and remaining boundaries. The finding below remains
the historical reviewed-source snapshot.

`json_decoders` (`check-trust-boundaries.py:29-60`) matches `serde_json::from_*` spellings,
imported aliases, `Deserializer::from_*` and `fn deserialize<`. It cannot see framework
extractors. At the tip, 15 control-plane HTTP handler files take axum `Json<T>` request
bodies, about 100 in all, and none of the 15 is in the census (`git grep` on `Json(x): Json<`). Among them are
signed documents: `certification_handlers.rs:51` (`Json<SignedCertificationCheck>`) and
`passport_handlers.rs:448` (`Json<SignedPassportVerifierPolicy>`). These are exactly what S2
names: signed JSON text crossing a trust boundary. The census also misses five reqwest
`.json()` calls, 16 `serde_yaml`/`toml`/`ciborium`/`bincode` decoders in 11 files, and any
caller of a shared helper. A file also leaves the census when its
`serde_json` call moves into a helper in another crate, which is how most migrations
removed files (census 556 to 253 files).

I did not find a bypass on these handlers. `handle_publish_certification` is service-token
authenticated and verifies the typed value, so the signed and interpreted meanings coincide
unless the original text is retained. Each needs that disposition, though, and the
program reports S2 progress as a number that excludes them. The fix is to add the
extractor forms (`Json<`, `.json::<`, `Form<`, YAML/TOML/CBOR) to the census, or to enumerate
HTTP routes from the router builders instead of from spellings.
**Confidence:** Confirmed for the counts and the census membership; Plausible for risk (no bypass traced).

## CA4. Medium: the campaign worked outside the TCB before finishing inside it

Of the 402 baseline files disposed since `f16d4e781c`, 236 (59 percent) are outside the 27 TCB
libraries in `docs/security/toolchain/rust-hardening.json`: products 83, protocol 49, trust 35,
platform 32, economy 22, guards 15. Thirteen baseline files remain in TCB libraries:
`chio-process/src/{store.rs, store/nonces.rs, store/children.rs, mailboxes/store.rs, state_reader.rs, worker.rs}`,
`chio-kernel-browser/src/{pure.rs, wasm.rs}`, `chio-kernel-mobile/src/lib.rs`,
`chio-runtime-harness/src/{lib.rs, proof_assembly.rs}`, `chio-runtime-proof-parity/src/lib.rs`
and `chio-supervisor/src/health.rs`. A nonce store in the TCB is still in the raw baseline while
every CLI, provider and guard reader has a contract.

Cost against yield, in changed lines: the S2-scoped phase (`1e791271dc`, `a9ae42ed69`,
`18be6b39be`, `21c831d396`, `253be7fe04`) touched 6,570 crate lines, committed no artifacts and
produced all four demonstrated reader defects. The census phase (13 commits from
`f16d4e781c`) touched 46,706 crate lines, 49,994 artifact lines and 19,705 other documentation
lines, and demonstrated none. Across the eight late batches, 15 of the 33 guard readers were
disposed with no change to the file, and evidence lines exceed crate lines in five of the
eight (trust 9,726 to 1,682; guard 10,702 to 1,771). S2 (pass 4, :105-140) asked which TCB boundaries
need the strict entry point. The expansion answered a different question, whether every
`serde_json` call in the workspace has a recorded contract. That question is cheaper to
measure and much less valuable.

The 13 TCB files belong to the next pinned batch (economy record :83-89), so finish them.
Reclassify the remaining 22 observability, product and tooling files (`chio-spec-codegen`,
`chio-conformance`, `chio-release-evidence`, `chio-siem` exporters and others) as outside the
S2 scope with a one-line reason, and stop the census-driven queue.
**Confidence:** Confirmed. Inventory history reconstructed per commit; `git show --numstat` totals.

## CA5. Medium: the design's Verified* acceptance count was met partly by renaming, and seven all-pub Deserialize Verified* types remain in TCB libraries

`21c831d396` renamed seven types: `VerifiedApprovalSetBody` became `ApprovalSetBody`,
`VerifiedCapabilityJson` became `CapabilityVerificationJson`, `VerifiedSecurityEvent` became
`SecurityEventVerificationRecord`, `VerifiedIsolationEvidence` became
`IsolationVerificationRecord`, and `AuthorizedBudgetHold`, `VerifiedSupplementalQuotaClaim` and
mobile `VerifiedCapability` became `*Record`. All seven keep all-`pub` fields, and four still
derive `Deserialize` (`governance.rs:1720`, `kernel-browser/src/wire.rs:255`,
`ports/events.rs:36`, `ports/flow.rs:64`). Four types were genuinely sealed
(`VerifiedCapability`, `VerifiedPassport`, `VerifiedActiveResponseOperatorCapability`,
`VerifiedWatermark`). The record discloses the renames (trust-boundary:20-25), and
`docs/security/verification-records.md` classifies each one as a trusted-port record. T1's own
nuance permits that for a pure data carrier. Even so, `correlation.rs:304-335` takes
`verified: &SecurityEventVerificationRecord`. That remember-to-call-the-verifier-first
convention is the very defect class T1 exists to remove.

Separately, by the same census method at both revisions (named-field structs prefixed
`Verified`/`Authorized`/`Admitted`/`Validated` in production files of the 27 TCB libraries):
all-`pub` types went 29 to 18 and the `Deserialize` subset 11 to 7. The seven are
`VerifiedFindingPurchase`, `VerifiedFindingStatusProof`, `VerifiedFindingRecovery` (chio-kernel),
`VerifiedFixPayload`, `VerifiedFixCommandResult` (control plane), `VerifiedOutcomeRequestV1`
(core types) and `AdmittedChildBudgetJson`. `VerifiedFindingPurchase`
(`crates/kernel/chio-kernel/src/finding_purchase.rs:75`) is documented as "admitted by the kernel
against the selected grant before any money movement" and is accepted as proof by
`crates/kernel/chio-kernel/src/kernel/purchase_gate.rs:37`. Yet any code can build it with a literal, and any input can produce it by
deserialization. I did not trace an untrusted deserialization path into the gate. The fix is to
apply mechanism A to these seven, starting with the purchase type, and to state the acceptance
count against the hardening catalog's TCB.
**Confidence:** Confirmed for the renames and counts; Plausible for the money-path risk (no path traced).

## CA6. Medium: mechanism C regressed in the broker; new cause-discarding `map_err(|_| ...)` sites were added in volume

The dispatch plan forbids new `map_err(|_| ...)` (:70-74), and standard section 3 requires
causes to be kept. Counted per revision over production files (test modules excluded by
path), the secret broker went from 164 to 226 sites. Most of the growth came from the native
consumer batches: +42 in `2a4c2fbe4f` and +21 in `7525fcdf0c`, in `docker_adapter`, `host_https`,
`repository_adapter` and `kernel_admission/routes.rs`. Examples are `.map_err(|_| denied())?` on
`symlink_metadata` and `peer_identity`. chio-kernel went 326 to 349 and chio-store-sqlite 831 to
851. Workspace-wide the count went 3,858 to 3,811, a 1.2 percent reduction. The record that
introduced the broker sites does not mention them. No gate counts this pattern, so the
orchestrator's mechanical check (:212-213) was the only control, and it was not applied. The
fix is a ratchet gate on `map_err(|_|` in TCB libraries, then source-preserving errors with
redacted Display at the new broker sites.
**Confidence:** Confirmed. Per-commit `git grep -c` counts.

## CA7. Low: one error registry is not achieved; two unregistered URNs were introduced and no gate binds URN literals to the registry

`spec/errors/registry.yaml` grew from 114 to 264 URNs, with 264 generated constants. Crates do
not consume the generated constants. They embed 1,065 URN string literals in 267 files.
`d51afb4a5f` added `urn:chio:error:kernel:dpop-invalid-capacity`
(`crates/kernel/chio-kernel/src/dpop/error.rs:58`) and
`urn:chio:error:kernel:approval-replay-invalid-capacity` (`governed_approval_replay.rs:30`),
neither of which is in the registry. `PortError` still carries `ErrorCode(String)` with the five
ad-hoc codes T2 named (`crates/security/chio-security-types/src/ports/error.rs:59-75`). These are
the "two registries will drift" failure the design predicted. The fix is a gate that
fails on any `urn:chio:error:` literal absent from `registry.yaml`, then registration of the five
port codes.
**Confidence:** Confirmed. Set difference between literals and registry entries.

## Ledger consistency

## CA8. Medium: the status documents contradict the inventories and each other

The ledger's own table agrees with the gates. `remaining-security-work.md:14-19` reports 45
baseline files, 85 pending of 638 arithmetic (553 classified, 133 repaired), 154 clock
occurrences at 149 keys, 1,257 weak assertions at 1,175 sites, 85 tables, 163 duplicated
identifiers and 32 domain exceptions. All of these match `trust-boundary-inventory.json`, the
arithmetic TSV and the gate outputs I ran. The per-batch baseline transitions in the eight late records (278, 250, 223, 194,
166, 131, 98, 67, 45) match the inventory history commit by commit. The contradictions:

- `remaining-security-work.md:170-177` still says "Next execute all 22 economy readers" and
  "There are 67 baseline files across the workspace", next to the completed economy paragraph
  at :182-189 that says 45.
- `remaining-security-work.md:186-187` says the economy batch's "terminal qualification and
  review records govern completion claims". `docs/reviews/artifacts/2026-10-01-economy-authority-readers/`
  has no README or review file, only `pre-review-packages.*`, and the record says results will be
  recorded "as they finish" (economy record :41-42). The tip commit records a batch whose
  review and qualification did not exist when it was committed.
- The addendum's "Current execution status (September 28)" (:26-74) is three days and about
  twenty batches stale. It gives 374 baseline files, 122 pending arithmetic entries (516
  classified, 132 repaired) and 157 clock occurrences at 152 keys (:68-70). Elsewhere it gives
  240 constructors across 162 files (:894-896), 12 unchecked accounting sites (:192, the gate
  reports 0), 516/132/122 again (:497-499) and 157 clock sites (:552). The tip has 45;
  85/553/133; 154/149; 464 constructors in 288 files with 589 registered files; and 0.
- Two addendum items are done but unchecked: 0.3's compiler lint (:196, 49 files) and all five
  1F boxes (:407-420), whose enumeration and P1 repair are in `signed-json-boundaries.md`.
- `signed-json-boundaries.md` stops at September 28: "The gate pins 240 constrained-reader
  constructors across 162 registered files ... The remaining baseline is 374" (:139-142). Ten
  later reader batches are not reflected in the document the plan names as the 1F/10.2 contract.

Standard 12.5 makes reconciling the ledger part of the change. The fix is to regenerate the
addendum status block and the boundary document from the inventory files (or delete their
numbers and link to the ledger), and to commit the economy review and qualification or mark
that batch incomplete.
**Confidence:** Confirmed. Line references above against gate output and inventory contents.

## CA9. Medium: structural and toolchain migrations ran out of sequence on the candidate branch

The addendum orders Packet 7 "after Packet 6" (:93), and the dispatch plan runs it "against a
separately qualified follow-up candidate, not the frozen launch candidate" (:180-185). The
adopted external-review rule says "defer broad connection, module and toolchain migrations to
separately reviewable changes with their own qualification" (addendum :103-106). Before any
freeze or hosted qualification, the branch nonetheless carries Packet 7 ranks 1-5 (`4c82a9178e`
to `e1e016f4d0`, including a 286-file formatting commit) and the compiler policy sweep
`d51afb4a5f`. That sweep is one commit touching 666 files, 580 of them Rust with 11,409 changed
lines. It mixes lint attributes, checked conversions, secret-ownership changes and new gates,
contrary to standard section 11 ("one reviewable packet per commit"). The Packet 7 commits
themselves respect the cut, visibility and format separation, and their record is careful.
The violation is sequencing and reviewability, not the quality of the cuts. The consequence is
CA1 and the merge problem below: a candidate that was supposed to be frozen and qualified now
contains the largest mechanical diffs in the program.
**Confidence:** Confirmed. Plan text and `git show --numstat d51afb4a5f`.

## Repository hygiene

## CA10. Medium: 18 MB of committed evidence in a public repository carries machine-local paths and cloud infrastructure identifiers

`docs/reviews/artifacts/` holds 1,531 files added in this range: 582 `.gz`, 525 `.log`, 304
`.json`, 40 `.md` and others. That is 18 MB on disk, 67 MB uncompressed, and 143,115 inserted
text lines, a third of the whole diff. Scanning every file, gzip members included: 205 files
contain the operator's home directory path (58,691 occurrences), 526 contain `/tmp/arc-security-launch` (78,349) and
209 contain the username. Three `worker.json` files
(`2026-09-29-native-consumers-acp-errors-openapi/`, `2026-09-29-native-multiroute-consumers/` and
its `continuation-20260930/`) carry an OCI instance OCID, boot and block volume OCIDs, region
`us-ashburn-1`, the worker's private IP, mount paths and an operator instruction ("Use the Mac
OCI CLI compute instance action --action START with this instance_id"). `gh api` reports the
repository as public. Reviewer agent identities (`/root/provider_reader_final_review`,
`gpt-6-astra`) appear in review files. I found no private keys, tokens or credentials; the
one `AKIA...` match is the AWS documentation example inside a test fixture.

The evidence policy also overcorrected. The 20 batch records from September 26 through the September 29 compiler batch cite
evidence only under `/tmp/chio-*` (66 references). Those directories exist on this host today
but are not in the repository. The root filesystem is 96 percent full, so a routine cleanup would
make 20 records unverifiable. The later 17 records commit everything, including whole build
logs (`kernel-cut-build.log`, 593 KB) and a 2.2 MB source snapshot (`kernel-source-before.json`).

Generated SDK churn is small but avoidable. `f25cd61f49` rewrote 158 generated Python files,
and 155 of them changed only a shared `# Schema sha256:` header line. Any schema change
repeats this.

The fix: move the artifacts out of the source tree (release assets or a separate evidence
repository with content-addressed manifests), keep in-repo only a SHA256SUMS manifest and the
short README and review files, strip host paths and infrastructure identifiers before
publication, and give the generated SDK files per-schema digests.
**Confidence:** Confirmed. A full-content scan with decompression; `gh api repos/bb-connor/arc` visibility.

**Can the branch be reviewed and merged as one unit?** No. It is 112 commits, 4,493 files and
+341k/-101k lines. One commit touches 666 files, and five touch more than 285. The inventory JSON
is edited by 22 commits and serializes everything after September 27. Twelve review slices
already had to be assigned to read it. Because later work depends on earlier contracts (shared
clock, `UntrustedJsonText`, the inventories), split it as stacked PRs along history, not by
topic, each green in hosted CI before the next is opened:

1. Gates and toolchain configuration (`407a590e17`..`f928453692`, the Lane K merge), plus the
   schema-manifest repair, so that CI is green first.
2. Overflow checks with the poison fence (`79d2e1b9ea`, `57816c2279`, `3b596d22bb`; coupled by
   plan), then analytics and measurement (`ba7282e18c`..`414aaea0b1`, `dc018fab21`).
3. Response authority and simulation (`f4bd52c981`..`fc8eb0c9be`, `3f279844e4`, `f25cd61f49`) with
   the signed-JSON and readback fixes (`1e791271dc`, `a9ae42ed69`, `18be6b39be`).
4. Accounting, clocks, replay and FROST (`4c35ce7867`..`0460314617`).
5. Kernel/SQLite and authority readers (`f16d4e781c`, `a3217b9145`, `a76864ad1a`).
6. Compiler policy (`d51afb4a5f`, split by crate family if at all possible), then Packet 7
   (`4c82a9178e`..`e1e016f4d0`) as a separately qualified follow-up, per plan.
7. Native consumers and protocol (`a8b5f11d3e`..`7525fcdf0c`).
8. Late readers (`943482d2cb`..`a2630c20a1`), after the scope decision in CA4.

Artifacts should not travel with any of these.

## Process-vocabulary leakage

Verified clean, with numbers. The range adds 153,364 lines under `crates/`, 3,760 of them
comment lines in `.rs`/`.inc` files. Matches in those comments: `Packet` 0, `correction` 0,
`wave` 0, review `pass N` 0, ISO dates 0, `hardened`/`hardening` 0, "per the review" 0.
`Lane` gives 16 hits, all domain usage (iroh federation lanes, "challenge lane") except one;
`batch` gives 31, all domain (receipt and finding batches); `finding` gives 19, all the Finding
market; `review` gives 3, all domain ("reviewed syscall set"). The two finding-ID comments,
`F2 (fail-open fix)` and `F3 guard`
(`crates/trust/chio-federation-transport-iroh/src/lanes/fanout/tests.rs:427,473`), are lines
moved from the pre-range `fanout.rs:1676`. The one genuine process narration added in the range
is `crates/platform/chio-store-sqlite/src/receipt_store/tests/retention/state_machine.rs:43-44`:
"Issue #1045 retains the runner-grade liveness question until the hosted lane completes." Code
identifiers are equally clean. The only process names are inventory keys in gate configuration
outside `crates/` (`"kernel_sqlite_review_2026_09_28"` and five siblings in
`scripts/security-clock-inventory.json`). The added lines of the whole range contain zero U+2014
characters.

## Scope drift

S2 scoped the strict-input problem to "JSON *text* [that] crosses a trust boundary and is then
signed or digested" in the security TCB (pass 4, :105-140). Correction 1F enumerated about a
dozen such boundaries (`signed-json-boundaries.md:20-33`). The campaign became a workspace
census of every `serde_json` decoder (556 files, 1,881 spellings at `f16d4e781c`) and then worked
the census down to 45 files over nine batches. The numbers, from CA4 and the value tally:

| Phase | Commits | Crate lines | Evidence/doc lines | Files disposed | Demonstrated reader defects |
| --- | --:| --:| --:| --:| --:|
| S2-scoped (Sep 26-28 early) | 5 | 6,570 | 3,282 | n/a (pre-census) | 4 |
| Census (Sep 28 17:40 to Oct 1) | 13 | 46,706 | 69,699 | 402 (236 outside the TCB) | 0 |

The expansion did not earn its cost as defect-finding. It earned something as hardening:
original-byte bounds before allocation in protocol and provider ingress, removal of
compatibility fallbacks, retained parser causes, and incidental catches such as the Vertex
guard. Those are worth having. They are better bought by owner-driven review of the network
ingress (which the census cannot see, CA3) than by working a lexical list in alphabetical crate
families. Bulk migration also carries its own risk, which the range demonstrates: the clock
migration made the kernel emergency stop fail open for 22 minutes of history (CA11), and a
reader cleanup removed native egress authorization checks before tests caught it
(kernel-admission-reader :131-137).

## CA11. Low: records present repairs of the campaign's own regressions as delivered fixes

The emergency stop: at the base, `emergency_stop` latched using the infallible
`current_unix_timestamp_ms()` (`07e963e8f5:crates/kernel/chio-kernel/src/kernel/construction.rs:1655-1663`).
`a8b5f11d3e` inserted `self.read_authority_time()?` before the latch, so a clock fault returned
early and the kill switch did not engage. `f965330c2a`, 22 minutes later, moved the latch ahead
of the clock read. The record (native-clock-test-ownership :80-84) says "The emergency stop now
latches before reading time ... failed before the fix", which is true, but it does not say the
batch introduced the defect. The same pattern appears in four of the six protocol "red before
repair" regressions (candidate code, artifact `final-review.md` items 1-4), in platform review R1/R2
(the batch's own over-restriction), in the FROST reseal acceptance and in the
remote-lifecycle `Ready`/`touch` ordering. Twelve such Self rows appear in the tally. They show
the reviews worked, but they are not value delivered, and a reader of the records cannot tell
which is which. The fix is to require each review resolution to state "pre-existing at base"
or "introduced in this batch" with the introducing commit.
**Confidence:** Confirmed for the emergency stop by source trace at base and both commits; the
others from the batches' own review files.

## CA12. Low: acceptance evidence for mechanisms A and 4B is thin

compile_fail doctests cover 8 of the 17 mechanism A types: the 14 sealed proofs in the
inventory plus `FreshLiveAdmission`, `CommittedDispatchAuthority` and
`CommittedAdmissionAuthority`. `VerifiedClassification`, `VerifiedDeclassification`,
`ConsumedDeclassification`, `VerifiedAuthorityExchange`, `VerifiedBrokerAuditRunnerAuthorization`,
`VerifiedAuthorizationReceiptConsumption`, `CageRequiredLaunch` and both committed authorities have
none. They rely on the trust gate's lexical sealed-field check instead. None of the 32
compile_fail doctests pins its failure reason or has a compiling positive twin, so a doctest
that fails on a wrong import passes. Weak assertion conversion (4B), which the addendum makes the
precondition for Packets 1 and 4 demonstrating their exits (:575-589), reached 41 of 1,298 (3.2
percent). The fix is a positive `no_run` twin beside each compile_fail block, and to schedule 4B
on the response-dispatch boundary before more reader work.
**Confidence:** Confirmed counts; Plausible for the doctest weakness (I did not mutate imports).

## CA13. Note: "independent review" is an executor-dispatched subagent with author re-grading and no re-review of fixes

The late batches' review files show a single read-only reviewer launched by the executing
agent (`/root/provider_reader_final_review`, `gpt-6-astra`). It reviewed uncommitted work, the
author "re-graded and resolved the findings" (provider `review-resolutions.md:3-8`), and no
second review saw the fixes (platform `review.md:6`, guard `review.md:6-7`). That is useful
self-checking. It is not the independent review standard 12.1 requires before a P0/P1 boundary
is called complete, and the ledger should not count it as such.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Economy readers previously skipped verification; altered bodies could flow into reports (signed-readback:21-24) | Holds | `signed_readback.rs:74` drives `query_underwriting_decisions`; the pre-repair reader had no verify |
| Receipt raw_json P1 repair (`signed-json-boundaries.md:28`) | Holds; storage-writer threat model only | pre-repair `receipt_verify.rs:129-134` used `serde_json::from_str::<Value>` |
| Emergency stop "failed before the fix" (native-clock-test-ownership:80-84) | Partially holds | true, but the defect was introduced by `a8b5f11d3e` in the same batch (CA11) |
| `signed_policy_failures_never_fall_back_to_bare_policy` (cli-authority :22-23) | Does not hold as a defect demonstration | pre-repair, a parseable signed policy with a bad signature already failed through `verify(...)?`; the test would fail before repair only on its error variant |
| All six protocol regressions red before repair (protocol :92) | Holds; 4 of 6 were candidate-introduced | artifact `final-review.md` items 1-4 versus "preexisting edge terminal-task eviction" |
| Economy review and qualification govern completion (ledger :186-187) | Does not hold at tip | no README or review file in the economy artifacts |
| Ledger inventory counts (ledger :14-19) | Holds | gates run at tip; TSV and JSON counts |
| Per-batch baseline transitions 278 to 45 (eight late records) | Holds | inventory reconstructed at each commit |
| 49 accounting lint owners (compiler-secret :25-26) | Holds | `git grep -l` gives 49 (0 at base) |
| Runtime bypass calibration (kernel-admission-reader :107-116) | Holds as non-vacuity evidence only | mutants of the new code, not pre-existing defects |
| "Reviewed" T1 types retired (trust-boundary :20-25) | Holds as disclosed; acceptance met partly by rename | CA5 |
| Vertex Allowed `finishReason: SAFETY` below threshold (guard `review.md`) | Holds | pre-repair `vertex_safety.rs:177` deserializes the finish reason; `:351-381` decides on probability alone |

## Verified clean

- No U+2014 in any added line of the range, documentation included.
- Process vocabulary in crate comments and identifiers is effectively absent (counts above).
- The ledger's summary table matches every inventory and gate at the tip, and the eight late
  records' baseline arithmetic matches the inventory history exactly.
- All eight Python security gates and the schema-registry check pass locally at `a2630c20a1`.
- The gates sit in the required `Build, lint, test` job under an active ruleset.
- The four pass-5 Deserialize `Verified*` names are gone. Four verifier results are genuinely
  sealed, with compile_fail doctests (`capability_verify.rs:55`, `passport_verify.rs`,
  `governed_active_response.rs`, `watermark.rs`).
- The `canonical.rs` render-A/sign-B comment is preserved (1F's last item).
- `require_execution_mode` has zero callers (1B). The store crate has no `parking_lot` (10.1).
- Escape hatches went 7 to 8; the new one is gated by `#[cfg(feature = "enforcement-mutants")]`.
- Packet 7's cut, visibility and format passes are separate commits, as the plan required.
- No secrets in the artifacts. The one key-shaped string is the AWS documentation example.
- The records are candid about local scope. Several state limits plainly
  (authority-boundary-closure:25-28, product :83-84, cli-remaining review-resolutions:16).

## Recommendations for the remaining plan

1. Get to green hosted CI first. Open the first stacked PR (gates plus the schema-manifest
   repair) and do not extend the branch until it passes. Freeze nothing until each slice is
   green.
2. Take the 13 TCB baseline files, `chio-process` nonce, mailbox and store readers first, and
   then end the census as a work queue. Reclassify the 22 non-TCB tooling and observability
   files with one-line reasons.
3. Close CA3 by making the census extractor-aware, then review the 15 control-plane handler
   files that take `Json<T>` signed documents under S2's original question.
4. Turn the inventories into checked claims (CA2): CODEOWNERS plus required review, or contracts
   that name a symbol the gate verifies.
5. Build the two missing design gates, the escape-hatch gate (mechanism D) and a URN-literal
   registry gate, and add a `map_err(|_|` ratchet for TCB libraries (CA6, CA7).
6. Apply mechanism A to the seven remaining all-pub Deserialize `Verified*` types, starting with
   `VerifiedFindingPurchase` (CA5).
7. Spend the next assertion effort on 4B in the response-dispatch boundary rather than on
   readers. It is the acceptance precondition the addendum named first.
8. Move evidence out of the source tree, scrub host paths and infrastructure identifiers from
   what is already committed (history rewrite is Connor's call), and stop citing `/tmp` as
   evidence.
9. Regenerate the addendum status block and `signed-json-boundaries.md` from the inventories,
   and either commit the economy review and qualification or mark that batch incomplete.
