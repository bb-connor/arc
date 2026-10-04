# Security and process landing ledger

> Execution owner: use `superpowers:executing-plans` inline, with one independent
> review before each protected landing. This is the authoritative landing order.

**Goal:** Land the qualified process/security foundation on `main`, retire
superseded PRs without losing source or review obligations, and retain an exact
remaining-work ledger.

**Current landing state (October 4):** #1168 is merged to `main` at
`4e3d94f07df30f37f364dd562b3e793c5cbf4e68`. All 25 exact-head workflow runs
passed on attempt 1, with 79 successful and ten explicitly skipped checks;
all 13 review threads are resolved. #1167 is now merged through protection at
`4f3c967f04af40b5025b9222e8db95a3aee0b5f4`, preserving exact head
`dd0e727ae6bc49728ec0e7e77be9b52ef85768a4` and the actual #1168 parent.
All four required checks passed. All eight exact-head runs are terminal on
attempt 1: seven succeeded and the historical-source controller refusal remains
failed. There are zero review threads and a Codex thumbs-up after the candidate
push; no formal GitHub review is claimed. Retained independent source review and
the repeated 20-method suite cover the unchanged definition bytes.

Local merge `f934e3ef7b` retains the actual definition landing without changing
the prepared source tree. The reusable caller now pins that full protected merge,
and its structural contract passes. All five authority workflow blobs match the
reviewed and landed prerequisite. #1160 is the sole active landing vehicle;
the bounded cut is committed, while final review and native/trusted/hosted
qualification remain pending. The [definition landing bundle](audits/foundation-definition-landing-20261004.json.gz)
retains the exact PR, protection, merge and component records. The foundation has
not landed.

The bounded-candidate review of `bc10d2b523` produced seven threads. Production
repair `dcae5d7ba4` uses the shared authority clock for worker issuance and
authentication, retires stale ACP contexts before every capability check, and
keeps malformed audit frames from terminating the broker daemon. Six worker
controls reproduce the original defect; all 18 worker protocol tests, 206 ACP
library tests, and three broker process tests pass. The broker process tests
reject wrong shapes, malformed JSON, duplicate keys and invalid UTF-8 before
valid provisioning, and retain graceful restart and no-secret-crossing checks.
The owning Clippy checks pass.

Fixture repair `a59fb7f564` reconciles Unix-only SQLite test modules, PQ fixture
visibility, injected nonce expiry, typed JWT errors, generated SDK models and
vectors, no-std tests, Cargo Deny inventory, and formal/fuzz/conformance test
inventories. All four generated-language checks, 73 Python model tests, Go
package tests, 109 vectors, 91 Unix recovery tests, 75 PQ threshold tests, all
ten active-defense scenarios and all ten process crash/recovery tests pass in
their retained component runs. Native MCP targets compile and four proxy
identity controls pass; actual Windows and native MCP execution remain required.
The runtime spine campaign is retained with its observed status, rather than
being inferred green from its component output. The separate npm parent-source
re-review passes eight real-scanner controls without broadening advisory scope
or claiming the advisory itself fixed.

Formal repair `b5ac107a94` pins Kani 0.68.0 and compiles its exact upstream source
with the one-line [upstream signature correction](https://github.com/model-checking/kani/pull/4819).
The actual Linux installer passes, the hosted kernel component verifies, and
reachable `catch_unwind` still fails as unsupported. The patch changes no proof
assumption or runtime source. The older MSRV failure, compiler crash and initial
zero-matching-harness invocation remain retained. The complete final proof sweep
is still required.

The [bounded review repair bundle](audits/foundation-bounded-review-repairs-20261004.json.gz)
retains these results and the unsuccessful hosted campaign. The ledger now has
**1,375 requirement records**, including all seven current threads and fourteen
repair boundaries. The worker and ACP threads have source repairs; five consumer
threads remain open under PR2, PB5, PB9, PR10 and TR9. Their original acceptance
and earlier foundation review assignment are preserved in each row's history.
They receive sequential follow-up landings under the existing
[foundation acceptance scope](foundation-acceptance-scope.md), and are not marked
fixed. Missing native fixtures in separate PostgreSQL and C++ consumers and
unqualified packaging jobs also remain explicit consumer acceptance.

These commits still require fresh independent review, exact-candidate hosted
checks, complete source-bound mutation/native evidence and the trusted capture
chain. Source authorization has not been rotated to an unqualified candidate.
There is one active landing PR, #1160; the 57 conditional retirement candidates
remain draft and none has been closed.

Projection `059c33104a` externalizes exactly 14,764 evidence files, keeps six
required local inputs byte for byte, and rewrites 101 links in 38 documents to
the immutable archive. The latest complete source is preserved remotely at
`archive/security-foundation-before-cut-20261004` (`bae73644c3`). Both required
histories and every later source repair remain ancestors of the cut. The cut
changes no production runtime source and preserves all 1,353 requirement rows.
Historical path literals resolve against archive `ecb44791501c2aba671de2a967d2506f039ab42e`;
use that commit's GitHub tree or `git show COMMIT:PATH` when a local artifact has
been externalized. Historical evidence keeps its original qualification limits.

The cut has 5,794 changed paths against prerequisite main `4f3c967f04`. Every path
has one primary review owner in the following dependency order. The retained
[projection bundle](audits/foundation-projection-20261004.json.gz) contains exact
path inventories and hashes; its own bookkeeping is a later packet-7 addition.

| Packet | Boundary | Paths at the cut |
| --- | --- | ---: |
| 1 | Wire, trust and time contracts | 326 |
| 2 | Durable authority and receipts | 938 |
| 3 | Kernel/process and privileged native boundary | 841 |
| 4 | Response and control-plane composition | 582 |
| 5 | Exposed consumers and network authority | 1,396 |
| 6 | Export, notification and existing product consumers | 88 |
| 7 | Qualification and operational definitions | 1,623 |

Ledger identities, all three source-copy controls, the full release-truth gate,
review classification, CI structure, all 20 definition methods and the 82-test
cage source inventory pass on the cut. These are bounded source checks. The
existing classifier retains its 15 defined classes, with 14 active in this diff.
Native execution, full mutation refresh, independent final review and exact
hosted qualification remain required before the foundation can land.

Before the bounded review repairs, the inventory contained 1,353 records. Commit
`dfb7543f40` adds five negative response-mode controls. Each detects deletion of
its production guard; restored source passes 39 focused tests with none ignored,
formatting and both owning crates' all-target Clippy. RP1 remains partial:
SQLite outbox invariants, authority-daemon mode checks and its distinct rejection
code still need their own controls and final candidate acceptance.

Two native-runner defects are repaired in source. Commit `875c5ba6d5` keeps the
five broker helpers in the fixed candidate-owned artifact target for their gate,
so the next command's ordinary Cargo cleanup cannot erase them. Its shell
regression fails before repair and passes afterward, and the complete
CI-contract suite passes in 556.170 seconds. Commit `80516260bc` permits bounded
broker readiness up to the smaller of 420 seconds and the operation budget;
cache setup already allowed 300 seconds plus execution probes. The delayed
readiness, shorter deadline and fixed ceiling controls pass, as does the full
CI-contract suite in 561.131 seconds. Process quiescence and the outer host
execution deadline remain unchanged. A real Linux image at
`536a677369` subsequently built successfully, matched all 14 installed boundary
files, and passed the Docker hostile-boundary suite in 77.817 seconds. This
component does not complete the native gates or final independent review.

A separate direct Linux cage run at `7c6bf2c8fd` passes all 82 tests, 29 real
probes and ten helper mutations with zero ignored. The initial driver parse
failure ran no native tests and is retained separately. The second native
mutation scenario, broker destination rebinding, also records a passing baseline
and one caught mutant; its command logs were removed by normal gate cleanup
before retention, so only its outcome and case bytes are retained. The third native
scenario, execution overspend, also passed its baseline and caught one mutant
with zero missed, unviable or timed-out mutants. Its outcome and case bytes are
retained; per-command logs were removed by normal gate cleanup. The complete
35-campaign refresh remains running and does not qualify later source.
The [response and runner bundle](audits/foundation-response-runner-controls-20261004.json.gz)
retains these bounded observations, failed fixtures and a zero-test invocation
without converting them into final foundation acceptance.

Native startup
repairs include source modes, exact bind-mount identity independent of Docker's
array order, bounded escaped verifier diagnostics, and constrained normalization
of valid Cargo-mutants Rust module paths. The latter passes eight boundary
methods, the existing checker fixtures and the real 16-file package inventory.
Ordinary validation still rejects stale mutation evidence. The first `c8d15236d2`
image build failed during unpacking because the worker disk was full. After
reclaiming unused private build cache and preserving every image ID, the exact
rebuild and all 14 installed boundary checks passed. The native run then failed
on an outdated mutation target after 127.052 seconds. These attempts remain
separate. The
[startup evidence bundle](audits/foundation-native-startup-20261004.json.gz)
preserves the original failures and component results.

The complete target scan found seven moved campaign owners and four moved test
paths after the response-model and cage crate extractions, affecting eight
campaigns. Commit `0e5a5812e6` repairs those references and two helper build gaps.
Both new helper regressions failed before their repairs; the final fixture block
passes. Real Cargo-mutants 25.3.1 selects all 35 intended viable mutants. Existing
outcomes remain unchanged and stale, and actual native execution is still
required. The [owner repair bundle](audits/foundation-mutant-owner-repairs-20261004.json.gz)
retains the source scan, regressions, exact selectors and failed native attempt.

The next native attempt on `0e5a5812e6` was cancelled after a confirmed invocation
defect: Cargo-mutants' cross-package baseline ran zero matching consumer tests
and derived its deadline from the smaller extracted owner. Commit `37cdda0454`
includes the existing consumer in the baseline. A real two-package Rust
regression failed before repair and then passed with one positive control and
one caught mutant. Commit `7c6bf2c8fd` permits four candidate compile jobs within
the existing four-CPU container quota. Mutation scheduling, command resets and
the memory/PID limits remain unchanged; forwarded concurrency variables are
rejected. Wrapper and adversarial fixtures pass. The complete shell gate still
rejects stale outcomes. The [baseline repair bundle](audits/foundation-mutant-baseline-repair-20261004.json.gz)
preserves the cancelled attempt, regressions, source review and cache cleanup.
The image for `7c6bf2c8fd` builds and all 14 installed boundary checks pass.
Its first native scenario passes the consumer baseline and catches the selected
response-plan authority-binding mutant, with zero missed, unviable or timed-out
mutants. The full refresh and final input-bound outcome validation are still
running. These component results do not qualify a later composed foundation.

The [definition composition bundle](audits/foundation-definition-composition-20261004.json.gz)
retains those partial native records, the complete composition regression
results and PR-retirement preparation. All 57 conditional retirement candidates
are now draft, including #1156. None has been closed. Original unique heads for
patch-equivalent #1140, #1139 and #1138 have remotely verified archive tags.
Their closure and retargeting of #1155 and #1172 still depend on the qualified
foundation reaching `main`.

Three superseded native preparation images were archived, fully checked and
successfully restored before their exact image IDs were removed from the worker
cache. The archive remains on the mounted evidence volume; the current image and
all other image IDs were retained. The bundle preserves the first failed archive
validator, corrected OCI index/manifest/config/layer verification, real restore
and explicit removal records separately.

Ruling: use the existing container CPU quota for candidate compilation while
keeping one mutation and one broker command active at a time. Dispose of Cargo
home, ordinary target and temporary state between commands. Candidate-owned
helper artifacts live only within their gate and are cleared at its boundaries.
Higher compilation memory may fail within the
unchanged 12 GiB limit; native duration and memory acceptance remain open.

Ruling: #1167's non-required controller run rejected the historical configured
source authorization, which predates the foundation execution files. Preserve
that failure and qualify this definition-only prerequisite through its reviewed
exact source and required ordinary CI. Do not change source authorization to
make the prerequisite green. The foundation still requires its full authorized
native capture and trusted evidence chain. If this separation were wrong, the
definition merge would lack required execution coverage; it cannot be used as
foundation acceptance.

**Architecture:** Preserve the accumulated branch as an immutable reference.
Land dependency closure and trusted workflow definitions first. Use PR #1160 for
the bounded foundation; qualify subsequent changes in dependency order. Keep at
most two PRs in the active landing queue.

**Tech Stack:** Rust, Cargo Vet/Deny, Python, Git, GitHub Actions and the existing
native Linux qualification and evidence contracts.

**Spec:** The user's October 4 landing directive, the
[launch execution contract](launch-execution-plan.md),
[September completion plan](../superpowers/plans/2026-09-22-security-roadmap-completion.md),
[assurance closeout](../superpowers/plans/2026-09-25-security-assurance-closeout.md)
and their recorded review corrections. This ledger changes sequencing, not the
security acceptance requirements.

## Global constraints

- The preserved source is `ecb44791501c2aba671de2a967d2506f039ab42e`, tagged
  `archive/security-roadmap-pre-landing-20261004`.
- Preserve security history `5d1a9ec0d900bd03ce55de903919d972be852d79` and process
  history `2e84f121273df7f205cc218739b86e93c91bdc37` in the foundation.
- A source repair, local pass, hosted pass, merge and operational acceptance are
  separate states. Historical checkboxes do not establish current qualification.
- Do not exempt the unaudited AWS-LC Rust dependency or weaken required checks.
- Use one Cargo owner per checkout, locked dependencies and `umask 022`. Bind
  `CHIO_CHECKOUT_ROOT` whenever a Cargo target is outside the checkout.
- Do not discard branches, untracked evidence or unique commits. No history
  rewrite is necessary for preservation or PR retirement.
- Workbench, funded-work, research and Mercury proof-feature development remain
  outside this security landing queue. Existing security repairs stay preserved.
- Automatic response remains disabled. A foundation merge is not M10 release or
  M11 pilot acceptance.
- Ruling: continue execution inline without subagents, as explicitly directed by
  the user. Retain completed independent reviews and require the final hosted
  review and qualification evidence; do not describe self-review as independent.

## Review focus

1. Missing or duplicate requirements in the ledger must be reported, including
   requirements inherited from review threads and superseded plan prose.
2. A dependency audit must identify exact upstream bytes and the local patch;
   Cargo Vet's registry-version model alone cannot authenticate a path fork.
3. Reduced build contexts and standalone locks must consume the same reviewed
   dependency, and its regression must actually run in CI.
4. A selected older foundation must carry later repairs to boundaries it exposes;
   choosing an old commit is not evidence that it is safe to merge.
5. PR retirement must preserve unique source and unresolved review obligations;
   an ancestor branch closed as superseded is not independently merged.

## Source of truth

The companion `landing-ledger.json` records each requirement's source,
disposition, repair/evidence references, remaining acceptance and landing unit.
It also records the PR ancestry inventory. Status pages link here instead of
maintaining competing continuation queues. Historical reports remain evidence
for their named source only.

The initial inventory contains 1,303 obligation records from 39 source documents:
explicit plan tasks/checklists, named findings, 109 inherited thread dispositions
and nine prerequisite review threads. The October 1 slices account for all 128
execution findings and 69 product/compliance findings. These records overlap by
design and are not 1,303 distinct defects. Uncorroborated historical claims remain
open for source/acceptance reconciliation; no count establishes readiness.
The October 4 prerequisite review adds 14 audit, regression and residual-debt
records, reaching 1,317 records from 45 source documents. Four further dependency
findings and three trusted-definition obligations bring the current inventory to
1,324 records from 49 source documents. These include the standalone lint boundary,
FIPS wrong-key regression, duplicate inventory, cipher module size, late-label
publication, conditional CI-history failure and bounded App issuance hardening.
The live retirement audit adds seven previously unmapped PR threads, bringing the
inventory to 1,331 records. They cover repository command framing, offline report
compatibility, preserved adaptive timeout provenance, macOS temporary paths,
release provenance ordering, six-host acceptance and the HTTP 201 approval client.
Their repairs and acceptance remain explicit; presence in the ledger is not closure.
The HTTP 201 client repair is committed at
`05b16402964e7288a80ed367d82b0ec88b2708eb`: final focused fixtures and independent
source review pass. Its foundation integration, native/hosted acceptance and
original thread disposition remain pending.
Three subsequent #1168 review threads and the exact serialized-patch-context
scanner repair bring the inventory to 1,335 records from the same 49 source
documents. The checker-context failure was reproduced and repaired; the reported
OpenSSL startup failure was not reproduced in the original static executable.
Explicit linkage hardening passed the real pinned native rebuild and a
read-only scratch-container runtime check. All three new threads are reconciled;
terminal exact-commit hosted checks and protected merge remain required. These
results are separate from full quickstart image or publication qualification.

The October 4 reconciliation assigns the 197 named October 1 findings by their
included owners: 126 foundation obligations and 71 bounded follow-ups. Of the
126, 38 retain inspected source repairs, eight retain partial repairs, six have
open archive-source observations and 74 retain original findings not freshly
reproduced. These are review and acceptance assignments, not 126 newly confirmed
defects or completed requirements. Source identities, linked checklist records,
historical evidence and remaining acceptance stay intact.

The foundation integration adds two concrete qualification repairs, reaching
1,337 records: current formal traceability/cancellation-clock modeling and
precise stub classification. KG4-KG8 now link their committed bounded repairs
and [retained source evidence](foundation-containment-20261004.md). Broader
original requirements and candidate acceptance remain open. The length-8
`SafetyInv` check passed in 5,598.248 seconds with retained exact model inputs.
The earlier 300-second timeout remains a separate unsuccessful calibration.
This is bounded model evidence, not runtime refinement. The broader affected-package run ended with
1,437 passed, one failed and one ignored. Its stale weak-key fixture was repaired
and all 83 finding-verifier package tests passed; the original campaign remains
failed and did not reach whole-package kernel tests.

The next source reconciliation reaches **1,342 records**. It records native
runner/wrapper binding, the checkpoint fixture repair, confirmed HTTP/portable
security-binding loss, post-refresh authority-time gaps and unbounded child
stderr. SF6 now links its explicit numeric decision. Preparatory packet 1 and 2
reviews and unsuccessful campaigns are in the
[review evidence bundle](audits/foundation-review-reconciliation-20261004.json.gz).
The HTTP/portable binding and post-refresh authority-time repairs are now
committed and independently source-reviewed. The later MCP and secret-output
repairs are recorded below; final qualification remains pending. No prerequisite
or foundation merge is claimed.

All six preparatory source packets now have retained reports and 148 linked
requirement assessments (including reviewed follow-ups). The
[acceptance scope](foundation-acceptance-scope.md) distinguishes included-owner
review from completion of every product feature. The
[frozen packet bundle](audits/foundation-packet-reviews-20261004.json.gz) has SHA-256
`dc2b69529a77c9a7cdad6aca1479beac587e988e72fcd708ed638fbfa36ac545`.
None of those reports qualifies the final integrated candidate. Later repairs,
remaining source findings and unexecuted acceptance stay distinct.

The current inventory contains **1,343 records**, including the three stale
kernel fixture migrations. Binding containment is committed at `ec1640c460`;
the owned-time repair at `7f168a0fb9`; and authenticated receipt, bounded journal
and retention fixture updates at `5ec8472b72`. The clock owner passed 33 tests.
The whole kernel campaign recorded 1,735 passed, one failed and two ignored;
its only failing target was the stale retention fixture. After correction, all
11 retention tests and strict lint passed. That focused result does not relabel
the earlier campaign or qualify the final integrated candidate.

The [authority follow-up evidence](audits/foundation-authority-followup-20261004.json.gz)
retains 109 records, their hashes, original failed commands, later successful
checks and independent reviews. Its SHA-256 is
`82a0fc321c609ab455e421d81ebc473163fff561df6b25882c5b4dc0155c5053`.
It also preserves the completed length-8 model result, scope review and archive
retrieval evidence. A fresh isolated Git fetch and anonymous HTTPS download both
retrieved the 14,764 evidence files selected for externalization with matching
bytes. Retrieval proves availability, not the truth of historical evidence.

MCP aggregate ingress and stderr containment is committed at `ea7b65b9b5`.
The final component run passed 144 unit tests and one integration test, with
strict lint and independent review. Shared admission counts wire bytes, JSON
nodes and decoded text before authoritative allocation; fixed stderr fragments
bound newline-free child output. These accounting limits do not claim an exact
process memory ceiling. Both the original failures and the later diagnostic
lock regression remain retained.

Canonical secret output now uses one checked, fixed allocation at `fffe1bdc33`.
The source review and 91 focused tests passed, along with a no-default build
and final strict lint. The original output-growth failure and the intermediate
test-fixture lint failure remain separate records. The same commit corrects
two unqualified FIPS Rustdoc claims and one test-only sorting lint. The
[memory-boundary evidence bundle](audits/foundation-memory-boundaries-20261004.json.gz)
retains the input snapshots, command logs and independent reviews. The inventory
remains 1,343 records at that checkpoint; composed foundation acceptance is still open.

The consumer-repair checkpoint contains **1,344 records**. The additional obligation records
the reproduced native unsigned-discovery decimal regression. Its repair and the
wrap evidence-claim containment are committed at `690ab00ada`. Sixty portable
tests and strict lint passed. The real native discovery control failed on the
baseline and passed all five modes on the frozen CLI snapshot; independent source
and native-evidence reviews accepted that component. This snapshot predates the
separate verifier test-module extraction and is not the final integration tree.
Wrap now refuses an explicit receipt-store option before launch and no longer
emits an unbound verification stamp. Durable denial evidence remains a follow-up.

Alert authenticity containment is committed at `6a4bfdad7c`. Paging requires
independent operator pins and fresh receipt ID, strict signature and action-hash
verification. The five original negative cases each reached both paging test
backends. The repaired default suites passed 199 tests with one explicitly
ignored feature-specific control; a separate actual P-256 feature run passed
that control. Six startup controls, strict lint and independent source review
passed. Existing paging deployments must configure pins before upgrading.

The verifier test-module extraction at `5c6b637af3` preserves both test bodies and
the existing file-size cap; all 83 package tests and strict lint passed. The
formal refresh at `8dd57215da` updates one reviewed portable-binding mirror,
documents its model limits and regenerates coverage. All 232 mirrors match;
65 rows and 179 declared artifacts are current. No new theorem is claimed.

The [consumer repair evidence](audits/foundation-consumer-repairs-20261004.json.gz)
retains 206 records, including command logs, source inventories, reviews and
original unsuccessful campaigns. Its SHA-256 is
`8d0db384ec986bd6f4af09bbd8d5024c1b59f1ada5dc1606aafbdabd67aa53ae`.
It also retains the disposable #1167/foundation composition preflight: all 596
named controls passed after including the 15 approved additions. The earlier
observer failure and incomplete 581-control assembly remain separate records.
Actual merged-base checks and final foundation qualification are still required.

The current inventory contains **1,346 records**. Twenty-five bounded #1168
requirements now have verified main ancestry and completed prerequisite landing
acceptance. Their prior acceptance lists remain in the JSON history. The two
new obligations record native wrapper defects: Docker's bind inventory order
was treated as authority, and `umask 077` prevented the isolated identity from
reading materialized source. Both failed before repair and pass component tests
at `98911149a4`. A native retry passed those startup boundaries but failed later
in the trusted verifier. The diagnostic repair at `77b8302ade` preserves a bounded,
escaped output tail only after verifier and broker cleanup; it does not change
acceptance. Final native/trusted evidence and independent hosted review remain
required. The [prerequisite landing evidence](audits/foundation-prerequisite-landing-20261004.json.gz)
retains 62 records, including unsuccessful attempts, with SHA-256
`fcaa9561afc96351a7f5cb9db108d6ae3d741c498e12c22215a439bce3305893`.

## Active queue

| Order | PR | Responsibility | Acceptance |
| --- | --- | --- | --- |
| 1 | [#1167](https://github.com/bb-connor/arc/pull/1167) | Trusted workflow definitions | Dependency base is merged; exact-head hosted checks, refreshed review and protected merge remain |
| Waiting | [#1160](https://github.com/bb-connor/arc/pull/1160) | Bounded process/security foundation | Both histories, required security repairs, independent review, native/trusted evidence, exact-candidate CI |

Later hardening and product-evidence slices receive a PR only when an active
slot becomes available. Their source remains in the preserved reference.

Both prerequisite merges are now present in the foundation history. The bounded
cut advances #1160 into the sole active landing slot. The composition preserves
the audited fork byte for byte and resolves shared manifests by retaining the
foundation source closure with the repaired dependency floors. The committed
projection is still awaiting final qualification.

### Task 1: Establish and validate the authoritative ledger

**Files:** `docs/security/landing-ledger.{md,json}`, existing status indexes and
`scripts/check-security-landing-ledger.py`.

**Interfaces:** Consume immutable specifications, execution records and live PR
threads; produce requirement-level dispositions and a bounded landing queue.

- [x] Inventory all requirement sources and inherited review threads.
- [x] Record repairs and evidence without converting historical passes to current
  qualification; explicitly retain unimplemented and unverified requirements.
- [x] Verify coverage, unique identities, source hashes, evidence links and queue
  limits with `python3 scripts/check-security-landing-ledger.py`.
- [x] Update existing status documents and remove competing continuation orders.
- [x] Commit and publish the reconciled ledger (`f6b9203728`).

### Task 2: Repair and land the prerequisites

**Files:** PR #1168's dependency manifests, vendored AWS-LC source/provenance,
audit records, regression and workflow inputs; PR #1167's five workflow files.

**Interfaces:** Consume Task 1's exact source and review IDs; produce reviewed
dependency closure and trusted workflow definitions on `main`.

- [x] Reproduce the Cargo Vet failure and disposition all 13 #1168 threads,
  including the later vendor, runtime and reduced-context reviews.
- [x] Complete genuine source review and exact fork reconstruction; retain
  failures and run default, FIPS and DES regression qualification.
- [x] Repair confirmed regressions with failing-then-passing checks. Verify
  standalone locks, reduced build contexts and workflow triggers.
- [x] Obtain an independent review and required terminal checks for #1168's exact
  head, then merge without bypassing protection.
- [x] Integrate that main base into #1167, qualify its reviewed definitions and
  exact-head checks, then merge without bypassing protection.

### Task 3: Qualify and land the bounded foundation

**Files:** PR #1160's selected foundation and the production/qualification owners
required by its dependency closure.

**Interfaces:** Consume both preserved histories and Task 2's merged main base;
produce a source-pinned qualified foundation on `main`.

- [x] Select a dependency-ordered cut and map later repairs onto exposed
  boundaries. Preserve all remaining source in the archive reference.
- [ ] Reconcile source, review, native runner, signed capture and CI identities.
- [ ] Run complete foundation acceptance and independent review, repair failures
  without weakening assertions, then require terminal exact-candidate CI.
- [ ] Merge #1160 through protection and verify the resulting main ancestry.

### October 1 finding reconciliation

The JSON's `review_reconciliation` fields distinguish the original review tip
from the archive source inspected on October 4. Product findings were reviewed
at `122414b48e`; execution findings were reviewed at `a2630c20a1`. Their original
wording and source line hashes remain unchanged. An open historical finding has
not been newly reproduced merely because its owner is included in foundation.
Each row records its scope reason, review packet, owner references, concrete
source observations where available and remaining acceptance. Null candidate
identity, `candidate_qualified: false` and `finding_closed: false` are explicit.

Review the foundation in this dependency order:

1. Wire, trust and time contracts.
2. Durable authority and receipts.
3. Kernel/process and privileged native boundaries.
4. Response and control-plane composition.
5. Exposed consumers and network authority.
6. Export, notification and existing product consumers.
7. Qualification and operational definitions.

Carry SR1/PB1/PR1/PR6/TR1 and AP1-AP11 with their exposed owners. TR1's previous
September 30 guard-record pointer was unrelated: its source repair is
`66e9ecc5bda75b15cf2e60d67a220a0c4bb396b2`, with direct-consumer qualification at
`f6c8c39067b7264aed41afbfb8f639675e3137d8`. The superseded pointer is retained as
bookkeeping, and the original failed consumer run stays distinct from its later
passing rerun. Repair checkpoints record provenance, not a cherry-pick recipe.

Keep the partial boundaries explicit:

- EV5 includes API/start retention arguments and serving maintenance wiring;
  other launchers and deployed retention acceptance remain open.
- NC1 includes native grant/base-tool and build/download workflow repairs;
  final supported native and trusted capture acceptance remains open. NC8 has
  an injected preparation clock, with direct issuance expiry/grant/failure
  acceptance still unverified.
- EV1 covers automatic pager minimization; general receipt/SIEM privacy remains
  open. EV15 signer containment is source-repaired, with final qualification
  pending. EV6 covers signed packages, independent pins and
  retained reads, with complete certificates, independent child proofs and a
  separate Mercury proof format still open.
- CA3 covers the catalogued actual JSON routers, not arbitrary macros, dynamic
  routes, generators or other formats. GT1's historical structural repair does
  not classify the later eight `chio-http-serve` paths. CA1's final hosted
  integration remains open.

The observed KG4/KG5/KG6 policy behavior, KG7/KG8 normalized attestation records
and RC9 ambient trust-control clock require current composition and contract
acceptance. Adjacent repairs do not close these questions. Other open historical
findings retain their original evidence and specific acceptance without being
relabeled as newly confirmed defects. The 71 follow-ups retain explicit limits
on foundation claims; moving a finding is not a waiver of an exposed authority
contract or permission to discard an existing repair.

Foundation acceptance still requires a concrete source SHA and supported
constructor/feature set, required owner regressions and full checks, fresh
independent integrated review and terminal exact-source hosted results. The
supported native Linux x86_64 profile requires kernel 6.7 or newer and all cage
prerequisites, source authorization, trusted workflow/caller/controller identity,
helper/runtime and immutable image identity, signed capture and independent
observation. Run the joined capability/task/cage/nonce/receipt evidence against
that candidate through the merged #1167 chain. Preserve required test fixtures,
retrievable original evidence and the distinct failed, interrupted, skipped or
ignored outcomes. No mapping entry establishes M5 operational acceptance,
M10/M11 completion, FIPS certification, broad privacy compliance or a release.

### Task 4: Retire superseded PRs and establish sequential follow-ups

**Files:** The PR disposition inventory, this ledger and affected PR metadata.

**Interfaces:** Consume requirement coverage and proven ancestry from Task 3;
produce fewer open PRs with preserved source and explicit follow-up ownership.

- [ ] Verify each retirement against current heads and transfer every review
  obligation to its replacement record.
- [ ] Retarget surviving dependents, close superseded PRs with replacement links
  and preserve branches containing unique source.
- [ ] Keep at most two PRs active; assign later security slices in dependency
  order and leave unrelated product/research tracks separate.
- [ ] Refresh main/remote/PR identities and report completed and remaining
  requirements with their actual acceptance boundaries.

## Execution record

- October 4: refreshed origin; main remains `f5566d9a765c21cb36652a99c79de64968a656bf`.
  PR #1168 remains `b0dfffb35e5e889d158767e31bfe0d2da1832413`.
  Fresh `cargo vet --locked` exits 255 with exactly one unvetted dependency:
  `aws-lc-rs:1.18.1` missing `safe-to-deploy`.
- Ruling: use the user's explicit execution and landing authorization throughout
  this sequence. Routine skill approval menus do not require another approval.
  Protected checks and genuine audit requirements remain mandatory.
- Ruling: retained raw logs stay outside the source tree; commit concise audit
  reports, exact identities and content hashes. If a required artifact cannot be
  independently retrieved, its public-evidence acceptance remains open.
- October 4 prerequisite candidate: `c5b36bd17bcd4c1189f40285451e30117480c236`
  is committed, pushed and independently source-approved. All nine original
  review threads are resolved. Exact-commit hosted checks and protected merge
  remain pending; main has not moved.
- Genuine AWS-LC review found six partial AES-key initialization sites and an
  invalid private C-string conversion. The fork repairs both and retains DES
  validation. The published registry wrapper is not certified safe to deploy;
  its non-implying review criterion is combined with mandatory authenticated fork
  reconstruction, six deployment graphs, native/transitive audits and tests.
  No Cargo Vet exemption was added.
- Independent review also drove mandatory immutable-source publisher gates,
  build-output isolation, current hosted/formal contracts, static native builder
  dependencies and a disputed-payment regression repair. The original failures
  remain retained. Native default/FIPS/Memcheck and focused repair tests passed.
  Actual aarch64 Alpine builder commands exited zero; 4,379 copied source inputs
  and the Dockerfile match the candidate. This is not full image publication or
  native security-enforcement qualification.
- The npm lock repair removes 23 patchable advisory IDs. Two unpatched
  peer-tooling exceptions expire on October 18 and have independently exercised
  scope/expiry controls. They, three inherited npm exceptions and the inherited
  cpp_demangle baseline audit remain explicit follow-up debt. An effective
  passing scan does not erase the retained raw findings.
- Foundation boundary assessment: retain #1160's lineage and both histories,
  integrate the qualified prerequisites, and project the archive's necessary
  source repairs into dependency-ordered review slices. Bare historical cuts
  omit later custody/authority repairs. RV1-RV5 are mandatory foundation
  obligations because their owners are exposed; they are no longer queued as
  optional follow-ups. The candidate has not yet been constructed or qualified.
- Raw evidence externalization requires dependency analysis. Four evidence
  trees account for 14,770 of the archive's 20,701 changed paths. Required test
  fixtures, exact-source manifests and retrievable evidence must survive a cut.
  The eight `chio-http-serve` paths also need a review-slice owner before the
  broad-diff gate can accept the projection. Existing Mercury security consumer
  repairs remain in scope; new proof development stays in its separate track.
- October 4 named-finding reconciliation: applied all 128 execution and 69
  product/compliance records without adding requirements. Assigned 126 to
  foundation/#1160 (122 newly moved) and retained 71 bounded follow-ups. Corrected
  TR1 provenance and partial EV5/NC1/NC8 records, retained 13 repair provenance
  groups and 57 bounded source observations, and preserved all original source
  identities and prerequisite execution prose. The active queue remains
  #1168 then #1167; no foundation candidate is qualified by this bookkeeping.

- October 4 prerequisite follow-up: dependency candidate `83e8e22cbbf3180430d0025a5627187c4cd1c0e4`
  preserves the reviewed standalone unwrap/expect policy and FIPS wrong-key repair.
  An exact forced-warning inventory supplements normal deny enforcement; 34 narrow
  items cover 39 distinct sites. The library passed 386 default/legacy and 492 FIPS
  tests; the mandatory source/audit/lint composite passed with authenticated
  reconstruction of all 186 files. Independent review approved the module move
  and exact exception spans. All ten source review threads are resolved; terminal
  exact-head CI and protected merge remain open.
- The superseded `5e17dd7703` hosted run failed the unchanged cipher file-size cap.
  The new source moves the identical HKDF key conversion into the existing key
  module, reducing the public cipher module from 2,271 to 2,258 lines under the
  unchanged 2,266 cap. The failed campaign is retained, alongside the earlier
  duplicate-baseline failure and actual FIPS wrong-key failure.
- Trusted-definition repair `859b2c26354099f6a11e5565768b77607780b344`
  revalidates labels/mode at success publication and explicitly propagates CI
  catalog failures from helpers invoked in Bash conditionals. The initial 14
  passing controls did not cover the catalog defect; independent reproduction
  and the later 20-method suite exercise the actual conditional helpers/callers,
  retries and all five revocation namespaces. Independent source review and a
  fresh root rerun passed. The actual merged dependency base, exact-candidate
  hosted checks and protected merge remain required. Real App operation and
  native/trusted foundation evidence are not established by these fixtures.
- Ruling: retain explicit repository selection at App token issuance as bounded
  follow-up hardening. Current publisher/revoker code rejects any post-issuance
  scope other than this repository before writes; no cross-repository write path
  was established by review. This is not a waiver of identity or scope checks.

- Ruling: prepare #1160 locally while prerequisite hosted checks run, using the
  preserved archive, latest published ledger and independently reviewed
  prerequisite heads. This avoids idle integration work; it does not change
  landing order. Bind and integrate actual prerequisite main merges before
  artifact projection, exact-candidate qualification or protected foundation
  landing. Keep #1160 outside the active landing queue until a slot opens.
- The provisional dependency integration retains the complete authenticated
  AWS-LC fork from #1168. Resolve shared manifests, locks, workflow contracts and
  source ratchets semantically, preserving the foundation's later exposed-owner
  repairs. No blanket choice of either branch qualifies that composition.

- Ruling: qualify current protocol names as ACP-Client in current documentation
  and review synopses. Preserve the original frozen reviews and source identities.
  The release-copy gate remains unchanged; three ambiguous historical artifact
  lines remain failing until the reviewed archive projection removes those local
  copies. No passing whole-tree release-copy result is claimed before projection.
