# Recovery review register

[review-register.json](review-register.json) is the canonical current inventory.
It preserves the original 328 IDs, separately catalogs later findings, and records
current applicability without rewriting historical acceptance. This register is
an inventory and local source-pin comparison. It grants no runtime, Linux,
provider, formal, hosted, or release qualification.

## Reconciliation

The live inventory and effective scoped dispositions are:

| Inventory | Records | Effective scoped dispositions | Currently open |
| --- | ---: | ---: | ---: |
| Canonical original findings | 328 | 101 | 227 |
| Additional maintained or actually executed support findings | 21 | 21 | 0 |
| Supplemental PR obligations | 1 | 0 | 1 |
| Current or executed-support total | 350 | 122 | 228 |
| Prevented candidate issues, counted separately | 31 | Not combined | Not combined |
| Follow-up findings first observed in uninstalled candidates | 13 | Not combined | Not combined |
| Provenance prerequisite, excluded from implementation findings | 1 | Not applicable | Not applicable |

The 122 scoped dispositions include 41 historical closures whose current source
applicability still needs review. They are not 122 current-source approvals.
`counts.current_acceptance` separates these dispositions from current applicability.

The explicitly historical **394-record baseline** retains 99 canonical closures
(92 source-only, seven scoped local), 19 additional closures (seven source-only,
twelve scoped local), and 231 unclosed maintained/support findings. Its 118 total
scoped closures and every `recorded_*` counter remain unchanged. New canonical
and additional closures are recorded through additive successors and counted in
`current_acceptance`. The earlier 117-closure snapshot also remains preserved.

There are **394 findings or candidate issues**, plus the excluded provenance
prerequisite, for **395 live records**. The original prevented inventory retains
23 assigned IDs and eight unassigned records. Thirteen candidate follow-ups and
two additional findings have null finding IDs. There are still 371 assigned
finding IDs, or 372 including the prerequisite, and twenty-three null IDs.
Every original ID and exact unassigned reviewer label remains preserved.

The current status counts are:

| Status | Records | Meaning |
| --- | ---: | --- |
| `open` | 228 | No complete independent disposition is recorded. |
| `needs_revalidation` | 41 | Historical closure remains, but cited source or document pins differ without an accepted current continuity review. |
| `recorded_scoped_closed` | 81 | Historical or additive accepted scoped disposition currently applies, with the limits stated per record. |
| `candidate_only` | 44 | The defective candidate was uninstalled when found; corrected successors may have separate evidence. |
| `prerequisite_only` | 1 | Provenance work, not a proved implementation defect. |

The 41 remaining revalidation flags are part of the original 117 historical scoped
closures. They are not added to the 228 currently open findings. No finding is declared
regressed merely because its bytes changed, and no matching pin constitutes a
new behavioral test. The initial audit flagged 48 closures. An independent
[explanation evidence continuity review](reviews/explanation-evidence-continuity.md)
subsequently confirmed that the README change for `A-planner-07` adds navigation
only and preserves its original source-only obligation. Its historical pin
difference remains recorded, alongside the current review and its scope.

The [SDK compatibility and portability continuity review](reviews/sdk-compatibility-portability.md)
then restores only the original scoped classifications of `H-SDK-02` and
`H-SDK-11` after SPEC_PASS and independent QUALITY_PASS. Their historical changed
pins remain recorded; additive `current_review` objects retain both previous
statuses and reasons. That update left 35 canonical and ten additional
revalidation flags. Historical closure totals and every other record are unchanged.
That historical update left fixture cleanup and metadata work pending. Their
subsequent bounded installation is recorded below; `H-SDK-01` remains open.

The [coverage locator continuity review](reviews/coverage-locator-continuity.md)
subsequently restores `C1-08`, `E-knowledge-15` and `G-product-07` for their original
source-locator obligations only. SPEC_PASS and independent QUALITY_PASS account
for all 243 pointers (160/55/28), 14 protected historical inputs and the unchanged
mappings of 108 references in the changed containing test file. Historical pins
and previous statuses/reasons remain intact. That update left 32 canonical
and ten additional flags. This grants no behavioral, test-run or runtime acceptance.

The installed SDK changes affect six direct pin pairs across `H-SDK-03`,
`H-SDK-08`, `H-SDK-09` and `SDK-INDEPENDENT-03`. The independent
[installed SDK continuity audit](reviews/installed-sdk-continuity.md) maps the
bounded reviews and maintained tests to their original scoped contracts. Each
record now states that its pins changed and links `current_continuity`. Its
historical `pin_check`, disposition and classification remain unchanged. These
four changes add no revalidation flag or runtime qualification.

The subsequent [Kernel installation audit](reviews/receipt-owner-registration.md)
checks 29 distinct paths from the finishing foundation and optional receipt
registration. None intersects the 767 canonical, five document or 30 additional
direct/current/accepted pin pairs for the 117 historical closures. It adds no
revalidation flag. The older retained-request execution snapshot for
`SEMANTIC-REVALIDATION-APPROVAL-BINDING-01` remains within its existing flag;
aggregate Kernel passes do not renew that obligation. The sealed audit is linked
under `current_updates`; the original pin audit remains intact.

The [checkpoint source retirement repair](reviews/checkpoint-source-retirement.md)
closes only `CK-LEGACY-RETIREMENT-SOURCE-01` in bounded local scope at
`7f5163ac4e8d0ef10f8ca0af41f2c8ea82542b69`. Genuine owning reproduction,
public-interface regressions and independent spec/quality reviews satisfy its
three preserved obligations. The original finding fields and historical counters
remain unchanged; its additive successor supplies the current disposition.
There are now 16 P1, 123 P2 and 89 P3 open records. Full-module, strict-lint,
native-prerequisite and qualification gates remain open. The same review records
the independently approved required-CI routing repair and its queued hosted run.
`continuation.working_queue` holds the dependency-ordered execution queue within
this existing register.

## Candidate follow-ups

Two independently reviewed source units have subsequently been installed and
verified locally: [SDK state projection](reviews/sdk-recovery-state-projection.md)
and [explicit authority provisioning](reviews/native-authority-provisioning.md).
Their evidence and remaining obligations are recorded in `current_updates`.
H-SDK-01 remains open and provisioning is a prerequisite. Those installations
did not change finding classifications or grant qualification. The subsequent
foundation reviews add the six candidate records below.

The first eight additive `candidate_followup` records below did not change
canonical closure counts or installed-finding totals. All preserve their original finding evidence;
the Kernel and receipt lifetime records add independently approved corrective successors. Their
exact local evidence hashes and accounting time are in `candidate_review_evidence`.

- `candidate:checkpoint-receipt-confirmation-envelope` records the third real
  integration run: the receipt INSERT fault passed, while the positive committed
  Process and failed Native confirmation with `OutcomeUnknown`. Source diagnosis
  found obsolete v1 receipt pricing that omitted v2 `result_basis` and used the
  wrong sequence-domain spelling. The correction uses the existing 8192-byte
  producer ceiling. Its successor passed three envelope controls and both
  mandatory external checkpoint cases locally, with zero failures or ignored
  cases. Independent spec and quality reviews approved the bounded repair.
  The candidate remains uninstalled and unqualified.
  No review severity was assigned, so the severity remains null.
- `candidate:checkpoint-stage-error-source-chain` preserves the authentic P3
  finding and its independently approved source-only repair. The corrected stage
  wrapper retains the original boxed error and source chain, with all 45 assertion
  expressions and both case bodies unchanged. The exact reviewed test successor
  also compiled and passed the two local cases. The candidate remains uninstalled
  and unqualified; source review and local execution retain their separate scopes.

- `candidate:kernel-foundation-ordinary-durable-original` is the P1 source-review
  finding that a legitimately absent retained request denies ordinary durable
  admission before Native selection is checked. A subsequent corrected pre-fix
  control reproduced that exact denial. The approved successor checks actual
  Native selection; both owning eligibility controls passed locally.
- `candidate:kernel-foundation-loom-runtime-gate` is the P2 missing configuration
  gate. The actual pre-fix loom compilation failed with 30 compiler errors and
  executed no tests. The approved successor adds `cfg(not(loom))`; all 18 local
  Session-only Loom controls passed with `LOOM_MAX_PREEMPTIONS=3`.
- `candidate:process-foundation-missing-test-suppliers` is the P2 registration
  defect affecting thirteen enrollment-dependent and two lifetime acceptance
  cases. The source reviewer ran no tests. Preserve all future positive
  obligations while making the supported default target executable.
- `candidate:receipt-owner-borrowed-backend-lifetime` is the P2 public trait
  compatibility regression: adding `Any` to the base `ReceiptStore` trait excludes
  ordinary non-static borrowed backends. Its genuine compile reproduction exited
  101 with `E0478`, `E0803` and `E0597`. The approved successor restores that
  contract and confines concrete identity to optional same-Arc owning registration.
  Only the nine-path Kernel subset is installed at `032d77338`: one borrowed
  control, 1,472 library tests, 25 doctests, strict library Clippy and format passed.
- `candidate:receipt-stored-original-comparison-control` preserves reviewer
  label `P3-B1`: the original added-field request control stopped at schema
  validation before stored raw JSON comparison. Its approved successor proves
  genuine committed-row substitution, the exact comparator refusal without row
  mutation, and successful readback after restoring the original bytes.
- `candidate:receipt-queued-lane-inflight-ownership` preserves reviewer label
  `P3-B2`: the predecessor terminal-supervisor control left inflight at 2 instead
  of 0. Its approved successor gives each command one accounting token across
  queued, dispatched and returned states, with actual actor failure controls.

Those eight records use register keys with null assigned finding IDs. The
[Kernel foundation successor](reviews/kernel-foundation.md) also records 1,469
passing Kernel library cases on the composed candidate. That candidate includes
the separately approved atomic-ledger overlay, while the foundation source
selection uses frozen preimages for two overlapping files. Candidate runs do not
establish a separately executed foundation-only or maintained installation build.
The reviewed 22-path foundation was subsequently installed at `b7d71059c` and
separately passed 1,468 maintained library cases, 25 doctests, 18 bounded Loom
controls, format, names, boundaries and strict library-only Kernel Clippy. The
excluded atomic-ledger callback test exactly explains the library count difference.
All-targets strict Clippy remains failed with 248 Store development-dependency
diagnostics whose exact primary signatures match the prior maintained run.
These installed results are separate from candidate results. The Process supplier
finding has no accepted successor here. Earlier failures, original dispositions and all
candidate-only classifications remain unchanged. The original two-case receipt
fault evidence is not retrospectively credited with the later, distinct
retained-reservation test.

The [receipt registration successor](reviews/receipt-owner-registration.md)
separates its 1,473-test composed-candidate run from the 1,472-test maintained
Kernel subset. The excluded atomic-ledger callback is the exact one-test delta.
The two Store P3s are **closed in the reviewed four-file candidate scope** after
SPEC_PASS, QUALITY_PASS and 27 owning cases passed with no failures or ignored
cases. Their original findings and candidate-only classifications remain intact.
The first repaired build failed E0583 before tests; that failure and the genuine
queued-lane red remain preserved. The Store repair is uninstalled: its genuine
`configured_owner` consumer, closed installation selection and isolated strict
checks remain pending. A broader receipt module run failed with 390 passed,
17 setup failures from absent `/dev/shm`, and two existing scale cases ignored.
The associated qualified anchor behavior was not exercised; this leaves the
broader gate open without erasing the 27-case P3 closure.
No Store/Process implementation, production host activation
or Capture overlay is imported by the Kernel registration installation. Complete
funding, retained debt, interruption/reopen, historical settlement and retirement
retain their own obligations.

## Installed fixture lifecycle and SDK readiness

The [fixture lifecycle and SDK readiness review](reviews/fixture-lifecycle-and-sdk-readiness.md)
records the eleven-file installation at `c5f53a96dbfc836bfc42805c2fee2d393dd78821`.
The exact maintained source passed 1,438 SDK/framework cases and 56 composed
fixture cases in each of normal and optimized Python, with zero recorded network
attempts. The later full fixture discovery at that epoch failed with 129 passed
and one assurance-map error across 130 tests; its scope and source pins remain
preserved. The subsequent accepted correction is recorded below. The canonical installation record pins the final selection, independent
reviews, EOF-only quality continuity and final runs. Previous failures and review
snapshots remain unchanged.

This adds six authentic findings: one maintained P2 readiness defect with both
inherited immediate and late-drain facets, and five candidate defects. The new
maintained record has a bounded local closure. The two campaign interruption P2s,
cooperative-grace P2, stale-import P3 and introduced completed-delivery P2 retain
`candidate_only` status with approved, installed corrective successors. No
canonical finding receives cross-credit or a new closure.

Independent final quality also preserves the original scoped contracts of
`H-SDK-08`, `H-SDK-09` and `SDK-INDEPENDENT-03` against the changed Python host pin.
Their old pins, prior continuity objects and exact previous reasons remain
available under additive continuity successors. `H-SDK-01`, `H-SDK-04` and
`QF-07` remain byte-identical and open, including their native and matched live
campaign obligations. The stopped Capture work remains parked.

The source-bound hosted snapshot has 64 queued checks and two skipped. Its two
unresolved comments map to existing `PR-SETTLEMENT-CAPACITY-01` and the
`R2-X-resources-01` large-database facet; the latter is outdated but unresolved.
`R2-X-authority-03` remains a distinct related obligation. This adds no duplicate,
thread resolution, behavioral acceptance or global qualification.

## Source-map, environment and comment successors

The [source-map and fixture-environment review](reviews/source-map-and-fixture-environment.md)
records four independent spec/quality acceptances. `R2-R-evidence-06` receives a
source-only successor closure for the two documents installed at `14b5b4170`.
A new maintained P2, `additional:assurance-map-removed-begin-anchor`, preserves
the original 129/130 failure and receives a bounded local closure after the
reviewed two-file repair was installed at `59431cb6b`.

Both full installed fixture suites passed 133 cases on 663 stable inputs, with
zero recorded external attempts. Independent review closes `QF-04` only for its
original import/cwd defect on the disclosed Python 3.12 supported profile and
exact five-value relative parent environment. Interpreter and audit-wrapper
substitutions are explicit; literal catalogue equality and qualification remain
false. The earlier fixture/SDK report stays an unchanged historical snapshot.

`SOURCE-HYGIENE-SUPPORT-03` regains its original source-only comment classification;
its changed manifest pin, historical closure and previous revalidation reason
remain intact. The current flags are 31 canonical and ten additional. Comment
continuity grants no dependency or build acceptance. The three original rows
retain every historical field, with additive successors and current status/reason
changes only. No native, provider, Linux, formal, hosted or whole-runtime
qualification is added.

## Model-response parser controls

The [SF-R02 parser acceptance](reviews/model-response-parsing.md) records all four
original local controls passing on unchanged maintained source. Three negatives
reuse the current 133 normal/optimized fixture runs and their 663 stable inputs;
only the missing original positive assertion set ran again, once per mode.
Exact refusal categories, consumed attempts and positive metadata are preserved.
The disclosed Python 3.12.11 profile supplies no provider, native, Linux, hosted
or primary qualification. Companion independent spec and quality reports cover
only this bounded local acceptance. `SF-R02` stays open for its original broader
catalogue obligations.
Its previous reason is retained in an additive successor; the other 394 records,
all counts and original obligation references are unchanged.

## Source-pin audit

The JSON records the inventory time, candidate HEAD, four source inventory
paths and hashes, changed pin pairs, and the IDs affected by each changed pair.
The comparison reads local bytes and does not run providers or qualification
campaigns.

Inventory refreshed at `2026-10-09T14:12:27.875880+00:00` after the STATUS navigation
update. Its historical expected pin and all disposition counts remain unchanged.

| Pin inventory | Distinct path/hash pairs | Matching | Changed | Affected recorded closures |
| --- | ---: | ---: | ---: | ---: |
| Canonical direct `current_source_pins` | 767 | 751 | 16 | 34 |
| Canonical installed documents and operating guide | 5 | 4 | 1 | 4 additional |
| Additional explicit current or accepted source pins | 30 | 16 | 14 | 10 |

No audited path is missing. Counts represent path/hash pairs within each
inventory, not distinct files across inventories. Some direct pins identify
support evidence rather than production source; their recorded scope remains
authoritative. Large transitive build inventories are left in their original
evidence records.

The document difference is `implementation/STATUS.md`; it affects `C1-08`,
`E-knowledge-15`, `G-product-07`, and `I-evidence-qualification-01`. The JSON
lists the other 34 canonical IDs and ten additional IDs under `pin_audit`.
Recorded successor reviews and source-continuity amendments remain linked.
They must be evaluated against the integrated candidate, rather than discarded
or treated as automatic current acceptance.

`G-product-11` and `G-product-14` have no direct pin arrays in the disposition
overlay. Their recorded closures are retained with an explicit note that their
referenced execution/review source applicability was not re-adjudicated here.
Other rows without directly supplied pins retain the same limitation. Consult
each record's `pin_check` and `current_reason` before interpreting its status.

## Record contract

Each `records` entry has:

- `key`: unique register identity. Assigned IDs are used verbatim. The eight
  `unassigned-prevented:<index>` values are register keys, not invented finding
  IDs; the index resolves to the unchanged addendum record. The thirteen descriptive
  `candidate:<behavior>` keys and both additional descriptive keys likewise have
  null finding IDs, with authentic reviewer labels retained separately.
- `id`, `severity`, `title`, and `dependency_group`: original identity and review
  priority, plus the execution workstream. A null severity means the reviewer
  did not assign one or the entry is an excluded prerequisite.
- `category`: `canonical`, `additional`, `supplemental_pr`,
  `prevented_candidate`, `candidate_followup`, or `provenance_prerequisite`.
- `obligation`: the canonical original obligation verbatim, apart from path and
  punctuation sanitization, or a concise behavior obligation for later records.
  Structured canonical obligations remain structured.
- `evidence_refs`: exact source records. `reviewed#/rows/0`, for example, means
  the `reviewed` path in `source_inventory` and JSON Pointer `/rows/0`. Candidate
  follow-ups use direct repository-relative paths pinned in
  `candidate_review_evidence.files`, `fixture_lifecycle_sdk_evidence.files`, or
  `source_map_fixture_environment_evidence.files`.
- `remaining_obligation_refs` or `remaining_obligations`: all applicable owner
  checks remain authoritative. A short summary does not replace the linked
  detailed requirements, nested support findings, same-ID updates, or limits.
- `recorded_disposition` and `recorded_scope_ref`: what the historical reviewer
  actually accepted or left open, separately from today's source applicability.
- `current_status`, `current_reason`, and, where available, `pin_check`: current
  inventory adjudication and its limits. They do not overwrite source records.
- `current_successor`, where present: additive corrective review and execution
  scope, including the exact previous `current_reason`, source evidence and
  installation boundary. Original disposition and status remain separate.

Source aliases resolve to repository-relative files in `source_inventory`.
Those files remain local historical evidence under `target/`; a fresh checkout
needs the preserved evidence archive to inspect them. The tracked register is
self-contained for identities, obligations, classification and current status,
but it is not a replacement for the original review and execution artifacts.

## Execution guidance

1. Start from one integrated candidate. Preserve the original inventories and
   historical execution epochs. The continuation's private compositions were
   recorded as uninstalled; merely indexing them does not integrate them.
2. Work in dependency order: productive native funding and complete owned source
   quotes; Process enrollment and debt-preserving writers; sealed retirement
   and active/history separation; historical signer acceptance; then bounded
   owning controls and the separately authorized qualification work. The full
   remaining continuation obligations are retained in the JSON.
3. Use `dependency_group` and severity to choose work, while keeping each ID's
   obligation intact. Related IDs are relationships, not duplicates. In
   particular, `PR-SETTLEMENT-CAPACITY-01` remains distinct from `C1-06`, and the
   large-database PR facet remains attached to existing `R2-X-resources-01` and
   distinct `R2-X-authority-03` without increasing the original count.
4. For a revalidation flag, inspect the recorded accepted source, applicable
   continuity amendments and current candidate diff. Re-run the owning controls
   where behavior changed or evidence no longer establishes the contract.
   Record a new scoped disposition and its candidate binding before removing
   the flag. A source hash match alone cannot establish new runtime acceptance.
5. Keep prevented and follow-up candidate defects separate from installed defects. Preserve
   any genuine isolated failures and limited corrected-source passes, without
   inventing a production failure for the uninstalled bad candidate. The Kani
   lifecycle follow-up remains the same ID with its interruption obligation.
6. Refresh the pin audit after candidate source or cited documents change. The
   inventory does not authorize retrying previously rejected work, using
   provider credentials, or performing network or cloud operations.

## Inventory verification

The reconciliation checked exact canonical ID equality against both original
inventories; exact additional, supplemental, prevented and provenance row
identity; original recorded closure IDs and counts; unique keys and non-null
IDs; source file hashes; local pin hashes; and absence of absolute user paths,
IP addresses and em dashes in the tracked JSON. The original source inventories
remain unchanged. The preceding foundation inventory update verified all 382
prior records were exact
apart from the four explicitly authorized `current_reason` and
`current_continuity` amendments. It checked the sealed foundation reviews, full
source-manifest references and actual loom failure, unique IDs and the derived
385-record counts. Historical closure IDs and all source pins remain unchanged.
The Kernel corrective successor update preserves 383 records exactly and changes
only the two Kernel `current_reason` fields, retaining both prior values verbatim
inside additive `current_successor` objects. All original record fields are
recoverable exactly. Fourteen new evidence pins retain the source reviews,
manifest, diff, earlier fixture failure, actual regression and three local passes.
That successor changes no count, original evidence pin, failure or historical
closure. The subsequent ReceiptStore P2 adds one candidate-only record, its
sealed review/manifest and actual compile failure: 386 total records, six candidate follow-ups,
37 candidate-only statuses and fourteen null IDs. All 385 preceding records are
unchanged by that addition. The 348 current or executed-support findings, 117
historical scoped closures and 231 historically unclosed findings remain exact.
The installed Kernel successor adds its sealed selection, applied snapshot,
maintained verification and two exact comparison records. All eight maintained
gate records and logs match the verification hashes, including the retained lint
failure. Its installation changes no finding classification or qualification.
The preceding receipt registration update preserves 385 of the 386 prior rows
exactly. The P2 row changes only `current_reason` and adds `current_successor`,
which retains the prior reason verbatim; all its historical fields remain exact.
Two distinct P3 candidate rows produce 388 total records, eight candidate
follow-ups, 39 candidate-only statuses and sixteen null IDs. Nineteen additive
evidence pins, five maintained gate records/logs and the exact candidate versus
maintained test-name difference were verified. Every canonical row, historical
closure, original inventory and prior source pin remains unchanged.
The receipt P3 successor preserves 386 of 388 rows exactly, changing only the two
P3 current reasons and adding successors that retain both prior reasons verbatim.
All counts and historical classifications stay unchanged. Twenty-eight additive
evidence pins were verified, including the four exact reviewed postimages within
the 18-file composed checkpoint and all four predecessor/corrected execution
records and logs. The broader
receipt failure and its source manifest are separately pinned. The twelve
initial Capture source/selection passes and SPEC_PASS were recorded with quality
review pending at that historical 14-path stage. The later documentation correction
records CHANGES_REQUIRED, a production compile failure and subsequent export
repair compilation within a RED owning run. One unresolved Capture finding and
related work remain parked after an automatic guard block and the instruction to
stop, with no retry. The [receipt report](reviews/receipt-owner-registration.md)
preserves that correction; no blocked case was re-inspected for this accounting.
The current Capture candidate remains uninstalled and unaccepted.
The SDK continuity update preserves 386 of 388 records byte-for-byte. Only the
two SDK current statuses and reasons change, with additive reviews retaining
their previous values. All canonical historical fields, pin audits, original
inventories and prior updates remain unchanged. The two restored scoped closures
changed only the then-current classification counts: 45 needed revalidation and
72 retained their scoped closure. The 269 reviewed source hashes, 58 evidence hashes and ten
frozen portable-packet files were verified without rerunning source tests.
After accounting, 268 source hashes still match; the frozen register pin matches
its pre-update Git blob. The reviewed manifest remains unchanged.
The later locator continuity update preserves 385 of 388 row byte sequences
exactly and every historical field in the three updated rows. Only their current
statuses/reasons and additive reviews change. All 19 prior updates, historical
pins and original inventories remain intact. That update left 42 needing
revalidation and 75 retaining scoped closure; the total remains 388. The 89
reviewed input pins and all eleven original/quality packet artifact pins were
verified, retaining the register input against its pre-update Git blob. No tests
or source modules were run or imported, and pending fixture/SDK findings were not
added by this update.
The installation-specific SDK continuity audit supplements the historical pin
audit; it does not rerun unrelated flags. Confidence is high for this accounting;
current integrated behavior remains unqualified.

The fixture/SDK accounting update preserves 385 of the original 388 record bodies
byte-for-byte. Only the three authorized SDK rows gain a new `current_reason`
and an additive `current_continuity.successor` preserving their exact prior
reason; every historical field remains recoverable unchanged. Six null-ID
records produce the derived 394-record inventory. Original source catalogs,
pin audit, 20 preceding current updates and candidate evidence remain intact.
The additive accounting validation and diff are in the installed fixture packet;
no source test or blocked investigation was rerun for this documentation update.

The subsequent four-item update preserves 391 of the 394 prior record bodies
byte-for-byte. Only `R2-R-evidence-06`, `QF-04` and `SOURCE-HYGIENE-SUPPORT-03`
change current status/reason and gain an additive successor retaining both prior
values. One additional null-ID P2 produces 395 records. Historical disposition
counters, catalogs, previous updates, failed runs and earlier review bytes remain
unchanged; current acceptance is counted separately. The exact baseline, diff
and validation are retained in the fixture-environment accounting packet.
