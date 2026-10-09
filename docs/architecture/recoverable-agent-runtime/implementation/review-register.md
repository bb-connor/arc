# Recovery review register

[review-register.json](review-register.json) is the canonical current inventory.
It preserves the original 328 IDs, separately catalogs later findings, and records
current applicability without rewriting historical acceptance. This register is
an inventory and local source-pin comparison. It grants no runtime, Linux,
provider, formal, hosted, or release qualification.

## Reconciliation

| Inventory | Records | Recorded scoped closures | Recorded unclosed |
| --- | ---: | ---: | ---: |
| Canonical original findings | 328 | 99 | 229 |
| Additional maintained or actually executed support findings | 19 | 18 | 1 |
| Supplemental PR obligations | 1 | 0 | 1 |
| Current or executed-support total | 348 | 117 | 231 |
| Prevented candidate issues, counted separately | 31 | Not combined | Not combined |
| Additional uninstalled candidate follow-ups | 5 | Not combined | Not combined |
| Provenance prerequisite, excluded from implementation findings | 1 | Not applicable | Not applicable |

The canonical 99 recorded closures comprise 92 source-only and seven scoped
local closures. The additional 18 comprise seven source-only and eleven scoped
local closures. These are recorded review classifications, not new acceptance.

There are **384 findings or candidate issues**, plus the excluded provenance
prerequisite, for **385 records**. The original prevented inventory retains 23
assigned IDs and eight unassigned records. The five candidate follow-ups have
register keys and null finding IDs. There are still 371 assigned finding IDs,
or 372 IDs including the provenance prerequisite, and thirteen null IDs. Every
original ID and exact unassigned reviewer label remains preserved.

The current status counts are:

| Status | Records | Meaning |
| --- | ---: | --- |
| `open` | 231 | No complete independent disposition is recorded. |
| `needs_revalidation` | 47 | Historical closure remains, but cited source or document pins differ without an accepted current continuity review. |
| `recorded_scoped_closed` | 70 | The recorded scoped disposition is retained, with the limits stated per record. |
| `candidate_only` | 36 | The defective candidate was uninstalled when found; corrected successors may have separate evidence. |
| `prerequisite_only` | 1 | Provenance work, not a proved implementation defect. |

The 47 remaining revalidation flags are part of the 117 historical scoped closures. They
are not added to the 231 historically unclosed findings. No finding is declared
regressed merely because its bytes changed, and no matching pin constitutes a
new behavioral test. The initial audit flagged 48 closures. An independent
[explanation evidence continuity review](reviews/explanation-evidence-continuity.md)
subsequently confirmed that the README change for `A-planner-07` adds navigation
only and preserves its original source-only obligation. Its historical pin
difference remains recorded, alongside the current review and its scope.

The installed SDK changes affect six direct pin pairs across `H-SDK-03`,
`H-SDK-08`, `H-SDK-09` and `SDK-INDEPENDENT-03`. The independent
[installed SDK continuity audit](reviews/installed-sdk-continuity.md) maps the
bounded reviews and maintained tests to their original scoped contracts. Each
record now states that its pins changed and links `current_continuity`. Its
historical `pin_check`, disposition and classification remain unchanged. These
four changes add no revalidation flag or runtime qualification.

## Candidate follow-ups

Two independently reviewed source units have subsequently been installed and
verified locally: [SDK state projection](reviews/sdk-recovery-state-projection.md)
and [explicit authority provisioning](reviews/native-authority-provisioning.md).
Their evidence and remaining obligations are recorded in `current_updates`.
H-SDK-01 remains open and provisioning is a prerequisite. Those installations
did not change finding classifications or grant qualification. The subsequent
foundation reviews add the three candidate records below.

The five additive `candidate_followup` records do not change canonical closure
counts or installed-finding totals. The initial two preserve their prior failure
and successor evidence; the latest three remain open. Their
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
  admission before Native selection is checked. Runtime reproduction was not
  performed by the reviewer; correction and owning acceptance remain pending.
- `candidate:kernel-foundation-loom-runtime-gate` is the P2 missing configuration
  gate. The actual pre-fix loom compilation failed with 30 compiler errors and
  executed no tests. Correction and corrected compilation remain pending.
- `candidate:process-foundation-missing-test-suppliers` is the P2 registration
  defect affecting thirteen enrollment-dependent and two lifetime acceptance
  cases. The source reviewer ran no tests. Preserve all future positive
  obligations while making the supported default target executable.

All five records use register keys with null assigned finding IDs. The three
foundation findings are uninstalled and open; they do not claim a production
runtime failure or a corrected pass. Earlier failure and review evidence remains
unchanged. The original two-case receipt fault evidence is not retrospectively
credited with the later, distinct retained-reservation test.

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
  IDs; the index resolves to the unchanged addendum record. The five descriptive
  `candidate:<behavior>` keys also identify records without assigned review IDs.
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
  `candidate_review_evidence.files`.
- `remaining_obligation_refs` or `remaining_obligations`: all applicable owner
  checks remain authoritative. A short summary does not replace the linked
  detailed requirements, nested support findings, same-ID updates, or limits.
- `recorded_disposition` and `recorded_scope_ref`: what the historical reviewer
  actually accepted or left open, separately from today's source applicability.
- `current_status`, `current_reason`, and, where available, `pin_check`: current
  inventory adjudication and its limits. They do not overwrite source records.

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
remain unchanged. The latest update verifies all 382 prior records are exact
apart from the four explicitly authorized `current_reason` and
`current_continuity` amendments. It checks the sealed foundation reviews, full
source-manifest references and actual loom failure, unique IDs and the derived
385-record counts. Historical closure IDs and all source pins remain unchanged.
The installation-specific SDK continuity audit supplements the historical pin
audit; it does not rerun unrelated flags. Confidence is high for this accounting;
current integrated behavior remains unqualified.
