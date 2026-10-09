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
| Provenance prerequisite, excluded from implementation findings | 1 | Not applicable | Not applicable |

The canonical 99 recorded closures comprise 92 source-only and seven scoped
local closures. The additional 18 comprise seven source-only and eleven scoped
local closures. These are recorded review classifications, not new acceptance.

There are **379 findings or candidate issues**, plus the excluded provenance
prerequisite, for **380 records**. The prevented inventory has 23 assigned IDs
and eight unassigned records. Accordingly, there are 371 assigned finding IDs,
or 372 IDs including the provenance prerequisite. Null IDs are intentional.
Every original ID and exact unassigned reviewer label remains preserved.

The current status counts are:

| Status | Records | Meaning |
| --- | ---: | --- |
| `open` | 231 | No complete independent disposition is recorded. |
| `needs_revalidation` | 47 | Historical closure remains, but cited source or document pins differ without an accepted current continuity review. |
| `recorded_scoped_closed` | 70 | The recorded scoped disposition is retained, with the limits stated per record. |
| `candidate_only` | 31 | The defective candidate was uninstalled when found; corrected successors may have separate evidence. |
| `prerequisite_only` | 1 | Provenance work, not a proved implementation defect. |

The 47 remaining revalidation flags are part of the 117 historical scoped closures. They
are not added to the 231 historically unclosed findings. No finding is declared
regressed merely because its bytes changed, and no matching pin constitutes a
new behavioral test. The initial audit flagged 48 closures. An independent
[explanation evidence continuity review](reviews/explanation-evidence-continuity.md)
subsequently confirmed that the README change for `A-planner-07` adds navigation
only and preserves its original source-only obligation. Its historical pin
difference remains recorded, alongside the current review and its scope.

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
  IDs; the index resolves to the unchanged addendum record.
- `id`, `severity`, `title`, and `dependency_group`: original identity and review
  priority, plus the execution workstream. A null severity means the reviewer
  did not assign one or the entry is an excluded prerequisite.
- `category`: `canonical`, `additional`, `supplemental_pr`,
  `prevented_candidate`, or `provenance_prerequisite`.
- `obligation`: the canonical original obligation verbatim, apart from path and
  punctuation sanitization, or a concise behavior obligation for later records.
  Structured canonical obligations remain structured.
- `evidence_refs`: exact source records. `reviewed#/rows/0`, for example, means
  the `reviewed` path in `source_inventory` and JSON Pointer `/rows/0`.
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
5. Keep prevented candidate defects separate from installed defects. Preserve
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
remain unchanged. Confidence is high for this inventory and pin comparison;
current integrated behavior remains unqualified.
