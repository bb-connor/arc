# Chio papers

This directory holds the paper family. One paper is active. The others are
drafts, a planning artifact, or retired, and each is listed below with the
Lean artifacts it cites, where those artifacts live, and the venue metadata
its source carries.

The proof root is `formal/lean4/Chio`: the modules imported by `Chio.lean`,
built by `lake build`, listed as root modules in `formal/proof-manifest.toml`,
and catalogued in `formal/theorem-inventory.json`. A Lean file kept beside a
paper is paper-local: it is not built by `lake build` and is not in the
inventory, whether or not it elaborates.

## Index

| Directory | Title | Status | Lean artifacts cited | Where they live | Venue metadata in the source |
| --- | --- | --- | --- | --- | --- |
| `programmable-sovereignty` | Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool Calls | active; the parent paper of the family | `finite_refinement_sound`, `finite_refinement_exact` | proof root (`Treaty/ReceiptPredicate.lean`); both in the inventory | USENIX Security 2027, double-blind, submission cycle to be confirmed; `paper.tex` is the ACM-format fallback |
| `bilateral-receipt-admission` | Bilateral Receipt Admission: Cross-Organizational Action Provenance with Treaty-Bound DSSE | retired (September 2026); do not circulate or cite | `freestanding_accept_set_theorem`, `accept_monotone_in_issuer_store`, `accept_conj_scope_decompose`, `accept_requires_issuer_key`; `treaty_admission_iff_predicate_intersection`, `amendment_admissible_iff_backward_refinement`, `essential_preserved_chain` | proof root (`Treaty/BilateralAccept.lean`, `Treaty/Intersection.lean`, `Treaty/PredicateLang.lean`); all seven in the inventory; the paper's description of the accept set (a receipt id subject, a lease epoch, six gates, and axioms beyond `propext`) does not match the module | ACM review format; no venue named |
| `reversible-action` | Programmable Sovereignty Over Reversible Action | planning artifact | `theorems.lean` beside the paper: `bounded_executive_action_carries_ttl_and_rollback_slot`, `rollback_closes_or_ttl_window_active`, `ttl_bounded_amendment_chain_preserves_baseline` (headline), `rollback_admission_composes_with_refinement`, `closure_to_syntactic_admission_bridge`, `destructive_action_requires_bilateral_admission`; also `treaty_admission_iff_predicate_intersection`, `amendment_admissible_iff_backward_refinement`, `essential_preserved_chain`, `treaty_admission_stable_under_ladder_floor` | `theorems.lean` is paper-local, in no lakefile, does not elaborate against the proof root (it names `Chio.Treaty.ReceiptId`, which no longer exists), and its headline theorem is closed by `sorry`; the four proof-root theorems are in the inventory | no venue named |
| `sensor-grounded-admission` | Sensor-Grounded Admission: Polity Receipts with Attested Substrate State | draft | `lean/SensorGroundedAdmission.lean` beside the paper: `admission_predicate_separates_healthy_and_degraded_witnesses` (headline), `partition_contingency_mode_iff_degraded_subset`, `healthy_attestation_required_for_destructive_admission`, `degraded_sensor_admission_requires_re_admission_witness`; also `treaty_admission_iff_predicate_intersection`, `treaty_admission_stable_under_ladder_floor` | the sensor file is paper-local: it elaborates against the proof root under `lake env lean` but is not imported by `Chio.lean`, not built by `lake build`, and not in the inventory; `supplementary/proof-manifest.toml` names a module `Chio.Treaty.SensorGroundedAdmission` the proof root does not contain and a toolchain (`v4.28.0-rc1`) older than the root's (`v4.28.0`); the two proof-root theorems are in the inventory | USENIX Security 2027 Cycle 1 in `paper-usenix.tex`, `supplementary/README.md`, and `supplementary/proof-manifest.toml`; that cycle's deadline has passed |
| `delegated-emergency-authority` | Delegated Emergency Authority as Bounded Executive Action: A Formal Grammar for Time-Limited Constitutional Amendments | draft | none; refers to unnamed Lean theorems of the parent | not applicable | "draft circulating for legal-academy review"; no venue named |
| `agentic-tool-safety` | Tool Calls as Reversible-Action Admission: A Substrate Layer for Agentic AI Safety | draft | none; states three theorems in prose (bounded executive action carries TTL and rollback slot; rollback admission composes with refinement; treaty admission iff predicate intersection) | the first two correspond to `reversible-action` planning candidates and are not in the proof root; the third is `treaty_admission_iff_predicate_intersection`, in the proof root and the inventory | NeurIPS 2026 workshop track, named in a `paper.tex` comment |

Status vocabulary: active (being prepared for submission); draft (a sibling
that is not being prepared and cites the parent under a title it no longer
has); planning artifact (theorem statements committed for inspection, not a
paper to submit); retired (must not be circulated or cited).

## Rules

1. A paper may cite a theorem by name only if that name is in
   `formal/theorem-inventory.json`. A paper-local Lean file may be described
   as a paper-local mechanization, with its elaboration status stated, and
   must not be presented as a proof-root result.
2. The family cites the parent paper under its current title only:
   "Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool
   Calls" (`programmable-sovereignty`). The titles "Programmable Sovereignty:
   Lean-Attestable Constitutions Over Capability-Bounded Federated Receipts"
   and "Programmable Sovereignty: A Predicate-Conditioned Polity Substrate
   with Bilateral Treaty Composition", still present in
   `reversible-action/paper.tex`, `agentic-tool-safety/bib.bib`,
   `delegated-emergency-authority/bib.bib`, and
   `sensor-grounded-admission/bib.bib`, name a draft that no longer exists;
   the parent contains none of the polity, amendment, or sovereignty material
   those citations attribute to it.
3. A retired paper's sources stay in the tree as a design note and are not
   rebuilt for distribution.
