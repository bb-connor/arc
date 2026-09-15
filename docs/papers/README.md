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
| `reversible-action` | Programmable Sovereignty Over Reversible Action | planning artifact | `theorems.lean` beside the paper: `bounded_executive_action_carries_ttl_and_rollback_slot`, `rollback_closes_or_ttl_window_active`, `ttl_bounded_amendment_chain_preserves_baseline` (headline), `rollback_admission_composes_with_refinement`, `closure_to_syntactic_admission_bridge`, `destructive_action_requires_bilateral_admission`; also `treaty_admission_iff_predicate_intersection`, `amendment_admissible_iff_backward_refinement`, `essential_preserved_chain`, `treaty_admission_stable_under_ladder_floor` | `theorems.lean` is paper-local, in no lakefile, not imported by `Chio.lean`, and not in the inventory; it elaborates by hand under `lake env lean` against the syntactic treaty model with no `sorry` (repaired September 2026; the headline theorem is finite-domain, over an explicit `AdmissionView` list); `closure_to_syntactic_admission_bridge` and `destructive_action_requires_bilateral_admission` are instances of the proof-root `bridge_pointwise` and `treaty_admission_iff_predicate_intersection`; the four proof-root theorems are in the inventory | no venue named |
| `sensor-grounded-admission` | Sensor-Grounded Admission: Polity Receipts with Attested Substrate State | draft | `lean/SensorGroundedAdmission.lean` beside the paper: `admission_predicate_separates_healthy_and_degraded_witnesses` (headline), `partition_contingency_mode_iff_degraded_subset`, `healthy_attestation_required_for_destructive_admission`, `degraded_sensor_admission_requires_re_admission_witness`; also `treaty_admission_iff_predicate_intersection`, `treaty_admission_stable_under_ladder_floor` | the sensor file is paper-local: it elaborates against the proof root under `lake env lean` (toolchain `v4.28.0`, re-checked September 2026) but is not imported by `Chio.lean`, not built by `lake build`, and not in the inventory; `supplementary/proof-manifest.toml` and `theorem-inventory.json` record it as paper-local; `supplementary/lean-source.tar.gz` was regenerated in September 2026 from the current module and the three Treaty modules in its import closure, pins `v4.28.0`, and ships a byte-identical copy of the paper-local file whose SHA-256 `supplementary/README.md` records; the two proof-root theorems are in the inventory | USENIX Security 2027, submission cycle to be confirmed, in `paper-usenix.tex`, `supplementary/README.md`, `supplementary/proof-manifest.toml`, and `supplementary/theorem-inventory.json`; the Cycle 1 naming was dropped in September 2026 after that deadline passed |
| `delegated-emergency-authority` | Delegated Emergency Authority as Bounded Executive Action: A Formal Grammar for Time-Limited Constitutional Amendments | draft | `capability_monotonicity`, `delegation_step_allow_requires_attenuation`, `finite_refinement_sound`, `finite_refinement_exact`, `amendment_without_refinement_rejected` | proof root (`Spec/Properties.lean`, `Proofs/FormalClosure.lean`, `Treaty/ReceiptPredicate.lean`, `Treaty/Intersection.lean`); all five in the inventory; the paper's Part on the substrate states that they are theorems of bounded Lean models and not of the running Rust | "draft circulating for legal-academy review"; no venue named |
| `agentic-tool-safety` | Tool Calls as Reversible-Action Admission: A Substrate Layer for Agentic AI Safety | draft | `treaty_admission_iff_predicate_intersection`, `capability_monotonicity`, `finite_refinement_sound`, `finite_refinement_exact` | proof root (`Treaty/Intersection.lean`, `Spec/Properties.lean`, `Treaty/ReceiptPredicate.lean`); all four in the inventory. Its Section 4 carries two further statements, on the TTL-and-rollback envelope invariant and on rollback admission under refinement, which the text marks as candidates: they are mechanized only in the `reversible-action` paper-local file and are not in the inventory | NeurIPS 2026 workshop track, named in a `paper.tex` comment |

Status vocabulary: active (being prepared for submission); draft (a sibling
that is not being prepared for submission); planning artifact (theorem statements committed for inspection, not a
paper to submit); retired (must not be circulated or cited).

## Rules

1. A paper may cite a theorem by name only if that name is in
   `formal/theorem-inventory.json`. A paper-local Lean file may be described
   as a paper-local mechanization, with its elaboration status stated, and
   must not be presented as a proof-root result.
2. The family cites the parent paper under its current title only:
   "Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool
   Calls" (`programmable-sovereignty`); the sibling bibliographies were
   brought to that title in September 2026. The former titles "Programmable
   Sovereignty: Lean-Attestable Constitutions Over Capability-Bounded
   Federated Receipts" and "Programmable Sovereignty: A Predicate-Conditioned
   Polity Substrate with Bilateral Treaty Composition" name a draft that no
   longer exists. The parent contains none of the polity, amendment, or
   sovereignty material; sibling passages that attributed that material to it
   were rewritten in September 2026 against rule 4.
3. A retired paper's sources stay in the tree as a design note and are not
   rebuilt for distribution.
4. A theorem in the proof root belongs to the proof root. A sibling may cite
   it, and must attribute it to the substrate's Lean development and its
   inventory rather than to the parent paper, whose own formal content is
   `finite_refinement_sound` and `finite_refinement_exact`. A statement that
   is mechanized only in a paper-local file is a candidate, and the citing
   paper says so at the point of use.
5. Every theorem the family cites is a theorem of a bounded Lean model. No
   paper may present one as a statement about the deployed Rust: no
   extraction step and no refinement proof connects them, and where the two
   are compared at all it is by differential testing of a bounded fragment.
