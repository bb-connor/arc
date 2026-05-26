# Research Paper Swarm Wave 1 Synthesis

Date: 2026-05-19
Branch: `research/programmable-sovereignty-papers`
Input: Wave 0 priority queue plus eight expert adversarial reviews.

## Agents Run

- Computer Science Theorist
- Cryptography Expert
- Formal Methods and Lean Reviewer
- Systems Security Reviewer
- Distributed Systems Reviewer
- Legal and Governance Reviewer
- AI Safety Reviewer
- Venue and PC Fit Reviewer

All Wave 1 agents were read-only.

## Consensus Findings

### P0

1. `papers/reversible-action/` is not submission-capable. The Lean file does not compile as a valid paper artifact, contains `sorry`, and is not registered in Lake. The runtime story also lacks scheduler, bilateral destructive path, write-ahead ledger semantics, and several inverse executors. This is a freeze or pivot gate, not a one-pass prose repair.

### P1

1. `papers/bilateral-receipt-admission/sections/03-predicate-schema-verifier.tex` has a real schema/specification inconsistency. The binding tuple is called ten-field while different prose, figure, and worked example enumerate different fields. The G4 trust-store gate is incorrectly bundled with predicate-type mismatch even though predicate type and key membership are independent.
2. `papers/bilateral-receipt-admission/paper.tex` and `sections/04-formal-sketch.tex` overstate the Lean result. The Lean file is useful, but it proves a three-gate structural projection, not the full six runtime gates or cryptographic correctness.
3. Bilateral freshness and replay semantics are underspecified. The primitive checks lease epoch and expiry but pushes intra-lease replay to receipt-graph deduplication without enough local semantics.
4. `papers/agentic-tool-safety/` overclaims survival under strategic composition and operator manipulation. Its true guarantee is mediated, correctly classified, single-envelope execution under independent cosigners, intact registry, no bypass, and working rollback executors.
5. `papers/agentic-tool-safety/sections/05-implementation-sketch.tex` uses a `db.dump` example that treats data restoration as if it undoes disclosure. This is a safety credibility issue.
6. `papers/sensor-grounded-admission/` should say the substrate-honesty assumption is made falsifiable or strictly strengthened, not retired outright. The present same-key construction creates an audit target, not cryptographic detection.
7. `papers/sensor-grounded-admission/sections/01-introduction.tex` currently suggests TEE-rooted attestation key separation, while `sections/03-substrate.tex` and `sections/09-limitations.tex` say body and attestation are signed by the same key and key separation is an extension axis.
8. `papers/programmable-sovereignty/sections/01-introduction.tex` overclaims that each operation is checked by Rust and attested by a named Lean theorem. The formal status is mixed: two load-bearing theorems, two definitional bridges, and several unformalized runtime assumptions.
9. USENIX appendix packaging and page gates are stale. Parent lacks Open Science and Ethics appendices in `paper-usenix.tex`; sensor has them after references while the current policy baseline requires them before references; both Makefiles count pages before References as body and mask TeX pass failures.
10. `papers/delegated-emergency-authority/` is circulation-ready, not submission-ready. It needs specialist legal review and possibly a legal co-author before law-review submission.

### P2

1. Several venue and README files are stale against current official dates and package state.
2. `formal/theorem-inventory.json` does not list `BilateralAccept` theorem artifacts even though `Chio.lean` imports that module.
3. Cross-paper overlap and companion-citation policy need a stable one-page note.
4. The agentic paper would benefit from a small red-team evaluation table, even if qualitative.

## Repair Wave Decisions

Proceed with scoped Wave 2 repairs:

1. USENIX packaging and build harness repair for parent and sensor papers.
2. Bilateral verifier/schema/formal-claim calibration.
3. Agentic tool-safety threat-model and example calibration.
4. Parent and sensor claim calibration plus relevant status-note cleanup.

Do not dispatch repairs for:

- Reversible-action theorem or runtime implementation. The required work is not a clear scoped repair.
- Delegated-emergency legal case restructuring. The required work needs human legal judgment and specialist review.
- Venue submission or outreach actions. These are human-only.

## Verification Constraints

Local TeX tools are unavailable in this environment as of 2026-05-19:

- `pdflatex`: absent
- `bibtex`: absent
- `latexmk`: absent
- `xelatex`: absent
- `tectonic`: absent
- `pdfinfo`: absent

Wave 2 repair agents must still run available gates and report LaTeX verification as blocked by missing tools where applicable. Lean changes, if any, must run `cd formal/lean4/Chio && lake build`.
