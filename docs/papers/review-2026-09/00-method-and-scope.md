# Whitepaper Review 2026-09: Method and Scope

- Review date: 2026-09-10
- Repository state reviewed: `main` at `fe5657020c` (clean working tree)
- Papers under review:
  - P1: `docs/papers/programmable-sovereignty/` ("Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool Calls", USENIX Security 2027 target)
  - P2: `docs/papers/bilateral-receipt-admission/` ("Bilateral Receipt Admission: Cross-Organizational Action Provenance with Treaty-Bound DSSE", ACM format)
- Goal set by the founder: determine whether these papers can reach the standard of a foundational document (Bitcoin whitepaper, the UNIX and seL4 papers) and what it would take to get there, cross-referencing the code, the Lean proofs, and every formal harness in the repository.

This directory is the review record. It is descriptive and advisory. Nothing here changes protocol, code, or paper text.

## Documents in this set

| File | Contents |
| --- | --- |
| `00-method-and-scope.md` | This file: method, waves, pinned facts, how to reproduce the checks |
| `01-executive-summary.md` | The verdict, the ten most consequential findings, and the recommended path |
| `02-p1-claim-audit.md` | Paper 1 claim-by-claim audit against source, tests, benches, and the artifact manifest |
| `03-p2-claim-audit.md` | Paper 2 claim-by-claim audit against source and the normative specs |
| `04-formal-evidence-audit.md` | What the cited Lean theorems actually prove, their axioms, proof depth, and the wider harness estate the papers do not use |
| `05-cross-paper-consistency.md` | Contradictions between P1, P2, the four sibling papers, and the specs |
| `06-foundational-paper-benchmark.md` | What makes a paper foundational, a rubric, and both papers scored against it |
| `07-simulated-pc-reviews.md` | Six program-committee reviews of the papers as submitted |
| `08-the-thesis.md` | Candidate theses for a foundational Chio paper, the judge panel, and the recommended unified thesis |
| `09-claim-surface-and-landscape.md` | What the repository truthfully supports today, and where Chio stands against adjacent systems |
| `10-roadmap.md` | Prioritized actions: what to prove, build, measure, cut, merge, and rewrite |
| `11-prose-and-structure-audit.md` | Reader-experience audit, missing related work, structural recommendations |
| `findings.json` | Machine-readable findings with verifier verdicts |
| `README.md` | Index |

## Method

The review ran in three waves. Waves 1 and 2 were executed as orchestrated multi-agent workflows with adversarial verification; wave 3 is the lead reviewer's synthesis.

### Wave 0: ground truth (lead reviewer)

Before any delegated work, the lead reviewer read both papers in full, the two Lean modules they cite, the normative specs (`spec/CHIO_BILATERAL_COSIGN_INVOCATION.md`, `spec/CHIO_LADDER.md`, `spec/CHIO_SELECTIVE_DISCLOSURE.md`), the formal registries (`formal/proof-manifest.toml`, `formal/assumptions.toml`, `formal/theorem-inventory.json`, `formal/MAPPING.md`), the claim registry (`docs/reference/CLAIM_REGISTRY.md`), the prior revision plan (`docs/superpowers/plans/2026-07-25-programmable-sovereignty-paper-revision.md`), and the Rust verifier sources. The facts established are listed under "Pinned facts" below and were handed to every agent as a brief, with the instruction to verify rather than trust.

### Wave 1: claim audit (7 finders, 7 adversarial verifiers, 1 completeness critic)

The first run completed 13 of 15 agents; the verifier for the P2 implementation finder and the completeness critic hit a session limit and were re-run from the workflow's cache afterward, so their verdicts arrived after the other groups. Findings from the P2 finder were corroborated independently by the cross-paper, formal, harness, and prose finders before the verifier's verdicts were available.

Seven finders each audited one dimension:

1. P1 implementation and evidence-pointer audit
2. P1 measurement and reproducibility audit
3. P2 implementation-claim audit
4. Formal-claims audit for both papers (Lean, with `#print axioms` run on every cited theorem)
5. Formal-harness and evidence-estate audit (Kani, Creusot, Aeneas, Apalache, Loom, mutation, differential, conformance, replay)
6. Cross-paper consistency, six-paper family, and spec alignment
7. Prose, structure, and reader-experience audit

Every finding names its location, quotes the claim, states what is true at HEAD, and proposes a fix. A separate verifier per finder group then tried to refute each finding from source, returning CONFIRMED, REFUTED, or ADJUSTED with independent evidence. Refuted findings are excluded from the documents. A completeness critic then looked for uncovered sections, claim classes, and repository surfaces and ran the highest-value missing checks itself.

Outcome: 165 finder findings, of which 121 were confirmed and 44 adjusted in detail; none was refuted. The critic added 7 findings and reported that the sections which drew no findings (P1 background, discussion, conclusion; the struct field lists in P1 section 3) re-checked clean. Final severity distribution across the 172 surviving findings: 19 blocker, 67 major, 57 minor, 29 note.

### Wave 2: positioning (canon analysis, thesis panel, simulated PC, claim surface, landscape)

- A canon analysis of foundational technical documents produced a ten-criterion rubric and scored both papers.
- Five independent authors proposed a foundational thesis from five angles (operating systems, cryptographic protocol, economics and institutions, AI safety, distributed systems); two judges scored and synthesized.
- Six simulated program-committee reviewers (USENIX Security, IEEE S&P, SOSP/OSDI, ACM CCS, a formal-methods reviewer, an industry practitioner) reviewed the papers exactly as submitted, without repository access.
- One agent mapped the truthful claim surface of the repository in the claim registry's evidence-class vocabulary.
- One agent mapped the competitive and prior-art landscape.

### Wave 3: synthesis (lead reviewer)

The lead reviewer read every wave output, resolved disagreements against source, and wrote the documents in this directory. Where an agent's statement could not be tied to a file, symbol, or command output, it was dropped.

## Pinned facts (verified by the lead reviewer at HEAD)

These are reproducible with the commands shown. They are the floor of the review, not its conclusion.

| Fact | How to check |
| --- | --- |
| The P1 artifact reproducibility gate fails at HEAD: `artifact generation failed: working artifact differs from pinned commit at Cargo.lock` | `python3 scripts/generate-programmable-sovereignty-artifact.py --check` |
| 922 commits since P1's pinned source commit `dfcd511651`; 72 files changed under the paper's covered crates (+15,298 / -1,803) | `git log --oneline dfcd511651..HEAD | wc -l`; `git diff --stat dfcd511651..HEAD -- crates/trust/chio-federation crates/kernel/chio-runtime-core crates/kernel/chio-kernel formal/lean4/Chio/Chio/Treaty formal/diff-tests crates/trust/chio-attest-loopback` |
| The Lean proof tree builds clean at HEAD (1,525 jobs), zero `sorry` in the Treaty modules | `cd formal/lean4/Chio && PATH=$HOME/.elan/bin:$PATH lake build` |
| Treaty-lane theorem counts: BilateralAccept 4, BridgeEquivalence 12, Intersection 4, IntersectionLegacy 4, IntersectionSyntactic 9, PredicateLang 23, ReceiptPredicate 2. Whole tree: 165 catalogued theorems | `grep -c '^theorem' formal/lean4/Chio/Chio/Treaty/*.lean`; `python3 -c "import json;print(len(json.load(open('formal/theorem-inventory.json'))['theorems']))"` |
| The envelope verifier checks structure first and verifies both Ed25519 signatures last | `crates/trust/chio-federation/src/bilateral_dsse/verify.rs`, `verify_chio_bilateral_dsse_envelope_inner` |
| The operational verifier exposes 16 rejection codes (`VerifierError::code`), and the envelope layer adds `signer.independence_required` and others (`BilateralCoSigningError::code`) | `crates/trust/chio-federation/src/bilateral_verifier/error.rs`; `crates/trust/chio-federation/src/bilateral.rs` |
| The shipped predicate is snake_case with an optional 15-field `treaty_binding_ref`; the subject digest is the SHA-256 of the canonical receipt body, not of a binding tuple | `crates/trust/chio-federation/src/bilateral_dsse/types.rs`; `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` section 4 |
| P1's negative corpus has 20 cases (PS-TH-01..20), all pre-dispatch, one explicit untestable assumption PS-A-01 | `examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json` |
| P1's claim ledger reports 11.124 ms p50 for pre-dispatch denial while the retained results and the inline TeX report 4.115 ms; the prose describes a Linux Neoverse-N1 host while the retained environment file records a Darwin MacBook Pro; the results pin commit `3dfd241e67` while the manifest pins `dfcd511651` | `docs/papers/programmable-sovereignty/CLAIM_LEDGER.md`; `bench/results/bilateral-admission.json`; `bench/results/bilateral-admission-environment.txt`; `supplementary/source-commit.txt` |
| P1 (USENIX build) is 10 pages and about 4,900 words; P2 is 10 pages and about 7,900 words, its PDF dated 2026-05-19, with 14 LaTeX double-hyphen dashes and 14 occurrences of "anonymized for review" | `pdfinfo`; `detex sections/*.tex | wc -w`; `grep -c -- ' -- '` |
| The paper's declared Rust gates pass at HEAD: diff tests 4, `chio-federation --lib` 105, `runtime_admission` 46, `runtime_treaty` 20, `runtime_buyer_review` 21 | `cargo test -p <crate> --test <name>`; results tabulated in `02-p1-claim-audit.md` |
| The paper's own benchmark scripts, rerun on this host (12-core Neoverse-N1, 49.2 GB, rustc 1.94.1), give 10.4 ms p50 / 17.0 ms p99 for the pre-dispatch denial, 20 of 20 negative cases and 50 of 50 replay fixtures passing, and a byte-identical 51,843-byte buyer package | `CHIO_PAPER_RESULT_DIR=<dir> CHIO_TARGET_DIR=<dir> bash docs/papers/programmable-sovereignty/bench/run-bilateral-admission.sh` and `run-replay-corpus.sh`; full table in `02-p1-claim-audit.md` |
| The timed denial path returns `chio_treaty_policy_denied` before the treaty-binding checks and before the Ed25519 verification call | `crates/kernel/chio-runtime-core/src/admission_hook/dsse.rs`, `verify_treaty_dsse_evidence` |
| Untracked logs from the 26 July 2026 Linux run remain in `bench/results/` on this host (Criterion log with 465 iterations, negative-matrix log), while the tracked result files are dated 15 August and record a Darwin host | `git status --ignored --short docs/papers/programmable-sovereignty/bench/results` |

## Rules applied to the review itself

- No em dashes anywhere in this review set (house rule).
- Every factual statement about the artifact cites a path, a symbol, or a command.
- Severity vocabulary: blocker (would cause rejection, or is a false statement of fact about the artifact), major (materially misleading or a real gap), minor (should fix), note (observation).
- Agents were forbidden from modifying repository files and from running cargo; the lead reviewer ran the test gates once, sequentially, in the background.
