# Bilateral Receipt Admission

Compact paper extracted from the same Chio substrate as the 12-page *Programmable Sovereignty* paper (`papers/programmable-sovereignty/`). This artifact is the cryptographic-primitive-only paper recommended by the round-3 swarm's "fundamental framing provocateur": strip the polity / Hart / sovereignty rhetoric, defend just the bilateral-DSSE-with-treaty-bound-subject-digest construction.

## Working title

*Bilateral Receipt Admission: Cross-Organizational Action Provenance with Treaty-Bound DSSE*

## Target

8-10 pages for USENIX Security 2027 Cycle 2 as a compact full-format paper. USENIX has no short-paper class; explicit short-paper venues remain fallback options only if the human chooses a lower-prestige format.

## Relationship to the 12-page paper

The two papers share a substrate but make different claims:

- **`papers/programmable-sovereignty/paper.tex`**: 12-page position-paper-plus-systems-contribution that frames the substrate as a constructive instance of the Hartian rule of recognition, defends the polity triple $(T, C, K)$, and engages legal-positivism and political-theory literature. Target audience: NDSS / USENIX Security with a controversial title that doubles as a rhetorical wedge.

- **`papers/bilateral-receipt-admission/paper.tex`**: 8-10 page compact full-format paper that ships just the cryptographic primitive (DSSE predicate type, strict verifier with six rejection codes, pre-dispatch admission hook, three-vendor closure) without the polity / Hart / sovereignty rhetoric. Target audience: USENIX Security 2027 Cycle 2 or similar; reviewers who want the substrate without the political framing.

The two should cross-reference and stand on their own grounds. This compact paper includes a narrow Lean accept-set witness for the bilateral primitive; the broader polity, amendment, and trajectory theorems stay in the 12-page paper.

## Proposed structure

1. **Abstract** (150 words). Problem, contribution, demonstration, negative result.
2. **§1 Introduction** (0.5 page). What's missing in cross-org agent provenance; why bilateral-DSSE-with-treaty-bound-subject-digest is the load-bearing primitive.
3. **§2 Receipt admission as a primitive** (1 page). The schema; the rejection-code taxonomy; the relationship to SLSA / Sigstore / in-toto / Rekor.
4. **§3 Predicate schema and strict verifier** (1.5 pages). The six rejection codes; the canonical-bytes binding; the type signature.
5. **§4 Formal sketch** (1 page). One theorem with deliberately narrow content: the abstract accept set equals issuer-key membership, kernel-key membership, and scope-predicate denotation. The Lean artifact is a schema-alignment witness, not a proof of the runtime cryptographic verifier.
6. **§5 Implementation** (1 page). The Rust runtime, the admission hook, the federation crate.
7. **§6 Three-vendor evaluation** (1 page). Admitted + denied paths in the same canonical schema. p50 latency. Replay corpus.
8. **§7 Attacks defeated by construction** (0.5 page). Sibling-treaty cross-receipt substitution. BBS stub-vs-real disambiguation. Single-lane witness compromise. Error-message oracles. Constitutional-ratchet (forward reference to companion paper).
9. **§8 Related work** (0.5 page). SLSA, Sigstore, in-toto, Rekor, DSSE, Cedar, SAGA, IsolateGPT, Omega - narrow and sharp.
10. **§9 Limitations** (0.25 page). No live federation. Single-vendor key custody. Observability gap. Reference to companion paper for polity / amendment / Lean obligations.

## Status

Full 10-page draft. The paper now contains the predicate schema, verifier gate sequence, formal sketch, implementation sketch, evaluation, attacks-defeated section, related work, and limitations. It is not yet a current submission package: USENIX Open Science and Ethics appendices remain to draft, and the PDF gate must rerun after the Wave 2/3 source repairs.

Remaining risks:

- The reported evaluation exercises noncanonical-payload, signer-reuse, stale-lease, and subject-digest-mismatch, but not predicate-type-mismatch or trust-store-miss.
- The Lean artifact checks a three abstract-gate schema projection only; runtime signature soundness, canonicalization, lease freshness, and digest correctness remain implementation and cryptographic assumptions.
- Intra-lease replay is outside the primitive unless the deployment adds a seen-set, continuation consumption rule, or equivalent verifier-owned replay state.
- Live cross-process federation, key-custody independence, observability, verifier side channels, malicious receiving kernels, and cryptographic-suite migration remain limitations.

## License

CC-BY-4.0, matching the 12-page paper.
