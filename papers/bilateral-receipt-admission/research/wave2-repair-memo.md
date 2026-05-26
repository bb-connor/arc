# Wave 2 Repair Memo

Date: 2026-05-19.

Changed:
- The verifier schema now consistently names a ten-field binding tuple.
- `trust-store-miss` is split into its own rejection code across the abstract, introduction, predicate schema, implementation table, evaluation, attacks, and README.
- Formal claims now describe a three-gate Lean schema-alignment witness instead of the full operational verifier.
- Freshness, replay, sibling-treaty substitution, and single-actor key-custody limits are more explicit.

Verification:
- `git diff --check` passed after integration.
- Targeted no-em-dash scan passed for changed files.
- Targeted stale five-code search over active sections passed.
- `cd formal/lean4/Chio && lake build` passed with 23 jobs.

Remaining:
- Run LaTeX once local TeX tooling is available.
- Keep the bilateral paper sequence-sensitive: it depends on parent-paper framing but should not claim the parent theorem proves the runtime verifier.
