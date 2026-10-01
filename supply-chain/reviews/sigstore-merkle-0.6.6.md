# sigstore-merkle 0.6.6 source review and repair

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the reproduced arithmetic defect, repair and tested proof behavior. This
is direct source review, not independent human certification.

## Exact source

Registry archive SHA-256:
`7c0d53558825c77716855c13794306fff766854c1bf92948e77d7890da3f2455`.
The archive identifies release source
`c9d76063833cb58a06483b181096294524d2dbf1` in
`prefix-dev/sigstore-rust`, under `crates/sigstore-merkle`.

The review covers all four production modules, both manifests, the upstream
test runner and retained vector inventory. Production code has no unsafe Rust,
build script, network or filesystem IO, environment access or process execution.
Hashing uses separately admitted Sigstore types and cryptographic dependencies.
The manual test-vector refresh script is retained but was not executed; tests
use the exact archive's vectors.

## Reproduction and repair

With the original production source, calling `verify_inclusion_proof` with
tree size `u64::MAX` and an empty proof panics at `proof.rs:244` in a checked
build. Its ceiling-half calculation adds one before division. In a wrapping
build, that arithmetic also loses the expected path length.

The selected fork backports the arithmetic hunk from upstream commit
[`eed06c33736b1bb36298facaf89c763de00f721b`](https://github.com/prefix-dev/sigstore-rust/commit/eed06c33736b1bb36298facaf89c763de00f721b).
It computes `size / 2 + size % 2`, preserving the complete unsigned range.
The upstream commit's unrelated removal of public helper functions is omitted.
The retained production diff is exactly this one line.

Chio's current Sigstore verifier first converts the proof's signed `i64` tree
size to `u64`, rejecting negative values, and verifies the signed checkpoint.
That caller cannot supply `u64::MAX`. This reproduction establishes an upstream
public API defect, not an exposed Chio checkpoint bypass or reachable panic at
that caller.

## Verification

The main, fuzz and generated Docker graphs select
`third_party/sigstore-merkle-chio`. Their lockfile changes only remove this
package's registry source and checksum; its version and dependencies remain
unchanged. The fork's standalone lock retains the selected AWS-LC versions.

On Rust 1.94.1, all 218 tests pass: 214 retained upstream cases and four added
regressions, with no failures or ignored tests. The upstream vector runner has
one existing exclusion for empty-to-nonempty consistency semantics; it remains
explicit and unchanged. New tests cover:

- Maximum-size trees at the first and final leaf, exact proof lengths, truncated
  and extra hashes, and a substituted leaf. An empty proof and the erroneous
  one-hash path reject without panicking.
- Recursive RFC 6962 reference trees for sizes 1 through 65, covering all 2,145
  leaf positions and 2,145 nonempty prefix pairs. These definitions independently
  generate roots, inclusion proofs and consistency proofs. Substituted roots,
  leaves and proof hashes, truncated proofs and extra hashes reject.

Strict Clippy passes for all targets and features with warnings denied.
Workspace and fork formatting, locked main/fuzz metadata, generated Docker
consistency and whitespace checks pass.

## Remaining boundary

The verifier checks relationships between caller-supplied hashes and tree
positions. It does not authenticate a log checkpoint, bind a log identity or
establish freshness; Chio's owned verifier supplies those separate checks.
Empty-tree consistency alone cannot authenticate a new root.

The fork is unpublished and explicitly owned as local source by cargo-vet.
No certificate is issued for the defective registry bytes. No criterion,
exemption or imported trust authority is relaxed. Dependency audits and
qualification of the final frozen integration graph remain open.

Evidence is retained under
`output/process-security-20260915/sigstore-merkle-audit-6554383cc/` in the primary
checkout: the original archive, red reproduction, upstream repair metadata,
production diff, complete source hashes, selected graph, test output and lint
output. The active foundation run at `6554383cc` predates this fork selection
and cannot certify the changed dependency graph.
