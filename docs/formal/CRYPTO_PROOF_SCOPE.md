# Concrete hash checks and cryptographic assumptions

The concrete Kani checks use real portable SHA-256. Their obligations concern
bounded execution properties, not collision resistance. A source harness or CI
enrollment is not evidence that its obligation passed. `ASSUME-SHA256` in
`formal/assumptions.toml` remains the audited cryptographic assumption for
receipt, checkpoint, model-weight and TEE report-data bindings.

| Surface | Mandatory concrete check | Domain | Separate unproved obligation |
| --- | --- | --- | --- |
| `weights_hash_of` | Deterministic 64-character lowercase encoding | All four-byte messages | Distinct digest after flipping bit zero at each of four input positions |
| `expect_report_data` | OPEN/UNPROVED: determinism, zero upper-half padding and context-wrapper equivalence | All 256 key seeds and 32 root-byte positions | Distinct digest after reverting the selected root byte |

## Open attestation residual (owner decision, October 9)

`KANI-PROOF-QUAL` remains open. Its P1 follow-up is `KANI-ATTEST-DECOMP`.
The full-domain attestation encoding/noncollision obligation is unproved.
The concrete real-SHA harness for determinism, zero padding and context-wrapper
binding is also unfinished, with timeout and resource-refusal evidence retained.
The separate `ASSUME-SHA256` decision does not prove any of these properties.

For #1160 landing, exactly this attestation enrollment carries
`open_residual = "KANI-ATTEST-DECOMP"`. The runner reports OPEN/UNPROVED,
does not execute it, and excludes it from passed/executed totals. The complete
source, all 256 key seeds and 32 root positions, assertions and exact completion
cover remain pinned. Other enrollments remain required. No new proof campaign
is authorized for #1160; postmerge decomposition requires a reviewed contract.

No release claim, including D8 previews under ADR-0011, may state or rely on
this unproved obligation. Existing runtime controls and bounded proof evidence
keep their recorded scope. Landing with an open residual does not close it.
See [the residual audit](../security/audits/kani-open-residual-20261009.json).

Both mandatory harnesses select the bundled Kissat solver with Kani attributes
and retain strict unwinding assertions and an exact-named reachable completion
cover. The normal runners do not override the solver. An explicit command-line
solver selection takes precedence and must be recorded in qualification evidence.
The attestation profile resolves fresh loop identifiers and exact function/source roles,
checks the P256 encoder source roles, and bounds its five-byte prefix and
65-byte key loops at 6 and 66. It also checks the pinned SHA-256 compressor's
source roles and bounds its block loop at 3 and its 16-word loading loop at 17.
The largest compressor input in one call is two blocks: the 135-byte key string
feeds two full blocks and buffers seven bytes; the 32-byte root leaves 39 bytes
buffered; finalization compresses one padded block. These bounds apply per
compressor call, with all three SHA evaluations retained. The pinned U64 eager
padding loop is bounded at 65: a checked delimiter write into a 64-byte buffer
leaves at most 63 bytes to zero. The resolver requires the exact SHA-256 finalizer
instantiation and source role. Global bound 136 and all unwinding assertions
remain active. The report-data Kani model additionally asserts that its P256
fixture always uses the checked stack renderer. Compatibility rendering for
other algorithms is a failing assertion in this model, while production retains
the established fallback. This obligation is checked over the fixture's
original input domain, not a general renderer theorem for arbitrary algorithms.
The standalone profile requests no owned-renderer recursion selector. Explicit
function profiles still require their exact function to be present in a fresh
diagnostic. A truncated execution, unreachable completion,
timeout or tool failure cannot qualify a harness. No cryptographic function is
replaced with a nondeterministic oracle or an assumed result.

The original complete harnesses are preserved in each crate's
`src/kani_crypto_research.rs`, behind `cfg(kani)` and the opt-in `kani-research`
feature. That feature is selected explicitly, never through defaults or local
or dependency-feature aliases. Their domain, assertions and source hashes are recorded in
`formal/rust-verification/crypto-proof-scope.toml`. Strict 1800-second runs timed
out; neither a proof nor a counterexample was established. They are excluded
from `.kani/harnesses.toml` and from mandatory proof-coverage counts. To pursue
one explicitly, run cargo-kani with `--features kani-research --lib --harness
kani_crypto_research::<original_name> --exact` and retain unwinding checks and
the original completion cover. Opting in does not make the obligation proved.

Runtime controls supplement this boundary: the weights known-vector and
binding/tamper tests (including 1024 seeded four-byte bit-flip controls in
`hash_binding.rs`), all 8192 attestation seed/root cases in
`report_data_symbolic_domain.rs`, and the encoder's independent byte/hex
oracle. The runtime cases are concrete controls, not a proof of general
collision resistance. The encoder proof covers all 32-byte inputs and compares
every output digit against an independent nibble oracle.

`check-kani-crypto-scope.py` checks the mandatory/research separation, retained
source hashes, opt-in feature and explicit assumption. The scope manifest pins
each complete mandatory harness module, including its input constructors. This
rejects constant or narrowed symbolic inputs, removed assertions, new stubs or
assumptions, and fixtures that silently ignore the symbolic seed. A source hash
is a review boundary, not proof evidence. Rebinding it requires reviewing the
domain, assertions, fixtures and completion cover; it is not automatic codegen.
Changing this scope requires reviewing the assumption and acceptance contract
together.
