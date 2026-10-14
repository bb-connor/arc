# Two-family composition experiment

This lab runs synthetic support publication and confined research returns over
the unchanged `kernel-work-composition` model and B1. It is a compatibility
experiment, not a production adapter or an independent integration study.

```sh
cargo test --locked --manifest-path labs/kernel-work-families/Cargo.toml
cargo run --locked --manifest-path labs/kernel-work-families/Cargo.toml
python3 docs/research/kernel-work/verify_followthrough.py --record
python3 docs/research/kernel-work/verify_followthrough.py --check
```

The executable asserts and emits all 28 comparison cases, including 17 refusals
in the shared materialization adapter. The remaining 11 cases enter KW1 in each
arm. Three test functions additionally exercise changed family identity, missing
seeds, malformed payloads and positive/lost-ACK/revoked-audience behavior.

The support schema is a nonempty title of at most 96 bytes and a body of at most
512 bytes. Research has a separately approved seed (512-byte document and source
index 0-3) and an at-most-64-byte return with decision `accept` or `reject` and
evidence index 0-3. Unknown fields refuse. Those eight permitted return values
are an explicit declassification budget, not a proof of semantic correctness or
zero information flow. A caller-supplied `qualified_host` flag represents the
assumed trusted-host premise; it is not an attestation verifier.

Every approval carries the full typed payload value, family, channel, recipient
and source version. These are unsigned symbolic approvals assumed genuine under
the fixed principal mapping (0 and 1 confidentiality owners, 2 integrity owner).
The adapter checks exact equality before reducing one materialization to KW1's
version-1 symbols and recipient 5. Each run gets a fresh model namespace. No
claim about collisions across multiple artifacts, canonical byte cryptography,
global identity or live receiver qualification follows from this reduction.

All added correctness work is charged to both arms: schema checks, exact
materialization binding, fixed recipient mapping, qualified-host premise check,
seed refusal stopping the pipeline, and result availability/current audience
gating before release. No candidate-only policy exception or baseline penalty
is introduced. This is an adapter inventory, not an integration-time estimate.
The recovery/source/funding rules inside KW1 are unchanged.

The harness constructs a trace in two stages. It inspects only the controller's
read-result decision when deciding whether to append a release. Re-evaluating
that trace computes a model result from its initial state; it does not perform
the physical operation again. The fault oracle remains confined to `run`.

The seed path models admitted knowledge, not a launched sandbox. Return/error/
log/payment probes cover this declared interface; ambient filesystem, network,
streaming, provider-session reuse, timing and all other native confinement paths
are outside this lab. Full PR #1172 family acceptance needs the owning native
implementation and its own channel tests. See the
[G3 decision](../../docs/research/kernel-work/results/G3.md).
