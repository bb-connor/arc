# composed-baseline

The strongest alternative a competent engineer assembles today out of parts that
already exist, put through the same two corpora as the Chio cross-organization
receiver, so that "nothing else defines this object" can be checked rather than
asserted.

This is a standalone Cargo project, deliberately not a member of the Chio
workspace: it is the alternative, not part of the system under comparison, and
it carries its own lockfile so the parts it composes are pinned independently.

## The alternative

Four parts, each of which exists off the shelf:

- a tool-call server;
- a caller identity authenticated by a public key pinned out of band, which is
  what a federated workload-identity trust bundle installs (the issuance
  mechanism is left out, because the property at stake is peer authentication
  and not how the peer's key was obtained);
- a policy engine that evaluates the request against a local rule set and signs
  its decision;
- a receiver-side replay table keyed by a request identifier.

Its one dependency on Chio is `chio-core-types`, for Ed25519 and RFC 8785
canonical JSON. That is deliberate: both sides then sign and hash with the same
code, so a latency difference between them is a difference in what they check
and never a difference in whose primitives were linked. Its store is SQLite in
WAL with `synchronous = FULL`, which is what the Chio receipt store runs under,
so a per-call byte or millisecond figure taken here is comparable with one taken
there.

## Two wirings

The same code runs under two profiles, and both are reported.

`composed` is what the parts produce when each is used the way it documents
itself: the policy engine is handed a context built from the incoming request,
the signed decision is verified over the bytes it arrived in, and a tool call
carries no audience to check.

`hardened` is the same parts with every check an operator could reasonably add
written in: the policy context is built only from receiver-held records and a
request that supplies an attribute the receiver owns is refused, the decision
must be in its canonical encoding, the two pinned keys must be distinct, the
decision must name this receiver, an agreement the receiver has retired is
refused, and the rule that gates the action resolves its approval in the
receiver's own table and takes nothing from the request.

Neither is a straw man. Reporting the hardened wiring alone would credit the
composition with checks that no part of it requires; reporting the composed
wiring alone would understate what a careful operator reaches. The distance
between them is itself a result: the same three components yield either, and
nothing in the composition records which one an operator deployed.

## The admission path

Twenty-three numbered steps with a closed denial vocabulary, so a denial can be
reported at a step. `src/receiver.rs` carries the path and `DENIAL_CODES` the
vocabulary.

## Running it

```bash
cargo run --release --bin run-composed-baseline -- \
  --work-dir /tmp/composed-baseline-work \
  --out /tmp/composed-baseline.json \
  --calls 2000 --warmup 50
```

The paper's comparison is produced by
`docs/papers/programmable-sovereignty/bench/run-baseline-comparison.sh`, which
runs this driver, reads the Chio side from the committed bilateral-admission
result rather than re-measuring it, and writes the merged result together with
its TeX macros.
